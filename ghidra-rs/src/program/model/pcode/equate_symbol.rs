//! Port of `ghidra.program.model.pcode.EquateSymbol`.
//!
//! A `HighSymbol` representing a named constant that replaces a raw numeric literal (or a numeric
//! literal being reformatted as hex/octal/binary/char/... rather than decimal) at a particular
//! `PcodeOp`/Varnode.
//!
//! In Java this `extends HighSymbol`; see
//! [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s module docs for the
//! shared "`extends X`" convention (composition, not inheritance) already established for this
//! `HighSymbol` hierarchy.
//!
//! # Deviation: `func` is stored for real, not `AbsentHighFunction`
//! Unlike `HighLabelSymbol`/`HighExternalSymbol`/`HighFunctionShellSymbol` (whose Java
//! constructors all route through the 6-arg `HighSymbol(..., PcodeDataTypeManager)` constructor,
//! which sets `function = null`), every `EquateSymbol` constructor calls the 4-arg
//! `HighSymbol(long, String, DataType, HighFunction)` (or the 1-arg `HighSymbol(HighFunction)`)
//! super constructor, both of which set `function = func` to the caller-supplied, real
//! `HighFunction`. So this port genuinely stores `func: Arc<dyn HighFunction>` and
//! [`HighSymbol::get_high_function`] simply clones it -- no `AbsentHighFunction`/panic stand-in is
//! needed here. [`HighSymbol::get_program`] is derived as `dtmanage.getProgram()` would be in Java
//! (`dtmanage = function.getDataTypeManager()`): since `PcodeDataTypeManager` is not ported here
//! (same gap the sibling classes document), this instead walks `func.getFunction().getProgram()`
//! directly, which is a real, always-available path through the already-ported [`HighFunction`]/
//! [`Function`](crate::program::model::listing::Function) traits (no extra constructor parameter
//! needed, unlike the siblings' `Program`/`ProgramArchitecture` injection, precisely because Java
//! already hands this constructor a real `HighFunction` to walk through).
//!
//! # Deviation: `DataType.DEFAULT` stand-in
//! Every constructor and `decode` sets `type = DataType.DEFAULT` and it is never anything else
//! for this class, so no mutable `type` field is stored at all --
//! [`HighSymbol::get_data_type`] always synthesizes a fresh value. `DataType.DEFAULT` itself (the
//! `DefaultDataType` singleton) is not ported; this uses
//! [`seam_stubs::undefined_data_type(1)`](crate::program::seam_stubs::undefined_data_type)
//! (a 1-byte "undefined" datatype) rather than the crate's more common `PlaceholderDataType`
//! (used by the sibling classes above), specifically because [`HighSymbol::get_size`] for this
//! class is derived from `get_data_type().get_length()` (mirroring `DynamicEntry.getSize()`,
//! see below) and `PlaceholderDataType::get_length()` defaults to `0`, which would silently make
//! every `EquateSymbol` report a wrong (`DataType.DEFAULT.getLength()` is `1` in real Ghidra) size.
//!
//! # Self-reference gap: no live `DynamicEntry`/`SymbolEntry`, and a faithfully-reproduced NPE
//! Java's two real constructors build `new DynamicEntry(this, addr, hash)` and attach it via the
//! protected `addMapEntry`, so `entryList[0]` is always populated *except* along the 1-arg
//! `EquateSymbol(HighFunction)` "for use with decode" constructor path. Constructing a `DynamicEntry`
//! that holds a live back-reference to `this` mid-construction has no direct Rust translation
//! (EquateSymbol would need to hold an `Arc` to itself before it exists), and separately, the real
//! `ghidra.program.model.pcode.DynamicEntry`/[`dynamic_entry::DynamicEntry`](crate::program::model::pcode::dynamic_entry::DynamicEntry)
//! trait in this crate is pinned to the older [`seam_stubs::HighSymbol`](crate::program::seam_stubs::HighSymbol)
//! placeholder rather than the real, now-ported [`high_symbol::HighSymbol`](crate::program::model::pcode::high_symbol::HighSymbol)
//! this struct implements (see [`symbol_entry`](crate::program::model::pcode::symbol_entry)'s
//! module docs -- reconciling that is explicitly called out there as a separate, larger change).
//! So instead of holding a `SymbolEntry`/`DynamicEntry` trait object, this struct stores the
//! mapping's two pieces of real state directly (`entry: Option<EquateEntry>` -- the constructed
//! `Address`/hash pair), and [`HighSymbol::get_storage`]/[`get_size`](HighSymbol::get_size)/
//! [`get_pc_address`](HighSymbol::get_pc_address)/[`get_mutability`](HighSymbol::get_mutability)
//! each reimplement the small amount of real `DynamicEntry` logic those methods would have
//! delegated to (`HashVariableStorage(hash)`, `getDataType().getLength()`, the stored `pcaddr`,
//! and a fixed `NORMAL`, respectively -- see `DynamicEntry.java`).
//!
//! Crucially, **`EquateSymbol.decode(Decoder)` never calls `addMapEntry`** (unlike the base
//! `HighSymbol.decode`, which `EquateSymbol` does not call `super.decode()`): it only decodes the
//! header, the format/convert code, and the numeric value. This means an `EquateSymbol` built via
//! the 1-arg decode constructor and then decoded still has `entry == None` (`entryList == null` in
//! Java) afterwards, so `getSize()`/`getPCAddress()`/`getStorage()`/`getMutability()` (and, via
//! `encodeHeader`'s call to `getMutability()`, `encode()` itself) would throw a
//! `NullPointerException` in real Ghidra on that path. This port reproduces that exactly: each of
//! those methods `panic!`s with a message documenting the gap when `entry` is `None`, rather than
//! fabricating a mapping. See `methods_needing_a_mapping_panic_when_constructed_for_decode_only`
//! below for a test proving it.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::mutability_settings_definition::NORMAL;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::Program;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::pcode::ids::{
    ATTRIB_CAT, ATTRIB_CONTENT, ATTRIB_FORMAT, ATTRIB_HIDDENRETPARM, ATTRIB_ID, ATTRIB_INDEX,
    ATTRIB_MERGE, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_THISPTR, ATTRIB_TYPELOCK,
    ATTRIB_VOLATILE, ELEM_EQUATESYMBOL, ELEM_VALUE,
};
use crate::program::seam_stubs::{undefined_data_type, HashVariableStorage};
use crate::program::model::data::mutability_settings_definition::{CONSTANT, VOLATILE};

fn decode_err(e: crate::program::model::pcode::decoder::DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode EquateSymbol", e)
}

/// A single mapping's real state: the `DynamicEntry`'s `pcaddr`/`hash`. See the module docs for
/// why this is stored directly rather than as a `SymbolEntry`/`DynamicEntry` trait object.
#[derive(Debug, Clone)]
struct EquateEntry {
    pc_address: Option<Address>,
    hash: i64,
}

/// A `HighSymbol` for a named constant/integer-format annotation. Port of
/// `ghidra.program.model.pcode.EquateSymbol`.
pub struct EquateSymbol {
    id: i64,
    name: String,
    value: i64,
    convert: i32,
    /// Sub-class of symbol; `-1`=none, `0`=parameter, `1`=equate. Port of the inherited
    /// `HighSymbol.category` field. Real constructors set this to `1`; the 1-arg decode
    /// constructor leaves it at Java's uninitialized `int` default of `0` (see the module docs on
    /// [`EquateSymbol::new_for_decode`]); `decodeHeader` resets it to `-1` before possibly
    /// re-reading `ATTRIB_CAT` from the stream.
    category: i32,
    category_index: i32,
    typelock: bool,
    namelock: bool,
    is_this: bool,
    is_hidden: bool,
    func: Arc<dyn HighFunction>,
    entry: Option<EquateEntry>,
}

impl EquateSymbol {
    pub const FORMAT_DEFAULT: i32 = 0;
    pub const FORMAT_HEX: i32 = 1;
    pub const FORMAT_DEC: i32 = 2;
    pub const FORMAT_OCT: i32 = 3;
    pub const FORMAT_BIN: i32 = 4;
    pub const FORMAT_CHAR: i32 = 5;
    pub const FORMAT_FLOAT: i32 = 6;
    pub const FORMAT_DOUBLE: i32 = 7;

    /// For use with [`HighSymbol::decode`]. Port of `EquateSymbol(HighFunction func)`, which
    /// calls the 1-arg protected `HighSymbol(HighFunction)` super constructor. That constructor
    /// leaves `name`/`type` at Java's `null` defaults, and -- critically -- leaves `category`/
    /// `categoryIndex`/`id` at Java's uninitialized-`int`/`long` defaults of `0`, *not* the `-1`
    /// the 4-arg constructor explicitly sets. This means a freshly-`new_for_decode`d symbol has
    /// `is_parameter() == true` (`category == 0`) until `decode` runs and resets it, a real Java
    /// quirk reproduced here rather than defaulting `category` to `-1` for tidiness. See
    /// `new_for_decode_has_category_zero_until_decoded` below.
    pub fn new_for_decode(func: Arc<dyn HighFunction>) -> Self {
        EquateSymbol {
            id: 0,
            name: String::new(),
            value: 0,
            convert: Self::FORMAT_DEFAULT,
            category: 0,
            category_index: 0,
            typelock: false,
            namelock: false,
            is_this: false,
            is_hidden: false,
            func,
            entry: None,
        }
    }

    /// Construct a plain named-equate symbol. Port of
    /// `EquateSymbol(long, String, long, HighFunction, Address, long)`.
    pub fn new(
        unique_id: i64,
        nm: impl Into<String>,
        val: i64,
        func: Arc<dyn HighFunction>,
        addr: Address,
        hash: i64,
    ) -> Self {
        EquateSymbol {
            id: unique_id,
            name: nm.into(),
            value: val,
            convert: Self::FORMAT_DEFAULT,
            category: 1,
            category_index: -1,
            typelock: false,
            namelock: false,
            is_this: false,
            is_hidden: false,
            func,
            entry: Some(EquateEntry { pc_address: Some(addr), hash }),
        }
    }

    /// Construct an integer-format-conversion equate symbol (name is left empty; the format code
    /// is stored directly rather than derived from a name string). Port of
    /// `EquateSymbol(long, int, long, HighFunction, Address, long)`.
    pub fn new_with_convert(
        unique_id: i64,
        conv: i32,
        val: i64,
        func: Arc<dyn HighFunction>,
        addr: Address,
        hash: i64,
    ) -> Self {
        EquateSymbol {
            id: unique_id,
            name: String::new(),
            value: val,
            convert: conv,
            category: 1,
            category_index: -1,
            typelock: false,
            namelock: false,
            is_this: false,
            is_hidden: false,
            func,
            entry: Some(EquateEntry { pc_address: Some(addr), hash }),
        }
    }

    /// The value of the equate. Port of `EquateSymbol.getValue()`.
    pub fn get_value(&self) -> i64 {
        self.value
    }

    /// Non-zero if this is a conversion equate. Port of `EquateSymbol.getConvert()`.
    pub fn get_convert(&self) -> i32 {
        self.convert
    }

    /// Port of the protected inherited `HighSymbol.decodeHeader(Decoder)`, inlined here since it
    /// is not modeled as shared trait API (see
    /// [`high_symbol`](crate::program::model::pcode::high_symbol)'s module docs). Deliberately
    /// does not touch `self.entry` -- Java's `decodeHeader` never touches `entryList` either.
    fn decode_header(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        self.name = String::new();
        self.id = 0;
        self.typelock = false;
        self.namelock = false;
        self.is_this = false;
        self.is_hidden = false;
        self.category_index = -1;
        self.category = -1;

        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            } else if attrib_id == ATTRIB_ID.id {
                self.id = decoder.read_unsigned_integer().map_err(decode_err)? as i64;
            } else if attrib_id == ATTRIB_TYPELOCK.id {
                self.typelock = decoder.read_bool().map_err(decode_err)?;
            } else if attrib_id == ATTRIB_NAMELOCK.id {
                self.namelock = decoder.read_bool().map_err(decode_err)?;
            } else if attrib_id == ATTRIB_THISPTR.id {
                self.is_this = decoder.read_bool().map_err(decode_err)?;
            } else if attrib_id == ATTRIB_HIDDENRETPARM.id {
                self.is_hidden = decoder.read_bool().map_err(decode_err)?;
            } else if attrib_id == ATTRIB_NAME.id {
                self.name = decoder.read_string().map_err(decode_err)?;
            } else if attrib_id == ATTRIB_CAT.id {
                self.category = decoder.read_signed_integer().map_err(decode_err)? as i32;
            } else if attrib_id == ATTRIB_INDEX.id {
                self.category_index = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
            }
        }
        if self.id == 0 {
            return Err(DecoderException::new("missing unique symbol id"));
        }
        Ok(())
    }

    /// Port of the protected inherited `HighSymbol.encodeHeader(Encoder)`, inlined here for the
    /// same reason as [`EquateSymbol::decode_header`]. Note this calls
    /// [`HighSymbol::get_mutability`], which panics if `self.entry` is `None` -- matching Java's
    /// `entryList[0].getMutability()` NPE on that same path (see the module docs).
    fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        use crate::program::model::pcode::high_symbol::ID_BASE;
        if (self.id >> 56) != (ID_BASE >> 56) {
            encoder.write_unsigned_integer(ATTRIB_ID, self.id as u64)?;
        }
        encoder.write_string(ATTRIB_NAME, &self.name)?;
        encoder.write_bool(ATTRIB_TYPELOCK, self.typelock)?;
        encoder.write_bool(ATTRIB_NAMELOCK, self.namelock)?;
        let mutability = self.get_mutability();
        if mutability == CONSTANT {
            encoder.write_bool(ATTRIB_READONLY, true)?;
        } else if mutability == VOLATILE {
            encoder.write_bool(ATTRIB_VOLATILE, true)?;
        }
        if self.is_isolated() {
            encoder.write_bool(ATTRIB_MERGE, false)?;
        }
        if self.is_this {
            encoder.write_bool(ATTRIB_THISPTR, true)?;
        }
        if self.is_hidden {
            encoder.write_bool(ATTRIB_HIDDENRETPARM, true)?;
        }
        encoder.write_signed_integer(ATTRIB_CAT, self.category as i64)?;
        if self.category_index >= 0 {
            encoder.write_unsigned_integer(ATTRIB_INDEX, self.category_index as u64)?;
        }
        Ok(())
    }

    /// Get the name of the corresponding conversion for an integer format code, or `"_"` if
    /// `convert` doesn't match any known format. Port of `EquateSymbol.getIntegerFormatString(int)`.
    pub fn get_integer_format_string(convert: i32) -> &'static str {
        if convert == Self::FORMAT_HEX {
            "hex"
        } else if convert == Self::FORMAT_DEC {
            "dec"
        } else if convert == Self::FORMAT_OCT {
            "oct"
        } else if convert == Self::FORMAT_BIN {
            "bin"
        } else if convert == Self::FORMAT_CHAR {
            "char"
        } else if convert == Self::FORMAT_FLOAT {
            "float"
        } else if convert == Self::FORMAT_DOUBLE {
            "double"
        } else {
            "_"
        }
    }

    /// Get the matching conversion type for a format name, or `FORMAT_DEFAULT` if there is no
    /// match. Port of `EquateSymbol.getFormatStringValue(String)`.
    pub fn get_format_string_value(format: &str) -> i32 {
        match format {
            "hex" => Self::FORMAT_HEX,
            "dec" => Self::FORMAT_DEC,
            "oct" => Self::FORMAT_OCT,
            "bin" => Self::FORMAT_BIN,
            "char" => Self::FORMAT_CHAR,
            "float" => Self::FORMAT_FLOAT,
            "double" => Self::FORMAT_DOUBLE,
            _ => Self::FORMAT_DEFAULT,
        }
    }

    /// Determine what format a given equate name is in. Port of `EquateSymbol.convertName(String,
    /// long)`. `val` is accepted (matching the Java signature) but, faithfully, unused -- the real
    /// method never reads its `val` parameter either.
    ///
    /// # Panics
    /// Panics if `nm` is empty, mirroring Java's uncaught `StringIndexOutOfBoundsException` from
    /// `nm.charAt(0)` on an empty equate name.
    pub fn convert_name(nm: &str, val: i64) -> i32 {
        let _ = val;
        let chars: Vec<char> = nm.chars().collect();
        let mut pos = 0usize;
        let mut first_char = chars[pos];
        pos += 1;
        if first_char == '-' {
            if chars.len() > pos {
                first_char = chars[pos];
                pos += 1;
            } else {
                return Self::FORMAT_DEFAULT;
            }
        }
        let _ = pos; // matches Java: `pos` is otherwise unread past this point (see below).
        match first_char {
            '\'' | '"' => return Self::FORMAT_CHAR,
            '0' => {
                if chars.len() >= 2 && chars[1] == 'x' {
                    return Self::FORMAT_HEX;
                }
                // No `break` in the Java source: falls through into the '1'..='9' case, i.e.
                // simply continues on to the second switch below.
            }
            '1'..='9' => {}
            'A'..='F' => {
                // Java hardcodes indices 2/1 here rather than deriving them from `pos` -- see the
                // module docs' "faithfully reproduced" note and this method's own doc comment.
                if chars.len() >= 3 && chars[2] == 'h' {
                    let second_char = chars[1];
                    if second_char.is_ascii_digit() || ('A'..='F').contains(&second_char) {
                        return Self::FORMAT_CHAR;
                    }
                }
                return Self::FORMAT_DEFAULT;
            }
            _ => return Self::FORMAT_DEFAULT,
        }
        match chars[chars.len() - 1] {
            'b' => Self::FORMAT_BIN,
            'o' => Self::FORMAT_OCT,
            '\'' | '"' | 'h' => Self::FORMAT_CHAR,
            _ => Self::FORMAT_DEC,
        }
    }
}

impl HighSymbol for EquateSymbol {
    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_high_function(&self) -> Arc<dyn HighFunction> {
        self.func.clone()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.func.get_function().get_program()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        undefined_data_type(1)
    }

    fn get_storage(&self) -> Box<dyn VariableStorage> {
        match &self.entry {
            Some(e) => Box::new(HashVariableStorage(e.hash)),
            None => panic!(
                "EquateSymbol has no attached mapping (entryList == null in Java); this symbol \
                 was constructed via new_for_decode and EquateSymbol.decode never calls \
                 addMapEntry -- see equate_symbol.rs module docs"
            ),
        }
    }

    fn get_size(&self) -> i32 {
        match &self.entry {
            Some(_) => self.get_data_type().get_length(),
            None => panic!(
                "EquateSymbol has no attached mapping (entryList == null in Java); see \
                 equate_symbol.rs module docs"
            ),
        }
    }

    fn get_pc_address(&self) -> Option<Address> {
        match &self.entry {
            Some(e) => e.pc_address.clone(),
            None => panic!(
                "EquateSymbol has no attached mapping (entryList == null in Java); see \
                 equate_symbol.rs module docs"
            ),
        }
    }

    fn get_mutability(&self) -> i32 {
        match &self.entry {
            Some(_) => NORMAL,
            None => panic!(
                "EquateSymbol has no attached mapping (entryList == null in Java); see \
                 equate_symbol.rs module docs"
            ),
        }
    }

    fn is_type_locked(&self) -> bool {
        self.typelock
    }

    fn is_name_locked(&self) -> bool {
        self.namelock
    }

    fn set_type_lock(&mut self, typelock: bool) {
        self.typelock = typelock;
    }

    fn set_name_lock(&mut self, namelock: bool) {
        self.namelock = namelock;
    }

    fn is_parameter(&self) -> bool {
        self.category == 0
    }

    fn get_category_index(&self) -> i32 {
        self.category_index
    }

    fn is_this_pointer(&self) -> bool {
        self.is_this
    }

    fn is_hidden_return(&self) -> bool {
        self.is_hidden
    }

    fn get_dynamic_hash(&self) -> Option<i64> {
        self.entry.as_ref().map(|e| e.hash)
    }

    /// Port of `EquateSymbol.encode(Encoder)`.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_EQUATESYMBOL)?;
        self.encode_header(encoder)?;
        if self.convert != 0 {
            let form_string = Self::get_integer_format_string(self.convert);
            encoder.write_string(ATTRIB_FORMAT, form_string)?;
        }
        encoder.open_element(ELEM_VALUE)?;
        encoder.write_unsigned_integer(ATTRIB_CONTENT, self.value as u64)?;
        encoder.close_element(ELEM_VALUE)?;
        encoder.close_element(ELEM_EQUATESYMBOL)
    }

    /// Port of `EquateSymbol.decode(Decoder)`. Deliberately does not call `addMapEntry` -- see the
    /// module docs.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let symel = decoder.open_element_with_id(ELEM_EQUATESYMBOL).map_err(decode_err)?;
        self.decode_header(decoder)?;
        // `type = DataType.DEFAULT;` -- no-op here, since `get_data_type` always synthesizes it.
        self.convert = Self::FORMAT_DEFAULT;
        decoder.rewind_attributes();
        let mut form_string: Option<String> = None;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_FORMAT.id {
                form_string = Some(decoder.read_string().map_err(decode_err)?);
            }
        }
        if let Some(fs) = form_string {
            self.convert = Self::get_format_string_value(&fs);
        }
        let valel = decoder.open_element_with_id(ELEM_VALUE).map_err(decode_err)?;
        self.value = decoder.read_unsigned_integer_with_id(ATTRIB_CONTENT).map_err(decode_err)? as i64;
        decoder.close_element(valel).map_err(decode_err)?;
        decoder.close_element(symel).map_err(decode_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{Function, FunctionSignature, FunctionTag, Parameter, Variable};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};
    use crate::program::seam_stubs::{StackFrame, VariableFilter};
    use std::io;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockSymbol {
        id: i64,
        name: String,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            Address::new(ram_space(), 0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    /// Full [`Function`] mock (mirroring
    /// [`high_function_symbol`](crate::program::model::pcode::high_function_symbol)'s own
    /// `MockFunction` precedent, needed for exactly the same reason: this port's `EquateSymbol`,
    /// like `HighFunctionSymbol`, is always constructed with a real, non-null `HighFunction`, so
    /// `get_program()` must genuinely walk `func.get_function().get_program()` -- see the module
    /// docs): only `get_name`/`get_program`/`get_entry_point` are given real bodies; everything
    /// else is required by the trait but is provably unreachable from `EquateSymbol`'s call paths.
    struct MockFunction;
    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol { id: 0, name: "mock_func".to_string() })
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }
    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock_func".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!()
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            Address::new(ram_space(), 0x1000)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(&mut self, _data_type: Box<dyn DataType>, _source: SourceType) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!()
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, _purge_size: i32) {}
        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
        #[allow(deprecated)]
        fn add_parameter(&mut self, _var: Box<dyn Variable>, _source: SourceType) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(&mut self, _from_ordinal: i32, _to_ordinal: i32) -> Result<Box<dyn Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn add_local_variable(&mut self, _var: Box<dyn Variable>, _source: SourceType) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(&mut self, _new_body: &dyn AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn is_inline(&self) -> bool {
            false
        }
        fn set_inline(&mut self, _is_inline: bool) {}
        fn has_no_return(&self) -> bool {
            false
        }
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn has_custom_variable_storage(&self) -> bool {
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn is_thunk(&self) -> bool {
            false
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    struct MockHighFunction;
    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn Function> {
            Box::new(MockFunction)
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_symbol_map(&self) -> Box<dyn crate::program::seam_stubs::LocalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_global_symbol_map(&self) -> Arc<dyn crate::program::model::pcode::global_symbol_map::GlobalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
            _vn: &crate::program::model::pcode::Varnode,
        ) -> Result<
            Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
            crate::program::model::pcode::pcode_exception::PcodeException,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn encode(
            &self,
            _encoder: &mut dyn Encoder,
            _id: i64,
            _namespace: &dyn crate::program::model::symbol::Namespace,
            _entry_point: Option<Address>,
            _size: i32,
        ) -> io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_volatile(&mut self, _vn: &crate::program::model::pcode::Varnode, _val: bool) {
            unimplemented!("not needed for this smoke test")
        }
    }

    fn mock_func() -> Arc<dyn HighFunction> {
        Arc::new(MockHighFunction)
    }

    #[test]
    fn new_sets_category_one_and_fixed_fields() {
        let addr = Address::new(ram_space(), 0x1000);
        let sym = EquateSymbol::new(5, "MY_EQUATE", 42, mock_func(), addr, 0xdead);

        assert_eq!(sym.get_id(), 5);
        assert_eq!(sym.get_name(), "MY_EQUATE");
        assert_eq!(sym.get_value(), 42);
        assert_eq!(sym.get_convert(), EquateSymbol::FORMAT_DEFAULT);
        assert!(!sym.is_parameter()); // category == 1, not 0
        assert_eq!(sym.get_category_index(), -1);
        assert!(!sym.is_type_locked());
        assert!(!sym.is_name_locked());
        assert!(!sym.is_this_pointer());
        assert!(!sym.is_hidden_return());
        assert_eq!(sym.get_dynamic_hash(), Some(0xdead));
    }

    #[test]
    fn new_with_convert_has_empty_name_and_stores_convert_code() {
        let addr = Address::new(ram_space(), 0x2000);
        let sym = EquateSymbol::new_with_convert(6, EquateSymbol::FORMAT_HEX, 255, mock_func(), addr, 7);

        assert_eq!(sym.get_name(), "");
        assert_eq!(sym.get_convert(), EquateSymbol::FORMAT_HEX);
    }

    /// The 1-arg decode constructor leaves `category` at Java's `int` default of `0`, so
    /// `isParameter()` reports `true` until `decode` resets it -- see the module docs and
    /// [`EquateSymbol::new_for_decode`]'s own doc comment.
    #[test]
    fn new_for_decode_has_category_zero_until_decoded() {
        let sym = EquateSymbol::new_for_decode(mock_func());
        assert!(sym.is_parameter());
        assert_eq!(sym.get_id(), 0);
        assert_eq!(sym.get_name(), "");
    }

    /// `getSize`/`getPCAddress`/`getStorage`/`getMutability` all panic (mirroring Java's
    /// `entryList[0]` NPE) on a symbol built via `new_for_decode`, since `EquateSymbol.decode`
    /// never populates `entryList`/`entry`. See the module docs.
    #[test]
    fn methods_needing_a_mapping_panic_when_constructed_for_decode_only() {
        let sym = EquateSymbol::new_for_decode(mock_func());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_size())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_pc_address())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_storage())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_mutability())).is_err());
    }

    /// A symbol built via the real `new` constructor has a live mapping, so the same four methods
    /// succeed and return values consistent with the constructed `addr`/`hash`.
    #[test]
    fn methods_needing_a_mapping_succeed_for_a_real_constructor() {
        let addr = Address::new(ram_space(), 0x3000);
        let sym = EquateSymbol::new(1, "X", 1, mock_func(), addr.clone(), 99);

        assert_eq!(sym.get_size(), 1); // DataType.DEFAULT stand-in has length 1
        assert_eq!(sym.get_pc_address(), Some(addr));
        assert!(sym.get_storage().is_hash_storage());
        assert_eq!(sym.get_mutability(), NORMAL);
    }

    #[test]
    fn get_program_walks_through_high_function() {
        let sym = EquateSymbol::new(1, "X", 1, mock_func(), Address::new(ram_space(), 0), 0);
        assert_eq!(Program::get_name(sym.get_program().as_ref()), "mock_program");
    }

    #[test]
    fn get_integer_format_string_round_trips_get_format_string_value() {
        let pairs = [
            (EquateSymbol::FORMAT_HEX, "hex"),
            (EquateSymbol::FORMAT_DEC, "dec"),
            (EquateSymbol::FORMAT_OCT, "oct"),
            (EquateSymbol::FORMAT_BIN, "bin"),
            (EquateSymbol::FORMAT_CHAR, "char"),
            (EquateSymbol::FORMAT_FLOAT, "float"),
            (EquateSymbol::FORMAT_DOUBLE, "double"),
        ];
        for (code, name) in pairs {
            assert_eq!(EquateSymbol::get_integer_format_string(code), name);
            assert_eq!(EquateSymbol::get_format_string_value(name), code);
        }
        assert_eq!(EquateSymbol::get_integer_format_string(999), "_");
        assert_eq!(EquateSymbol::get_format_string_value("nonsense"), EquateSymbol::FORMAT_DEFAULT);
    }

    #[test]
    fn convert_name_recognizes_quotes_as_char() {
        assert_eq!(EquateSymbol::convert_name("'a'", 0), EquateSymbol::FORMAT_CHAR);
        assert_eq!(EquateSymbol::convert_name("\"a\"", 0), EquateSymbol::FORMAT_CHAR);
    }

    #[test]
    fn convert_name_recognizes_hex_prefix() {
        assert_eq!(EquateSymbol::convert_name("0x1f", 0), EquateSymbol::FORMAT_HEX);
    }

    /// `case '0':` has no `break` in the Java source, so a `'0'` that isn't followed by `'x'`
    /// falls through to the `'1'..='9'` handling (i.e. continues to the trailing-character
    /// switch) rather than returning `FORMAT_DEFAULT`. See `convert_name`'s doc comment.
    #[test]
    fn convert_name_zero_without_x_falls_through_like_java() {
        // "07" -> not hex (no 'x'), falls through, trailing char '7' isn't b/o/'/"/h -> FORMAT_DEC
        assert_eq!(EquateSymbol::convert_name("07", 0), EquateSymbol::FORMAT_DEC);
        // "01b" -> falls through, trailing char 'b' -> FORMAT_BIN
        assert_eq!(EquateSymbol::convert_name("01b", 0), EquateSymbol::FORMAT_BIN);
    }

    #[test]
    fn convert_name_recognizes_trailing_suffixes() {
        assert_eq!(EquateSymbol::convert_name("101b", 0), EquateSymbol::FORMAT_BIN);
        assert_eq!(EquateSymbol::convert_name("17o", 0), EquateSymbol::FORMAT_OCT);
        assert_eq!(EquateSymbol::convert_name("41h", 0), EquateSymbol::FORMAT_CHAR);
        assert_eq!(EquateSymbol::convert_name("123", 0), EquateSymbol::FORMAT_DEC);
    }

    /// Leading `A`-`F` hex-looking names ending in `h` are `FORMAT_CHAR` (an "unrepresentable
    /// character" encoding), but only when at least 3 characters long.
    #[test]
    fn convert_name_recognizes_hex_digit_leading_char_encoding() {
        assert_eq!(EquateSymbol::convert_name("41h", 0), EquateSymbol::FORMAT_CHAR);
        assert_eq!(EquateSymbol::convert_name("Ah", 0), EquateSymbol::FORMAT_DEFAULT); // too short
    }

    #[test]
    fn convert_name_rejects_unrecognized_leading_char() {
        assert_eq!(EquateSymbol::convert_name("xyz", 0), EquateSymbol::FORMAT_DEFAULT);
    }

    /// Reproduces Java's uncaught `StringIndexOutOfBoundsException` on an empty equate name.
    #[test]
    #[should_panic]
    fn convert_name_panics_on_empty_string() {
        EquateSymbol::convert_name("", 0);
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<ElementId>,
        closed: Vec<ElementId>,
        bools: Vec<(AttributeId, bool)>,
        strings: Vec<(AttributeId, String)>,
        signed: Vec<(AttributeId, i64)>,
        unsigned: Vec<(AttributeId, u64)>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opened.push(elem_id);
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.closed.push(elem_id);
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.bools.push((attrib_id, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.signed.push((attrib_id, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.unsigned.push((attrib_id, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, format!("[{index}]{val}")));
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_header_and_value_but_no_format_when_convert_is_default() {
        let addr = Address::new(ram_space(), 0x4000);
        let sym = EquateSymbol::new(9, "EQ", 123, mock_func(), addr, 1);

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, vec![ELEM_EQUATESYMBOL, ELEM_VALUE]);
        assert_eq!(encoder.closed, vec![ELEM_VALUE, ELEM_EQUATESYMBOL]);
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "EQ".to_string())));
        assert!(!encoder.strings.iter().any(|(id, _)| *id == ATTRIB_FORMAT));
        assert!(encoder.unsigned.contains(&(ATTRIB_CONTENT, 123)));
        assert!(encoder.signed.contains(&(ATTRIB_CAT, 1)));
        assert!(!encoder.unsigned.iter().any(|(id, _)| *id == ATTRIB_INDEX)); // categoryIndex == -1
    }

    #[test]
    fn encode_writes_format_attribute_when_convert_is_set() {
        let addr = Address::new(ram_space(), 0x5000);
        let sym = EquateSymbol::new_with_convert(10, EquateSymbol::FORMAT_HEX, 255, mock_func(), addr, 2);

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert!(encoder.strings.contains(&(ATTRIB_FORMAT, "hex".to_string())));
    }

    /// `encode` panics on a decode-only symbol, since `encodeHeader` calls `getMutability()`,
    /// which panics with no mapping -- matching Java's NPE. See the module docs.
    #[test]
    fn encode_panics_when_constructed_for_decode_only() {
        let sym = EquateSymbol::new_for_decode(mock_func());
        let mut encoder = RecordingEncoder::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.encode(&mut encoder)));
        assert!(result.is_err());
    }

    struct MockDecoder {
        attrs: Vec<(i32, DecodedAttr)>,
        step: std::sync::atomic::AtomicUsize,
        content: u64,
    }

    #[derive(Clone)]
    enum DecodedAttr {
        Str(String),
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let step = self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if step < self.attrs.len() {
                Ok(self.attrs[step].0)
            } else {
                Ok(0)
            }
        }
        fn rewind_attributes(&self) {
            self.step.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            // Only ATTRIB_ID is read via the no-id overload in decode_header, and this test's
            // MockDecoder always supplies a non-zero id via `attrs`.
            Ok(7)
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            if attrib_id == ATTRIB_CONTENT {
                Ok(self.content)
            } else {
                Ok(0)
            }
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            let step = self.step.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
            match &self.attrs[step].1 {
                DecodedAttr::Str(s) => Ok(s.clone()),
            }
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    /// `decode` reads the header (id/name), the `ATTRIB_FORMAT` string (via the second,
    /// rewound pass), and the value -- but never populates `entry`, matching Java's
    /// `EquateSymbol.decode` (see the module docs).
    #[test]
    fn decode_reads_header_format_and_value_but_never_populates_entry() {
        let decoder = MockDecoder {
            attrs: vec![
                (ATTRIB_ID.id, DecodedAttr::Str(String::new())),
                (ATTRIB_NAME.id, DecodedAttr::Str("MYNAME".to_string())),
                (ATTRIB_FORMAT.id, DecodedAttr::Str("hex".to_string())),
            ],
            step: std::sync::atomic::AtomicUsize::new(0),
            content: 0xabc,
        };

        let mut sym = EquateSymbol::new_for_decode(mock_func());
        sym.decode(&decoder).unwrap();

        assert_eq!(sym.get_name(), "MYNAME");
        assert_eq!(sym.get_id(), 7);
        assert_eq!(sym.get_convert(), EquateSymbol::FORMAT_HEX);
        assert_eq!(sym.get_value(), 0xabc);
        assert!(sym.entry.is_none());
    }
}
