//! Port of `ghidra.program.model.pcode.UnionFacetSymbol`.
//!
//! A specialized `HighSymbol` that directs the decompiler to use a specific field of a union when
//! interpreting a particular `PcodeOp` that accesses a Varnode whose data-type involves the union.
//! The symbol is stored as a dynamic variable annotation. The data-type must either be the union
//! itself or a pointer to the union. The first-use offset and dynamic hash identifying the
//! particular `PcodeOp`/Varnode affected, and the field number (the ordinal of the desired field
//! within the union), are currently both encoded into the symbol's *name* rather than tracked as
//! separate fields.
//!
//! In Java this `extends HighSymbol`; see
//! [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s module docs for the
//! shared "`extends X`" convention (composition, not inheritance). Like
//! [`EquateSymbol`](crate::program::model::pcode::equate_symbol::EquateSymbol) (not like
//! `HighLabelSymbol`/`HighExternalSymbol`/`HighFunctionShellSymbol`), this class's single Java
//! constructor calls the 4-arg `HighSymbol(long, String, DataType, HighFunction)` super
//! constructor, which sets `function` to the caller-supplied, real `HighFunction` -- so this port
//! genuinely stores `func: Arc<dyn HighFunction>` (no `AbsentHighFunction` stand-in needed), and
//! [`HighSymbol::get_program`] walks `func.get_function().get_program()` directly, exactly as
//! [`EquateSymbol`](crate::program::model::pcode::equate_symbol::EquateSymbol)'s module docs
//! explain in more detail.
//!
//! # Quirk: this class never attaches a mapping (`entryList` is always `null`)
//! Unlike `EquateSymbol` (whose two real constructors both build a `DynamicEntry` and
//! `addMapEntry` it), `UnionFacetSymbol`'s single constructor never calls `addMapEntry` at all --
//! and `UnionFacetSymbol` does not override `decode()` either (so the base `HighSymbol.decode()`,
//! which *would* populate `entryList`, is never reached through this class's own code -- this
//! port's [`high_symbol::HighSymbol::decode`] default is a no-op for the same reason documented on
//! that trait). This means that for every `UnionFacetSymbol` this port (or real Ghidra) can
//! actually construct, `entryList` stays `null` permanently, so
//! `getSize()`/`getPCAddress()`/`getStorage()`/`getMutability()` all throw
//! `NullPointerException` if ever called on a real instance -- and, critically, `encode()` itself
//! calls `encodeHeader()`, which calls `getMutability()`, so **`encode()` also always throws**.
//! This is reproduced faithfully: those four methods `panic!` unconditionally (there is no
//! "success" branch to fall back to, since no construction path here ever supplies a mapping), and
//! `encode()` panics for the same underlying reason. See
//! `getters_needing_a_mapping_panic_unconditionally` and `encode_panics_unconditionally` below.
//!
//! # Quirk: `extractAddressBased` can index past the end of the name
//! `extractAddressBased`'s bounds check only tests `nm.length() <= pos` (`pos` being the position
//! *within* `BASENAME`, i.e. `indexOf(BASENAME)`), not `pos + BASENAME.length()`, the actual index
//! it reads. A name that ends exactly at `BASENAME` (e.g. the literal string `"unionfacet"`) passes
//! that guard but then throws `StringIndexOutOfBoundsException` from `nm.charAt(pos +
//! BASENAME.length())`. This port reproduces the crash via an unguarded byte index rather than a
//! safe `.get()`; see `extract_address_based_panics_when_name_ends_exactly_at_basename` below.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Program;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_symbol::{HighSymbol, ID_BASE};
use crate::program::model::pcode::ids::{
    ATTRIB_ADDRTIED, ATTRIB_CAT, ATTRIB_FIELD, ATTRIB_HIDDENRETPARM, ATTRIB_ID, ATTRIB_INDEX,
    ATTRIB_MERGE, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_THISPTR, ATTRIB_TYPELOCK,
    ATTRIB_VOLATILE, ELEM_FACETSYMBOL,
};
use crate::program::model::pcode::Encoder;
use crate::program::model::data::mutability_settings_definition::{CONSTANT, VOLATILE};
use crate::program::seam_stubs::share_data_type;

/// Parse an integer the way `java.lang.Integer.decode(String)` does: optional leading `-`, then a
/// `0x`/`0X`/`#`-prefixed hex literal, a `0`-prefixed octal literal, or a plain decimal literal.
/// Used by [`UnionFacetSymbol::extract_field_number`].
///
/// # Panics
/// Panics if `s` is not a valid `Integer.decode` literal, mirroring Java's uncaught
/// `NumberFormatException`.
fn java_integer_decode(s: &str) -> i32 {
    let (negative, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (radix, digits) = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (16, hex)
    } else if let Some(hex) = rest.strip_prefix('#') {
        (16, hex)
    } else if rest.len() > 1 && rest.starts_with('0') {
        (8, &rest[1..])
    } else {
        (10, rest)
    };
    let magnitude = i32::from_str_radix(digits, radix)
        .unwrap_or_else(|e| panic!("Integer.decode(\"{s}\") failed (mirrors Java's NumberFormatException): {e}"));
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

/// A `HighSymbol` directing the decompiler to a specific union field. Port of
/// `ghidra.program.model.pcode.UnionFacetSymbol`.
pub struct UnionFacetSymbol {
    id: i64,
    name: String,
    dt: Arc<dyn DataType>,
    typelock: bool,
    namelock: bool,
    /// Ordinal of field within union being selected. Port of the private `fieldNumber` field.
    field_number: i32,
    /// Controls facets for any op at the address. Port of the private `isAddrBased` field.
    is_addr_based: bool,
    func: Arc<dyn HighFunction>,
}

impl UnionFacetSymbol {
    pub const BASENAME: &'static str = "unionfacet";

    /// Port of `UnionFacetSymbol(long, String, DataType, HighFunction)`.
    pub fn new(unique_id: i64, nm: impl Into<String>, dt: Box<dyn DataType>, func: Arc<dyn HighFunction>) -> Self {
        let nm = nm.into();
        let field_number = Self::extract_field_number(&nm);
        let is_addr_based = Self::extract_address_based(&nm);
        UnionFacetSymbol {
            id: unique_id,
            name: nm,
            dt: Arc::from(dt),
            typelock: false,
            namelock: false,
            field_number,
            is_addr_based,
            func,
        }
    }

    /// Generate an automatic symbol name, given a field number and address. Port of
    /// `UnionFacetSymbol.buildSymbolName(int, Address, boolean)`.
    pub fn build_symbol_name(fld_num: i32, addr: &Address, is_addr: bool) -> String {
        let mut buffer = String::new();
        buffer.push_str(Self::BASENAME);
        if is_addr {
            buffer.push('a');
        }
        buffer.push_str(&(fld_num + 1).to_string());
        buffer.push('_');
        buffer.push_str(&format!("{:x}", addr.unsigned_offset()));
        buffer
    }

    /// The actual field number is encoded in the symbol name. Port of
    /// `UnionFacetSymbol.extractFieldNumber(String)`.
    ///
    /// # Panics
    /// Panics if the numeric portion of `nm` is not a valid `Integer.decode` literal, mirroring
    /// Java's uncaught `NumberFormatException`.
    pub fn extract_field_number(nm: &str) -> i32 {
        let pos = match nm.find(Self::BASENAME) {
            Some(p) => p,
            None => return -1,
        };
        let mut pos = pos + Self::BASENAME.len();
        if nm.len() > pos && nm.as_bytes()[pos] == b'a' {
            pos += 1;
        }
        let endpos = match nm[pos..].find('_') {
            Some(rel) => pos + rel,
            None => return -1,
        };
        java_integer_decode(&nm[pos..endpos]) - 1
    }

    /// First character of `'a'` after `BASENAME` indicates an address-based facet. Port of
    /// `UnionFacetSymbol.extractAddressBased(String)`. See the module docs for the faithfully
    /// reproduced out-of-bounds panic when `nm` ends exactly at `BASENAME`.
    ///
    /// # Panics
    /// Panics if `nm` ends exactly at `BASENAME` (see the module docs).
    pub fn extract_address_based(nm: &str) -> bool {
        let pos = match nm.find(Self::BASENAME) {
            Some(p) => p,
            None => return false,
        };
        if nm.len() <= pos {
            return false;
        }
        // Unguarded index -- see the module docs' "Quirk" section: this can read past the end of
        // `nm` when it ends exactly at `BASENAME`, matching Java's `StringIndexOutOfBoundsException`.
        nm.as_bytes()[pos + Self::BASENAME.len()] == b'a'
    }

    /// Return true if the given data-type is either a union or a pointer to a union and is
    /// suitable for being the data-type of a `UnionFacetSymbol`. Port of
    /// `UnionFacetSymbol.isUnionType(DataType)`.
    #[allow(unused_assignments)] // `owned`'s initial `None` is only "dead" when a narrowing
    // branch below reassigns it; `current` keeps borrowing from whichever `owned` value is live,
    // so every assignment is meaningful even though the lint can't see that through the borrow.
    pub fn is_union_type(dt: &dyn DataType) -> bool {
        let mut owned: Option<Box<dyn DataType>> = None;
        let mut current: &dyn DataType = dt;

        if let Some(td) = current.as_typedef() {
            owned = Some(td.get_base_data_type());
            current = owned.as_ref().unwrap().as_ref();
        }
        if let Some(ptr) = current.as_pointer() {
            let inner = match ptr.get_data_type() {
                Some(i) => i,
                None => return false,
            };
            owned = Some(inner);
            current = owned.as_ref().unwrap().as_ref();
            if let Some(td2) = current.as_typedef() {
                let base2 = td2.get_base_data_type();
                owned = Some(base2);
                current = owned.as_ref().unwrap().as_ref();
            }
        }
        current.is_union()
    }

    /// Port of the protected inherited `HighSymbol.encodeHeader(Encoder)`, inlined here since it
    /// is not modeled as shared trait API (see
    /// [`high_symbol`](crate::program::model::pcode::high_symbol)'s module docs). Calls
    /// [`HighSymbol::get_mutability`], which -- for this class -- always panics (see the module
    /// docs' "Quirk" section), matching Java's `entryList[0]` NPE.
    fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
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
        // isThis/isHidden are always false for this class (never set by its one constructor, and
        // no addMapEntry call ever runs to flip them), so these branches never fire; the
        // constants are still referenced for documentation fidelity with Java's encodeHeader.
        let _ = (ATTRIB_THISPTR, ATTRIB_HIDDENRETPARM);
        encoder.write_signed_integer(ATTRIB_CAT, 2)?;
        // categoryIndex is always -1 for this class -> ATTRIB_INDEX is never written.
        let _ = ATTRIB_INDEX;
        Ok(())
    }
}

impl HighSymbol for UnionFacetSymbol {
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
        // `dt` is stored as `Arc<dyn DataType>` (rather than `Box<dyn DataType>`) specifically so
        // this `&self` method can hand back an owned handle without needing a `DataTypeManager`
        // (`DataType::clone_data_type` requires one); see `share_data_type`'s own docs and
        // `typedef_data_type.rs`'s module docs for this crate-wide precedent.
        share_data_type(&self.dt)
    }

    /// # Panics
    /// Always panics -- see the module docs' "Quirk" section (`entryList` is always `null` for
    /// this class).
    fn get_storage(&self) -> Box<dyn VariableStorage> {
        panic!(
            "UnionFacetSymbol has no attached mapping (entryList == null in Java, always, for \
             this class); see union_facet_symbol.rs module docs"
        )
    }

    /// # Panics
    /// Always panics -- see [`HighSymbol::get_storage`]'s panic message.
    fn get_size(&self) -> i32 {
        panic!(
            "UnionFacetSymbol has no attached mapping (entryList == null in Java, always, for \
             this class); see union_facet_symbol.rs module docs"
        )
    }

    /// # Panics
    /// Always panics -- see [`HighSymbol::get_storage`]'s panic message.
    fn get_pc_address(&self) -> Option<Address> {
        panic!(
            "UnionFacetSymbol has no attached mapping (entryList == null in Java, always, for \
             this class); see union_facet_symbol.rs module docs"
        )
    }

    /// # Panics
    /// Always panics -- see [`HighSymbol::get_storage`]'s panic message.
    fn get_mutability(&self) -> i32 {
        panic!(
            "UnionFacetSymbol has no attached mapping (entryList == null in Java, always, for \
             this class); see union_facet_symbol.rs module docs"
        )
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
        false // category is always 2 for this class, never 0
    }

    fn get_category_index(&self) -> i32 {
        -1 // never set away from the 4-arg HighSymbol super constructor's default
    }

    /// Port of `UnionFacetSymbol.encode(Encoder)`.
    ///
    /// # Panics
    /// Always panics -- `encodeHeader` calls [`HighSymbol::get_mutability`], which always panics
    /// for this class. See the module docs' "Quirk" section.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_FACETSYMBOL)?;
        self.encode_header(encoder)?;
        encoder.write_signed_integer(ATTRIB_FIELD, self.field_number as i64)?;
        encoder.write_bool(ATTRIB_ADDRTIED, self.is_addr_based)?;
        // `dtmanage.encodeTypeRef(encoder, type, getSize())` is unreachable in practice: encode()
        // already panics inside encode_header's get_mutability() call above for every instance
        // this port can construct (see the module docs), and PcodeDataTypeManager itself is not
        // ported in this crate regardless.
        encoder.close_element(ELEM_FACETSYMBOL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::function_definition::FunctionDefinition;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::typedef::TypeDef;
    use crate::program::model::data::union::Union;
    use crate::program::model::listing::{Function, FunctionSignature};
    use crate::program::model::pcode::decoder::{Decoder, DecoderError};
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::seam_stubs::PlaceholderDataType;
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

    struct MockFunction;
    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }
    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock_func".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
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
        fn set_return_type(&mut self, _data_type: Box<dyn DataType>, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!()
        }
        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
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
        fn add_parameter(&mut self, _var: Box<dyn crate::program::model::listing::Variable>, _source: crate::program::model::symbol::SourceType) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(&mut self, _from_ordinal: i32, _to_ordinal: i32) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }
        fn add_local_variable(&mut self, _var: Box<dyn crate::program::model::listing::Variable>, _source: crate::program::model::symbol::SourceType) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}
        fn set_body(&mut self, _new_body: &dyn crate::program::model::address::AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
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
        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
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
    fn build_symbol_name_and_extract_round_trip() {
        let addr = Address::new(ram_space(), 0x1000);
        let name = UnionFacetSymbol::build_symbol_name(2, &addr, false);
        assert_eq!(name, "unionfacet3_1000");
        assert_eq!(UnionFacetSymbol::extract_field_number(&name), 2);
        assert!(!UnionFacetSymbol::extract_address_based(&name));
    }

    #[test]
    fn build_symbol_name_marks_address_based_facets() {
        let addr = Address::new(ram_space(), 0x2000);
        let name = UnionFacetSymbol::build_symbol_name(0, &addr, true);
        assert_eq!(name, "unionfaceta1_2000");
        assert_eq!(UnionFacetSymbol::extract_field_number(&name), 0);
        assert!(UnionFacetSymbol::extract_address_based(&name));
    }

    #[test]
    fn extract_field_number_returns_minus_one_when_basename_absent() {
        assert_eq!(UnionFacetSymbol::extract_field_number("somethingelse"), -1);
    }

    #[test]
    fn extract_address_based_returns_false_when_basename_absent() {
        assert!(!UnionFacetSymbol::extract_address_based("somethingelse"));
    }

    /// See the module docs' "Quirk" section: `nm` ending exactly at `BASENAME` (with no trailing
    /// character at all) causes an unguarded out-of-bounds index, mirroring Java's
    /// `StringIndexOutOfBoundsException`.
    #[test]
    #[should_panic]
    fn extract_address_based_panics_when_name_ends_exactly_at_basename() {
        UnionFacetSymbol::extract_address_based(UnionFacetSymbol::BASENAME);
    }

    struct MockUnion;
    impl DataType for MockUnion {
        fn is_union(&self) -> bool {
            true
        }
    }

    #[test]
    fn is_union_type_true_for_a_direct_union() {
        assert!(UnionFacetSymbol::is_union_type(&MockUnion));
    }

    #[test]
    fn is_union_type_false_for_an_unrelated_type() {
        assert!(!UnionFacetSymbol::is_union_type(&PlaceholderDataType));
    }

    struct MockPointerToUnion;
    impl DataType for MockPointerToUnion {
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for MockPointerToUnion {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockUnion))
        }
        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not needed for this smoke test")
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn is_union_type_true_for_a_pointer_to_union() {
        assert!(UnionFacetSymbol::is_union_type(&MockPointerToUnion));
    }

    struct MockPointerToNothing;
    impl DataType for MockPointerToNothing {
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for MockPointerToNothing {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not needed for this smoke test")
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn is_union_type_false_for_a_pointer_to_nothing() {
        assert!(!UnionFacetSymbol::is_union_type(&MockPointerToNothing));
    }

    #[test]
    fn new_sets_id_name_field_number_and_address_based() {
        let addr = Address::new(ram_space(), 0x3000);
        let name = UnionFacetSymbol::build_symbol_name(4, &addr, true);
        let sym = UnionFacetSymbol::new(11, name.clone(), Box::new(MockUnion), mock_func());

        assert_eq!(sym.get_id(), 11);
        assert_eq!(sym.get_name(), name);
        assert_eq!(sym.field_number, 4);
        assert!(sym.is_addr_based);
        assert!(!sym.is_parameter()); // category == 2, never 0
        assert_eq!(sym.get_category_index(), -1);
        assert!(!sym.is_type_locked());
        assert!(!sym.is_name_locked());
    }

    #[test]
    fn get_program_walks_through_high_function() {
        let sym = UnionFacetSymbol::new(1, "unionfacet1_0", Box::new(MockUnion), mock_func());
        assert_eq!(Program::get_name(sym.get_program().as_ref()), "mock_program");
    }

    /// See the module docs' "Quirk" section: this class never attaches a mapping, so these four
    /// methods panic unconditionally, matching Java's `entryList[0]` NPE.
    #[test]
    fn getters_needing_a_mapping_panic_unconditionally() {
        let sym = UnionFacetSymbol::new(1, "unionfacet1_0", Box::new(MockUnion), mock_func());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_size())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_pc_address())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_storage())).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.get_mutability())).is_err());
    }

    #[derive(Default)]
    struct RecordingEncoder;
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
            Ok(())
        }
        fn close_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> io::Result<()> {
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

    /// See the module docs' "Quirk" section: `encode` always panics for this class.
    #[test]
    fn encode_panics_unconditionally() {
        let sym = UnionFacetSymbol::new(1, "unionfacet1_0", Box::new(MockUnion), mock_func());
        let mut encoder = RecordingEncoder;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sym.encode(&mut encoder)));
        assert!(result.is_err());
    }

    #[test]
    fn java_integer_decode_handles_decimal_hex_and_octal() {
        assert_eq!(java_integer_decode("42"), 42);
        assert_eq!(java_integer_decode("-7"), -7);
        assert_eq!(java_integer_decode("0x2A"), 42);
        assert_eq!(java_integer_decode("#2A"), 42);
        assert_eq!(java_integer_decode("052"), 42); // octal
    }

    // Silence unused-import warnings for narrowing traits only referenced via `dyn` bounds above.
    #[allow(unused_imports)]
    use {FunctionDefinition as _, TypeDef as _, Union as _};
}
