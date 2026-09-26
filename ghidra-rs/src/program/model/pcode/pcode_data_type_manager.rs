//! Port of `ghidra.program.model.pcode.PcodeDataTypeManager`.
//!
//! Class for marshaling [`DataType`] objects to and from the Decompiler.
//!
//! `PcodeDataTypeManager` sits at the hub of a dependency cycle with several collaborators that
//! are not yet ported (`AddressXML`, the rest of `PcodeFactory`, `LocalSymbolMap`) and was
//! selected as the cut-point: its public API is modeled as a trait rather than a concrete struct,
//! promoting the minimal placeholder that used to live in `seam_stubs.rs` (see `STUBS.tsv`).
//!
//! Every accessor whose Java implementation only reads constructor-injected state with no
//! sensible empty value (`getProgram`, `decodeDataType`, `encodeType`, `encodeTypeRef`, the
//! private `encodeNameIdAttributes` helper needed by [`encode_union`](PcodeDataTypeManager::encode_union)) is left as a required
//! method with no default body, mirroring the precedent set by
//! [`FunctionPrototype::encode_prototype`](crate::program::model::pcode::function_prototype::FunctionPrototype::encode_prototype):
//! a concrete implementor has direct access to its own fields (`progDataTypes`,
//! `builtInDataTypes`, `displayLanguage`, the temporary-id maps) and can implement these
//! precisely once its collaborators (`BuiltInDataTypeManager`, `Undefined.getUndefinedDataType`,
//! `PointerTypedefInspector`, `ClassUtils`, the concrete `Pointer`/`Array`/`TypeDef`/
//! `FunctionDefinition`/string data-type implementations) are ported -- see those types' own
//! module docs (e.g. `Undefined`'s) for why their factories were explicitly deferred rather than
//! guessed at here.
//!
//! [`encode_union`](PcodeDataTypeManager::encode_union),
//! [`encode_composite_placeholder`](PcodeDataTypeManager::encode_composite_placeholder), and
//! [`encode_core_types`](PcodeDataTypeManager::encode_core_types) *are* given real default
//! bodies: their Java implementations only depend on already-ported collaborators
//! ([`Union`], [`DataTypeComponent`], [`DataType`]'s `instanceof`-standing-in predicates,
//! [`Program::get_data_type_manager`], [`DataTypeManager::get_id`]) plus, for `encode_union`, the
//! required `encode_type_ref`/`encode_name_id_attributes` hooks above (a default method calling a
//! required one is the normal way Rust traits express a Java default method built on abstract
//! ones, matching the convention already used throughout
//! [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager)).
//! `encode_core_types` is parameterized over a new [`core_type_entries`](PcodeDataTypeManager::core_type_entries) accessor (standing in for
//! the private `coreBuiltin` map built by `generateCoreTypes`) rather than that map directly,
//! since the trait has no fields to hold it; it defaults to empty, matching a
//! not-yet-initialized manager.
//!
//! The three static utility methods (`findPointerRelativeInner`, the two `getMetatype` overloads,
//! `getMetatypeString`) are pure functions of their arguments and are ported faithfully as free
//! functions. [`get_metatype`] leans on two new [`DataType`] predicates
//! ([`is_boolean_type`](DataType::is_boolean_type), [`is_wide_char_type`](DataType::is_wide_char_type)) and one new downcast
//! ([`as_enum`](DataType::as_enum)), added following the exact pattern already established by
//! `is_default_data_type`/`is_undefined_type`/`as_pointer`/`as_structure`. It also collapses the
//! Java method's separate `instanceof AbstractSignedIntegerDataType` / `instanceof
//! AbstractUnsignedIntegerDataType` / `instanceof CharDataType` branches into one check against
//! [`is_integer_type`](DataType::is_integer_type)/[`is_signed_integer_type`](DataType::is_signed_integer_type): in Java, `CharDataType`
//! extends `AbstractIntegerDataType` directly (not either signed/unsigned subclass), so its
//! dedicated `instanceof CharDataType` branch only exists because the earlier two checks can't
//! see it -- but it computes the identical `isSigned() ? TYPE_INT : TYPE_UINT` outcome, so folding
//! it into the generic integer check (which a `CharDataType` implementor is expected to satisfy
//! by also setting `is_integer_type`/`is_signed_integer_type`) is behavior-preserving.
//! [`find_pointer_relative_inner`] returns `None` where the Java method returns the
//! `Undefined1DataType.dataType` singleton, since that concrete class is not ported yet (`Undefined`'s
//! module docs explicitly defer its sibling factories); callers should map `None` to that
//! singleton once it exists.

use std::io;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::union::Union;
use crate::program::model::listing::Program;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_ALIGNMENT, ATTRIB_CHAR, ATTRIB_ID, ATTRIB_INCOMPLETE, ATTRIB_METATYPE, ATTRIB_NAME,
    ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_UTF, ELEM_CORETYPES, ELEM_FIELD, ELEM_TYPE,
};
use crate::program::model::symbol::name_transformer::{IdentityNameTransformer, NameTransformer};
use crate::app::util::xml::xml_error_handler::XmlParseException;

/// Mask for routing bits at head of a data-type's temporary id.
pub const TEMP_ID_MASK: i64 = 0xC000_0000_0000_0000u64 as i64;
/// Bits at the head of a temporary id indicating a builtin data-type, distinguished from a
/// `DataTypeDB`.
pub const BUILTIN_ID_HEADER: i64 = 0xC000_0000_0000_0000u64 as i64;
/// Bits at the head of a temporary id indicating a non-builtin and non-database data-type.
pub const NONDB_ID_HEADER: i64 = 0x8000_0000_0000_0000u64 as i64;

/// Standard "void" type, absence of type.
pub const TYPE_VOID: i32 = 14;
/// An unknown low-level type. Treated as an unsigned integer.
pub const TYPE_UNKNOWN: i32 = 12;
/// Signed integer. Signed is considered less specific than unsigned in C.
pub const TYPE_INT: i32 = 11;
/// Unsigned integer.
pub const TYPE_UINT: i32 = 10;
/// Boolean.
pub const TYPE_BOOL: i32 = 9;
/// Data is actual executable code.
pub const TYPE_CODE: i32 = 8;
/// Floating-point.
pub const TYPE_FLOAT: i32 = 7;
/// Pointer data-type.
pub const TYPE_PTR: i32 = 6;
/// Pointer relative to another data-type (specialization of [`TYPE_PTR`]).
pub const TYPE_PTRREL: i32 = 5;
/// Array data-type, made up of a sequence of "element" datatype.
pub const TYPE_ARRAY: i32 = 4;
/// Structure data-type, made up of component datatypes.
pub const TYPE_STRUCT: i32 = 3;
/// An overlapping union of multiple datatypes.
pub const TYPE_UNION: i32 = 2;

/// A single entry of the "core" decompiler datatypes always available to the Decompiler,
/// associated with a (metatype, size) pair.
///
/// Stands in for `PcodeDataTypeManager.TypeMap`, trimmed to just the fields
/// [`encode_core_types`](PcodeDataTypeManager::encode_core_types) reads (the full `TypeMap` also carries the underlying `DataType`
/// object, used elsewhere by `findBaseType`, which is out of scope here -- see the module docs).
#[derive(Debug, Clone, PartialEq)]
pub struct CoreTypeEntry {
    /// Name of the datatype on the decompiler side.
    pub name: String,
    /// Size, in bytes, of the underlying datatype.
    pub size: i32,
    /// Extra decompiler metatype information for the type (e.g. `"int"`, `"float"`).
    pub metatype: String,
    /// Whether this is a character data-type.
    pub is_char: bool,
    /// Whether this is a UTF encoded character data-type.
    pub is_utf: bool,
    /// Calculated id for the type.
    pub id: u64,
}

/// Class for marshaling [`DataType`] objects to and from the Decompiler.
///
/// Port of `ghidra.program.model.pcode.PcodeDataTypeManager`. See the module docs for what was
/// ported with a real default, what was left required, and why.
pub trait PcodeDataTypeManager {
    /// Returns the program associated with this `PcodeDataTypeManager`.
    ///
    /// Port of `PcodeDataTypeManager.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Returns the name transformer.
    ///
    /// Port of `PcodeDataTypeManager.getNameTransformer()`. Defaults to an
    /// [`IdentityNameTransformer`] since the trait has no field to store a constructor-injected
    /// one; overriding implementors should return whatever they were actually constructed with.
    fn get_name_transformer(&self) -> Arc<dyn NameTransformer> {
        Arc::new(IdentityNameTransformer)
    }

    /// Sets the name transformer.
    ///
    /// Port of `PcodeDataTypeManager.setNameTransformer(NameTransformer)`. No-op by default, for
    /// the same reason as [`get_name_transformer`](Self::get_name_transformer); mirrors how
    /// `DataType::set_name` defaults to a no-op `Ok(())` when there is no field to update.
    fn set_name_transformer(&mut self, new_transformer: Arc<dyn NameTransformer>) {
        let _ = new_transformer;
    }

    /// Find a base/built-in data-type with the given name and/or id. If an id is provided and a
    /// corresponding data-type exists, this data-type is returned. Otherwise the first
    /// built-in data-type with a matching name is returned.
    ///
    /// Port of `PcodeDataTypeManager.findBaseType(String, long)`. Defaults to `None` (no match),
    /// matching the state of a manager whose core/temporary-id maps have not been populated;
    /// concrete implementors should override this once `generateCoreTypes` is ported.
    fn find_base_type(&self, nm: &str, id: i64) -> Option<Box<dyn DataType>> {
        let _ = (nm, id);
        None
    }

    /// Decode a data-type from the stream.
    ///
    /// Port of `PcodeDataTypeManager.decodeDataType(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode_data_type(&self, decoder: &dyn Decoder) -> Result<Box<dyn DataType>, DecoderException>;

    /// Encode the name and id associated with a given data-type to a stream as attributes of the
    /// current element.
    ///
    /// Port of the private `PcodeDataTypeManager.encodeNameIdAttributes(Encoder, DataType)`,
    /// promoted to a required trait method (rather than a default) since the real algorithm
    /// branches on `instanceof BuiltIn`/`instanceof DefaultDataType` and, for neither case, falls
    /// back to assigning a temporary id from private mutable counter/map state that this trait
    /// does not hold.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_name_id_attributes(&self, encoder: &mut dyn Encoder, data_type: &dyn DataType) -> io::Result<()>;

    /// Encode a reference to the given data-type to stream.
    ///
    /// Port of `PcodeDataTypeManager.encodeTypeRef(Encoder, DataType, int)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_type_ref(&self, encoder: &mut dyn Encoder, data_type: &dyn DataType, size: i32) -> io::Result<()>;

    /// Encode information for a data-type to the stream.
    ///
    /// Port of `PcodeDataTypeManager.encodeType(Encoder, DataType, int)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_type(&self, encoder: &mut dyn Encoder, data_type: &dyn DataType, size: i32) -> io::Result<()>;

    /// Encode a Union data-type to the stream.
    ///
    /// Port of `PcodeDataTypeManager.encodeUnion(Encoder, Union)`, given a real default built
    /// entirely from already-ported collaborators plus [`encode_name_id_attributes`](Self::encode_name_id_attributes)/
    /// [`encode_type_ref`](Self::encode_type_ref).
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_union(&self, encoder: &mut dyn Encoder, union_type: &dyn Union) -> io::Result<()> {
        encoder.open_element(ELEM_TYPE)?;
        self.encode_name_id_attributes(encoder, union_type)?;
        encoder.write_string(ATTRIB_METATYPE, "union")?;
        encoder.write_signed_integer(ATTRIB_SIZE, union_type.get_length() as i64)?;
        encoder.write_signed_integer(ATTRIB_ALIGNMENT, union_type.get_alignment() as i64)?;
        for comp in union_type.get_defined_components() {
            if comp.get_length() == 0 {
                continue;
            }
            encoder.open_element(ELEM_FIELD)?;
            let field_name = comp
                .get_field_name()
                .filter(|n| !n.is_empty())
                .or_else(|| comp.get_default_field_name())
                .unwrap_or_default();
            encoder.write_string(ATTRIB_NAME, &field_name)?;
            encoder.write_signed_integer(ATTRIB_OFFSET, comp.get_offset() as i64)?;
            encoder.write_signed_integer(ATTRIB_ID, comp.get_ordinal() as i64)?;
            let field_type = comp.get_data_type();
            self.encode_type_ref(encoder, field_type.as_ref(), comp.get_length())?;
            encoder.close_element(ELEM_FIELD)?;
        }
        encoder.close_element(ELEM_TYPE)
    }

    /// Encode a Structure/Union to the stream without listing its fields.
    ///
    /// Port of `PcodeDataTypeManager.encodeCompositePlaceholder(Encoder, DataType)`, given a real
    /// default built from [`get_program`](Self::get_program) + [`DataTypeManager::get_id`](crate::program::model::data::data_type_manager::DataTypeManager::get_id).
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_composite_placeholder(&self, encoder: &mut dyn Encoder, data_type: &dyn DataType) -> io::Result<()> {
        let meta_string = if data_type.is_structure() {
            "struct"
        } else if data_type.is_union() {
            "union"
        } else {
            return Ok(()); // matches the Java `return; //empty. Could throw AssertException.`
        };
        let id = self
            .get_program()
            .get_data_type_manager()
            .map(|dtm| dtm.get_id(data_type))
            .unwrap_or(0);
        encoder.open_element(ELEM_TYPE)?;
        encoder.write_string(ATTRIB_NAME, &data_type.get_display_name())?;
        encoder.write_unsigned_integer(ATTRIB_ID, id as u64)?;
        encoder.write_string(ATTRIB_METATYPE, meta_string)?;
        encoder.write_signed_integer(ATTRIB_SIZE, data_type.get_length() as i64)?;
        encoder.write_signed_integer(ATTRIB_ALIGNMENT, data_type.get_alignment() as i64)?;
        encoder.write_bool(ATTRIB_INCOMPLETE, true)?;
        encoder.close_element(ELEM_TYPE)
    }

    /// The "core" decompiler datatypes always available to the Decompiler, associated with a
    /// (metatype, size) pair.
    ///
    /// Stands in for reading the private `coreBuiltin` map built by the (not-yet-ported)
    /// `generateCoreTypes`. Defaults to empty, matching a not-yet-initialized manager; concrete
    /// implementors should override this once `generateCoreTypes` is ported.
    fn core_type_entries(&self) -> Vec<CoreTypeEntry> {
        Vec::new()
    }

    /// Encode the core data-types to the stream.
    ///
    /// Port of `PcodeDataTypeManager.encodeCoreTypes(Encoder)`, given a real default
    /// parameterized over [`core_type_entries`](Self::core_type_entries).
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_core_types(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_CORETYPES)?;
        for entry in self.core_type_entries() {
            encoder.open_element(ELEM_TYPE)?;
            encoder.write_string(ATTRIB_NAME, &entry.name)?;
            encoder.write_signed_integer(ATTRIB_SIZE, entry.size as i64)?;
            encoder.write_string(ATTRIB_METATYPE, &entry.metatype)?;
            if entry.is_char {
                encoder.write_bool(ATTRIB_CHAR, true)?;
            }
            if entry.is_utf {
                encoder.write_bool(ATTRIB_UTF, true)?;
            }
            encoder.write_unsigned_integer(ATTRIB_ID, entry.id)?;
            encoder.close_element(ELEM_TYPE)?;
        }
        encoder.close_element(ELEM_CORETYPES)
    }

    /// Throw out any temporary ids (from previous function decompilation) and reset the counter.
    ///
    /// Port of `PcodeDataTypeManager.clearTemporaryIds()`. No-op by default since the trait holds
    /// no temporary-id state (see [`find_base_type`](Self::find_base_type)).
    fn clear_temporary_ids(&mut self) {}
}

/// Get the inner data-type being referred to by an offset from a relative/shifted pointer.
/// Generally we expect the base of the relative pointer to be a structure and the offset refers
/// to a (possibly nested) field. In this case, we return the data-type of the field.
///
/// Port of the static `PcodeDataTypeManager.findPointerRelativeInner(DataType, int)`. Returns
/// `None` where the Java method returns `Undefined1DataType.dataType`, since that concrete
/// singleton is not ported yet; see the module docs.
pub fn find_pointer_relative_inner(base: Box<dyn DataType>, offset: i32) -> Option<Box<dyn DataType>> {
    let mut current = if base.is_typedef() {
        match base.typedef_base_data_type() {
            Some(base_type) => base_type,
            None => base,
        }
    } else {
        base
    };
    let mut offset = offset;
    while current.is_structure() {
        let component = match current.as_structure().and_then(|s| s.get_component_containing(offset)) {
            Some(component) => component,
            None => break,
        };
        current = component.get_data_type();
        offset -= component.get_offset();
        if offset == 0 {
            return Some(current);
        }
    }
    None
}

/// Get the decompiler meta-type associated with a data-type.
///
/// Port of the static `PcodeDataTypeManager.getMetatype(DataType)`. See the module docs for how
/// the `CharDataType`/`AbstractSignedIntegerDataType`/`AbstractUnsignedIntegerDataType` branches
/// were collapsed.
pub fn get_metatype(tp: &dyn DataType) -> i32 {
    let unwrapped;
    let tp = if tp.is_typedef() {
        match tp.typedef_base_data_type() {
            Some(base) => {
                unwrapped = base;
                unwrapped.as_ref()
            }
            None => tp,
        }
    } else {
        tp
    };
    if tp.is_undefined_type() {
        return TYPE_UNKNOWN;
    }
    if tp.is_floating_point() {
        return TYPE_FLOAT;
    }
    if tp.is_pointer() {
        return TYPE_PTR;
    }
    if tp.is_boolean_type() {
        return TYPE_BOOL;
    }
    if tp.is_integer_type() {
        return if tp.is_signed_integer_type() { TYPE_INT } else { TYPE_UINT };
    }
    if tp.is_structure() {
        return TYPE_STRUCT;
    }
    if tp.is_union() {
        return TYPE_UNION;
    }
    if tp.is_array() {
        return TYPE_ARRAY;
    }
    if tp.is_wide_char_type() {
        return TYPE_INT;
    }
    if let Some(e) = tp.as_enum() {
        return if e.is_signed() { TYPE_INT } else { TYPE_UINT };
    }
    if tp.is_function_definition_type() {
        return TYPE_CODE;
    }
    TYPE_UNKNOWN
}

/// Convert an XML marshaling string to a metatype code.
///
/// Port of the static `PcodeDataTypeManager.getMetatype(String)`.
///
/// # Errors
/// Returns an error if the string does not represent a valid metatype.
pub fn get_metatype_from_string(meta_string: &str) -> Result<i32, XmlParseException> {
    let metatype = match meta_string {
        "ptr" => TYPE_PTR,
        "ptrrel" => TYPE_PTRREL,
        "array" => TYPE_ARRAY,
        "struct" => TYPE_STRUCT,
        "unknown" => TYPE_UNKNOWN,
        "uint" => TYPE_UINT,
        "union" => TYPE_UNION,
        "int" => TYPE_INT,
        "float" => TYPE_FLOAT,
        "bool" => TYPE_BOOL,
        "code" => TYPE_CODE,
        "void" => TYPE_VOID,
        _ => {
            return Err(XmlParseException::new(
                0,
                format!("Unknown metatype: {meta_string}"),
            ))
        }
    };
    Ok(metatype)
}

/// Convert a decompiler metatype code to a string for XML marshaling.
///
/// Port of the static `PcodeDataTypeManager.getMetatypeString(int)`.
///
/// # Errors
/// Returns an error if the metatype is invalid.
pub fn get_metatype_string(meta: i32) -> io::Result<String> {
    let s = match meta {
        TYPE_VOID => "void",
        TYPE_UNKNOWN => "unknown",
        TYPE_INT => "int",
        TYPE_UINT => "uint",
        TYPE_BOOL => "bool",
        TYPE_CODE => "code",
        TYPE_FLOAT => "float",
        TYPE_PTR => "ptr",
        TYPE_PTRREL => "ptrrel",
        TYPE_ARRAY => "array",
        TYPE_STRUCT => "struct",
        TYPE_UNION => "union",
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unknown metatype")),
    };
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::op_code::OpCode;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::enum_::Enum;
    use crate::program::model::data::structure::Structure;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::docking::settings::settings::Settings;

    /// Minimal `Encoder` mock that just records how many elements were opened, since no concrete
    /// `Encoder`/`CachedEncoder` implementation is ported yet (only test-local mocks exist).
    struct RecordingEncoder {
        elements_opened: usize,
    }

    impl RecordingEncoder {
        fn new() -> Self {
            Self { elements_opened: 0 }
        }

        fn is_empty(&self) -> bool {
            self.elements_opened == 0
        }
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
            self.elements_opened += 1;
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
        fn write_string_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: OpCode) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockDataType {
        length: i32,
        is_struct: bool,
        is_union: bool,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_structure(&self) -> bool {
            self.is_struct
        }
        fn is_union(&self) -> bool {
            self.is_union
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {
        fn get_id(&self, _dt: &dyn DataType) -> i64 {
            42
        }
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test".to_string()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(MockDataTypeManager))
        }
    }

    struct MockManager;
    impl PcodeDataTypeManager for MockManager {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn decode_data_type(&self, _decoder: &dyn Decoder) -> Result<Box<dyn DataType>, DecoderException> {
            Err(DecoderException::new("not exercised by this test"))
        }

        fn encode_name_id_attributes(&self, encoder: &mut dyn Encoder, data_type: &dyn DataType) -> io::Result<()> {
            encoder.write_string(ATTRIB_NAME, &data_type.get_name())?;
            encoder.write_unsigned_integer(ATTRIB_ID, 7)
        }

        fn encode_type_ref(&self, encoder: &mut dyn Encoder, data_type: &dyn DataType, size: i32) -> io::Result<()> {
            encoder.write_signed_integer(ATTRIB_SIZE, size.max(data_type.get_length()) as i64)
        }

        fn encode_type(&self, _encoder: &mut dyn Encoder, _data_type: &dyn DataType, _size: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let manager: Box<dyn PcodeDataTypeManager> = Box::new(MockManager);
        assert!(manager.find_base_type("int", 0).is_none());
        assert!(manager
            .get_program()
            .get_data_type_manager()
            .is_some());
    }

    #[test]
    fn encode_composite_placeholder_writes_struct_metadata() {
        let manager = MockManager;
        let dt = MockDataType {
            length: 8,
            is_struct: true,
            is_union: false,
        };
        let mut encoder = RecordingEncoder::new();
        manager
            .encode_composite_placeholder(&mut encoder, &dt)
            .unwrap();
        // A non-composite datatype produces no element at all.
        let non_composite = MockDataType {
            length: 4,
            is_struct: false,
            is_union: false,
        };
        let mut empty_encoder = RecordingEncoder::new();
        manager
            .encode_composite_placeholder(&mut empty_encoder, &non_composite)
            .unwrap();
        assert!(empty_encoder.is_empty());
        assert!(!encoder.is_empty());
    }

    #[test]
    fn encode_core_types_round_trips_entries() {
        struct WithCoreTypes;
        impl PcodeDataTypeManager for WithCoreTypes {
            fn get_program(&self) -> Arc<dyn Program> {
                Arc::new(MockProgram)
            }
            fn decode_data_type(&self, _decoder: &dyn Decoder) -> Result<Box<dyn DataType>, DecoderException> {
                unimplemented!()
            }
            fn encode_name_id_attributes(&self, _e: &mut dyn Encoder, _t: &dyn DataType) -> io::Result<()> {
                unimplemented!()
            }
            fn encode_type_ref(&self, _e: &mut dyn Encoder, _t: &dyn DataType, _s: i32) -> io::Result<()> {
                unimplemented!()
            }
            fn encode_type(&self, _e: &mut dyn Encoder, _t: &dyn DataType, _s: i32) -> io::Result<()> {
                unimplemented!()
            }
            fn core_type_entries(&self) -> Vec<CoreTypeEntry> {
                vec![CoreTypeEntry {
                    name: "int".to_string(),
                    size: 4,
                    metatype: "int".to_string(),
                    is_char: false,
                    is_utf: false,
                    id: 5,
                }]
            }
        }

        let manager = WithCoreTypes;
        let mut encoder = RecordingEncoder::new();
        manager.encode_core_types(&mut encoder).unwrap();
        assert!(!encoder.is_empty());
    }

    struct MockEnum {
        signed: bool,
    }
    impl DataType for MockEnum {}
    impl Enum for MockEnum {
        fn get_value_for_name(&self, _name: &str) -> Option<i64> {
            None
        }
        fn get_name_for_value(&self, _value: i64) -> Option<String> {
            None
        }
        fn get_names_for_value(&self, _value: i64) -> Option<Vec<String>> {
            None
        }
        fn get_comment(&self, _name: &str) -> String {
            String::new()
        }
        fn get_values(&self) -> Vec<i64> {
            Vec::new()
        }
        fn get_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_count(&self) -> i32 {
            0
        }
        fn add(&mut self, _name: &str, _value: i64) {}
        fn add_with_comment(&mut self, _name: &str, _value: i64, _comment: &str) {}
        fn remove(&mut self, _name: &str) {}
        fn set_description(&mut self, _description: &str) {}
        fn get_enum_representation(&self, _big_int: i128, _settings: &dyn Settings, _bit_length: i32) -> String {
            String::new()
        }
        fn contains_name(&self, _name: &str) -> bool {
            false
        }
        fn contains_value(&self, _value: i64) -> bool {
            false
        }
        fn is_signed(&self) -> bool {
            self.signed
        }
        fn get_signed_state(&self) -> crate::program::database::data::EnumSignedState {
            if self.signed {
                crate::program::database::data::EnumSignedState::Signed
            } else {
                crate::program::database::data::EnumSignedState::None
            }
        }
        fn get_max_possible_value(&self) -> i64 {
            i64::MAX
        }
        fn get_min_possible_value(&self) -> i64 {
            i64::MIN
        }
        fn get_minimum_possible_length(&self) -> i32 {
            1
        }
        fn clone_enum(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Enum> {
            Box::new(MockEnum { signed: self.signed })
        }
    }

    #[test]
    fn get_metatype_dispatches_on_flags() {
        struct Flagged {
            floating_point: bool,
            pointer: bool,
            boolean: bool,
            integer: bool,
            signed_integer: bool,
            structure: bool,
            union: bool,
            array: bool,
            wide_char: bool,
            function_definition: bool,
        }
        impl DataType for Flagged {
            fn is_floating_point(&self) -> bool {
                self.floating_point
            }
            fn is_pointer(&self) -> bool {
                self.pointer
            }
            fn is_boolean_type(&self) -> bool {
                self.boolean
            }
            fn is_integer_type(&self) -> bool {
                self.integer
            }
            fn is_signed_integer_type(&self) -> bool {
                self.signed_integer
            }
            fn is_structure(&self) -> bool {
                self.structure
            }
            fn is_union(&self) -> bool {
                self.union
            }
            fn is_array(&self) -> bool {
                self.array
            }
            fn is_wide_char_type(&self) -> bool {
                self.wide_char
            }
            fn is_function_definition_type(&self) -> bool {
                self.function_definition
            }
        }
        fn base() -> Flagged {
            Flagged {
                floating_point: false,
                pointer: false,
                boolean: false,
                integer: false,
                signed_integer: false,
                structure: false,
                union: false,
                array: false,
                wide_char: false,
                function_definition: false,
            }
        }

        assert_eq!(get_metatype(&Flagged { floating_point: true, ..base() }), TYPE_FLOAT);
        assert_eq!(get_metatype(&Flagged { pointer: true, ..base() }), TYPE_PTR);
        assert_eq!(get_metatype(&Flagged { boolean: true, ..base() }), TYPE_BOOL);
        assert_eq!(
            get_metatype(&Flagged { integer: true, signed_integer: true, ..base() }),
            TYPE_INT
        );
        assert_eq!(get_metatype(&Flagged { integer: true, ..base() }), TYPE_UINT);
        assert_eq!(get_metatype(&Flagged { structure: true, ..base() }), TYPE_STRUCT);
        assert_eq!(get_metatype(&Flagged { union: true, ..base() }), TYPE_UNION);
        assert_eq!(get_metatype(&Flagged { array: true, ..base() }), TYPE_ARRAY);
        assert_eq!(get_metatype(&Flagged { wide_char: true, ..base() }), TYPE_INT);
        assert_eq!(
            get_metatype(&Flagged { function_definition: true, ..base() }),
            TYPE_CODE
        );
        assert_eq!(get_metatype(&base()), TYPE_UNKNOWN);

        let signed_enum = MockEnum { signed: true };
        struct EnumHolder(MockEnum);
        impl DataType for EnumHolder {
            fn as_enum(&self) -> Option<&dyn Enum> {
                Some(&self.0)
            }
        }
        assert_eq!(get_metatype(&EnumHolder(signed_enum)), TYPE_INT);
        assert_eq!(get_metatype(&EnumHolder(MockEnum { signed: false })), TYPE_UINT);
    }

    #[test]
    fn get_metatype_string_round_trips() {
        for &meta in &[
            TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_CODE, TYPE_FLOAT,
            TYPE_PTR, TYPE_PTRREL, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION,
        ] {
            let s = get_metatype_string(meta).unwrap();
            assert_eq!(get_metatype_from_string(&s).unwrap(), meta);
        }
        assert!(get_metatype_string(999).is_err());
        assert!(get_metatype_from_string("bogus").is_err());
    }

    struct Leaf(i32);
    impl DataType for Leaf {
        fn get_length(&self) -> i32 {
            self.0
        }
    }

    struct LeafComponent {
        offset: i32,
        length: i32,
    }
    impl DataTypeComponent for LeafComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(Leaf(self.length))
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    /// A structure with a single field of length 1 at offset 4, and nothing else.
    struct OuterStructure;
    impl DataType for OuterStructure {
        fn is_structure(&self) -> bool {
            true
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl crate::program::model::data::composite::Composite for OuterStructure {}
    impl Structure for OuterStructure {
        fn get_component_containing(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
            if offset == 4 {
                Some(Box::new(LeafComponent { offset: 4, length: 1 }))
            } else {
                None
            }
        }
    }

    #[test]
    fn find_pointer_relative_inner_finds_component_at_matching_offset() {
        let found = find_pointer_relative_inner(Box::new(OuterStructure), 4);
        assert_eq!(found.unwrap().get_length(), 1);
    }

    #[test]
    fn find_pointer_relative_inner_returns_none_when_offset_has_no_component() {
        let not_found = find_pointer_relative_inner(Box::new(OuterStructure), 99);
        assert!(not_found.is_none());
    }
}
