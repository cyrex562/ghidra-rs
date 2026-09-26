//! Port of `sarif.export.dd.ExtData`.

use crate::program::model::data::isf::{AbstractIsfObject, IsfObject};
use crate::program::model::listing::Data;
use crate::sarif::export::dd::ext_comment_set::ExtCommentSet;

/// An ISF description of a [`Data`] value's own data type, plus a recursive collection of its
/// comments/settings (its [`ExtCommentSet`]).
///
/// Port of `sarif.export.dd.ExtData`, which `extends AbstractIsfObject`. Following this crate's
/// composition-over-inheritance convention, this wraps an [`AbstractIsfObject`] by composition
/// instead (the same pattern already used by `isf_enum.rs`/`isf_function.rs`/etc.).
///
/// # Deviations from Java
///
/// Java's `typeName`/`typeLocation` fields are a genuine redundant duplication: the inherited
/// `AbstractIsfObject(DataType)` constructor (called via `super(data.getDataType())`) already
/// computes and stores `dt.getName()`/`dt.getCategoryPath().getPath()` into its own `name`/
/// `location` fields, and `ExtData`'s constructor then computes the exact same two values a
/// second time into `typeName`/`typeLocation`. This port preserves that duplication faithfully
/// (as [`ExtData::type_name`]/[`ExtData::type_location`] alongside
/// [`ExtData::abstract_isf_object`]'s own `name`/`location`) rather than collapsing it, since
/// nothing indicates the two pairs are meant to diverge -- it is simply how the Java source reads.
pub struct ExtData {
    /// The inherited `AbstractIsfObject` state (`name`/`location`/`settings`), computed from
    /// `data`'s data type. Mirrors `super(data.getDataType())`.
    pub abstract_isf_object: AbstractIsfObject,
    /// Mirrors the Java class's package-private `typeName` field. See the struct docs for why
    /// this duplicates [`AbstractIsfObject::name`].
    pub type_name: String,
    /// Mirrors the Java class's package-private `typeLocation` field. See the struct docs for why
    /// this duplicates [`AbstractIsfObject::location`].
    pub type_location: String,
    /// Mirrors the Java class's package-private `nested` field.
    pub nested: ExtCommentSet,
}

impl ExtData {
    /// Java: `ExtData(Data data)`.
    pub fn new(data: &dyn Data) -> Self {
        let dt = data.get_data_type();
        let abstract_isf_object = AbstractIsfObject::new(Some(dt.as_ref()));
        let type_name = dt.get_name();
        let type_location = dt.get_category_path().get_path();
        let nested = ExtCommentSet::new(data);
        Self { abstract_isf_object, type_name, type_location, nested }
    }
}

impl IsfObject for ExtData {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType, Reference};
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    struct MockDataType {
        name: String,
        path: String,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse(&self.path).unwrap()
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// Minimal [`Data`] mock reporting a fixed data type and no comments/settings/components,
    /// enough to exercise [`ExtData::new`] without pulling in a real database.
    struct MockData {
        type_name: String,
        type_path: String,
    }

    impl MemBuffer for MockData {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            mock_address(0)
        }
    }
    impl PropertySet for MockData {}

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000000".to_string()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            mock_address(0)
        }
        fn get_max_address(&self) -> Address {
            mock_address(0)
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock.bin".to_string()
                }
                fn get_language_id(&self) -> String {
                    "test:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Settings for MockData {
        fn get_value(&self, _name: &str) -> Option<Box<dyn Any>> {
            None
        }
        fn get_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { name: self.type_name.clone(), path: self.type_path.clone() })
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { name: self.type_name.clone(), path: self.type_path.clone() })
        }
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "mock".to_string()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            false
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn Data> {
            Box::new(MockData { type_name: self.type_name.clone(), type_path: self.type_path.clone() })
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            0
        }
        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    #[test]
    fn captures_type_name_and_location_from_the_data_type() {
        let data = MockData { type_name: "dword".to_string(), type_path: "/Category/Path".to_string() };
        let ext = ExtData::new(&data);
        assert_eq!(ext.type_name, "dword");
        assert_eq!(ext.type_location, "/Category/Path");
    }

    #[test]
    fn duplicates_name_and_location_into_the_inherited_abstract_isf_object() {
        // See the struct docs: `typeName`/`typeLocation` and the inherited `name`/`location` are
        // genuinely redundant in Java -- both pairs should carry the same values.
        let data = MockData { type_name: "byte".to_string(), type_path: "/X".to_string() };
        let ext = ExtData::new(&data);
        assert_eq!(ext.abstract_isf_object.name, Some("byte".to_string()));
        assert_eq!(ext.abstract_isf_object.location, Some("/X".to_string()));
        assert_eq!(ext.type_name, ext.abstract_isf_object.name.clone().unwrap());
        assert_eq!(ext.type_location, ext.abstract_isf_object.location.clone().unwrap());
    }

    #[test]
    fn nested_comment_set_is_built_from_the_data() {
        let data = MockData { type_name: "dword".to_string(), type_path: "/".to_string() };
        let ext = ExtData::new(&data);
        assert!(ext.nested.comment.is_none());
        assert!(ext.nested.setting.is_none());
        assert!(ext.nested.embedded.is_none());
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let data = MockData { type_name: "dword".to_string(), type_path: "/".to_string() };
        let ext = ExtData::new(&data);
        accepts_isf_object(&ext);
    }
}
