use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::{Data, Program};

/// Holds matched data from two programs.
///
/// This is a data container holding match information between data elements in two programs,
/// including the addresses, data objects, and a reason for the match.
///
/// Ported from `ghidra.app.plugin.match.MatchedData`.
#[derive(Clone)]
pub struct MatchedData {
    a_prog: Arc<dyn Program>,
    b_prog: Arc<dyn Program>,
    a_addr: Address,
    b_addr: Address,
    a_data: Arc<dyn Data>,
    b_data: Arc<dyn Data>,
    a_match_num: i32,
    b_match_num: i32,
    reason: String,
}

impl MatchedData {
    /// Creates a new matched data container.
    ///
    /// # Arguments
    ///
    /// * `a_prog` - The first program
    /// * `b_prog` - The second program
    /// * `a_addr` - The address in the first program
    /// * `b_addr` - The address in the second program
    /// * `a_data` - The data in the first program
    /// * `b_data` - The data in the second program
    /// * `a_match_num` - Match number in the first program
    /// * `b_match_num` - Match number in the second program
    /// * `reason` - Reason for the match
    pub fn new(
        a_prog: Arc<dyn Program>,
        b_prog: Arc<dyn Program>,
        a_addr: Address,
        b_addr: Address,
        a_data: Arc<dyn Data>,
        b_data: Arc<dyn Data>,
        a_match_num: i32,
        b_match_num: i32,
        reason: impl Into<String>,
    ) -> Self {
        MatchedData {
            a_prog,
            b_prog,
            a_addr,
            b_addr,
            a_data,
            b_data,
            a_match_num,
            b_match_num,
            reason: reason.into(),
        }
    }

    /// Returns the first program.
    pub fn get_a_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.a_prog)
    }

    /// Returns the second program.
    pub fn get_b_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.b_prog)
    }

    /// Returns the address in the first program.
    pub fn get_a_data_address(&self) -> Address {
        self.a_addr.clone()
    }

    /// Returns the address in the second program.
    pub fn get_b_data_address(&self) -> Address {
        self.b_addr.clone()
    }

    /// Returns the data in the first program.
    pub fn get_a_data(&self) -> Arc<dyn Data> {
        Arc::clone(&self.a_data)
    }

    /// Returns the data in the second program.
    pub fn get_b_data(&self) -> Arc<dyn Data> {
        Arc::clone(&self.b_data)
    }

    /// Returns the match number in the first program.
    pub fn get_a_match_num(&self) -> i32 {
        self.a_match_num
    }

    /// Returns the match number in the second program.
    pub fn get_b_match_num(&self) -> i32 {
        self.b_match_num
    }

    /// Returns the reason for the match.
    pub fn get_reason(&self) -> &str {
        &self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::any::{Any, TypeId};
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer, RefType, Reference};

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockReference;
    impl Reference for MockReference {}

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockData;

    impl MemBuffer for MockData {}
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

    impl Settings for MockData {}

    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            Some(Box::new(0i32))
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<i32>())
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
            Box::new(MockDataType)
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            vec![Box::new(MockReference)]
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
            Box::new(MockData)
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
            "0".to_string()
        }

        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    fn create_test_data() -> (Arc<dyn Program>, Arc<dyn Program>, Arc<dyn Data>, Arc<dyn Data>) {
        (
            Arc::new(MockProgram),
            Arc::new(MockProgram),
            Arc::new(MockData),
            Arc::new(MockData),
        )
    }

    #[test]
    fn test_new() {
        let (a_prog, b_prog, a_data, b_data) = create_test_data();
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let a_addr = Address::new(space.clone(), 0x1000);
        let b_addr = Address::new(space, 0x2000);

        let matched = MatchedData::new(
            Arc::clone(&a_prog),
            Arc::clone(&b_prog),
            a_addr,
            b_addr,
            Arc::clone(&a_data),
            Arc::clone(&b_data),
            1,
            2,
            "test reason",
        );

        assert_eq!(matched.get_a_match_num(), 1);
        assert_eq!(matched.get_b_match_num(), 2);
        assert_eq!(matched.get_reason(), "test reason");
        assert_eq!(matched.get_a_data_address(), a_addr);
        assert_eq!(matched.get_b_data_address(), b_addr);
    }

    #[test]
    fn test_getters() {
        let (a_prog, b_prog, a_data, b_data) = create_test_data();
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let a_addr = Address::new(space.clone(), 0x100);
        let b_addr = Address::new(space, 0x200);

        let matched = MatchedData::new(
            Arc::clone(&a_prog),
            Arc::clone(&b_prog),
            a_addr,
            b_addr,
            Arc::clone(&a_data),
            Arc::clone(&b_data),
            5,
            10,
            "another reason",
        );

        assert_eq!(matched.get_a_match_num(), 5);
        assert_eq!(matched.get_b_match_num(), 10);
        assert_eq!(matched.get_reason(), "another reason");
    }

    #[test]
    fn test_clone() {
        let (a_prog, b_prog, a_data, b_data) = create_test_data();
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let a_addr = Address::new(space.clone(), 0x1000);
        let b_addr = Address::new(space, 0x2000);

        let matched = MatchedData::new(
            Arc::clone(&a_prog),
            Arc::clone(&b_prog),
            a_addr,
            b_addr,
            Arc::clone(&a_data),
            Arc::clone(&b_data),
            1,
            2,
            "test",
        );

        let cloned = matched.clone();
        assert_eq!(cloned.get_a_match_num(), matched.get_a_match_num());
        assert_eq!(cloned.get_b_match_num(), matched.get_b_match_num());
        assert_eq!(cloned.get_reason(), matched.get_reason());
    }
}
