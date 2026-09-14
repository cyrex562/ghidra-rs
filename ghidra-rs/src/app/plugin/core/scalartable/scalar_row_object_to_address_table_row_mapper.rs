//! Port of `ghidra.app.plugin.core.scalartable.ScalarRowObjectToAddressTableRowMapper`.

use crate::app::plugin::core::scalartable::ScalarRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`ScalarRowObject`] to its [`Address`], letting columns designed for address tables be
/// reused by the Scalar table.
///
/// Port of `ghidra.app.plugin.core.scalartable.ScalarRowObjectToAddressTableRowMapper`, which
/// `extends ProgramLocationTableRowMapper<ScalarRowObject, Address>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct ScalarRowObjectToAddressTableRowMapper;

impl TableRowMapper<ScalarRowObject, Address> for ScalarRowObjectToAddressTableRowMapper {
    fn map(
        &self,
        row_object: &ScalarRowObject,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Address {
        row_object.get_address()
    }
}

impl ProgramLocationTableRowMapper<ScalarRowObject, Address> for ScalarRowObjectToAddressTableRowMapper {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::CodeUnit;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol};
    use crate::program::model::util::PropertySet;
    use crate::program::model::listing::CommentType;
    use crate::program::model::lang::register::Register;
    use std::sync::Arc;

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

    struct MockServiceProvider;
    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
    }

    struct MockCodeUnit {
        min_address: Address,
    }
    impl MemBuffer for MockCodeUnit {
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
            self.min_address.clone()
        }
    }
    impl PropertySet for MockCodeUnit {}
    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
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
            self.min_address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
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
            4
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() == self.min_address.offset()
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            (self.min_address.offset() - addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!()
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SourceType, _ref_type: RefType) {}
        fn set_register_reference(&mut self, _op_index: i32, _reg: &Register, _source_type: SourceType, _ref_type: RefType) {}
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn scalar_row_object(offset: i64) -> ScalarRowObject {
        let code_unit: Arc<dyn CodeUnit> = Arc::new(MockCodeUnit { min_address: ram_address(offset) });
        ScalarRowObject::new(code_unit, Scalar::new(8, 0x42))
    }

    #[test]
    fn map_returns_the_row_objects_address() {
        let mapper = ScalarRowObjectToAddressTableRowMapper;
        let row = scalar_row_object(0x4000);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&row, &program, &provider);

        assert_eq!(mapped, ram_address(0x4000));
    }

    #[test]
    fn different_row_objects_map_to_their_own_addresses() {
        let mapper = ScalarRowObjectToAddressTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a = scalar_row_object(0x10);
        let b = scalar_row_object(0x20);

        assert_eq!(mapper.map(&a, &program, &provider), ram_address(0x10));
        assert_eq!(mapper.map(&b, &program, &provider), ram_address(0x20));
    }
}
