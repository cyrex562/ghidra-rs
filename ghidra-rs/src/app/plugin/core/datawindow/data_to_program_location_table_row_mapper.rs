//! Port of `ghidra.app.plugin.core.datawindow.DataToProgramLocationTableRowMapper`.

use std::sync::Arc;

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::{Data, Program};
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// A minimal, owned snapshot of the two [`Program`] accessors every implementor is guaranteed to
/// have (`get_name`/`get_language_id`), used to back [`MappedProgramLocation::get_program`].
///
/// Same approach as
/// [`ScalarRowObjectToProgramLocationTableRowMapper`](crate::app::plugin::core::scalartable::scalar_row_object_to_program_location_table_row_mapper::ScalarRowObjectToProgramLocationTableRowMapper)'s
/// own `ProgramSnapshot`: [`TableRowMapper::map`]'s `data` parameter is `&dyn Program` --
/// borrowed, not `'static` -- while [`ProgramLocation::get_program`] must return an owned
/// `Arc<dyn Program>`, and there is no way to recover an existing `Arc<dyn Program>` from a bare
/// `&dyn Program` without `unsafe`.
struct ProgramSnapshot {
    name: String,
    language_id: String,
}

impl crate::framework::model::DomainObject for ProgramSnapshot {}

impl Program for ProgramSnapshot {
    fn get_name(&self) -> String {
        self.name.clone()
    }
    fn get_language_id(&self) -> String {
        self.language_id.clone()
    }
}

/// The `new ProgramLocation(program, address)` this mapper's `map` builds.
struct MappedProgramLocation {
    program: Arc<dyn Program>,
    address: Address,
}

impl ProgramLocation for MappedProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }
    fn get_address(&self) -> Address {
        self.address.clone()
    }
    fn get_byte_address(&self) -> Address {
        self.address.clone()
    }
}

/// Maps a [`Data`] to a [`ProgramLocation`] over its minimum [`Address`], letting columns
/// designed for program-location tables be reused by the Data table.
///
/// Port of `ghidra.app.plugin.core.datawindow.DataToProgramLocationTableRowMapper`, which
/// `extends ProgramLocationTableRowMapper<Data, ProgramLocation>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`ScalarRowObjectToProgramLocationTableRowMapper`](crate::app::plugin::core::scalartable::scalar_row_object_to_program_location_table_row_mapper::ScalarRowObjectToProgramLocationTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// Unlike most of this crate's other row mappers, the Java `ROW_TYPE` here is `Data` itself
/// (an interface), not a dedicated row-object wrapper class -- ported as `Box<dyn Data>`, matching
/// [`DataToAddressTableRowMapper`](super::data_to_address_table_row_mapper::DataToAddressTableRowMapper).
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct DataToProgramLocationTableRowMapper;

impl TableRowMapper<Box<dyn Data>, Box<dyn ProgramLocation>> for DataToProgramLocationTableRowMapper {
    fn map(
        &self,
        row_object: &Box<dyn Data>,
        data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Box<dyn ProgramLocation> {
        let program: Arc<dyn Program> = Arc::new(ProgramSnapshot {
            name: Program::get_name(data),
            language_id: data.get_language_id(),
        });
        Box::new(MappedProgramLocation { program, address: row_object.get_min_address() })
    }
}

impl ProgramLocationTableRowMapper<Box<dyn Data>, Box<dyn ProgramLocation>>
    for DataToProgramLocationTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::{CodeUnit, CommentType};
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType as DataRefType, Reference as DataReference};
    use std::any::{Any, TypeId};

    struct MockDataType;
    impl DataType for MockDataType {}

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
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn Any + Send + Sync>> {
            None
        }
        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
    }

    /// A minimal [`Data`] test double whose only behavior that matters here is its
    /// [`CodeUnit::get_min_address`].
    struct MockData {
        min_address: Address,
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
            self.min_address.clone()
        }
    }
    impl PropertySet for MockData {}

    impl CodeUnit for MockData {
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
        fn get_bytes_in_code_unit(&self, _buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
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
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
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
    impl Settings for MockData {}

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
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn DataReference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn DataRefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            String::new()
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
            Box::new(MockData { min_address: self.min_address.clone() })
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

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn data_at(offset: i64) -> Box<dyn Data> {
        Box::new(MockData { min_address: ram_address(offset) })
    }

    #[test]
    fn map_returns_a_program_location_over_the_datas_min_address() {
        let mapper = DataToProgramLocationTableRowMapper;
        let row = data_at(0x5000);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row, &program, &provider);

        assert_eq!(location.get_address(), ram_address(0x5000));
        assert_eq!(location.get_byte_address(), ram_address(0x5000));
    }

    #[test]
    fn mapped_locations_program_carries_the_source_programs_identity() {
        let mapper = DataToProgramLocationTableRowMapper;
        let row = data_at(0x10);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row, &program, &provider);

        let mapped_program = location.get_program();
        assert_eq!(Program::get_name(mapped_program.as_ref()), "mock_program");
        assert_eq!(mapped_program.get_language_id(), "mock:LE:32:default");
    }

    #[test]
    fn different_data_rows_map_to_their_own_locations() {
        let mapper = DataToProgramLocationTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a = data_at(0x100);
        let b = data_at(0x200);

        assert_eq!(mapper.map(&a, &program, &provider).get_address(), ram_address(0x100));
        assert_eq!(mapper.map(&b, &program, &provider).get_address(), ram_address(0x200));
    }
}
