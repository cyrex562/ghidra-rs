//! Port of `ghidra.util.table.mapper.AddressToProgramLocationTableRowMapper`.

use std::sync::Arc;

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
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

/// Maps an [`Address`] to a [`ProgramLocation`] over it, letting columns designed for
/// program-location tables be reused by address tables.
///
/// Port of `ghidra.util.table.mapper.AddressToProgramLocationTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<Address, ProgramLocation>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct AddressToProgramLocationTableRowMapper;

impl TableRowMapper<Address, Box<dyn ProgramLocation>> for AddressToProgramLocationTableRowMapper {
    fn map(
        &self,
        row_object: &Address,
        data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Box<dyn ProgramLocation> {
        let program: Arc<dyn Program> = Arc::new(ProgramSnapshot {
            name: Program::get_name(data),
            language_id: data.get_language_id(),
        });
        Box::new(MappedProgramLocation { program, address: row_object.clone() })
    }
}

impl ProgramLocationTableRowMapper<Address, Box<dyn ProgramLocation>>
    for AddressToProgramLocationTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

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

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_a_program_location_over_the_address() {
        let mapper = AddressToProgramLocationTableRowMapper;
        let addr = ram_address(0x5000);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&addr, &program, &provider);

        assert_eq!(location.get_address(), addr);
        assert_eq!(location.get_byte_address(), addr);
    }

    #[test]
    fn mapped_locations_program_carries_the_source_programs_identity() {
        let mapper = AddressToProgramLocationTableRowMapper;
        let addr = ram_address(0x10);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&addr, &program, &provider);
        let mapped_program = location.get_program();
        assert_eq!(Program::get_name(mapped_program.as_ref()), "mock_program");
        assert_eq!(mapped_program.get_language_id(), "mock:LE:32:default");
    }

    #[test]
    fn different_addresses_map_to_their_own_locations() {
        let mapper = AddressToProgramLocationTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a = ram_address(0x100);
        let b = ram_address(0x200);

        assert_eq!(mapper.map(&a, &program, &provider).get_address(), a);
        assert_eq!(mapper.map(&b, &program, &provider).get_address(), b);
    }
}
