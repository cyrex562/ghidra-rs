//! Port of `ghidra.util.table.mapper.ProgramLocationToAddressTableRowMapper`.

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`ProgramLocation`] to its [`Address`], letting columns designed for address tables be
/// reused by program-location tables.
///
/// Port of `ghidra.util.table.mapper.ProgramLocationToAddressTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<ProgramLocation, Address>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct ProgramLocationToAddressTableRowMapper;

impl TableRowMapper<Box<dyn ProgramLocation>, Address> for ProgramLocationToAddressTableRowMapper {
    fn map(
        &self,
        row_object: &Box<dyn ProgramLocation>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Address {
        row_object.get_address()
    }
}

impl ProgramLocationTableRowMapper<Box<dyn ProgramLocation>, Address>
    for ProgramLocationToAddressTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
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

    struct MockProgramLocation {
        address: Address,
    }
    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn loc(offset: i64) -> Box<dyn ProgramLocation> {
        Box::new(MockProgramLocation { address: ram_address(offset) })
    }

    #[test]
    fn map_returns_the_locations_address() {
        let mapper = ProgramLocationToAddressTableRowMapper;
        let location = loc(0x4000);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&location, &program, &provider);

        assert_eq!(mapped, ram_address(0x4000));
    }

    #[test]
    fn different_locations_map_to_their_own_addresses() {
        let mapper = ProgramLocationToAddressTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        assert_eq!(mapper.map(&loc(0x10), &program, &provider), ram_address(0x10));
        assert_eq!(mapper.map(&loc(0x20), &program, &provider), ram_address(0x20));
    }
}
