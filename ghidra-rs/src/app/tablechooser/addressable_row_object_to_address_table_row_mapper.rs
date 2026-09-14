//! Port of `ghidra.app.tablechooser.AddressableRowObjectToAddressTableRowMapper`.

use std::sync::Arc;

use crate::app::tablechooser::AddressableRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps an [`AddressableRowObject`] row object to its [`Address`], letting columns designed for
/// address tables be reused by any table whose rows are addressable.
///
/// Port of `ghidra.app.tablechooser.AddressableRowObjectToAddressTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<AddressableRowObject, Address>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct AddressableRowObjectToAddressTableRowMapper;

impl TableRowMapper<Arc<dyn AddressableRowObject>, Address> for AddressableRowObjectToAddressTableRowMapper {
    fn map(
        &self,
        row_object: &Arc<dyn AddressableRowObject>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Address {
        row_object.get_address().clone()
    }
}

impl ProgramLocationTableRowMapper<Arc<dyn AddressableRowObject>, Address>
    for AddressableRowObjectToAddressTableRowMapper
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

    struct MockRowObject {
        address: Address,
    }
    impl AddressableRowObject for MockRowObject {
        fn get_address(&self) -> &Address {
            &self.address
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_the_row_objects_address() {
        let mapper = AddressableRowObjectToAddressTableRowMapper;
        let row_object: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x4000) });
        let program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&row_object, &program, &provider);

        assert_eq!(mapped, ram_address(0x4000));
    }

    #[test]
    fn different_row_objects_map_to_their_own_addresses() {
        let mapper = AddressableRowObjectToAddressTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x10) });
        let b: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x20) });

        assert_eq!(mapper.map(&a, &program, &provider), ram_address(0x10));
        assert_eq!(mapper.map(&b, &program, &provider), ram_address(0x20));
    }
}
