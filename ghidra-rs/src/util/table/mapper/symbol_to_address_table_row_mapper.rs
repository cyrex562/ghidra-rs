//! Port of `ghidra.util.table.mapper.SymbolToAddressTableRowMapper`.

use std::sync::Arc;

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Symbol;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`Symbol`] row object to its [`Address`], letting columns designed for address tables
/// be reused by symbol tables.
///
/// Port of `ghidra.util.table.mapper.SymbolToAddressTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<Symbol, Address>`. As with the other row-mapper ports (see
/// [`ProgramLocationTableRowMapper`]'s own doc comment), the Java `extends` becomes implementing
/// [`TableRowMapper`] plus a blanket, field-less impl of [`ProgramLocationTableRowMapper`] to
/// pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct SymbolToAddressTableRowMapper;

impl TableRowMapper<Arc<dyn Symbol>, Address> for SymbolToAddressTableRowMapper {
    fn map(
        &self,
        row_object: &Arc<dyn Symbol>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Address {
        row_object.get_address()
    }
}

impl ProgramLocationTableRowMapper<Arc<dyn Symbol>, Address> for SymbolToAddressTableRowMapper {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolType};

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

    struct MockSymbol {
        address: Address,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "mock_symbol"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_symbol_address() {
        let mapper = SymbolToAddressTableRowMapper;
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_address(0x1000),
        });
        let program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&symbol, &program, &provider);

        assert_eq!(mapped, ram_address(0x1000));
    }

    #[test]
    fn different_symbols_map_to_their_own_addresses() {
        let mapper = SymbolToAddressTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_address(0x10),
        });
        let b: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_address(0x20),
        });

        assert_eq!(mapper.map(&a, &program, &provider), ram_address(0x10));
        assert_eq!(mapper.map(&b, &program, &provider), ram_address(0x20));
    }
}
