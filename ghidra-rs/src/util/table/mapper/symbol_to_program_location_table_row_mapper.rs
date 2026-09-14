//! Port of `ghidra.util.table.mapper.SymbolToProgramLocationTableRowMapper`.

use std::sync::Arc;

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Symbol;
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`Symbol`] to its [`ProgramLocation`], letting columns designed for program-location
/// tables be reused by symbol tables.
///
/// Port of `ghidra.util.table.mapper.SymbolToProgramLocationTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<Symbol, ProgramLocation>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// Java: `return rowObject.getProgramLocation();`, which delegates to
/// [`Symbol::get_program_location`] -- a defaulted trait method in this port, returning `None`
/// unless the concrete `Symbol` overrides it.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct SymbolToProgramLocationTableRowMapper;

impl TableRowMapper<Arc<dyn Symbol>, Option<Box<dyn ProgramLocation>>>
    for SymbolToProgramLocationTableRowMapper
{
    fn map(
        &self,
        row_object: &Arc<dyn Symbol>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Option<Box<dyn ProgramLocation>> {
        row_object.get_program_location()
    }
}

impl ProgramLocationTableRowMapper<Arc<dyn Symbol>, Option<Box<dyn ProgramLocation>>>
    for SymbolToProgramLocationTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
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

    struct MockSymbol {
        address: Address,
        location: Option<Address>,
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
        fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>> {
            self.location
                .clone()
                .map(|address| Box::new(MockProgramLocation { address }) as Box<dyn ProgramLocation>)
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_the_symbols_program_location() {
        let mapper = SymbolToProgramLocationTableRowMapper;
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_address(0x1000),
            location: Some(ram_address(0x1000)),
        });
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&symbol, &program, &provider).expect("expected a location");
        assert_eq!(location.get_address(), ram_address(0x1000));
    }

    #[test]
    fn map_returns_none_when_the_symbol_has_no_program_location() {
        let mapper = SymbolToProgramLocationTableRowMapper;
        let symbol: Arc<dyn Symbol> =
            Arc::new(MockSymbol { address: ram_address(0x1000), location: None });
        let program = MockProgram;
        let provider = MockServiceProvider;

        assert!(mapper.map(&symbol, &program, &provider).is_none());
    }
}
