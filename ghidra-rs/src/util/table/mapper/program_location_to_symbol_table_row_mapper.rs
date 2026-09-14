//! Port of `ghidra.util.table.mapper.ProgramLocationToSymbolTableRowMapper`.

use std::sync::Arc;

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Symbol;
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`ProgramLocation`] to the [`Symbol`] primary at its byte address, letting columns
/// designed for symbol tables be reused by program-location tables.
///
/// Port of `ghidra.util.table.mapper.ProgramLocationToSymbolTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<ProgramLocation, Symbol>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// Java: `SymbolTable symbolTable = program.getSymbolTable(); return
/// symbolTable.getPrimarySymbol(rowObject.getByteAddress());`. This port reaches the symbol table
/// through [`Program::get_symbol_table_ref`] (grown for
/// [`AddressToSymbolTableRowMapper`](super::address_to_symbol_table_row_mapper::AddressToSymbolTableRowMapper)'s
/// identical need -- see that method's own doc comment for why `map`'s `&dyn Program` cannot use
/// the pre-existing `&mut self` `get_symbol_table`), and treats both "no symbol table available"
/// and a lookup error the same as "no primary symbol": `None`.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct ProgramLocationToSymbolTableRowMapper;

impl TableRowMapper<Box<dyn ProgramLocation>, Option<Arc<dyn Symbol>>>
    for ProgramLocationToSymbolTableRowMapper
{
    fn map(
        &self,
        row_object: &Box<dyn ProgramLocation>,
        data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Option<Arc<dyn Symbol>> {
        let symbol_table = data.get_symbol_table_ref()?;
        symbol_table.get_primary_symbol(&row_object.get_byte_address()).ok()?
    }
}

impl ProgramLocationTableRowMapper<Box<dyn ProgramLocation>, Option<Arc<dyn Symbol>>>
    for ProgramLocationToSymbolTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolTable, SymbolType};
    use std::io;

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
        id: i64,
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
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockSymbolTable {
        primary: Option<Arc<dyn Symbol>>,
    }
    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
        fn get_primary_symbol(&self, _addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.primary.clone())
        }
    }

    struct MockProgram {
        symbol_table: Arc<MockSymbolTable>,
    }
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_symbol_table_ref(&self) -> Option<Arc<dyn SymbolTable>> {
            Some(Arc::clone(&self.symbol_table) as Arc<dyn SymbolTable>)
        }
    }

    struct NoSymbolTableProgram;
    impl crate::framework::model::DomainObject for NoSymbolTableProgram {}
    impl Program for NoSymbolTableProgram {
        fn get_name(&self) -> String {
            "no_table".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockProgramLocation {
        byte_address: Address,
    }
    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(NoSymbolTableProgram)
        }
        fn get_address(&self) -> Address {
            self.byte_address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.byte_address.clone()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn loc(offset: i64) -> Box<dyn ProgramLocation> {
        Box::new(MockProgramLocation { byte_address: ram_address(offset) })
    }

    #[test]
    fn map_returns_primary_symbol_at_byte_address() {
        let mapper = ProgramLocationToSymbolTableRowMapper;
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol { address: ram_address(0x1000), id: 7 });
        let program = MockProgram { symbol_table: Arc::new(MockSymbolTable { primary: Some(symbol) }) };
        let provider = MockServiceProvider;

        let mapped = mapper.map(&loc(0x1000), &program, &provider).expect("expected a symbol");
        assert_eq!(mapped.get_id(), 7);
    }

    #[test]
    fn map_returns_none_when_no_primary_symbol() {
        let mapper = ProgramLocationToSymbolTableRowMapper;
        let program = MockProgram { symbol_table: Arc::new(MockSymbolTable { primary: None }) };
        let provider = MockServiceProvider;

        assert!(mapper.map(&loc(0x1000), &program, &provider).is_none());
    }

    #[test]
    fn map_returns_none_when_program_has_no_symbol_table() {
        let mapper = ProgramLocationToSymbolTableRowMapper;
        let program = NoSymbolTableProgram;
        let provider = MockServiceProvider;

        assert!(mapper.map(&loc(0x1000), &program, &provider).is_none());
    }
}
