//! Port of `ghidra.app.plugin.core.symtable.SymbolRowObjectToProgramLocationTableRowMapper`.

use std::sync::{Arc, Mutex};

use crate::app::plugin::core::symtable::SymbolRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::listing::Program;
use crate::program::model::symbol::Symbol;
use crate::program::util::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`SymbolRowObject`] to a [`ProgramLocation`], letting columns designed for
/// program-location tables be reused by the Symbol table.
///
/// Port of `ghidra.app.plugin.core.symtable.SymbolRowObjectToProgramLocationTableRowMapper`,
/// which `extends ProgramLocationTableRowMapper<SymbolRowObject, ProgramLocation>`. As with this
/// crate's other row-mapper ports, the Java `extends` becomes implementing [`TableRowMapper`]
/// plus a blanket, field-less impl of [`ProgramLocationTableRowMapper`] to pick up its default
/// methods.
///
/// See
/// [`SymbolRowObjectToAddressTableRowMapper`](crate::app::plugin::core::symtable::symbol_row_object_to_address_table_row_mapper::SymbolRowObjectToAddressTableRowMapper)'s
/// own doc comment for why `ROW_TYPE` is `Arc<Mutex<SymbolRowObject>>` rather than a bare
/// `SymbolRowObject`, and why `EXPECTED_ROW_TYPE` is wrapped in `Option` (Java's `map` can return
/// `null` when the row's symbol has been deleted or no longer exists, and -- unlike that sibling
/// mapper's `Address` -- [`Symbol::get_program_location`] can itself report `None`).
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct SymbolRowObjectToProgramLocationTableRowMapper;

impl TableRowMapper<Arc<Mutex<SymbolRowObject>>, Option<Box<dyn ProgramLocation>>>
    for SymbolRowObjectToProgramLocationTableRowMapper
{
    fn map(
        &self,
        row_object: &Arc<Mutex<SymbolRowObject>>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Option<Box<dyn ProgramLocation>> {
        let mut row = row_object.lock().expect("SymbolRowObject mutex poisoned");
        let symbol = row.get_symbol()?;
        if symbol.is_deleted() {
            return None;
        }
        symbol.get_program_location()
    }
}

impl ProgramLocationTableRowMapper<Arc<Mutex<SymbolRowObject>>, Option<Box<dyn ProgramLocation>>>
    for SymbolRowObjectToProgramLocationTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolTable, SymbolType};
    use std::collections::HashMap;

    struct MockProgram;
    impl DomainObject for MockProgram {}
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

    /// Standing in for the real `getProgramLocation()` override a concrete symbol type would
    /// provide -- unlike [`Symbol::get_program_location`]'s generic default (which needs
    /// [`Symbol::get_program`] to be known), this mock always knows its own program.
    struct MockSymbol {
        id: i64,
        address: Address,
        deleted: bool,
        program: Arc<dyn Program>,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "sym"
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
        fn is_deleted(&self) -> bool {
            self.deleted
        }
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            Some(Arc::clone(&self.program))
        }
    }

    struct MockSymbolTable {
        symbols: HashMap<i64, Arc<dyn Symbol>>,
    }
    impl SymbolTable for MockSymbolTable {
        fn create_label(&mut self, _addr: &Address, _name: &str, _source: SourceType) -> std::io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }
        fn get_symbol(&self, id: i64) -> std::io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols.get(&id).cloned())
        }
        fn get_symbols(&self, _addr: &Address) -> std::io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    struct MockRowProgram {
        table: MockSymbolTable,
    }
    impl DomainObject for MockRowProgram {}
    impl Program for MockRowProgram {
        fn get_name(&self) -> String {
            "row_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.table)
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn row_program(symbols: Vec<(i64, Arc<dyn Symbol>)>) -> Arc<dyn Program> {
        let mut table = MockSymbolTable { symbols: HashMap::new() };
        for (id, symbol) in symbols {
            table.symbols.insert(id, symbol);
        }
        Arc::new(MockRowProgram { table })
    }

    #[test]
    fn map_returns_the_symbols_program_location() {
        let owning_program: Arc<dyn Program> = Arc::new(MockProgram);
        let symbol: Arc<dyn Symbol> =
            Arc::new(MockSymbol { id: 1, address: ram_address(0x4000), deleted: false, program: owning_program });
        let program = row_program(vec![(1, symbol)]);
        let row_object = Arc::new(Mutex::new(SymbolRowObject::with_id(program, 1)));

        let mapper = SymbolRowObjectToProgramLocationTableRowMapper;
        let data_program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row_object, &data_program, &provider).expect("a location");

        assert_eq!(location.get_address(), ram_address(0x4000));
    }

    #[test]
    fn map_returns_none_when_the_symbol_no_longer_exists() {
        let program = row_program(vec![]);
        let row_object = Arc::new(Mutex::new(SymbolRowObject::with_id(program, 99)));

        let mapper = SymbolRowObjectToProgramLocationTableRowMapper;
        let data_program = MockProgram;
        let provider = MockServiceProvider;

        assert!(mapper.map(&row_object, &data_program, &provider).is_none());
    }

    #[test]
    fn map_returns_none_when_the_symbol_is_deleted() {
        let owning_program: Arc<dyn Program> = Arc::new(MockProgram);
        let symbol: Arc<dyn Symbol> =
            Arc::new(MockSymbol { id: 2, address: ram_address(0x8000), deleted: true, program: owning_program });
        let program = row_program(vec![(2, symbol)]);
        let row_object = Arc::new(Mutex::new(SymbolRowObject::with_id(program, 2)));

        let mapper = SymbolRowObjectToProgramLocationTableRowMapper;
        let data_program = MockProgram;
        let provider = MockServiceProvider;

        assert!(mapper.map(&row_object, &data_program, &provider).is_none());
    }
}
