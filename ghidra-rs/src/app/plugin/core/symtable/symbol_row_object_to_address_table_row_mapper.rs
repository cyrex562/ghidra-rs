//! Port of `ghidra.app.plugin.core.symtable.SymbolRowObjectToAddressTableRowMapper`.

use std::sync::Mutex;

use crate::app::plugin::core::symtable::SymbolRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::Symbol;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`SymbolRowObject`] to its [`Address`], letting columns designed for address tables be
/// reused by the Symbol table.
///
/// Port of `ghidra.app.plugin.core.symtable.SymbolRowObjectToAddressTableRowMapper`, which
/// `extends ProgramLocationTableRowMapper<SymbolRowObject, Address>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// # `ROW_TYPE` is `Arc<Mutex<SymbolRowObject>>`, not `SymbolRowObject`
///
/// [`SymbolRowObject::get_symbol`] needs `&mut self` (it recovers unique access to the row's own
/// `Arc<dyn Program>` via `Arc::get_mut` in order to reach `Program::get_symbol_table`, which
/// itself requires `&mut self` -- see that method's doc comment). [`TableRowMapper::map`],
/// however, only hands `map` a `&ROW_TYPE`. Wrapping the row object in `Arc<Mutex<..>>` (rather
/// than changing the shared [`TableRowMapper`] signature, which every other row-mapper port also
/// implements against a plain shared reference) reconciles the two: `map` locks the mutex to get
/// the `&mut SymbolRowObject` `get_symbol` needs.
///
/// # `Option<Address>` in place of a nullable `Address`
///
/// Unlike this crate's other row-mapper ports, Java's `map` here can return `null` (when the row
/// object is deleted, not found, or its symbol has since been deleted) -- so `EXPECTED_ROW_TYPE`
/// is `Option<Address>` rather than a bare `Address`.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct SymbolRowObjectToAddressTableRowMapper;

impl TableRowMapper<std::sync::Arc<Mutex<SymbolRowObject>>, Option<Address>>
    for SymbolRowObjectToAddressTableRowMapper
{
    fn map(
        &self,
        row_object: &std::sync::Arc<Mutex<SymbolRowObject>>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Option<Address> {
        // Java: `if (rowObject == null) { return null; }`. `row_object` here is a `&Arc<..>`,
        // which (unlike a Java reference) can never itself be null, so that guard has no Rust
        // counterpart -- the mutex lock below is the first point of possible failure instead.
        let mut row = row_object.lock().expect("SymbolRowObject mutex poisoned");
        let symbol = row.get_symbol()?;
        if symbol.is_deleted() {
            return None;
        }
        Some(symbol.get_address())
    }
}

impl ProgramLocationTableRowMapper<std::sync::Arc<Mutex<SymbolRowObject>>, Option<Address>>
    for SymbolRowObjectToAddressTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolTable, SymbolType};
    use std::collections::HashMap;
    use std::sync::Arc;

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

    struct MockSymbol {
        id: i64,
        address: Address,
        deleted: bool,
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
    fn map_returns_the_symbols_address() {
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol { id: 1, address: ram_address(0x4000), deleted: false });
        let program = row_program(vec![(1, symbol)]);
        let row_object = Arc::new(Mutex::new(SymbolRowObject::with_id(program, 1)));

        let mapper = SymbolRowObjectToAddressTableRowMapper;
        let data_program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&row_object, &data_program, &provider);

        assert_eq!(mapped, Some(ram_address(0x4000)));
    }

    #[test]
    fn map_returns_none_when_the_symbol_no_longer_exists() {
        let program = row_program(vec![]);
        let row_object = Arc::new(Mutex::new(SymbolRowObject::with_id(program, 99)));

        let mapper = SymbolRowObjectToAddressTableRowMapper;
        let data_program = MockProgram;
        let provider = MockServiceProvider;

        assert_eq!(mapper.map(&row_object, &data_program, &provider), None);
    }

    #[test]
    fn map_returns_none_when_the_symbol_is_deleted() {
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol { id: 2, address: ram_address(0x8000), deleted: true });
        let program = row_program(vec![(2, symbol)]);
        let row_object = Arc::new(Mutex::new(SymbolRowObject::with_id(program, 2)));

        let mapper = SymbolRowObjectToAddressTableRowMapper;
        let data_program = MockProgram;
        let provider = MockServiceProvider;

        assert_eq!(mapper.map(&row_object, &data_program, &provider), None);
    }
}
