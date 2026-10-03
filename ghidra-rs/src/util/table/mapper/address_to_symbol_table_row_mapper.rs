//! Port of `ghidra.util.table.mapper.AddressToSymbolTableRowMapper`.

use std::sync::Arc;

use crate::app::plugin::core::symtable::SymbolRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// A minimal, owned snapshot of the two [`Program`] accessors every implementor is guaranteed to
/// have (`get_name`/`get_language_id`), used to give the mapped [`SymbolRowObject`] an owning
/// program handle.
///
/// Same approach as
/// [`AddressToProgramLocationTableRowMapper`](super::address_to_program_location_table_row_mapper::AddressToProgramLocationTableRowMapper)'s
/// own `ProgramSnapshot`: [`TableRowMapper::map`]'s `data` parameter is `&dyn Program` --
/// borrowed, not `'static` -- while [`SymbolRowObject::new`] needs an owned `Arc<dyn Program>`,
/// and there is no way to recover an existing `Arc<dyn Program>` from a bare `&dyn Program`
/// without `unsafe`.
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

/// Maps an [`Address`] to the [`SymbolRowObject`] wrapping its primary symbol, letting columns
/// designed for symbol tables be reused by address tables.
///
/// Port of `ghidra.util.table.mapper.AddressToSymbolTableRowMapper`, which `extends
/// ProgramLocationTableRowMapper<Address, SymbolRowObject>`. As with this crate's other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// Java: `SymbolTable symbolTable = program.getSymbolTable(); Symbol s =
/// symbolTable.getPrimarySymbol(rowObject); return s != null ? new SymbolRowObject(s) : null;`.
/// This port reaches the symbol table through [`Program::get_symbol_table_ref`] (grown for this
/// port -- see that method's own doc comment for why `map`'s `&dyn Program` cannot use the
/// pre-existing `&mut self` `get_symbol_table`), and treats both "no symbol table available" and
/// a lookup error the same as "no primary symbol": `None`.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct AddressToSymbolTableRowMapper;

impl TableRowMapper<Address, Option<SymbolRowObject>> for AddressToSymbolTableRowMapper {
    fn map(
        &self,
        row_object: &Address,
        data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Option<SymbolRowObject> {
        let symbol_table = data.get_symbol_table_ref()?;
        let symbol = symbol_table.get_primary_symbol(row_object).ok()??;
        let program: Arc<dyn Program> = Arc::new(ProgramSnapshot {
            name: Program::get_name(data),
            language_id: data.get_language_id(),
        });
        Some(SymbolRowObject::new(symbol.as_ref(), program))
    }
}

impl ProgramLocationTableRowMapper<Address, Option<SymbolRowObject>> for AddressToSymbolTableRowMapper {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, Symbol, SymbolTable, SymbolType};
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

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_symbol_row_object_for_primary_symbol() {
        let mapper = AddressToSymbolTableRowMapper;
        let addr = ram_address(0x1000);
        let symbol: Arc<dyn Symbol> = Arc::new(MockSymbol { address: addr.clone(), id: 42 });
        let program = MockProgram { symbol_table: Arc::new(MockSymbolTable { primary: Some(symbol) }) };
        let provider = MockServiceProvider;

        let mapped = mapper.map(&addr, &program, &provider).expect("expected a symbol row object");
        assert_eq!(mapped.get_id(), 42);
    }

    #[test]
    fn map_returns_none_when_no_primary_symbol() {
        let mapper = AddressToSymbolTableRowMapper;
        let addr = ram_address(0x1000);
        let program = MockProgram { symbol_table: Arc::new(MockSymbolTable { primary: None }) };
        let provider = MockServiceProvider;

        assert!(mapper.map(&addr, &program, &provider).is_none());
    }

    #[test]
    fn map_returns_none_when_program_has_no_symbol_table() {
        let mapper = AddressToSymbolTableRowMapper;
        let addr = ram_address(0x1000);
        let program = NoSymbolTableProgram;
        let provider = MockServiceProvider;

        assert!(mapper.map(&addr, &program, &provider).is_none());
    }
}
