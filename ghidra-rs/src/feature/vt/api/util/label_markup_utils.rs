//! Port of `ghidra.feature.vt.api.util.LabelMarkupUtils`.
//!
//! Java's version is a statics-only utility class (implicit default constructor, no instance
//! state); this port represents that directly as a module of free functions rather than a
//! zero-instance struct, per this crate's convention for statics holders (see e.g.
//! [`crate::feature::vt::api::util::vt_session_file_util`]).

use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{Symbol, SymbolType};

/// Removes every non-function label symbol at `address` in `destination_program`.
///
/// Port of `LabelMarkupUtils.removeAllLabels(Program, Address)`.
///
/// Function symbols are skipped (mirroring Java's `symbol instanceof FunctionSymbol` check,
/// modeled here as [`Symbol::get_symbol_type`] returning [`SymbolType::Function`], the only kind
/// a `FunctionSymbol` ever reports) rather than removed: a function must always have a primary
/// symbol, so `SymbolTable.removeSymbolSpecial` handles that case by renaming the function
/// instead of deleting its symbol -- behavior this port's caller never needs to trigger, since it
/// filters function symbols out first, same as Java.
///
/// Symbols are snapshotted into a list *before* any are removed (mirroring Java's `Symbol[]
/// symbols = symbolTable.getSymbols(address)`), so removing one symbol never disturbs iteration
/// over the rest.
pub fn remove_all_labels(destination_program: &mut dyn Program, address: &Address) {
    let Some(symbol_table) = destination_program.get_symbol_table() else {
        return;
    };
    let symbols = symbol_table.get_symbols(address).unwrap_or_default();
    for symbol in symbols {
        if symbol.get_symbol_type() == SymbolType::Function {
            continue;
        }
        symbol_table.remove_symbol_special(symbol.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolTable};
    use std::sync::{Arc, Mutex};

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    struct MockSymbol {
        id: i64,
        address: Address,
        symbol_type: SymbolType,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "mock_symbol"
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            false
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    /// A [`SymbolTable`] holding a fixed set of symbols at one address, tracking which symbol
    /// IDs [`SymbolTable::remove_symbol_special`] was asked to remove -- real enough to verify
    /// `remove_all_labels`'s dispatch (which symbols it calls removal on, and which it skips)
    /// without needing a full database-backed symbol table.
    struct RecordingSymbolTable {
        symbols_by_address: Vec<(Address, Vec<Arc<MockSymbol>>)>,
        removed_ids: Mutex<Vec<i64>>,
    }

    impl SymbolTable for RecordingSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> std::io::Result<Arc<dyn Symbol>> {
            unimplemented!("not exercised by this test")
        }

        fn get_symbol(&self, id: i64) -> std::io::Result<Option<Arc<dyn Symbol>>> {
            for (_, symbols) in &self.symbols_by_address {
                if let Some(s) = symbols.iter().find(|s| s.id == id) {
                    return Ok(Some(s.clone()));
                }
            }
            Ok(None)
        }

        fn get_symbols(&self, addr: &Address) -> std::io::Result<Vec<Arc<dyn Symbol>>> {
            for (a, symbols) in &self.symbols_by_address {
                if a == addr {
                    return Ok(symbols.iter().map(|s| s.clone() as Arc<dyn Symbol>).collect());
                }
            }
            Ok(Vec::new())
        }

        fn remove_symbol_special(&mut self, symbol: &dyn Symbol) -> bool {
            self.removed_ids.lock().unwrap().push(symbol.get_id());
            true
        }
    }

    struct MockProgram {
        symbol_table: RecordingSymbolTable,
    }

    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbol_table)
        }
    }

    #[test]
    fn removes_every_non_function_symbol_at_the_address() {
        let addr = ram_address(0x1000);
        let label1 = Arc::new(MockSymbol { id: 1, address: addr.clone(), symbol_type: SymbolType::Label });
        let label2 = Arc::new(MockSymbol { id: 2, address: addr.clone(), symbol_type: SymbolType::Label });
        let mut program = MockProgram {
            symbol_table: RecordingSymbolTable {
                symbols_by_address: vec![(addr.clone(), vec![label1, label2])],
                removed_ids: Mutex::new(Vec::new()),
            },
        };

        remove_all_labels(&mut program, &addr);

        let mut removed = program.symbol_table.removed_ids.lock().unwrap().clone();
        removed.sort();
        assert_eq!(removed, vec![1, 2]);
    }

    #[test]
    fn skips_function_symbols() {
        let addr = ram_address(0x2000);
        let label = Arc::new(MockSymbol { id: 10, address: addr.clone(), symbol_type: SymbolType::Label });
        let function = Arc::new(MockSymbol { id: 11, address: addr.clone(), symbol_type: SymbolType::Function });
        let mut program = MockProgram {
            symbol_table: RecordingSymbolTable {
                symbols_by_address: vec![(addr.clone(), vec![label, function])],
                removed_ids: Mutex::new(Vec::new()),
            },
        };

        remove_all_labels(&mut program, &addr);

        // Only the label (id 10) is removed; the function symbol (id 11) is left untouched,
        // mirroring Java's `if (symbol instanceof FunctionSymbol) continue;`.
        assert_eq!(program.symbol_table.removed_ids.lock().unwrap().clone(), vec![10]);
    }

    #[test]
    fn does_nothing_when_there_are_no_symbols_at_the_address() {
        let addr = ram_address(0x3000);
        let mut program = MockProgram {
            symbol_table: RecordingSymbolTable {
                symbols_by_address: vec![],
                removed_ids: Mutex::new(Vec::new()),
            },
        };

        remove_all_labels(&mut program, &addr);

        assert!(program.symbol_table.removed_ids.lock().unwrap().is_empty());
    }

    #[test]
    fn does_nothing_when_the_program_has_no_symbol_table() {
        struct NoSymbolTableProgram;
        impl crate::framework::model::DomainObject for NoSymbolTableProgram {}
        impl Program for NoSymbolTableProgram {
            fn get_name(&self) -> String {
                "no_symbol_table".to_string()
            }
            fn get_language_id(&self) -> String {
                "mock:LE:32:default".to_string()
            }
        }

        let mut program = NoSymbolTableProgram;
        // Should not panic even though `get_symbol_table` defaults to `None`.
        remove_all_labels(&mut program, &ram_address(0x4000));
    }
}
