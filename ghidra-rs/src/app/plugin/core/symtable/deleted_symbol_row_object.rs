use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use crate::program::model::listing::Program;
use crate::program::model::symbol::Symbol;

/// A lightweight `Symbol` table row object for a deleted symbol.
///
/// Port of `ghidra.app.plugin.core.symtable.DeletedSymbolRowObject`.
/// This always returns `None` from `get_symbol()` since the symbol no longer exists.
pub struct DeletedSymbolRowObject {
    id: i64,
    program: Arc<dyn Program>,
}

impl DeletedSymbolRowObject {
    /// Construct a deleted symbol row object directly from a program and symbol id.
    pub fn new(program: Arc<dyn Program>, symbol_id: i64) -> Self {
        Self {
            id: symbol_id,
            program,
        }
    }

    /// Get symbol id used to acquire the symbol from the program.
    pub fn get_id(&self) -> i64 {
        self.id
    }

    /// Get the symbol associated with this row object. Always returns `None` since
    /// the symbol has been deleted.
    pub fn get_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        None
    }

    /// Display string for this row object: always `"<DELETED>"` since the symbol
    /// no longer exists.
    pub fn to_display_string(&self) -> String {
        "<DELETED>".to_string()
    }
}

impl fmt::Debug for DeletedSymbolRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeletedSymbolRowObject")
            .field("id", &self.id)
            .finish()
    }
}

impl PartialEq for DeletedSymbolRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.program, &other.program)
    }
}

impl Eq for DeletedSymbolRowObject {}

impl std::hash::Hash for DeletedSymbolRowObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialOrd for DeletedSymbolRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DeletedSymbolRowObject {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{SourceType, SymbolTable, SymbolType};
    use std::collections::HashMap;
    use std::io;

    struct MockSymbol {
        id: i64,
        name: String,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            unimplemented!()
        }

        fn get_name(&self) -> &str {
            &self.name
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
        symbols: HashMap<i64, Arc<dyn Symbol>>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }

        fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols.get(&id).cloned())
        }

        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    struct MockProgram {
        table: MockSymbolTable,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }

        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.table)
        }
    }

    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram {
            table: MockSymbolTable {
                symbols: HashMap::new(),
            },
        })
    }

    #[test]
    fn test_new_with_id() {
        let program = mock_program();
        let row = DeletedSymbolRowObject::new(program, 42);
        assert_eq!(row.get_id(), 42);
    }

    #[test]
    fn test_get_symbol_always_none() {
        let program = mock_program();
        let mut row = DeletedSymbolRowObject::new(program, 99);
        assert!(row.get_symbol().is_none());
    }

    #[test]
    fn test_to_display_string_always_deleted() {
        let program = mock_program();
        let row = DeletedSymbolRowObject::new(program, 5);
        assert_eq!(row.to_display_string(), "<DELETED>");
    }

    #[test]
    fn test_equality_same_id_and_program() {
        let program = mock_program();
        let row_a = DeletedSymbolRowObject::new(program.clone(), 5);
        let row_b = DeletedSymbolRowObject::new(program, 5);
        assert_eq!(row_a, row_b);
    }

    #[test]
    fn test_inequality_different_program() {
        let program_a = mock_program();
        let program_b = mock_program();
        let row_a = DeletedSymbolRowObject::new(program_a, 5);
        let row_b = DeletedSymbolRowObject::new(program_b, 5);
        assert_ne!(row_a, row_b);
    }

    #[test]
    fn test_inequality_different_id() {
        let program = mock_program();
        let row_a = DeletedSymbolRowObject::new(program.clone(), 5);
        let row_b = DeletedSymbolRowObject::new(program, 6);
        assert_ne!(row_a, row_b);
    }

    #[test]
    fn test_ordering_by_id() {
        let program = mock_program();
        let mut rows = vec![
            DeletedSymbolRowObject::new(program.clone(), 3),
            DeletedSymbolRowObject::new(program.clone(), 1),
            DeletedSymbolRowObject::new(program, 2),
        ];
        rows.sort();
        assert_eq!(rows[0].get_id(), 1);
        assert_eq!(rows[1].get_id(), 2);
        assert_eq!(rows[2].get_id(), 3);
    }

    #[test]
    fn test_hash_consistency() {
        let program = mock_program();
        let row_a = DeletedSymbolRowObject::new(program.clone(), 11);
        let row_b = DeletedSymbolRowObject::new(program, 11);

        let mut set = std::collections::HashSet::new();
        set.insert(row_a);
        assert!(set.contains(&row_b));
    }
}
