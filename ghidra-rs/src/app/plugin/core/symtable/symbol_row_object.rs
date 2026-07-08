use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use crate::program::model::listing::Program;
use crate::program::model::symbol::Symbol;

/// A lightweight `Symbol` table row object which may be used to acquire an associated symbol.
///
/// Port of `ghidra.app.plugin.core.symtable.SymbolRowObject`.
pub struct SymbolRowObject {
    id: i64,
    program: Arc<dyn Program>,
}

impl SymbolRowObject {
    /// Construct a symbol row object from a symbol and its owning program.
    ///
    /// Java's public constructor obtains the program via `Symbol.getProgram()`; the Rust
    /// `Symbol` trait has no such accessor, so the program is supplied explicitly.
    pub fn new(symbol: &dyn Symbol, program: Arc<dyn Program>) -> Self {
        Self::with_id(program, symbol.get_id())
    }

    /// Construct a symbol row object directly from a program and symbol id.
    ///
    /// Port of the protected `SymbolRowObject(Program, long)` constructor, intended for use
    /// by subclasses.
    pub fn with_id(program: Arc<dyn Program>, symbol_id: i64) -> Self {
        Self {
            id: symbol_id,
            program,
        }
    }

    /// Get symbol id used to acquire the symbol from the program.
    pub fn get_id(&self) -> i64 {
        self.id
    }

    /// Get the symbol associated with this row object. If the symbol no longer exists,
    /// `None` is returned.
    ///
    /// Requires unique ownership of the underlying program in order to obtain its symbol
    /// table; returns `None` if the program is currently shared elsewhere.
    pub fn get_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        Arc::get_mut(&mut self.program)?
            .get_symbol_table()?
            .get_symbol(self.id)
            .ok()
            .flatten()
    }

    /// Display string for this row object: the symbol's name, or `"<DELETED>"` if the symbol
    /// no longer exists.
    ///
    /// Named method rather than a `Display` impl because symbol lookup requires `&mut self`
    /// (see [`Self::get_symbol`]).
    pub fn to_display_string(&mut self) -> String {
        match self.get_symbol() {
            Some(s) => s.get_name().to_string(),
            None => "<DELETED>".to_string(),
        }
    }
}

impl fmt::Debug for SymbolRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolRowObject")
            .field("id", &self.id)
            .finish()
    }
}

impl PartialEq for SymbolRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.program, &other.program)
    }
}

impl Eq for SymbolRowObject {}

impl std::hash::Hash for SymbolRowObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialOrd for SymbolRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The Java `AbstractSortedTableModel.EndOfChainComparator` makes it necessary to implement
/// this comparison to avoid use of identity hash equality when two instances are otherwise
/// equal.
impl Ord for SymbolRowObject {
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

    fn mock_program(symbols: Vec<(i64, &str)>) -> Arc<dyn Program> {
        let mut table = MockSymbolTable {
            symbols: HashMap::new(),
        };
        for (id, name) in symbols {
            table.symbols.insert(
                id,
                Arc::new(MockSymbol {
                    id,
                    name: name.to_string(),
                }) as Arc<dyn Symbol>,
            );
        }
        Arc::new(MockProgram { table })
    }

    #[test]
    fn test_new_from_symbol_takes_its_id() {
        let symbol = MockSymbol {
            id: 42,
            name: "foo".to_string(),
        };
        let program = mock_program(vec![(42, "foo")]);
        let row = SymbolRowObject::new(&symbol, program);
        assert_eq!(row.get_id(), 42);
    }

    #[test]
    fn test_with_id_constructor() {
        let program = mock_program(vec![]);
        let row = SymbolRowObject::with_id(program, 7);
        assert_eq!(row.get_id(), 7);
    }

    #[test]
    fn test_get_symbol_found() {
        let program = mock_program(vec![(42, "foo")]);
        let mut row = SymbolRowObject::with_id(program, 42);
        let symbol = row.get_symbol().expect("symbol should be found");
        assert_eq!(symbol.get_id(), 42);
        assert_eq!(symbol.get_name(), "foo");
    }

    #[test]
    fn test_get_symbol_deleted_returns_none() {
        let program = mock_program(vec![]);
        let mut row = SymbolRowObject::with_id(program, 99);
        assert!(row.get_symbol().is_none());
    }

    #[test]
    fn test_to_display_string_found_and_deleted() {
        let program = mock_program(vec![(1, "bar")]);
        let mut row = SymbolRowObject::with_id(program, 1);
        assert_eq!(row.to_display_string(), "bar");

        let program = mock_program(vec![]);
        let mut row = SymbolRowObject::with_id(program, 2);
        assert_eq!(row.to_display_string(), "<DELETED>");
    }

    #[test]
    fn test_equality_same_id_and_program() {
        let program = mock_program(vec![(5, "a")]);
        let row_a = SymbolRowObject::with_id(program.clone(), 5);
        let row_b = SymbolRowObject::with_id(program, 5);
        assert_eq!(row_a, row_b);
    }

    #[test]
    fn test_inequality_different_program() {
        let program_a = mock_program(vec![(5, "a")]);
        let program_b = mock_program(vec![(5, "a")]);
        let row_a = SymbolRowObject::with_id(program_a, 5);
        let row_b = SymbolRowObject::with_id(program_b, 5);
        assert_ne!(row_a, row_b);
    }

    #[test]
    fn test_inequality_different_id() {
        let program = mock_program(vec![(5, "a"), (6, "b")]);
        let row_a = SymbolRowObject::with_id(program.clone(), 5);
        let row_b = SymbolRowObject::with_id(program, 6);
        assert_ne!(row_a, row_b);
    }

    #[test]
    fn test_ordering_by_id() {
        let program = mock_program(vec![]);
        let mut rows = vec![
            SymbolRowObject::with_id(program.clone(), 3),
            SymbolRowObject::with_id(program.clone(), 1),
            SymbolRowObject::with_id(program, 2),
        ];
        rows.sort();
        assert_eq!(rows[0].get_id(), 1);
        assert_eq!(rows[1].get_id(), 2);
        assert_eq!(rows[2].get_id(), 3);
    }

    #[test]
    fn test_hash_consistency() {
        let program = mock_program(vec![(11, "x")]);
        let row_a = SymbolRowObject::with_id(program.clone(), 11);
        let row_b = SymbolRowObject::with_id(program, 11);

        let mut set = std::collections::HashSet::new();
        set.insert(row_a);
        assert!(set.contains(&row_b));
    }
}
