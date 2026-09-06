//! Port of `ghidra.program.database.symbol.TypeFilteredSymbolIterator`.

use std::cell::RefCell;
use std::sync::Arc;

use crate::program::model::symbol::{Symbol, SymbolIterator, SymbolType};

/// Filters a symbol iterator to only return a specific symbol type.
///
/// Port of `ghidra.program.database.symbol.TypeFilteredSymbolIterator`. The Rust
/// [`SymbolIterator::has_next`] takes `&self` (rather than Java's mutating `hasNext()`), so the
/// one-ahead lookahead cache is held behind a [`RefCell`].
pub struct TypeFilteredSymbolIterator {
    it: RefCell<Box<dyn SymbolIterator>>,
    symbol_type: SymbolType,
    next_symbol: RefCell<Option<Arc<dyn Symbol>>>,
}

impl TypeFilteredSymbolIterator {
    /// Construct a new `TypeFilteredSymbolIterator`. `it` is the symbol iterator to filter, and
    /// `symbol_type` is the symbol type to filter on.
    pub fn new(it: Box<dyn SymbolIterator>, symbol_type: SymbolType) -> Self {
        TypeFilteredSymbolIterator {
            it: RefCell::new(it),
            symbol_type,
            next_symbol: RefCell::new(None),
        }
    }

    fn find_next(&self) -> bool {
        let mut it = self.it.borrow_mut();
        while it.has_next() {
            match it.next_symbol() {
                Some(s) if s.get_symbol_type() == self.symbol_type => {
                    *self.next_symbol.borrow_mut() = Some(s);
                    return true;
                }
                Some(_) => continue,
                None => break,
            }
        }
        false
    }
}

impl SymbolIterator for TypeFilteredSymbolIterator {
    fn has_next(&self) -> bool {
        if self.next_symbol.borrow().is_some() {
            return true;
        }
        self.find_next()
    }

    fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        if self.has_next() {
            self.next_symbol.borrow_mut().take()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolIteratorAdapter};

    struct TestSymbol {
        name: String,
        symbol_type: SymbolType,
    }

    impl Symbol for TestSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    fn symbols() -> Vec<Arc<dyn Symbol>> {
        vec![
            Arc::new(TestSymbol {
                name: "label1".to_string(),
                symbol_type: SymbolType::Label,
            }),
            Arc::new(TestSymbol {
                name: "func1".to_string(),
                symbol_type: SymbolType::Function,
            }),
            Arc::new(TestSymbol {
                name: "label2".to_string(),
                symbol_type: SymbolType::Label,
            }),
            Arc::new(TestSymbol {
                name: "func2".to_string(),
                symbol_type: SymbolType::Function,
            }),
        ]
    }

    #[test]
    fn filters_to_only_matching_type() {
        let inner = Box::new(SymbolIteratorAdapter::new(symbols()));
        let mut iter = TypeFilteredSymbolIterator::new(inner, SymbolType::Function);

        let mut names = Vec::new();
        while iter.has_next() {
            names.push(iter.next_symbol().unwrap().get_name().to_string());
        }
        assert_eq!(names, vec!["func1", "func2"]);
    }

    #[test]
    fn repeated_has_next_calls_do_not_advance() {
        let inner = Box::new(SymbolIteratorAdapter::new(symbols()));
        let mut iter = TypeFilteredSymbolIterator::new(inner, SymbolType::Label);

        assert!(iter.has_next());
        assert!(iter.has_next());
        assert_eq!(iter.next_symbol().unwrap().get_name(), "label1");
        assert_eq!(iter.next_symbol().unwrap().get_name(), "label2");
        assert!(!iter.has_next());
        assert!(iter.next_symbol().is_none());
    }

    #[test]
    fn no_matches_yields_empty_iteration() {
        let inner = Box::new(SymbolIteratorAdapter::new(symbols()));
        let mut iter = TypeFilteredSymbolIterator::new(inner, SymbolType::Namespace);
        assert!(!iter.has_next());
        assert!(iter.next_symbol().is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let inner = Box::new(SymbolIteratorAdapter::new(symbols()));
        let mut iter: Box<dyn SymbolIterator> =
            Box::new(TypeFilteredSymbolIterator::new(inner, SymbolType::Function));
        let mut count = 0;
        while iter.has_next() {
            iter.next_symbol();
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
