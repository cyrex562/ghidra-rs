//! Iterator for symbols.
//!
//! Port of `ghidra.program.model.symbol.SymbolIterator` and
//! `ghidra.program.model.symbol.SymbolIteratorAdapter`.

use crate::program::model::symbol::Symbol;
use std::sync::Arc;

/// Iterator that returns symbols.
///
/// This mirrors Ghidra's `SymbolIterator`, using `Option` in place of
/// Java's null return when no symbol is available.
pub trait SymbolIterator {
    /// Returns true when another symbol is available.
    fn has_next(&self) -> bool;

    /// Returns the next symbol, or `None` when no symbol is available.
    fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>>;
}

/// Empty symbol iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptySymbolIterator;

impl SymbolIterator for EmptySymbolIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        None
    }
}

/// Adapter from a vector of symbols to a `SymbolIterator`.
pub struct SymbolIteratorAdapter {
    symbols: Vec<Arc<dyn Symbol>>,
    index: usize,
}

impl SymbolIteratorAdapter {
    /// Creates an adapter over the supplied symbols.
    pub fn new(symbols: Vec<Arc<dyn Symbol>>) -> Self {
        Self { symbols, index: 0 }
    }
}

impl SymbolIterator for SymbolIteratorAdapter {
    fn has_next(&self) -> bool {
        self.index < self.symbols.len()
    }

    fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        if !self.has_next() {
            return None;
        }
        let symbol = self.symbols[self.index].clone();
        self.index += 1;
        Some(symbol)
    }
}

/// Adapter that wraps any iterator of symbols.
///
/// This is the Rust equivalent of Java's `SymbolIteratorAdapter`, providing
/// a convenient way to wrap a boxed iterator to implement the `SymbolIterator` trait.
pub struct SymbolAdapter {
    iter: Box<dyn Iterator<Item = Arc<dyn Symbol>>>,
    current: Option<Arc<dyn Symbol>>,
}

impl SymbolAdapter {
    /// Creates an adapter from a boxed iterator of symbols.
    ///
    /// # Arguments
    ///
    /// * `iter` - A boxed iterator that yields symbols
    pub fn new(mut iter: Box<dyn Iterator<Item = Arc<dyn Symbol>>>) -> Self {
        let current = iter.next();
        Self { iter, current }
    }
}

impl SymbolIterator for SymbolAdapter {
    fn has_next(&self) -> bool {
        self.current.is_some()
    }

    fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
        let result = self.current.take();
        self.current = self.iter.next();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolType};

    struct TestSymbol {
        address: Address,
        name: String,
    }

    impl TestSymbol {
        fn new(name: &str, offset: i64) -> Self {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Self {
                address: Address::new(space, offset),
                name: name.to_string(),
            }
        }
    }

    impl Symbol for TestSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
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
            1
        }

        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    #[test]
    fn empty_iterator_has_no_symbols() {
        let mut iterator = EmptySymbolIterator;

        assert!(!iterator.has_next());
        assert!(iterator.next_symbol().is_none());
    }

    #[test]
    fn vec_adapter_iterates_symbols_and_then_returns_none() {
        let symbols: Vec<Arc<dyn Symbol>> = vec![
            Arc::new(TestSymbol::new("first", 0x1000)),
            Arc::new(TestSymbol::new("second", 0x1001)),
        ];
        let mut iterator = SymbolIteratorAdapter::new(symbols);

        assert!(iterator.has_next());
        assert_eq!(iterator.next_symbol().unwrap().get_name(), "first");
        assert!(iterator.has_next());
        assert_eq!(iterator.next_symbol().unwrap().get_name(), "second");
        assert!(!iterator.has_next());
        assert!(iterator.next_symbol().is_none());
    }

    #[test]
    fn symbol_adapter_iterates_from_boxed_iterator() {
        let symbols: Vec<Arc<dyn Symbol>> = vec![
            Arc::new(TestSymbol::new("first", 0x1000)),
            Arc::new(TestSymbol::new("second", 0x1001)),
            Arc::new(TestSymbol::new("third", 0x1002)),
        ];
        let boxed_iter: Box<dyn Iterator<Item = Arc<dyn Symbol>>> = Box::new(symbols.into_iter());
        let mut iterator = SymbolAdapter::new(boxed_iter);

        assert!(iterator.has_next());
        assert_eq!(iterator.next_symbol().unwrap().get_name(), "first");
        assert!(iterator.has_next());
        assert_eq!(iterator.next_symbol().unwrap().get_name(), "second");
        assert!(iterator.has_next());
        assert_eq!(iterator.next_symbol().unwrap().get_name(), "third");
        assert!(!iterator.has_next());
        assert!(iterator.next_symbol().is_none());
    }

    #[test]
    fn symbol_adapter_with_single_element() {
        let symbols: Vec<Arc<dyn Symbol>> = vec![Arc::new(TestSymbol::new("only", 0x5000))];
        let boxed_iter: Box<dyn Iterator<Item = Arc<dyn Symbol>>> = Box::new(symbols.into_iter());
        let mut iterator = SymbolAdapter::new(boxed_iter);

        assert!(iterator.has_next());
        assert_eq!(iterator.next_symbol().unwrap().get_name(), "only");
        assert!(!iterator.has_next());
        assert!(iterator.next_symbol().is_none());
    }

    #[test]
    fn symbol_adapter_with_empty_iterator() {
        let symbols: Vec<Arc<dyn Symbol>> = vec![];
        let boxed_iter: Box<dyn Iterator<Item = Arc<dyn Symbol>>> = Box::new(symbols.into_iter());
        let mut iterator = SymbolAdapter::new(boxed_iter);

        assert!(!iterator.has_next());
        assert!(iterator.next_symbol().is_none());
    }
}
