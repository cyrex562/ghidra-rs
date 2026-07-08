use crate::program::model::address::{Address, AddressIterator};
use crate::program::model::symbol::SymbolIterator;

/// Wrapper around a SymbolIterator for label search operations.
///
/// Port of `ghidra.app.plugin.core.searchtext.iterators.LabelSearchAddressIterator`.
/// This adapts a SymbolIterator (which iterates over label symbols) into an
/// AddressIterator by extracting the address from each symbol.
pub struct LabelSearchAddressIterator {
    symbol_iterator: Box<dyn SymbolIterator>,
}

impl LabelSearchAddressIterator {
    /// Creates a new label search iterator wrapping the given symbol iterator.
    pub fn new(symbol_iterator: Box<dyn SymbolIterator>) -> Self {
        Self { symbol_iterator }
    }
}

impl AddressIterator for LabelSearchAddressIterator {
    fn has_next(&self) -> bool {
        self.symbol_iterator.has_next()
    }

    fn next_address(&mut self) -> Option<Address> {
        self.symbol_iterator
            .next_symbol()
            .map(|symbol| symbol.get_address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolIterator, SymbolType};
    use std::sync::Arc;

    struct TestSymbol {
        address: Address,
        name: String,
    }

    impl TestSymbol {
        fn new(name: &str, offset: i64) -> Self {
            let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
            Self {
                address: Address::new(space, offset),
                name: name.to_string(),
            }
        }
    }

    impl crate::program::model::symbol::Symbol for TestSymbol {
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

    struct TestSymbolIterator {
        symbols: Vec<Arc<dyn crate::program::model::symbol::Symbol>>,
        index: usize,
    }

    impl TestSymbolIterator {
        fn new(symbols: Vec<Arc<dyn crate::program::model::symbol::Symbol>>) -> Self {
            Self { symbols, index: 0 }
        }
    }

    impl SymbolIterator for TestSymbolIterator {
        fn has_next(&self) -> bool {
            self.index < self.symbols.len()
        }

        fn next_symbol(&mut self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            if !self.has_next() {
                return None;
            }
            let symbol = self.symbols[self.index].clone();
            self.index += 1;
            Some(symbol)
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn empty_iterator_has_no_next() {
        let inner = TestSymbolIterator::new(vec![]);
        let iter = LabelSearchAddressIterator::new(Box::new(inner));
        assert!(!iter.has_next());
    }

    #[test]
    fn iterator_delegates_to_symbol_iterator() {
        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x1008);
        let symbols: Vec<Arc<dyn crate::program::model::symbol::Symbol>> = vec![
            Arc::new(TestSymbol::new("label1", 0x1000)),
            Arc::new(TestSymbol::new("label2", 0x1008)),
        ];
        let inner = TestSymbolIterator::new(symbols);
        let mut iter = LabelSearchAddressIterator::new(Box::new(inner));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr1));
        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr2));
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn multiple_next_calls_when_empty() {
        let inner = TestSymbolIterator::new(vec![]);
        let mut iter = LabelSearchAddressIterator::new(Box::new(inner));
        assert!(iter.next_address().is_none());
        assert!(iter.next_address().is_none());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn single_symbol_iteration() {
        let symbols: Vec<Arc<dyn crate::program::model::symbol::Symbol>> =
            vec![Arc::new(TestSymbol::new("single", 0x2000))];
        let addr_expected = test_address(0x2000);
        let inner = TestSymbolIterator::new(symbols);
        let mut iter = LabelSearchAddressIterator::new(Box::new(inner));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr_expected));
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }
}
