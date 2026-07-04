use crate::program::model::address::Address;

/// A simple interface for searching that will allow for iteration over addresses.
///
/// Port of `ghidra.app.plugin.core.searchtext.iterators.SearchAddressIterator`.
pub trait SearchAddressIterator {
    /// Returns true if there is another address available.
    fn has_next(&self) -> bool;

    /// Returns the next address, or `None` if no more addresses are available.
    fn next(&mut self) -> Option<Address>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct TestIterator {
        addresses: VecDeque<Address>,
    }

    impl TestIterator {
        fn new(addresses: Vec<Address>) -> Self {
            TestIterator {
                addresses: addresses.into_iter().collect(),
            }
        }
    }

    impl SearchAddressIterator for TestIterator {
        fn has_next(&self) -> bool {
            !self.addresses.is_empty()
        }

        fn next(&mut self) -> Option<Address> {
            self.addresses.pop_front()
        }
    }

    #[test]
    fn empty_iterator_has_no_next() {
        let iter = TestIterator::new(vec![]);
        assert!(!iter.has_next());
    }

    #[test]
    fn iterator_with_items_has_next() {
        let addr_space = crate::program::model::address::AddressSpace::new("test", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 1);
        let addr = Address::new(addr_space.clone(), 0);
        let iter = TestIterator::new(vec![addr]);
        assert!(iter.has_next());
    }

    #[test]
    fn iterator_returns_addresses_in_order() {
        let addr_space = crate::program::model::address::AddressSpace::new("test", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 1);
        let addr1 = Address::new(addr_space.clone(), 0);
        let addr2 = Address::new(addr_space.clone(), 8);
        let addr3 = Address::new(addr_space.clone(), 16);

        let mut iter = TestIterator::new(vec![addr1.clone(), addr2.clone(), addr3.clone()]);

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr1));

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr2));

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr3));

        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn next_returns_none_when_empty() {
        let mut iter = TestIterator::new(vec![]);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn multiple_next_calls_when_empty() {
        let mut iter = TestIterator::new(vec![]);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }
}
