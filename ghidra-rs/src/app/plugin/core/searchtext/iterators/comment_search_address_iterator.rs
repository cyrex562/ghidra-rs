use crate::program::model::address::{Address, BoxedAddressIterator};

/// Wrapper around an BoxedAddressIterator for searching comments.
///
/// Port of `ghidra.app.plugin.core.searchtext.iterators.CommentSearchAddressIterator`.
/// This is a simple delegation wrapper that allows comment search operations to use
/// any BoxedAddressIterator implementation transparently.
pub struct CommentSearchAddressIterator {
    iterator: BoxedAddressIterator,
}

impl CommentSearchAddressIterator {
    /// Creates a new comment search iterator wrapping the given address iterator.
    pub fn new(iterator: BoxedAddressIterator) -> Self {
        Self { iterator }
    }
}

impl Iterator for CommentSearchAddressIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        self.iterator.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct TestIterator {
        addresses: Vec<Address>,
        index: usize,
    }

    impl TestIterator {
        fn new(addresses: Vec<Address>) -> Self {
            Self { addresses, index: 0 }
        }
    }

    impl Iterator for TestIterator {
        type Item = Address;

        fn next(&mut self) -> Option<Address> {
            let addr = self.addresses.get(self.index)?.clone();
            self.index += 1;
            Some(addr)
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn empty_iterator_has_no_next() {
        let inner = TestIterator::new(vec![]);
        let mut iter = CommentSearchAddressIterator::new(Box::new(inner));
        assert_eq!(iter.next(), None);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_delegates_to_inner_iterator() {
        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x1008);
        let inner = TestIterator::new(vec![addr1.clone(), addr2.clone()]);
        let mut iter = CommentSearchAddressIterator::new(Box::new(inner));
        assert_eq!(iter.next(), Some(addr1));
        assert_eq!(iter.next(), Some(addr2));
        assert_eq!(iter.next(), None);
        assert!(iter.next().is_none());
    }

    #[test]
    fn multiple_next_calls_when_empty() {
        let inner = TestIterator::new(vec![]);
        let mut iter = CommentSearchAddressIterator::new(Box::new(inner));
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }
}
