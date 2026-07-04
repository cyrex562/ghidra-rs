use crate::program::model::address::{Address, AddressIterator};

/// Wrapper around an AddressIterator for searching comments.
///
/// Port of `ghidra.app.plugin.core.searchtext.iterators.CommentSearchAddressIterator`.
/// This is a simple delegation wrapper that allows comment search operations to use
/// any AddressIterator implementation transparently.
pub struct CommentSearchAddressIterator {
    iterator: Box<dyn AddressIterator>,
}

impl CommentSearchAddressIterator {
    /// Creates a new comment search iterator wrapping the given address iterator.
    pub fn new(iterator: Box<dyn AddressIterator>) -> Self {
        Self { iterator }
    }
}

impl AddressIterator for CommentSearchAddressIterator {
    fn has_next(&self) -> bool {
        self.iterator.has_next()
    }

    fn next_address(&mut self) -> Option<Address> {
        self.iterator.next_address()
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

    impl AddressIterator for TestIterator {
        fn has_next(&self) -> bool {
            self.index < self.addresses.len()
        }

        fn next_address(&mut self) -> Option<Address> {
            if !self.has_next() {
                return None;
            }
            let addr = self.addresses[self.index].clone();
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
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn iterator_delegates_to_inner_iterator() {
        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x1008);
        let inner = TestIterator::new(vec![addr1.clone(), addr2.clone()]);
        let mut iter = CommentSearchAddressIterator::new(Box::new(inner));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr1));
        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr2));
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn multiple_next_calls_when_empty() {
        let inner = TestIterator::new(vec![]);
        let mut iter = CommentSearchAddressIterator::new(Box::new(inner));
        assert!(iter.next_address().is_none());
        assert!(iter.next_address().is_none());
        assert!(iter.next_address().is_none());
    }
}
