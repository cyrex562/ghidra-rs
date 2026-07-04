use crate::program::model::address::{Address, AddressRange};
use std::cell::RefCell;

/// Iterator over addresses.
///
/// This mirrors Ghidra's `AddressIterator`, using `Option` in place of Java's
/// null return when no address is available.
pub trait AddressIterator {
    /// Returns true when another address is available.
    fn has_next(&self) -> bool;

    /// Returns the next address, or `None` when no address is available.
    fn next_address(&mut self) -> Option<Address>;
}

/// Empty address iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAddressIterator;

impl AddressIterator for EmptyAddressIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_address(&mut self) -> Option<Address> {
        None
    }
}

/// Adapter from an iterator of addresses to an `AddressIterator`.
///
/// This wraps any iterator that produces `Address` items and implements
/// the `AddressIterator` trait. It caches the next value to implement
/// the `has_next()` check without consuming from the underlying iterator
/// in an immutable context.
pub struct AddressIteratorAdapter {
    iterator: RefCell<Box<dyn Iterator<Item = Address>>>,
    cached_next: RefCell<Option<Option<Address>>>,
}

impl AddressIteratorAdapter {
    /// Creates an adapter over the supplied iterator.
    ///
    /// Accepts any `Iterator<Item = Address>` by taking ownership.
    pub fn new<I: Iterator<Item = Address> + 'static>(iterator: I) -> Self {
        Self {
            iterator: RefCell::new(Box::new(iterator)),
            cached_next: RefCell::new(None),
        }
    }

    /// Creates an adapter over a vector of addresses.
    ///
    /// This is a convenience constructor for the common case of adapting a `Vec<Address>`.
    pub fn from_vec(addresses: Vec<Address>) -> Self {
        Self::new(addresses.into_iter())
    }

    fn ensure_cached(&self) {
        if self.cached_next.borrow().is_none() {
            let next = self.iterator.borrow_mut().next();
            *self.cached_next.borrow_mut() = Some(next);
        }
    }
}

impl AddressIterator for AddressIteratorAdapter {
    fn has_next(&self) -> bool {
        self.ensure_cached();
        self.cached_next.borrow().as_ref().map(|opt| opt.is_some()).unwrap_or(false)
    }

    fn next_address(&mut self) -> Option<Address> {
        self.ensure_cached();
        self.cached_next.borrow_mut().take().flatten()
    }
}

/// Iterator over address ranges.
///
/// This mirrors Ghidra's `AddressRangeIterator`, using `Option` in place of
/// Java's null return when no range is available.
pub trait AddressRangeIterator {
    /// Returns true when another address range is available.
    fn has_next(&self) -> bool;

    /// Returns the next address range, or `None` when no range is available.
    fn next_range(&mut self) -> Option<AddressRange>;
}

/// Empty address range iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAddressRangeIterator;

impl AddressRangeIterator for EmptyAddressRangeIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_range(&mut self) -> Option<AddressRange> {
        None
    }
}

/// Adapter from a vector of address ranges to an `AddressRangeIterator`.
#[derive(Debug, Clone)]
pub struct AddressRangeIteratorAdapter {
    ranges: Vec<AddressRange>,
    index: usize,
}

impl AddressRangeIteratorAdapter {
    /// Creates an adapter over the supplied address ranges.
    pub fn new(ranges: Vec<AddressRange>) -> Self {
        Self { ranges, index: 0 }
    }
}

impl AddressRangeIterator for AddressRangeIteratorAdapter {
    fn has_next(&self) -> bool {
        self.index < self.ranges.len()
    }

    fn next_range(&mut self) -> Option<AddressRange> {
        if !self.has_next() {
            return None;
        }
        let range = self.ranges[self.index].clone();
        self.index += 1;
        Some(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn empty_address_iterator_has_no_addresses() {
        let mut iterator = EmptyAddressIterator;

        assert!(!iterator.has_next());
        assert!(iterator.next_address().is_none());
    }

    #[test]
    fn address_adapter_iterates_addresses_and_then_returns_none() {
        let vec = vec![addr(0x1000), addr(0x1001)];
        let mut iterator = AddressIteratorAdapter::new(vec.into_iter());

        assert!(iterator.has_next());
        assert_eq!(iterator.next_address(), Some(addr(0x1000)));
        assert!(iterator.has_next());
        assert_eq!(iterator.next_address(), Some(addr(0x1001)));
        assert!(!iterator.has_next());
        assert!(iterator.next_address().is_none());
    }

    #[test]
    fn address_adapter_from_vec_works() {
        let mut iterator = AddressIteratorAdapter::from_vec(vec![addr(0x2000), addr(0x2001)]);

        assert!(iterator.has_next());
        assert_eq!(iterator.next_address(), Some(addr(0x2000)));
        assert_eq!(iterator.next_address(), Some(addr(0x2001)));
        assert!(!iterator.has_next());
    }

    #[test]
    fn address_adapter_with_filtered_iterator() {
        let addresses = vec![addr(0x1000), addr(0x1001), addr(0x1002), addr(0x1003)];
        let filtered = addresses.into_iter().filter(|a| a.offset() % 2 == 0);
        let mut iterator = AddressIteratorAdapter::new(filtered);

        assert!(iterator.has_next());
        assert_eq!(iterator.next_address(), Some(addr(0x1000)));
        assert!(iterator.has_next());
        assert_eq!(iterator.next_address(), Some(addr(0x1002)));
        assert!(!iterator.has_next());
        assert!(iterator.next_address().is_none());
    }

    #[test]
    fn empty_range_iterator_has_no_ranges() {
        let mut iterator = EmptyAddressRangeIterator;

        assert!(!iterator.has_next());
        assert!(iterator.next_range().is_none());
    }

    #[test]
    fn range_adapter_iterates_ranges_and_then_returns_none() {
        let first = AddressRange::new(addr(0x1000), addr(0x100f));
        let second = AddressRange::new(addr(0x2000), addr(0x200f));
        let mut iterator = AddressRangeIteratorAdapter::new(vec![first.clone(), second.clone()]);

        assert!(iterator.has_next());
        assert_eq!(iterator.next_range(), Some(first));
        assert!(iterator.has_next());
        assert_eq!(iterator.next_range(), Some(second));
        assert!(!iterator.has_next());
        assert!(iterator.next_range().is_none());
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
