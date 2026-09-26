use crate::program::model::address::{Address, AddressRange};

/// A type-erased iterator over addresses.
///
/// Ghidra's `AddressIterator` interface (`hasNext()` + `next()`) was translated as a bespoke
/// trait; it is gone. Address iterators are plain [`Iterator<Item = Address>`][Iterator], so
/// callers get `map`/`filter`/`take_while`/`chain` and can be fed by any std iterator. Use
/// [`Peekable`](std::iter::Peekable) where Java called `hasNext()`.
///
/// `Box<dyn Iterator<Item = Address>>` is idiomatic Rust, not the Java-interface-as-trait-object
/// pattern the ownership migration removes: the erased type is `std::Iterator` itself. Prefer a
/// concrete iterator or `impl Iterator<Item = Address>` where the type is known at the call site.
///
/// See `OWNERSHIP_MIGRATION.md` (the `ITER` verdict in `CONVENTION_QUEUE.tsv`).
pub type BoxedAddressIterator = Box<dyn Iterator<Item = Address>>;

/// Empty address iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAddressIterator;

impl Iterator for EmptyAddressIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        None
    }
}

/// Adapter that owns any `Iterator<Item = Address>`.
///
/// Previously this wrapped the iterator in `RefCell<Box<dyn Iterator<Item = Address>>>` plus a
/// one-element lookahead cache, purely so it could offer `has_next(&self)` -- a Java signature
/// that needs to inspect the next item through a shared reference. With the bespoke trait gone
/// there is nothing to fake: the adapter just holds the iterator, and callers who need
/// lookahead use `.peekable()`.
pub struct AddressIteratorAdapter {
    iterator: Box<dyn Iterator<Item = Address>>,
}

impl AddressIteratorAdapter {
    /// Creates an adapter over the supplied iterator.
    ///
    /// Accepts any `Iterator<Item = Address>` by taking ownership.
    pub fn new<I: Iterator<Item = Address> + 'static>(iterator: I) -> Self {
        Self { iterator: Box::new(iterator) }
    }

    /// Creates an adapter over a vector of addresses.
    ///
    /// This is a convenience constructor for the common case of adapting a `Vec<Address>`.
    pub fn from_vec(addresses: Vec<Address>) -> Self {
        Self::new(addresses.into_iter())
    }

}

impl Iterator for AddressIteratorAdapter {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        self.iterator.next()
    }
}

/// Iterator over address ranges.
///
/// Mirrors Ghidra's `AddressRangeIterator`, which extends `java.util.Iterator<AddressRange>`.
///
/// A marker supertrait over [`Iterator`] rather than a hand-rolled `has_next`/`next_range`
/// pair: with one cursor-advancing operation, `for`/`while let` cannot express the
/// double-advance that dropped every other address in the regression recorded in AGENTS.md.
pub trait AddressRangeIterator: Iterator<Item = AddressRange> {}

/// Empty address range iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAddressRangeIterator;

impl Iterator for EmptyAddressRangeIterator {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl AddressRangeIterator for EmptyAddressRangeIterator {}

/// Adapter from a vector of address ranges to an `AddressRangeIterator`.
#[derive(Debug, Clone)]
pub struct AddressRangeIteratorAdapter {
    iter: std::vec::IntoIter<AddressRange>,
}

impl AddressRangeIteratorAdapter {
    /// Creates an adapter over the supplied address ranges.
    pub fn new(ranges: Vec<AddressRange>) -> Self {
        Self { iter: ranges.into_iter() }
    }
}

impl Iterator for AddressRangeIteratorAdapter {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl AddressRangeIterator for AddressRangeIteratorAdapter {}

#[cfg(test)]
mod tests {

    #[test]
    fn adapter_yields_every_range_when_driven_by_a_for_loop() {
        // The regression this shape exists to prevent. Under the previous has_next/next_range
        // pair a caller could write `while it.has_next() { v.push(it.next_range()) }`, advance
        // the cursor twice per turn and silently drop every other range -- and it compiled.
        // AGENTS.md records exactly that break ("dropped every other address").
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let ranges: Vec<AddressRange> = (0..6)
            .map(|i| {
                AddressRange::new(
                    Address::new(space.clone(), 0x1000 + i * 0x10),
                    Address::new(space.clone(), 0x1000 + i * 0x10 + 0xf),
                )
            })
            .collect();

        let seen: Vec<i64> = AddressRangeIteratorAdapter::new(ranges)
            .map(|r| r.min_address().offset())
            .collect();

        assert_eq!(seen, vec![0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050]);
    }
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn empty_address_iterator_has_no_addresses() {
        let mut iterator = EmptyAddressIterator;

        assert_eq!(iterator.next(), None);
        assert!(iterator.next().is_none());
    }

    #[test]
    fn address_adapter_iterates_addresses_and_then_returns_none() {
        let vec = vec![addr(0x1000), addr(0x1001)];
        let mut iterator = AddressIteratorAdapter::new(vec.into_iter());
        assert_eq!(iterator.next(), Some(addr(0x1000)));
        assert_eq!(iterator.next(), Some(addr(0x1001)));
        assert_eq!(iterator.next(), None);
        assert!(iterator.next().is_none());
    }

    #[test]
    fn address_adapter_from_vec_works() {
        let mut iterator = AddressIteratorAdapter::from_vec(vec![addr(0x2000), addr(0x2001)]);
        assert_eq!(iterator.next(), Some(addr(0x2000)));
        assert_eq!(iterator.next(), Some(addr(0x2001)));
        assert_eq!(iterator.next(), None);
    }

    #[test]
    fn address_adapter_with_filtered_iterator() {
        let addresses = vec![addr(0x1000), addr(0x1001), addr(0x1002), addr(0x1003)];
        let filtered = addresses.into_iter().filter(|a| a.offset() % 2 == 0);
        let mut iterator = AddressIteratorAdapter::new(filtered);
        assert_eq!(iterator.next(), Some(addr(0x1000)));
        assert_eq!(iterator.next(), Some(addr(0x1002)));
        assert_eq!(iterator.next(), None);
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_range_iterator_has_no_ranges() {
        let mut iterator = EmptyAddressRangeIterator;

        assert!(iterator.next().is_none());
    }

    #[test]
    fn range_adapter_iterates_ranges_and_then_returns_none() {
        let first = AddressRange::new(addr(0x1000), addr(0x100f));
        let second = AddressRange::new(addr(0x2000), addr(0x200f));
        let mut iterator = AddressRangeIteratorAdapter::new(vec![first.clone(), second.clone()]);
        assert_eq!(iterator.next(), Some(first));
        assert_eq!(iterator.next(), Some(second));
        assert!(iterator.next().is_none());
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
