use crate::app::plugin::core::searchtext::iterators::BoxedSearchAddressIterator;
use crate::program::model::address::Address;
use std::iter::Peekable;

/// An iterator for returning addresses that can take in 1 or more search iterators to iterate
/// over addresses provided by each of those search iterators.
///
/// Port of `ghidra.app.plugin.core.searchtext.ListingDisplaySearchAddressIterator`.
pub struct ListingDisplaySearchAddressIterator {
    last_address: Option<Address>,
    /// One entry per search category: the category's iterator, plus the address it is
    /// currently parked on. `Peekable` supplies what Java's `hasNext()` did -- looking at the
    /// next address without consuming it -- so no bespoke iterator trait is needed.
    last_address_map: Vec<(Peekable<BoxedSearchAddressIterator>, Option<Address>)>,
    forward: bool,
}

impl ListingDisplaySearchAddressIterator {
    pub fn new(
        start_address: Option<Address>,
        iterators: Vec<BoxedSearchAddressIterator>,
        forward: bool,
    ) -> Self {
        let mut result = ListingDisplaySearchAddressIterator {
            last_address: None,
            last_address_map: Vec::new(),
            forward,
        };
        result.update_last_address(start_address);

        for iterator in iterators {
            result.last_address_map.push((iterator.peekable(), None));
        }

        result
    }

    fn update_last_address(&mut self, start_address: Option<Address>) {
        let start_address = match start_address {
            Some(address) => address,
            None => return,
        };

        if self.forward {
            if start_address.offset() > 0 {
                if let Ok(address) = start_address.add(-1) {
                    self.last_address = Some(address);
                }
            }
        }
        else {
            // don't add past the address range: only step forward one address when the
            // start is not already the maximum address of its space. Offsets are stored as
            // i64 but represent unsigned values (the space max is -1 == u64::MAX), so compare
            // by equality rather than signed ordering.
            let max_address = start_address.space().max_address();
            if start_address.offset() != max_address.offset() {
                if let Ok(address) = start_address.add(1) {
                    self.last_address = Some(address);
                }
            }
        }
    }

    fn get_already_found_next_address(&self) -> Option<Address> {
        let mut addresses: Vec<Address> = self
            .last_address_map
            .iter()
            .filter_map(|(_, address)| address.clone())
            .collect();

        // smallest first for forward
        addresses.sort();
        if !self.forward {
            addresses.reverse();
        }

        addresses
            .into_iter()
            .find(|address| is_greater_than_last_address(Some(address), self.last_address.as_ref(), self.forward))
    }

    fn maybe_push_iterators_forward(&mut self) -> Option<Address> {
        for entry in self.last_address_map.iter_mut() {
            if is_greater_than_last_address(entry.1.as_ref(), self.last_address.as_ref(), self.forward) {
                continue; // last value for this iterator is still good--don't move forward
            }

            entry.1 = move_past_last_address(&mut entry.0, self.last_address.as_ref(), self.forward);
        }

        self.get_already_found_next_address()
    }
}

/// Advances `iterator` until it yields an address beyond `last_address`, or it runs out.
///
/// Generic over any address iterator rather than taking a trait object: the caller already
/// knows the concrete type, so there is nothing to erase here.
fn move_past_last_address<I: Iterator<Item = Address>>(
    iterator: &mut I,
    last_address: Option<&Address>,
    forward: bool,
) -> Option<Address> {
    iterator.find(|address| is_greater_than_last_address(Some(address), last_address, forward))
}

impl Iterator for ListingDisplaySearchAddressIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        let address = self.maybe_push_iterators_forward();
        self.last_address = address.clone();
        address
    }
}

fn is_greater_than_last_address(
    address: Option<&Address>,
    last_address: Option<&Address>,
    forward: bool,
) -> bool {
    let address = match address {
        Some(address) => address,
        None => return false,
    };
    let last_address = match last_address {
        Some(last_address) => last_address,
        None => return true,
    };

    if forward {
        last_address < address
    }
    else {
        last_address > address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    /// Previously a hand-rolled `VecIterator` implementing the old two-method trait. Any
    /// `Iterator<Item = Address>` is a search iterator now, so a plain `Vec` will do.
    fn source(addresses: Vec<Address>) -> BoxedSearchAddressIterator {
        Box::new(addresses.into_iter())
    }

    #[test]
    fn empty_iterators_have_no_next() {
        let mut iter = ListingDisplaySearchAddressIterator::new(None, Vec::new(), true);
        assert!(iter.next().is_none());
    }

    #[test]
    fn forward_single_iterator_returns_addresses_in_order() {
        let source = source(vec![addr(0x1000), addr(0x1008), addr(0x1010)]);
        let mut iter = ListingDisplaySearchAddressIterator::new(None, vec![source], true);

        assert_eq!(iter.next(), Some(addr(0x1000)));

        assert_eq!(iter.next(), Some(addr(0x1008)));

        assert_eq!(iter.next(), Some(addr(0x1010)));

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn forward_merges_multiple_iterators_in_sorted_order() {
        let first = source(vec![addr(0x1000), addr(0x1010)]);
        let second = source(vec![addr(0x1004), addr(0x1008)]);
        let iter = ListingDisplaySearchAddressIterator::new(None, vec![first, second], true);

        let results: Vec<Address> = iter.collect();

        assert_eq!(
            results,
            vec![addr(0x1000), addr(0x1004), addr(0x1008), addr(0x1010)]
        );
    }

    #[test]
    fn backward_merges_multiple_iterators_in_reverse_order() {
        let first = source(vec![addr(0x1010), addr(0x1000)]);
        let second = source(vec![addr(0x1008), addr(0x1004)]);
        let iter = ListingDisplaySearchAddressIterator::new(None, vec![first, second], false);

        let results: Vec<Address> = iter.collect();

        assert_eq!(
            results,
            vec![addr(0x1010), addr(0x1008), addr(0x1004), addr(0x1000)]
        );
    }

    #[test]
    fn forward_start_address_includes_start_and_excludes_addresses_before_it() {
        let source = source(vec![
            addr(0x1000),
            addr(0x1008),
            addr(0x1010),
        ]);
        let mut iter =
            ListingDisplaySearchAddressIterator::new(Some(addr(0x1008)), vec![source], true);

        let results: Vec<Address> = iter.collect();

        assert_eq!(results, vec![addr(0x1008), addr(0x1010)]);
    }

    #[test]
    fn backward_start_address_includes_start_and_excludes_addresses_after_it() {
        let source = source(vec![
            addr(0x1010),
            addr(0x1008),
            addr(0x1000),
        ]);
        let mut iter =
            ListingDisplaySearchAddressIterator::new(Some(addr(0x1008)), vec![source], false);

        let results: Vec<Address> = iter.collect();

        assert_eq!(results, vec![addr(0x1008), addr(0x1000)]);
    }

    #[test]
    fn forward_start_address_at_zero_offset_does_not_underflow() {
        let source = source(vec![addr(0), addr(8)]);
        let mut iter =
            ListingDisplaySearchAddressIterator::new(Some(addr(0)), vec![source], true);

        let results: Vec<Address> = iter.collect();

        assert_eq!(results, vec![addr(0), addr(8)]);
    }

    #[test]
    fn backward_start_address_at_max_offset_does_not_overflow() {
        let max_offset = space().max_address().offset();
        let source = source(vec![addr(max_offset), addr(max_offset - 8)]);
        let mut iter = ListingDisplaySearchAddressIterator::new(
            Some(addr(max_offset)),
            vec![source],
            false,
        );

        let results: Vec<Address> = iter.collect();

        assert_eq!(results, vec![addr(max_offset), addr(max_offset - 8)]);
    }
}
