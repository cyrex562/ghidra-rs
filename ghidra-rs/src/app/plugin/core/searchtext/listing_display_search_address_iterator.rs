use crate::app::plugin::core::searchtext::iterators::SearchAddressIterator;
use crate::program::model::address::Address;

/// An iterator for returning addresses that can take in 1 or more search iterators to iterate
/// over addresses provided by each of those search iterators.
///
/// Port of `ghidra.app.plugin.core.searchtext.ListingDisplaySearchAddressIterator`.
pub struct ListingDisplaySearchAddressIterator {
    last_address: Option<Address>,
    last_address_map: Vec<(Box<dyn SearchAddressIterator>, Option<Address>)>,
    forward: bool,
}

impl ListingDisplaySearchAddressIterator {
    pub fn new(
        start_address: Option<Address>,
        iterators: Vec<Box<dyn SearchAddressIterator>>,
        forward: bool,
    ) -> Self {
        let mut result = ListingDisplaySearchAddressIterator {
            last_address: None,
            last_address_map: Vec::new(),
            forward,
        };
        result.update_last_address(start_address);

        for iterator in iterators {
            result.last_address_map.push((iterator, None));
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
            // don't add past the address range
            let max_address = start_address.space().max_address();
            let max_offset = max_address.offset();
            let start_offset = start_address.offset();
            let result = start_offset.wrapping_add(1);
            if result > start_offset && result < max_offset {
                if let Ok(address) = start_address.add(1) {
                    self.last_address = Some(address);
                }
            }
        }
    }

    pub fn has_next(&mut self) -> bool {
        if self.get_already_found_next_address().is_some() {
            return true;
        }

        self.maybe_push_iterators_forward();

        for (iterator, _) in &self.last_address_map {
            if iterator.has_next() {
                return true;
            }
        }

        // any remaining addresses we've already pulled-out?
        self.get_already_found_next_address().is_some()
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

    pub fn next(&mut self) -> Option<Address> {
        let address = self.maybe_push_iterators_forward();
        self.last_address = address.clone();
        address
    }

    fn maybe_push_iterators_forward(&mut self) -> Option<Address> {
        for entry in self.last_address_map.iter_mut() {
            if is_greater_than_last_address(entry.1.as_ref(), self.last_address.as_ref(), self.forward) {
                continue; // last value for this iterator is still good--don't move forward
            }

            entry.1 = move_past_last_address(entry.0.as_mut(), self.last_address.as_ref(), self.forward);
        }

        self.get_already_found_next_address()
    }
}

fn move_past_last_address(
    iterator: &mut dyn SearchAddressIterator,
    last_address: Option<&Address>,
    forward: bool,
) -> Option<Address> {
    while iterator.has_next() {
        let address = iterator.next();
        if is_greater_than_last_address(address.as_ref(), last_address, forward) {
            return address;
        }
    }
    None
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

    struct VecIterator {
        addresses: Vec<Address>,
        index: usize,
    }

    impl VecIterator {
        fn new(addresses: Vec<Address>) -> Self {
            VecIterator { addresses, index: 0 }
        }
    }

    impl SearchAddressIterator for VecIterator {
        fn has_next(&self) -> bool {
            self.index < self.addresses.len()
        }

        fn next(&mut self) -> Option<Address> {
            if !self.has_next() {
                return None;
            }
            let address = self.addresses[self.index].clone();
            self.index += 1;
            Some(address)
        }
    }

    #[test]
    fn empty_iterators_have_no_next() {
        let mut iter = ListingDisplaySearchAddressIterator::new(None, Vec::new(), true);
        assert!(!iter.has_next());
        assert!(iter.next().is_none());
    }

    #[test]
    fn forward_single_iterator_returns_addresses_in_order() {
        let source: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(0x1000), addr(0x1008), addr(0x1010)]));
        let mut iter = ListingDisplaySearchAddressIterator::new(None, vec![source], true);

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr(0x1000)));

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr(0x1008)));

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr(0x1010)));

        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn forward_merges_multiple_iterators_in_sorted_order() {
        let first: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(0x1000), addr(0x1010)]));
        let second: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(0x1004), addr(0x1008)]));
        let mut iter = ListingDisplaySearchAddressIterator::new(None, vec![first, second], true);

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        assert_eq!(
            results,
            vec![addr(0x1000), addr(0x1004), addr(0x1008), addr(0x1010)]
        );
    }

    #[test]
    fn backward_merges_multiple_iterators_in_reverse_order() {
        let first: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(0x1010), addr(0x1000)]));
        let second: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(0x1008), addr(0x1004)]));
        let mut iter = ListingDisplaySearchAddressIterator::new(None, vec![first, second], false);

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        assert_eq!(
            results,
            vec![addr(0x1010), addr(0x1008), addr(0x1004), addr(0x1000)]
        );
    }

    #[test]
    fn forward_start_address_includes_start_and_excludes_addresses_before_it() {
        let source: Box<dyn SearchAddressIterator> = Box::new(VecIterator::new(vec![
            addr(0x1000),
            addr(0x1008),
            addr(0x1010),
        ]));
        let mut iter =
            ListingDisplaySearchAddressIterator::new(Some(addr(0x1008)), vec![source], true);

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        assert_eq!(results, vec![addr(0x1008), addr(0x1010)]);
    }

    #[test]
    fn backward_start_address_includes_start_and_excludes_addresses_after_it() {
        let source: Box<dyn SearchAddressIterator> = Box::new(VecIterator::new(vec![
            addr(0x1010),
            addr(0x1008),
            addr(0x1000),
        ]));
        let mut iter =
            ListingDisplaySearchAddressIterator::new(Some(addr(0x1008)), vec![source], false);

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        assert_eq!(results, vec![addr(0x1008), addr(0x1000)]);
    }

    #[test]
    fn forward_start_address_at_zero_offset_does_not_underflow() {
        let source: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(0), addr(8)]));
        let mut iter =
            ListingDisplaySearchAddressIterator::new(Some(addr(0)), vec![source], true);

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        assert_eq!(results, vec![addr(0), addr(8)]);
    }

    #[test]
    fn backward_start_address_at_max_offset_does_not_overflow() {
        let max_offset = space().max_address().offset();
        let source: Box<dyn SearchAddressIterator> =
            Box::new(VecIterator::new(vec![addr(max_offset), addr(max_offset - 8)]));
        let mut iter = ListingDisplaySearchAddressIterator::new(
            Some(addr(max_offset)),
            vec![source],
            false,
        );

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        assert_eq!(results, vec![addr(max_offset), addr(max_offset - 8)]);
    }
}
