use crate::program::model::address::{Address, AddressIterator};

/// Iterates through multiple address iterators simultaneously. `next()` returns
/// the next address as determined from all the iterators.
///
/// Mirrors Ghidra's `MultiAddressIterator`. Java allows `null` entries in the
/// iterators array; that is modeled here with `Option<Box<dyn AddressIterator>>`.
pub struct MultiAddressIterator {
    iters: Vec<Option<Box<dyn AddressIterator>>>,
    addrs: Vec<Option<Address>>,
    forward: bool,
}

impl MultiAddressIterator {
    /// Creates a multi address iterator for multiple forward address iterators.
    pub fn new(iters: Vec<Option<Box<dyn AddressIterator>>>) -> Self {
        let addrs = vec![None; iters.len()];
        Self {
            iters,
            addrs,
            forward: true,
        }
    }

    /// Creates a multi address iterator.
    ///
    /// Note: all iterators must iterate in the same direction (forwards or
    /// backwards). `forward` indicates the direction of every iterator in
    /// `iters`.
    pub fn new_with_direction(iters: Vec<Option<Box<dyn AddressIterator>>>, forward: bool) -> Self {
        let addrs = vec![None; iters.len()];
        Self {
            iters,
            addrs,
            forward,
        }
    }

    /// Determines whether any of the original iterators has a next address.
    pub fn has_next(&self) -> bool {
        for i in 0..self.iters.len() {
            let has_pending = self.addrs[i].is_some();
            let iter_has_next = match &self.iters[i] {
                Some(iter) => iter.has_next(),
                None => false,
            };
            if has_pending || iter_has_next {
                return true;
            }
        }
        false
    }

    /// Returns the next address. The next address could be from any one of
    /// the iterators.
    pub fn next(&mut self) -> Option<Address> {
        self.advance().0
    }

    /// Returns the next address(es). The next address could be from any one
    /// or more of the iterators.
    ///
    /// Each element in the returned vector corresponds to each iterator
    /// passed to the constructor. `None` is present in an element if the
    /// next overall address is not the next address from the corresponding
    /// iterator.
    pub fn next_addresses(&mut self) -> Vec<Option<Address>> {
        self.advance().1
    }

    fn advance(&mut self) -> (Option<Address>, Vec<Option<Address>>) {
        let len = self.iters.len();

        // Get a next value from each iterator.
        for i in 0..len {
            if self.addrs[i].is_none() {
                if let Some(iter) = &mut self.iters[i] {
                    if iter.has_next() {
                        self.addrs[i] = iter.next_address();
                    }
                }
            }
        }

        // Find next address.
        let mut addr_next: Option<Address> = None;
        let mut next = vec![false; len];
        for i in 0..len {
            let Some(candidate) = &self.addrs[i] else {
                continue;
            };
            match &addr_next {
                None => {
                    addr_next = Some(candidate.clone());
                    next[i] = true;
                }
                Some(current) => {
                    let result = current.cmp(candidate);
                    if result == std::cmp::Ordering::Equal {
                        next[i] = true;
                    } else if (self.forward && result == std::cmp::Ordering::Greater)
                        || (!self.forward && result == std::cmp::Ordering::Less)
                    {
                        addr_next = Some(candidate.clone());
                        for slot in next.iter_mut().take(i) {
                            *slot = false;
                        }
                        next[i] = true;
                    }
                }
            }
        }

        // Load array with all addresses that match the next address, and
        // consume them from the pending addresses.
        let mut next_addrs = vec![None; len];
        for i in 0..len {
            if next[i] {
                next_addrs[i] = self.addrs[i].take();
            }
        }
        (addr_next, next_addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressIteratorAdapter, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn adapter(offsets: &[i64]) -> Option<Box<dyn AddressIterator>> {
        Some(Box::new(AddressIteratorAdapter::new(
            offsets.iter().map(|o| addr(*o)).collect(),
        )))
    }

    #[test]
    fn merges_forward_iterators_in_address_order() {
        let mut iter = MultiAddressIterator::new(vec![
            adapter(&[0x1000, 0x2000, 0x4000]),
            adapter(&[0x1500, 0x2000, 0x3000]),
        ]);

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        let expected: Vec<Address> = [0x1000, 0x1500, 0x2000, 0x3000, 0x4000]
            .iter()
            .map(|o| addr(*o))
            .collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn merges_backward_iterators_in_reverse_order() {
        let mut iter = MultiAddressIterator::new_with_direction(
            vec![adapter(&[0x4000, 0x2000]), adapter(&[0x3000, 0x1000])],
            false,
        );

        let mut results = Vec::new();
        while iter.has_next() {
            results.push(iter.next().unwrap());
        }

        let expected: Vec<Address> = [0x4000, 0x3000, 0x2000, 0x1000]
            .iter()
            .map(|o| addr(*o))
            .collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn next_addresses_groups_matching_addresses_per_iterator() {
        let mut iter =
            MultiAddressIterator::new(vec![adapter(&[0x1000, 0x2000]), adapter(&[0x1000])]);

        let first = iter.next_addresses();
        assert_eq!(first, vec![Some(addr(0x1000)), Some(addr(0x1000))]);

        let second = iter.next_addresses();
        assert_eq!(second, vec![Some(addr(0x2000)), None]);

        assert!(!iter.has_next());
    }

    #[test]
    fn treats_missing_iterators_as_empty() {
        let mut iter = MultiAddressIterator::new(vec![adapter(&[0x1000]), None]);

        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(addr(0x1000)));
        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn empty_iterators_have_no_next_address() {
        let mut iter = MultiAddressIterator::new(vec![]);

        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }
}
