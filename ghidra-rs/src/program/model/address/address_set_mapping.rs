use crate::program::model::address::{Address, AddressRange, AddressSetView};

/// Random access to addresses in an address set by contiguous set index.
///
/// This mirrors Ghidra's `AddressSetMapping`.
#[derive(Debug, Clone)]
pub struct AddressSetMapping {
    ranges: Vec<AddressRange>,
    indexes: Vec<usize>,
    current_range: Option<AddressRange>,
    current_range_start: isize,
    current_range_end: isize,
    current_range_index: isize,
    max_index: usize,
}

impl AddressSetMapping {
    pub fn new(set: &dyn AddressSetView) -> Result<Self, String> {
        let num_addresses = set.num_addresses();
        if num_addresses > i32::MAX as u64 {
            return Err(
                "This class does not support AddressSets whose size >= 0x7fffffff byte addresses."
                    .to_string(),
            );
        }
        let mut range_iterator = set.address_ranges();
        let mut ranges = Vec::new();
        while let Some(range) = range_iterator.next_range() {
            ranges.push(range);
        }

        let mut indexes = Vec::with_capacity(ranges.len() + 1);
        indexes.push(0);
        for range in &ranges {
            let next = indexes[indexes.len() - 1] + range.length() as usize;
            indexes.push(next);
        }

        Ok(Self {
            ranges,
            indexes,
            current_range: None,
            current_range_start: -1,
            current_range_end: -1,
            current_range_index: -1,
            max_index: num_addresses as usize,
        })
    }

    /// Returns the address at the given zero-based position in the address set.
    pub fn address(&mut self, index: usize) -> Option<Address> {
        if index >= self.max_index {
            return None;
        }
        if !self.index_in_current_range(index) {
            self.set_current_range(index);
        }
        let offset = index - self.current_range_start as usize;
        self.current_range
            .as_ref()
            .map(|range| range.min_address().add(offset as i64).unwrap())
    }

    fn set_current_range(&mut self, index: usize) {
        if self.current_range_index >= 0 && index as isize == self.current_range_end + 1 {
            self.current_range_index += 1;
        } else {
            self.current_range_index = match self.indexes.binary_search(&index) {
                Ok(i) => i as isize,
                Err(i) => i as isize - 2,
            };
        }

        let range_index = self.current_range_index as usize;
        let range = self.ranges[range_index].clone();
        self.current_range_start = self.indexes[range_index] as isize;
        self.current_range_end = self.current_range_start + range.length() as isize - 1;
        self.current_range = Some(range);
    }

    fn index_in_current_range(&self, index: usize) -> bool {
        index as isize >= self.current_range_start && index as isize <= self.current_range_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};

    #[test]
    fn maps_sparse_set_indexes_to_addresses() {
        let mut set = AddressSet::new();
        set.add_range(&addr(0), &addr(4));
        set.add_range(&addr(90), &addr(94));
        let mut mapping = AddressSetMapping::new(&set).unwrap();

        assert_eq!(mapping.address(0), Some(addr(0)));
        assert_eq!(mapping.address(1), Some(addr(1)));
        assert_eq!(mapping.address(4), Some(addr(4)));
        assert_eq!(mapping.address(5), Some(addr(90)));
        assert_eq!(mapping.address(9), Some(addr(94)));
        assert_eq!(mapping.address(10), None);
    }

    #[test]
    fn empty_set_has_no_mapped_addresses() {
        let set = AddressSet::new();
        let mut mapping = AddressSetMapping::new(&set).unwrap();

        assert_eq!(mapping.address(0), None);
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
