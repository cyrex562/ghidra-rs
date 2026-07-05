use crate::program::model::address::{AddressRange, AddressSet};

/// Utilities for collecting address ranges.
///
/// This mirrors Ghidra's `AddressCollectors`.
pub struct AddressCollectors;

impl AddressCollectors {
    /// Unions ranges into a single mutable address set.
    pub fn to_address_set<I>(ranges: I) -> AddressSet
    where
        I: IntoIterator<Item = AddressRange>,
    {
        let mut set = AddressSet::new();
        for range in ranges {
            set.add_range_object(&range);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};

    #[test]
    fn collects_ranges_into_normalized_address_set() {
        let set = AddressCollectors::to_address_set(vec![
            AddressRange::new(addr(0x1000), addr(0x1002)),
            AddressRange::new(addr(0x1003), addr(0x1005)),
            AddressRange::new(addr(0x2000), addr(0x2000)),
        ]);

        assert_eq!(set.num_address_ranges(), 2);
        assert!(set.contains_range(&addr(0x1000), &addr(0x1005)));
        assert!(set.contains(&addr(0x2000)));
    }

    #[test]
    fn collects_empty_iterator() {
        let empty: Vec<AddressRange> = vec![];
        let set = AddressCollectors::to_address_set(empty);
        assert!(set.is_empty());
        assert_eq!(set.num_address_ranges(), 0);
    }

    #[test]
    fn collects_single_range() {
        let set = AddressCollectors::to_address_set(vec![
            AddressRange::new(addr(0x1000), addr(0x1010)),
        ]);

        assert_eq!(set.num_address_ranges(), 1);
        assert!(set.contains(&addr(0x1000)));
        assert!(set.contains(&addr(0x1010)));
        assert!(!set.contains(&addr(0x0fff)));
        assert!(!set.contains(&addr(0x1011)));
    }

    #[test]
    fn collects_overlapping_ranges_into_single_merged_range() {
        let set = AddressCollectors::to_address_set(vec![
            AddressRange::new(addr(0x1000), addr(0x1010)),
            AddressRange::new(addr(0x100f), addr(0x1020)),
        ]);

        assert_eq!(set.num_address_ranges(), 1);
        assert!(set.contains_range(&addr(0x1000), &addr(0x1020)));
    }

    #[test]
    fn collects_adjacent_ranges() {
        let set = AddressCollectors::to_address_set(vec![
            AddressRange::new(addr(0x1000), addr(0x1010)),
            AddressRange::new(addr(0x1011), addr(0x1020)),
        ]);

        assert_eq!(set.num_address_ranges(), 1);
        assert!(set.contains_range(&addr(0x1000), &addr(0x1020)));
    }

    #[test]
    fn collects_duplicate_ranges() {
        let set = AddressCollectors::to_address_set(vec![
            AddressRange::new(addr(0x1000), addr(0x1010)),
            AddressRange::new(addr(0x1000), addr(0x1010)),
        ]);

        assert_eq!(set.num_address_ranges(), 1);
        assert!(set.contains_range(&addr(0x1000), &addr(0x1010)));
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
