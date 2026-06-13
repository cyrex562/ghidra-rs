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

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
