//! Port of `ghidra.app.util.viewer.util.AddressIndexMap`: maps the addresses
//! of an address set onto a dense index space (one index per address, gaps
//! removed) so a listing can scroll it like a list. Indices are `u128`
//! (Java `BigInteger`): a full 64-bit space has 2^64 addresses.

use crate::program::model::address::{Address, AddressRange, AddressSetView};

/// Dense index space over an address set's ranges.
#[derive(Debug, Clone)]
pub struct AddressIndexMap {
    ranges: Vec<AddressRange>,
    /// First index of each range.
    starts: Vec<u128>,
    count: u128,
}

fn range_len(r: &AddressRange) -> u128 {
    (r.max_address().offset() as u64 as u128) - (r.min_address().offset() as u64 as u128) + 1
}

impl AddressIndexMap {
    /// Builds the map over `set`'s ranges, in address order.
    pub fn new(set: &dyn AddressSetView) -> Self {
        let ranges: Vec<AddressRange> = set.address_ranges().collect();
        let mut starts = Vec::with_capacity(ranges.len());
        let mut count: u128 = 0;
        for r in &ranges {
            starts.push(count);
            count += range_len(r);
        }
        Self { ranges, starts, count }
    }

    /// Number of indices (addresses).
    pub fn index_count(&self) -> u128 {
        self.count
    }

    /// The address at `index`, or `None` past the end.
    pub fn address(&self, index: u128) -> Option<Address> {
        if index >= self.count {
            return None;
        }
        let i = self.starts.partition_point(|&s| s <= index) - 1;
        let r = &self.ranges[i];
        let min = r.min_address();
        let offset = (min.offset() as u64).wrapping_add((index - self.starts[i]) as u64);
        Some(Address::new(min.space().clone(), offset as i64))
    }

    /// The index of `address`, or `None` if it is not in the set.
    pub fn index(&self, address: &Address) -> Option<u128> {
        let target = address.offset() as u64;
        let i = self.ranges.iter().position(|r| {
            let lo = r.min_address().offset() as u64;
            let hi = r.max_address().offset() as u64;
            r.min_address().space() == address.space() && lo <= target && target <= hi
        })?;
        Some(self.starts[i] + (target - self.ranges[i].min_address().offset() as u64) as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn space(bits: i32) -> Arc<AddressSpace> {
        AddressSpace::new("ram", bits, 1, AddressSpaceType::Ram, 0)
    }
    fn set(sp: &Arc<AddressSpace>, ranges: &[(i64, i64)]) -> AddressSet {
        let mut s = AddressSet::new();
        for (a, b) in ranges {
            s.add_range(&Address::new(sp.clone(), *a), &Address::new(sp.clone(), *b));
        }
        s
    }

    #[test]
    fn gaps_are_removed_and_indices_are_dense() {
        let sp = space(32);
        let m = AddressIndexMap::new(&set(&sp, &[(0x1000, 0x100f), (0x2000, 0x2003)]));
        assert_eq!(m.index_count(), 20);
        assert_eq!(m.address(0).unwrap().offset(), 0x1000);
        assert_eq!(m.address(15).unwrap().offset(), 0x100f);
        assert_eq!(m.address(16).unwrap().offset(), 0x2000);
        assert_eq!(m.address(19).unwrap().offset(), 0x2003);
        assert!(m.address(20).is_none());
        assert_eq!(m.index(&Address::new(sp.clone(), 0x2001)), Some(17));
        assert_eq!(m.index(&Address::new(sp.clone(), 0x1800)), None); // in the gap
    }

    #[test]
    fn top_of_a_64_bit_space_does_not_overflow() {
        let sp = space(64);
        let lo = 0xffff_ffff_ffff_ff00_u64 as i64;
        let hi = -1_i64; // 0xffff_ffff_ffff_ffff
        let m = AddressIndexMap::new(&set(&sp, &[(0, 0xff), (lo, hi)]));
        assert_eq!(m.index_count(), 512);
        assert_eq!(m.address(511).unwrap().offset(), hi);
        assert_eq!(m.index(&Address::new(sp.clone(), hi)), Some(511));
    }

    #[test]
    fn whole_64_bit_space_counts_2_pow_64() {
        let sp = space(64);
        let m = AddressIndexMap::new(&set(&sp, &[(0, -1)]));
        assert_eq!(m.index_count(), 1u128 << 64);
        assert_eq!(m.address((1u128 << 64) - 1).unwrap().offset(), -1);
    }

    #[test]
    fn empty_set_has_no_indices() {
        let m = AddressIndexMap::new(&AddressSet::new());
        assert_eq!(m.index_count(), 0);
        assert!(m.address(0).is_none());
    }
}
