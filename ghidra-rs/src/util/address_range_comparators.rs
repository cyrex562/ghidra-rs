use crate::program::model::address::AddressRange;
use std::cmp::Ordering;

/// Comparators used for sorting address ranges.
///
/// This mirrors Ghidra's `AddressRangeComparators` enum. Each variant provides
/// a different comparison strategy for `AddressRange` objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRangeComparators {
    /// Compare ranges by their minimum address and order them smallest first.
    Forward,
    /// Compare ranges by their maximum address and order them largest first.
    ///
    /// Which address is compared might not ordinarily matter, since `AddressSet`
    /// requires a disjoint union of ranges. However, these comparators often compare
    /// ranges from different sets, e.g., in order to merge two or more iterators. Thus, in
    /// reverse, we want to ensure ranges are ordered by their *maximum* address.
    Backward,
}

impl AddressRangeComparators {
    /// Compares two `AddressRange` objects according to this comparator variant.
    pub fn compare(&self, a: &AddressRange, b: &AddressRange) -> Ordering {
        match self {
            Self::Forward => a.min_address().cmp(b.min_address()),
            Self::Backward => b.max_address().cmp(a.max_address()),
        }
    }

    /// Returns a comparator function for use with sort operations.
    ///
    /// Example:
    /// ```ignore
    /// let mut ranges = vec![range1, range2, range3];
    /// ranges.sort_by(|a, b| AddressRangeComparators::Forward.compare(a, b));
    /// ```
    pub fn as_fn(&self) -> impl Fn(&AddressRange, &AddressRange) -> Ordering + '_ {
        move |a, b| self.compare(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn range(start: i64, end: i64) -> AddressRange {
        AddressRange::new(addr(start), addr(end))
    }

    #[test]
    fn forward_compares_by_min_address() {
        let comparator = AddressRangeComparators::Forward;

        let range1 = range(0x1000, 0x1100);
        let range2 = range(0x2000, 0x2100);
        let range3 = range(0x0800, 0x0900);

        assert_eq!(comparator.compare(&range3, &range1), Ordering::Less);
        assert_eq!(comparator.compare(&range1, &range2), Ordering::Less);
        assert_eq!(comparator.compare(&range2, &range3), Ordering::Greater);
    }

    #[test]
    fn forward_equal_when_min_addresses_equal() {
        let comparator = AddressRangeComparators::Forward;

        let range1 = range(0x1000, 0x1100);
        let range2 = range(0x1000, 0x2000);

        assert_eq!(comparator.compare(&range1, &range2), Ordering::Equal);
    }

    #[test]
    fn backward_compares_by_max_address_reversed() {
        let comparator = AddressRangeComparators::Backward;

        let range1 = range(0x1000, 0x1100);
        let range2 = range(0x2000, 0x2100);
        let range3 = range(0x0800, 0x3000);

        assert_eq!(comparator.compare(&range1, &range2), Ordering::Greater);
        assert_eq!(comparator.compare(&range2, &range1), Ordering::Less);
        assert_eq!(comparator.compare(&range3, &range1), Ordering::Greater);
    }

    #[test]
    fn backward_equal_when_max_addresses_equal() {
        let comparator = AddressRangeComparators::Backward;

        let range1 = range(0x1000, 0x2000);
        let range2 = range(0x0800, 0x2000);

        assert_eq!(comparator.compare(&range1, &range2), Ordering::Equal);
    }

    #[test]
    fn comparator_as_fn() {
        let forward_cmp = AddressRangeComparators::Forward.as_fn();

        let range1 = range(0x1000, 0x1100);
        let range2 = range(0x2000, 0x2100);

        assert_eq!(forward_cmp(&range1, &range2), Ordering::Less);
    }

    #[test]
    fn sorting_with_forward() {
        let mut ranges = vec![range(0x2000, 0x2100), range(0x0800, 0x0900), range(0x1000, 0x1100)];
        ranges.sort_by(|a, b| AddressRangeComparators::Forward.compare(a, b));

        assert_eq!(ranges[0].min_address(), &addr(0x0800));
        assert_eq!(ranges[1].min_address(), &addr(0x1000));
        assert_eq!(ranges[2].min_address(), &addr(0x2000));
    }

    #[test]
    fn sorting_with_backward() {
        let mut ranges = vec![range(0x2000, 0x2100), range(0x0800, 0x3000), range(0x1000, 0x1100)];
        ranges.sort_by(|a, b| AddressRangeComparators::Backward.compare(a, b));

        assert_eq!(ranges[0].max_address(), &addr(0x3000));
        assert_eq!(ranges[1].max_address(), &addr(0x2100));
        assert_eq!(ranges[2].max_address(), &addr(0x1100));
    }
}
