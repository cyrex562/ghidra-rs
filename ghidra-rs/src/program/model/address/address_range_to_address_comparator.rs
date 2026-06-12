use crate::program::model::address::{Address, AddressRange};
use std::cmp::Ordering;

/// Compares an address against an address range.
///
/// This mirrors Ghidra's `AddressRangeToAddressComparator`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AddressRangeToAddressComparator;

impl AddressRangeToAddressComparator {
    /// Compares a range to an address.
    ///
    /// Returns `Ordering::Less` if the address is greater than the range,
    /// `Ordering::Equal` if the address is in the range, and
    /// `Ordering::Greater` if the address is less than the range.
    pub fn compare_range_to_address(range: &AddressRange, address: &Address) -> Ordering {
        range.compare_to_address(address)
    }

    /// Compares an address to a range, matching the inverse branch in Ghidra's
    /// object comparator.
    pub fn compare_address_to_range(address: &Address, range: &AddressRange) -> Ordering {
        range.compare_to_address(address).reverse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn compares_range_to_address() {
        let range = AddressRange::new(addr(0x1000), addr(0x10ff));

        assert_eq!(
            AddressRangeToAddressComparator::compare_range_to_address(&range, &addr(0x0fff)),
            Ordering::Greater
        );
        assert_eq!(
            AddressRangeToAddressComparator::compare_range_to_address(&range, &addr(0x1000)),
            Ordering::Equal
        );
        assert_eq!(
            AddressRangeToAddressComparator::compare_range_to_address(&range, &addr(0x10ff)),
            Ordering::Equal
        );
        assert_eq!(
            AddressRangeToAddressComparator::compare_range_to_address(&range, &addr(0x1100)),
            Ordering::Less
        );
    }

    #[test]
    fn compares_address_to_range_as_inverse() {
        let range = AddressRange::new(addr(0x1000), addr(0x10ff));

        assert_eq!(
            AddressRangeToAddressComparator::compare_address_to_range(&addr(0x0fff), &range),
            Ordering::Less
        );
        assert_eq!(
            AddressRangeToAddressComparator::compare_address_to_range(&addr(0x1001), &range),
            Ordering::Equal
        );
        assert_eq!(
            AddressRangeToAddressComparator::compare_address_to_range(&addr(0x1100), &range),
            Ordering::Greater
        );
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
