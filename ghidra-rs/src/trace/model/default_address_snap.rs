use std::cmp::Ordering;

use crate::program::model::address::Address;
use crate::trace::model::address_snap::AddressSnap;

/// A simple, concrete pairing of an address with a snapshot key.
///
/// Java source: `ghidra.trace.model.DefaultAddressSnap`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DefaultAddressSnap {
    address: Address,
    snap: i64,
}

impl DefaultAddressSnap {
    pub fn new(address: Address, snap: i64) -> Self {
        Self { address, snap }
    }
}

impl AddressSnap for DefaultAddressSnap {
    fn get_address(&self) -> &Address {
        &self.address
    }

    fn get_snap(&self) -> i64 {
        self.snap
    }
}

impl PartialOrd for DefaultAddressSnap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultAddressSnap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address
            .cmp(&other.address)
            .then_with(|| (self.snap as u64).cmp(&(other.snap as u64)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use std::sync::Arc;

    fn make_space() -> Arc<AddressSpace> {
        AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    fn make_snap(offset: i64, snap: i64) -> DefaultAddressSnap {
        let space = make_space();
        DefaultAddressSnap::new(Address::new(space, offset), snap)
    }

    #[test]
    fn get_address_and_snap_return_constructor_values() {
        let as_default = make_snap(0x1000, 42);
        assert_eq!(as_default.get_address().offset(), 0x1000);
        assert_eq!(as_default.get_snap(), 42);
    }

    #[test]
    fn equality_with_same_address_and_snap() {
        let a = make_snap(0x1000, 50);
        let b = make_snap(0x1000, 50);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_with_different_snap() {
        let a = make_snap(0x1000, 50);
        let b = make_snap(0x1000, 51);
        assert_ne!(a, b);
    }

    #[test]
    fn ordering_by_address_first() {
        let a = make_snap(0x1000, 50);
        let b = make_snap(0x2000, 50);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn ordering_by_snap_when_addresses_equal() {
        let a = make_snap(0x1000, 10);
        let b = make_snap(0x1000, 20);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn ordering_treats_snap_as_unsigned() {
        let a = make_snap(0x1000, -1);
        let b = make_snap(0x1000, 1);
        assert!(a > b);
    }

    #[test]
    fn comparable_to_self() {
        let a = make_snap(0x1234, 99);
        assert_eq!(a.cmp(&a), Ordering::Equal);
    }
}
