/// A pairing of an address with a snapshot key, representing a point in space-time.
///
/// Java source: `ghidra.trace.model.AddressSnap`.
///
/// In the original, `AddressSnap` is an interface requiring implementors to supply an
/// `Address` and a snapshot key (long). Because `Address` is a concrete type in our
/// codebase, we define this as a trait with associated types for flexibility in
/// concrete implementations.
pub trait AddressSnap: Ord {
    /// The address at this point in time.
    fn get_address(&self) -> &crate::program::model::address::Address;

    /// The snapshot key at this point in space.
    fn get_snap(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::AddressSnap;
    use std::cmp::Ordering;
    use std::sync::Arc;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockAddressSnap {
        addr: crate::program::model::address::Address,
        snap: i64,
    }

    impl PartialOrd for MockAddressSnap {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for MockAddressSnap {
        fn cmp(&self, other: &Self) -> Ordering {
            match self.addr.offset().cmp(&other.addr.offset()) {
                Ordering::Equal => self.snap.cmp(&other.snap),
                other_ord => other_ord,
            }
        }
    }

    impl AddressSnap for MockAddressSnap {
        fn get_address(&self) -> &crate::program::model::address::Address {
            &self.addr
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    fn make_mock_space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    fn make_address_snap(offset: i64, snap: i64) -> MockAddressSnap {
        let space = make_mock_space();
        MockAddressSnap {
            addr: crate::program::model::address::Address::new(space, offset),
            snap,
        }
    }

    #[test]
    fn get_address_returns_address() {
        let as_mock = make_address_snap(0x1000, 42);
        assert_eq!(as_mock.get_address().offset(), 0x1000);
    }

    #[test]
    fn get_snap_returns_snapshot_key() {
        let as_mock = make_address_snap(0x2000, 100);
        assert_eq!(as_mock.get_snap(), 100);
    }

    #[test]
    fn ordering_by_address_first() {
        let as1 = make_address_snap(0x1000, 50);
        let as2 = make_address_snap(0x2000, 50);
        assert!(as1 < as2);
        assert!(as2 > as1);
    }

    #[test]
    fn ordering_by_snap_when_addresses_equal() {
        let as1 = make_address_snap(0x1000, 10);
        let as2 = make_address_snap(0x1000, 20);
        assert!(as1 < as2);
        assert!(as2 > as1);
    }

    #[test]
    fn equality_with_same_address_and_snap() {
        let as1 = make_address_snap(0x1000, 50);
        let as2 = make_address_snap(0x1000, 50);
        assert_eq!(as1, as2);
    }

    #[test]
    fn comparable_to_self() {
        let as_mock = make_address_snap(0x1234, 99);
        assert_eq!(as_mock.cmp(&as_mock), Ordering::Equal);
    }
}
