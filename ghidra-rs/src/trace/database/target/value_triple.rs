use crate::util::database::spatial::hyper::HyperPoint;
use super::rec_address::RecAddress;

/// A triple representing a value in the trace database.
///
/// This is the Rust equivalent of `ghidra.trace.database.target.ValueTriple`,
/// a record storing a parent key, child key, entry key, snapshot, and record address.
/// It implements the `HyperPoint` marker trait for use in spatial indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueTriple {
    /// The key of the parent object.
    pub parent_key: i64,
    /// The key of the child object.
    pub child_key: i64,
    /// The entry key for the value.
    pub entry_key: String,
    /// The snapshot number.
    pub snap: i64,
    /// The record address for this value.
    pub address: RecAddress,
}

impl ValueTriple {
    /// Creates a new value triple.
    ///
    /// # Arguments
    /// * `parent_key` - The key of the parent object.
    /// * `child_key` - The key of the child object.
    /// * `entry_key` - The entry key for the value.
    /// * `snap` - The snapshot number.
    /// * `address` - The record address for this value.
    pub fn new(
        parent_key: i64,
        child_key: i64,
        entry_key: impl Into<String>,
        snap: i64,
        address: RecAddress,
    ) -> Self {
        Self {
            parent_key,
            child_key,
            entry_key: entry_key.into(),
            snap,
            address,
        }
    }
}

impl HyperPoint for ValueTriple {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_all_fields() {
        let addr = RecAddress::new(1, 0x1000);
        let vt = ValueTriple::new(10, 20, "key1", 5, addr);
        assert_eq!(vt.parent_key, 10);
        assert_eq!(vt.child_key, 20);
        assert_eq!(vt.entry_key, "key1");
        assert_eq!(vt.snap, 5);
        assert_eq!(vt.address, addr);
    }

    #[test]
    fn new_converts_entry_key_to_string() {
        let addr = RecAddress::new(1, 0x1000);
        let vt = ValueTriple::new(10, 20, "test_key", 5, addr);
        assert_eq!(vt.entry_key, "test_key");
    }

    #[test]
    fn clone_creates_independent_copy() {
        let addr = RecAddress::new(1, 0x1000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr);
        let vt2 = vt1.clone();
        assert_eq!(vt1, vt2);
    }

    #[test]
    fn equality_with_same_fields() {
        let addr = RecAddress::new(1, 0x1000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr);
        let vt2 = ValueTriple::new(10, 20, "key1", 5, addr);
        assert_eq!(vt1, vt2);
    }

    #[test]
    fn inequality_on_different_parent_key() {
        let addr = RecAddress::new(1, 0x1000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr);
        let vt2 = ValueTriple::new(11, 20, "key1", 5, addr);
        assert_ne!(vt1, vt2);
    }

    #[test]
    fn inequality_on_different_child_key() {
        let addr = RecAddress::new(1, 0x1000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr);
        let vt2 = ValueTriple::new(10, 21, "key1", 5, addr);
        assert_ne!(vt1, vt2);
    }

    #[test]
    fn inequality_on_different_entry_key() {
        let addr = RecAddress::new(1, 0x1000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr);
        let vt2 = ValueTriple::new(10, 20, "key2", 5, addr);
        assert_ne!(vt1, vt2);
    }

    #[test]
    fn inequality_on_different_snap() {
        let addr = RecAddress::new(1, 0x1000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr);
        let vt2 = ValueTriple::new(10, 20, "key1", 6, addr);
        assert_ne!(vt1, vt2);
    }

    #[test]
    fn inequality_on_different_address() {
        let addr1 = RecAddress::new(1, 0x1000);
        let addr2 = RecAddress::new(1, 0x2000);
        let vt1 = ValueTriple::new(10, 20, "key1", 5, addr1);
        let vt2 = ValueTriple::new(10, 20, "key1", 5, addr2);
        assert_ne!(vt1, vt2);
    }

    #[test]
    fn implements_hyper_point() {
        fn accepts<P: HyperPoint>(_p: &P) {}
        let addr = RecAddress::new(1, 0x1000);
        let vt = ValueTriple::new(10, 20, "key1", 5, addr);
        accepts(&vt);
    }

    #[test]
    fn empty_entry_key_is_valid() {
        let addr = RecAddress::new(1, 0x1000);
        let vt = ValueTriple::new(10, 20, "", 5, addr);
        assert_eq!(vt.entry_key, "");
    }

    #[test]
    fn zero_keys_are_valid() {
        let addr = RecAddress::new(1, 0x1000);
        let vt = ValueTriple::new(0, 0, "key", 0, addr);
        assert_eq!(vt.parent_key, 0);
        assert_eq!(vt.child_key, 0);
        assert_eq!(vt.snap, 0);
    }

    #[test]
    fn negative_keys_are_valid() {
        let addr = RecAddress::new(1, 0x1000);
        let vt = ValueTriple::new(-1, -2, "key", -3, addr);
        assert_eq!(vt.parent_key, -1);
        assert_eq!(vt.child_key, -2);
        assert_eq!(vt.snap, -3);
    }
}
