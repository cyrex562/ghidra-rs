use crate::program::model::address::Address;

/// Abstract base for information about type methods and interface methods.
///
/// Mirrors Ghidra's `MethodInfo` Java abstract class. This struct provides a base
/// address for method information and is typically composed with additional
/// method-specific data in Rust.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodInfo {
    address: Address,
}

impl MethodInfo {
    /// Creates a new MethodInfo with the given entry point address.
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    /// Returns the entry point of the method.
    pub fn address(&self) -> Address {
        self.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::MethodInfo;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn create_test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn new_stores_address() {
        let addr = create_test_address(0x1000);
        let method_info = MethodInfo::new(addr);
        assert_eq!(method_info.address(), addr);
    }

    #[test]
    fn equality_based_on_address() {
        let addr1 = create_test_address(0x1000);
        let addr2 = create_test_address(0x1000);
        let addr3 = create_test_address(0x2000);

        let info1 = MethodInfo::new(addr1);
        let info2 = MethodInfo::new(addr2);
        let info3 = MethodInfo::new(addr3);

        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
    }

    #[test]
    fn clone_preserves_address() {
        let addr = create_test_address(0x5000);
        let info = MethodInfo::new(addr);
        let cloned = info.clone();

        assert_eq!(info, cloned);
        assert_eq!(cloned.address(), addr);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;

        let addr = create_test_address(0x3000);
        let info1 = MethodInfo::new(addr);
        let info2 = MethodInfo::new(addr);

        let mut set = HashSet::new();
        set.insert(info1);
        assert!(set.contains(&info2));
    }

    #[test]
    fn different_addresses_have_different_hashes_usually() {
        let addr1 = create_test_address(0x1000);
        let addr2 = create_test_address(0x2000);

        let info1 = MethodInfo::new(addr1);
        let info2 = MethodInfo::new(addr2);

        let mut set = std::collections::HashSet::new();
        set.insert(info1);
        assert!(!set.contains(&info2));
    }
}
