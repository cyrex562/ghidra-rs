use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use std::sync::Arc;

/// Minimum non-global namespace ID supported by old namespace addresses.
pub const OLD_MIN_NAMESPACE_ID: i64 = 1;

/// Maximum non-global namespace ID supported by old namespace addresses.
pub const OLD_MAX_NAMESPACE_ID: i64 = 0x0fffffff;

/// Upgrade-only namespace-oriented address representation.
///
/// This mirrors Ghidra's `OldGenericNamespaceAddress`, which existed for old
/// external, stack, and register address encodings.  It intentionally remains a
/// distinct value type instead of changing the modern `Address` identity model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OldGenericNamespaceAddress {
    address: Address,
    namespace_id: i64,
}

impl OldGenericNamespaceAddress {
    pub fn new(
        address_space: Arc<AddressSpace>,
        offset: i64,
        namespace_id: i64,
    ) -> Result<Self, String> {
        if !(0..=OLD_MAX_NAMESPACE_ID).contains(&namespace_id) {
            return Err("namespaceID too large".to_string());
        }
        Ok(Self {
            address: Address::new(address_space, offset),
            namespace_id,
        })
    }

    pub fn namespace_id(&self) -> i64 {
        self.namespace_id
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn address_space(&self) -> &Arc<AddressSpace> {
        self.address.space()
    }

    pub fn offset(&self) -> i64 {
        self.address.offset()
    }

    pub fn global_address(&self) -> Address {
        Address::new(self.address.space().clone(), self.address.offset())
    }

    pub fn min_address(
        address_space: Arc<AddressSpace>,
        namespace_id: i64,
    ) -> Result<Self, String> {
        Self::new(address_space, 0, namespace_id)
    }

    pub fn max_address(
        address_space: Arc<AddressSpace>,
        namespace_id: i64,
    ) -> Result<Self, String> {
        let offset = if address_space.space_type() == AddressSpaceType::Stack {
            -1
        } else {
            address_space.max_address().offset()
        };
        Self::new(address_space, offset, namespace_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_namespace_address_fields() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let address = OldGenericNamespaceAddress::new(ram.clone(), 0x1234, 7).unwrap();

        assert_eq!(address.namespace_id(), 7);
        assert_eq!(address.address_space(), &ram);
        assert_eq!(address.offset(), 0x1234);
        assert_eq!(address.global_address(), Address::new(ram, 0x1234));
    }

    #[test]
    fn rejects_invalid_namespace_ids() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);

        assert!(OldGenericNamespaceAddress::new(ram.clone(), 0, -1).is_err());
        assert!(OldGenericNamespaceAddress::new(ram, 0, OLD_MAX_NAMESPACE_ID + 1).is_err());
    }

    #[test]
    fn min_and_max_addresses_match_java_upgrade_helpers() {
        let ram = AddressSpace::new("ram", 8, 1, AddressSpaceType::Ram, 1);
        let stack = AddressSpace::new("stack", 8, 1, AddressSpaceType::Stack, 2);

        let min =
            OldGenericNamespaceAddress::min_address(ram.clone(), OLD_MIN_NAMESPACE_ID).unwrap();
        assert_eq!(min.offset(), 0);
        assert_eq!(min.namespace_id(), OLD_MIN_NAMESPACE_ID);

        let max = OldGenericNamespaceAddress::max_address(ram, 2).unwrap();
        assert_eq!(max.offset(), 0xff);
        assert_eq!(max.namespace_id(), 2);

        let stack_max = OldGenericNamespaceAddress::max_address(stack, 3).unwrap();
        assert_eq!(stack_max.offset(), -1);
        assert_eq!(stack_max.namespace_id(), 3);
    }

    #[test]
    fn equality_includes_namespace_id() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let first = OldGenericNamespaceAddress::new(ram.clone(), 0x20, 1).unwrap();
        let same = OldGenericNamespaceAddress::new(ram.clone(), 0x20, 1).unwrap();
        let different_namespace = OldGenericNamespaceAddress::new(ram, 0x20, 2).unwrap();

        assert_eq!(first, same);
        assert_ne!(first, different_namespace);
    }
}
