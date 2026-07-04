use crate::program::model::address::Address;
use std::collections::HashSet;

use super::OpenCloseManager;

/// Manages open/close state for addresses in memory.
///
/// Maintains a simple open/close state for address locations. The default open/close
/// state can be set and then a set of addresses is kept for the locations that are the
/// opposite of the default.
///
/// Corresponds to Java `ghidra.app.util.viewer.util.InMemoryOpenCloseManager`.
pub struct InMemoryOpenCloseManager {
    open_by_default: bool,
    addresses: HashSet<Address>,
}

impl InMemoryOpenCloseManager {
    /// Creates a new manager with the default open state.
    ///
    /// # Returns
    ///
    /// A new manager with "open by default" set to true and an empty address set.
    pub fn new() -> Self {
        Self {
            open_by_default: true,
            addresses: HashSet::new(),
        }
    }
}

impl Default for InMemoryOpenCloseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenCloseManager for InMemoryOpenCloseManager {
    fn is_open(&self, address: &Address) -> bool {
        let contains = self.addresses.contains(address);
        if self.open_by_default {
            !contains
        } else {
            contains
        }
    }

    fn open(&mut self, address: &Address) {
        if self.open_by_default {
            self.addresses.remove(address);
        } else {
            self.addresses.insert(address.clone());
        }
    }

    fn close(&mut self, address: &Address) {
        if self.open_by_default {
            self.addresses.insert(address.clone());
        } else {
            self.addresses.remove(address);
        }
    }

    fn is_open_by_default(&self) -> bool {
        self.open_by_default
    }

    fn open_all(&mut self) {
        self.open_by_default = true;
        self.addresses.clear();
    }

    fn close_all(&mut self) {
        self.open_by_default = false;
        self.addresses.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn create_test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn test_new_default_state() {
        let manager = InMemoryOpenCloseManager::new();
        assert!(manager.is_open_by_default());
    }

    #[test]
    fn test_default_trait() {
        let manager = InMemoryOpenCloseManager::default();
        assert!(manager.is_open_by_default());
    }

    #[test]
    fn test_is_open_with_default_true() {
        let manager = InMemoryOpenCloseManager::new();
        let addr = create_test_address(0x1000);
        assert!(manager.is_open(&addr));
    }

    #[test]
    fn test_is_open_with_default_false() {
        let mut manager = InMemoryOpenCloseManager::new();
        manager.close_all();
        let addr = create_test_address(0x1000);
        assert!(!manager.is_open(&addr));
    }

    #[test]
    fn test_open_address_when_default_true() {
        let mut manager = InMemoryOpenCloseManager::new();
        let addr = create_test_address(0x1000);
        manager.close(&addr);
        assert!(!manager.is_open(&addr));
        manager.open(&addr);
        assert!(manager.is_open(&addr));
    }

    #[test]
    fn test_close_address_when_default_true() {
        let mut manager = InMemoryOpenCloseManager::new();
        let addr = create_test_address(0x1000);
        assert!(manager.is_open(&addr));
        manager.close(&addr);
        assert!(!manager.is_open(&addr));
    }

    #[test]
    fn test_open_address_when_default_false() {
        let mut manager = InMemoryOpenCloseManager::new();
        manager.close_all();
        let addr = create_test_address(0x1000);
        assert!(!manager.is_open(&addr));
        manager.open(&addr);
        assert!(manager.is_open(&addr));
    }

    #[test]
    fn test_close_address_when_default_false() {
        let mut manager = InMemoryOpenCloseManager::new();
        manager.close_all();
        let addr = create_test_address(0x1000);
        manager.open(&addr);
        assert!(manager.is_open(&addr));
        manager.close(&addr);
        assert!(!manager.is_open(&addr));
    }

    #[test]
    fn test_multiple_addresses() {
        let mut manager = InMemoryOpenCloseManager::new();
        let addr1 = create_test_address(0x1000);
        let addr2 = create_test_address(0x2000);
        let addr3 = create_test_address(0x3000);

        manager.close(&addr1);
        manager.close(&addr2);

        assert!(!manager.is_open(&addr1));
        assert!(!manager.is_open(&addr2));
        assert!(manager.is_open(&addr3));
    }

    #[test]
    fn test_open_all() {
        let mut manager = InMemoryOpenCloseManager::new();
        manager.close_all();
        assert!(!manager.is_open_by_default());

        let addr1 = create_test_address(0x1000);
        let addr2 = create_test_address(0x2000);
        manager.open(&addr1);

        manager.open_all();
        assert!(manager.is_open_by_default());
        assert!(manager.is_open(&addr1));
        assert!(manager.is_open(&addr2));
    }

    #[test]
    fn test_close_all() {
        let mut manager = InMemoryOpenCloseManager::new();
        assert!(manager.is_open_by_default());

        let addr1 = create_test_address(0x1000);
        let addr2 = create_test_address(0x2000);
        manager.close(&addr1);

        manager.close_all();
        assert!(!manager.is_open_by_default());
        assert!(!manager.is_open(&addr1));
        assert!(!manager.is_open(&addr2));
    }

    #[test]
    fn test_toggle_default_state() {
        let mut manager = InMemoryOpenCloseManager::new();
        let addr = create_test_address(0x1000);

        manager.close(&addr);
        assert!(!manager.is_open(&addr));

        manager.close_all();
        assert!(!manager.is_open(&addr));

        manager.open_all();
        assert!(manager.is_open(&addr));

        manager.open(&addr);
        assert!(manager.is_open(&addr));
    }

    #[test]
    fn test_idempotent_operations() {
        let mut manager = InMemoryOpenCloseManager::new();
        let addr = create_test_address(0x1000);

        manager.open(&addr);
        manager.open(&addr);
        assert!(manager.is_open(&addr));

        manager.close(&addr);
        manager.close(&addr);
        assert!(!manager.is_open(&addr));
    }

    #[test]
    fn test_state_preservation_across_operations() {
        let mut manager = InMemoryOpenCloseManager::new();
        let addr1 = create_test_address(0x1000);
        let addr2 = create_test_address(0x2000);

        manager.close(&addr1);
        manager.close(&addr2);

        assert!(!manager.is_open(&addr1));
        assert!(!manager.is_open(&addr2));

        manager.open(&addr1);
        assert!(manager.is_open(&addr1));
        assert!(!manager.is_open(&addr2));
    }
}
