//! Trait for tracking the open/close state at an address.

use crate::program::model::address::Address;

/// Manages the open/close state of addresses in the viewer.
///
/// Corresponds to Java `ghidra.app.util.viewer.util.OpenCloseManager`.
pub trait OpenCloseManager {
    /// Checks if the state is "open" for the given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to test
    ///
    /// # Returns
    ///
    /// Returns `true` if the state of the given address is "open"
    fn is_open(&self, address: &Address) -> bool;

    /// Sets the state at the given address to be "open".
    ///
    /// # Arguments
    ///
    /// * `address` - The address to set "open"
    fn open(&mut self, address: &Address);

    /// Sets the state at the given address to be "closed".
    ///
    /// # Arguments
    ///
    /// * `address` - The address to set "closed"
    fn close(&mut self, address: &Address);

    /// Checks if the default state is "open".
    ///
    /// # Returns
    ///
    /// Returns `true` if the default state for addresses is "open"
    fn is_open_by_default(&self) -> bool;

    /// Sets all addresses to "open" and makes "open" the default state.
    ///
    /// This makes "open" the default state and clears all individual settings.
    fn open_all(&mut self);

    /// Sets all addresses to "closed" and makes "closed" the default state.
    ///
    /// This makes "closed" the default state and clears all individual settings.
    fn close_all(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct TestManager {
        default_open: bool,
    }

    impl TestManager {
        fn new(default_open: bool) -> Self {
            Self { default_open }
        }
    }

    impl OpenCloseManager for TestManager {
        fn is_open(&self, _address: &Address) -> bool {
            self.default_open
        }

        fn open(&mut self, _address: &Address) {}

        fn close(&mut self, _address: &Address) {}

        fn is_open_by_default(&self) -> bool {
            self.default_open
        }

        fn open_all(&mut self) {
            self.default_open = true;
        }

        fn close_all(&mut self) {
            self.default_open = false;
        }
    }

    #[test]
    fn test_is_open_by_default_true() {
        let manager = TestManager::new(true);
        assert!(manager.is_open_by_default());
    }

    #[test]
    fn test_is_open_by_default_false() {
        let manager = TestManager::new(false);
        assert!(!manager.is_open_by_default());
    }

    #[test]
    fn test_open_all() {
        let mut manager = TestManager::new(false);
        manager.open_all();
        assert!(manager.is_open_by_default());
    }

    #[test]
    fn test_close_all() {
        let mut manager = TestManager::new(true);
        manager.close_all();
        assert!(!manager.is_open_by_default());
    }

    #[test]
    fn test_is_open() {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0);
        let address = space.address(0x1000);

        let manager = TestManager::new(true);
        assert!(manager.is_open(&address));

        let manager = TestManager::new(false);
        assert!(!manager.is_open(&address));
    }

    #[test]
    fn test_trait_object() {
        let mut manager: Box<dyn OpenCloseManager> = Box::new(TestManager::new(false));
        assert!(!manager.is_open_by_default());
        manager.open_all();
        assert!(manager.is_open_by_default());
    }
}
