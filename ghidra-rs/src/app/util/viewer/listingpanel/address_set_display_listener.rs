//! Listener interface for changes to the set of visible addresses in the listing.

use crate::program::model::address::AddressSetView;

/// Notified whenever the set of visible addresses change in the listing.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener`.
pub trait AddressSetDisplayListener {
    /// Called whenever the set of visible addresses change in the listing.
    ///
    /// # Arguments
    ///
    /// * `visible_addresses` - The current set of visible addresses in the listing.
    ///   If no visible addresses are in the listing view, an empty `AddressSetView` is passed.
    fn visible_addresses_changed(&mut self, visible_addresses: &dyn AddressSetView);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSet;

    struct RecordingListener {
        calls: Vec<usize>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self { calls: Vec::new() }
        }
    }

    impl AddressSetDisplayListener for RecordingListener {
        fn visible_addresses_changed(&mut self, visible_addresses: &dyn AddressSetView) {
            self.calls.push(visible_addresses.num_addresses() as usize);
        }
    }

    #[test]
    fn test_visible_addresses_changed_called() {
        let mut listener = RecordingListener::new();
        let address_set = AddressSet::new();
        listener.visible_addresses_changed(&address_set);
        assert_eq!(listener.calls.len(), 1);
        assert_eq!(listener.calls[0], 0);
    }

    #[test]
    fn test_visible_addresses_changed_multiple_calls() {
        let mut listener = RecordingListener::new();
        let address_set = AddressSet::new();
        listener.visible_addresses_changed(&address_set);
        listener.visible_addresses_changed(&address_set);
        listener.visible_addresses_changed(&address_set);
        assert_eq!(listener.calls.len(), 3);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener: Box<dyn AddressSetDisplayListener> = Box::new(RecordingListener::new());
        let address_set = AddressSet::new();
        listener.visible_addresses_changed(&address_set);
    }

    #[test]
    fn test_empty_address_set() {
        let mut listener = RecordingListener::new();
        let empty_set = AddressSet::new();
        listener.visible_addresses_changed(&empty_set);
        assert_eq!(listener.calls[0], 0);
    }
}
