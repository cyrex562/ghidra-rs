/// Listener for an address editor panel.
///
/// Implementors are notified of address edit changes when a double-click or
/// `<Enter>` key action occurs. After notification the implementor may call
/// `get_address()` on the editor panel to retrieve the current address value.
pub trait AddressEditorPanelListener {
    /// Called when the address in the panel has been edited via a double-click
    /// or `<Enter>` key action.
    fn address_edited(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        call_count: usize,
    }

    impl AddressEditorPanelListener for TestListener {
        fn address_edited(&mut self) {
            self.call_count += 1;
        }
    }

    #[test]
    fn test_address_edited_called() {
        let mut listener = TestListener { call_count: 0 };
        listener.address_edited();
        assert_eq!(listener.call_count, 1);
    }

    #[test]
    fn test_address_edited_called_multiple_times() {
        let mut listener = TestListener { call_count: 0 };
        listener.address_edited();
        listener.address_edited();
        listener.address_edited();
        assert_eq!(listener.call_count, 3);
    }
}
