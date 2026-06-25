/// Listener notified when graph display providers change.
///
/// This mirrors Ghidra's `GraphDisplayBrokerListener` interface.
pub trait GraphDisplayBrokerListener {
    /// Called when the graph display providers have changed.
    fn providers_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestListener {
        call_count: usize,
    }

    impl GraphDisplayBrokerListener for TestListener {
        fn providers_changed(&mut self) {
            self.call_count += 1;
        }
    }

    #[test]
    fn test_providers_changed_called() {
        let mut listener = TestListener::default();
        assert_eq!(listener.call_count, 0);

        listener.providers_changed();
        assert_eq!(listener.call_count, 1);

        listener.providers_changed();
        assert_eq!(listener.call_count, 2);
    }
}
