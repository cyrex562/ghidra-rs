//! Listener interface for decompiler token highlight changes.

/// Listener notified whenever the decompiler token highlights have changed.
pub trait ClangHighlightListener {
    /// Called whenever the decompiler token highlights have changed.
    fn token_highlights_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockListener {
        call_count: usize,
    }

    impl ClangHighlightListener for MockListener {
        fn token_highlights_changed(&mut self) {
            self.call_count += 1;
        }
    }

    #[test]
    fn test_listener_called_once() {
        let mut listener = MockListener { call_count: 0 };
        listener.token_highlights_changed();
        assert_eq!(listener.call_count, 1);
    }

    #[test]
    fn test_listener_called_multiple_times() {
        let mut listener = MockListener { call_count: 0 };
        listener.token_highlights_changed();
        listener.token_highlights_changed();
        listener.token_highlights_changed();
        assert_eq!(listener.call_count, 3);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener = MockListener { call_count: 0 };
        let dyn_listener: &mut dyn ClangHighlightListener = &mut listener;
        dyn_listener.token_highlights_changed();
        assert_eq!(listener.call_count, 1);
    }
}
