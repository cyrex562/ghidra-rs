/// Listener notified when the `ListingDiff`'s set of differences and unmatched
/// addresses has changed.
pub trait ListingDiffChangeListener {
    /// Called when the `ListingDiff`'s set of differences and unmatched addresses has changed.
    fn listing_diff_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        call_count: usize,
    }

    impl ListingDiffChangeListener for TestListener {
        fn listing_diff_changed(&mut self) {
            self.call_count += 1;
        }
    }

    #[test]
    fn test_listing_diff_changed_called() {
        let mut listener = TestListener { call_count: 0 };
        listener.listing_diff_changed();
        assert_eq!(listener.call_count, 1);
    }

    #[test]
    fn test_listing_diff_changed_called_multiple_times() {
        let mut listener = TestListener { call_count: 0 };
        listener.listing_diff_changed();
        listener.listing_diff_changed();
        listener.listing_diff_changed();
        assert_eq!(listener.call_count, 3);
    }
}
