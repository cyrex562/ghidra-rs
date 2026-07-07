/// Listener interface for when the trable row model changes.
///
/// Corresponds to `docking.widgets.trable.GTrableModeRowlListener`.
pub trait GTrableModeRowlListener {
    /// Called when the trable row model has changed.
    fn trable_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        call_count: usize,
    }

    impl GTrableModeRowlListener for Recorder {
        fn trable_changed(&mut self) {
            self.call_count += 1;
        }
    }

    #[test]
    fn callback_is_invoked() {
        let mut r = Recorder { call_count: 0 };
        r.trable_changed();
        assert_eq!(r.call_count, 1);
    }

    #[test]
    fn callback_is_invoked_multiple_times() {
        let mut r = Recorder { call_count: 0 };
        r.trable_changed();
        r.trable_changed();
        r.trable_changed();
        assert_eq!(r.call_count, 3);
    }
}
