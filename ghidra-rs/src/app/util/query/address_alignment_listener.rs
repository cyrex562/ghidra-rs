/// Listener notified when address alignment settings change.
pub trait AddressAlignmentListener {
    /// Called when the alignment value changes.
    fn alignment_changed(&mut self);

    /// Called when alignment permission changes.
    fn alignment_permission_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recording {
        alignment_changed_count: usize,
        permission_changed_count: usize,
    }

    impl AddressAlignmentListener for Recording {
        fn alignment_changed(&mut self) {
            self.alignment_changed_count += 1;
        }

        fn alignment_permission_changed(&mut self) {
            self.permission_changed_count += 1;
        }
    }

    #[test]
    fn alignment_changed_fires() {
        let mut r = Recording::default();
        r.alignment_changed();
        assert_eq!(r.alignment_changed_count, 1);
        assert_eq!(r.permission_changed_count, 0);
    }

    #[test]
    fn alignment_permission_changed_fires() {
        let mut r = Recording::default();
        r.alignment_permission_changed();
        assert_eq!(r.alignment_changed_count, 0);
        assert_eq!(r.permission_changed_count, 1);
    }

    #[test]
    fn both_callbacks_can_fire_independently() {
        let mut r = Recording::default();
        r.alignment_changed();
        r.alignment_changed();
        r.alignment_permission_changed();
        assert_eq!(r.alignment_changed_count, 2);
        assert_eq!(r.permission_changed_count, 1);
    }
}
