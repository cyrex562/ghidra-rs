/// Listener notified when the "apply" button is hit in an options editor.
///
/// Corresponds to `docking.options.editor.OptionsEditorListener`.
pub trait OptionsEditorListener {
    /// Called immediately before pending changes are applied.
    fn before_changes_applied(&mut self);

    /// Called after the apply button is hit and changes have been applied.
    fn changes_applied(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        before_count: usize,
        after_count: usize,
    }

    impl OptionsEditorListener for Recorder {
        fn before_changes_applied(&mut self) {
            self.before_count += 1;
        }

        fn changes_applied(&mut self) {
            self.after_count += 1;
        }
    }

    #[test]
    fn before_called_before_after() {
        let mut r = Recorder { before_count: 0, after_count: 0 };
        r.before_changes_applied();
        assert_eq!(r.before_count, 1);
        assert_eq!(r.after_count, 0);
        r.changes_applied();
        assert_eq!(r.before_count, 1);
        assert_eq!(r.after_count, 1);
    }

    #[test]
    fn multiple_apply_cycles() {
        let mut r = Recorder { before_count: 0, after_count: 0 };
        for _ in 0..3 {
            r.before_changes_applied();
            r.changes_applied();
        }
        assert_eq!(r.before_count, 3);
        assert_eq!(r.after_count, 3);
    }

    #[test]
    fn before_without_after() {
        let mut r = Recorder { before_count: 0, after_count: 0 };
        r.before_changes_applied();
        r.before_changes_applied();
        assert_eq!(r.before_count, 2);
        assert_eq!(r.after_count, 0);
    }
}
