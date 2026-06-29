use super::GhidraFile;

/// Listener for notifications when the file in a file chooser panel has changed.
///
/// Corresponds to `docking.widgets.filechooser.GhidraFileChooserPanelListener`.
pub trait GhidraFileChooserPanelListener {
    /// Called when the selected file changes.
    fn file_changed(&mut self, file: GhidraFile);

    /// Called when a new file is dropped onto the panel.
    fn file_dropped(&mut self, file: GhidraFile);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::MAIN_SEPARATOR;

    struct TestListener {
        changed: Option<GhidraFile>,
        dropped: Option<GhidraFile>,
    }

    impl TestListener {
        fn new() -> Self {
            Self { changed: None, dropped: None }
        }
    }

    impl GhidraFileChooserPanelListener for TestListener {
        fn file_changed(&mut self, file: GhidraFile) {
            self.changed = Some(file);
        }

        fn file_dropped(&mut self, file: GhidraFile) {
            self.dropped = Some(file);
        }
    }

    fn make_file(path: &str) -> GhidraFile {
        GhidraFile::from_path(path, MAIN_SEPARATOR)
    }

    #[test]
    fn file_changed_sets_changed() {
        let mut listener = TestListener::new();
        let f = make_file("dir/file.txt");
        listener.file_changed(f.clone());
        assert_eq!(listener.changed, Some(f));
        assert!(listener.dropped.is_none());
    }

    #[test]
    fn file_dropped_sets_dropped() {
        let mut listener = TestListener::new();
        let f = make_file("dir/dropped.txt");
        listener.file_dropped(f.clone());
        assert_eq!(listener.dropped, Some(f));
        assert!(listener.changed.is_none());
    }

    #[test]
    fn file_changed_and_dropped_are_independent() {
        let mut listener = TestListener::new();
        let fa = make_file("a.txt");
        let fb = make_file("b.txt");
        listener.file_changed(fa.clone());
        listener.file_dropped(fb.clone());
        assert_eq!(listener.changed, Some(fa));
        assert_eq!(listener.dropped, Some(fb));
    }

    #[test]
    fn file_changed_can_be_called_multiple_times() {
        let mut listener = TestListener::new();
        listener.file_changed(make_file("first.txt"));
        let second = make_file("second.txt");
        listener.file_changed(second.clone());
        assert_eq!(listener.changed, Some(second));
    }
}
