use crate::framework::seam_stubs::Archive;

/// Port of `ghidra.app.plugin.core.datamgr.archive.ArchiveManagerListener`.
///
/// Java is an `interface` with 4 abstract methods and (in this port's scope) at least one
/// in-repo implementor, so this becomes a `trait` (rule R-interface-open-ext-point) rather than
/// a struct/enum.
///
/// # Seams
///
/// `Archive` is the Java class this interface's methods take. Two unrelated placeholders for it
/// used to exist crate-wide ([`crate::framework::seam_stubs::Archive`], used by
/// `ArchiveProvider`, and a separate empty `crate::app::seam_stubs::Archive` used by the sibling
/// files in this same Java package, e.g.
/// [`DomainFileArchive`](super::domain_file_archive::DomainFileArchive)); the `app` copy has since
/// been retired, so this listener (and its siblings in this directory) now use the `framework`
/// placeholder as the single canonical one.
pub trait ArchiveManagerListener {
    /// Called when a new archive is opened.
    ///
    /// Mirrors `ArchiveManagerListener.archiveOpened(Archive)`.
    fn archive_opened(&self, archive: &dyn Archive);

    /// Called when an archive is closed.
    ///
    /// Mirrors `ArchiveManagerListener.archiveClosed(Archive)`.
    fn archive_closed(&self, archive: &dyn Archive);

    /// Called when the edited state of the archive has changed, for example, when an archive has
    /// had a data type or category added or removed.
    ///
    /// Mirrors `ArchiveManagerListener.archiveStateChanged(Archive)`.
    fn archive_state_changed(&self, archive: &dyn Archive);

    /// Called when the `DataTypeManager` of the archive has changed. This can happen when an
    /// archive is locked or unlocked.
    ///
    /// Mirrors `ArchiveManagerListener.archiveDataTypeManagerChanged(Archive)`.
    fn archive_data_type_manager_changed(&self, archive: &dyn Archive);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Minimal mock implementation of `ArchiveManagerListener` that records which callback fired.
    #[derive(Default)]
    struct RecordingListener {
        events: RefCell<Vec<&'static str>>,
    }

    struct MockArchive;
    impl Archive for MockArchive {
        fn get_name(&self) -> String {
            "MockArchive".to_string()
        }

        fn close(&self) {}

        fn is_modifiable(&self) -> bool {
            false
        }

        fn is_savable(&self) -> bool {
            false
        }

        fn is_changed(&self) -> bool {
            false
        }

        fn save(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ArchiveManagerListener for RecordingListener {
        fn archive_opened(&self, _archive: &dyn Archive) {
            self.events.borrow_mut().push("opened");
        }

        fn archive_closed(&self, _archive: &dyn Archive) {
            self.events.borrow_mut().push("closed");
        }

        fn archive_state_changed(&self, _archive: &dyn Archive) {
            self.events.borrow_mut().push("state_changed");
        }

        fn archive_data_type_manager_changed(&self, _archive: &dyn Archive) {
            self.events.borrow_mut().push("dtm_changed");
        }
    }

    #[test]
    fn dispatches_all_four_callbacks() {
        let listener = RecordingListener::default();
        let archive = MockArchive;
        listener.archive_opened(&archive);
        listener.archive_closed(&archive);
        listener.archive_state_changed(&archive);
        listener.archive_data_type_manager_changed(&archive);
        assert_eq!(
            *listener.events.borrow(),
            vec!["opened", "closed", "state_changed", "dtm_changed"]
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let listener: Box<dyn ArchiveManagerListener> = Box::new(RecordingListener::default());
        let archive = MockArchive;
        listener.archive_opened(&archive);
    }
}
