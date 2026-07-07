use crate::program::model::data::archive_type::ArchiveType;
use crate::util::UniversalID;

/// Holds information about a single data type archive which supplied a data type to the program.
///
/// Port of `ghidra.program.model.data.SourceArchive`.
pub trait SourceArchive {
    /// Gets the ID that the program has associated with the data type archive.
    fn source_archive_id(&self) -> UniversalID;

    /// Gets the ID used to uniquely identify the domain file for the data type archive.
    fn domain_file_id(&self) -> String;

    /// Gets an indicator for the type of data type archive.
    fn archive_type(&self) -> ArchiveType;

    /// Returns the name of the source archive.
    fn name(&self) -> String;

    /// Returns the last time that this source archive was synchronized to the containing
    /// `DataTypeManager`.
    fn last_sync_time(&self) -> i64;

    /// Returns true if at least one data type that originally came from this source archive has
    /// been changed.
    fn is_dirty(&self) -> bool;

    /// Sets the last time that this source archive was synchronized to the containing
    /// `DataTypeManager`.
    fn set_last_sync_time(&mut self, time: i64);

    /// Sets the name of the source archive associated with this `SourceArchive` object.
    fn set_name(&mut self, name: String);

    /// Sets the dirty flag to indicate if at least one data type that originally came from the
    /// associated source archive has been changed since the last time the containing
    /// `DataTypeManager` was synchronized with it.
    fn set_dirty_flag(&mut self, dirty: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSourceArchive {
        id: UniversalID,
        domain_file_id: String,
        archive_type: ArchiveType,
        name: String,
        last_sync_time: i64,
        dirty: bool,
    }

    impl SourceArchive for MockSourceArchive {
        fn source_archive_id(&self) -> UniversalID {
            self.id
        }

        fn domain_file_id(&self) -> String {
            self.domain_file_id.clone()
        }

        fn archive_type(&self) -> ArchiveType {
            self.archive_type
        }

        fn name(&self) -> String {
            self.name.clone()
        }

        fn last_sync_time(&self) -> i64 {
            self.last_sync_time
        }

        fn is_dirty(&self) -> bool {
            self.dirty
        }

        fn set_last_sync_time(&mut self, time: i64) {
            self.last_sync_time = time;
        }

        fn set_name(&mut self, name: String) {
            self.name = name;
        }

        fn set_dirty_flag(&mut self, dirty: bool) {
            self.dirty = dirty;
        }
    }

    #[test]
    fn setters_update_state() {
        let mut archive = MockSourceArchive {
            id: UniversalID::new(1),
            domain_file_id: "domain-1".to_string(),
            archive_type: ArchiveType::File,
            name: "orig".to_string(),
            last_sync_time: 0,
            dirty: false,
        };

        archive.set_last_sync_time(42);
        archive.set_name("renamed".to_string());
        archive.set_dirty_flag(true);

        assert_eq!(archive.last_sync_time(), 42);
        assert_eq!(archive.name(), "renamed");
        assert!(archive.is_dirty());
        assert_eq!(archive.source_archive_id(), UniversalID::new(1));
        assert_eq!(archive.domain_file_id(), "domain-1");
        assert_eq!(archive.archive_type(), ArchiveType::File);
    }

    #[test]
    fn usable_as_trait_object() {
        let archive = MockSourceArchive {
            id: UniversalID::new(2),
            domain_file_id: "domain-2".to_string(),
            archive_type: ArchiveType::Project,
            name: "proj".to_string(),
            last_sync_time: 7,
            dirty: false,
        };
        let dyn_archive: &dyn SourceArchive = &archive;
        assert_eq!(dyn_archive.name(), "proj");
        assert_eq!(dyn_archive.archive_type(), ArchiveType::Project);
    }
}
