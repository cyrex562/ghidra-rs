//! Port of `ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive`.
//!
//! The Java class is a singleton (private constructor, public static `INSTANCE`) implementing
//! `SourceArchive` plus two extra public methods (`getPathname`/`setPathname`) that are not part
//! of that interface. This port models the extra pair as their own trait, since this type was
//! selected as a dependency-cycle cut-point: callers can depend on `dyn BuiltInSourceArchive`
//! (or the already-ported `dyn SourceArchive`) instead of the concrete singleton type.

use crate::program::model::data::archive_type::ArchiveType;
use crate::program::model::data::data_type_manager::{
    built_in_archive_universal_id, BUILT_IN_DATA_TYPES_NAME,
};
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::UniversalID;

/// The pathname/setPathname surface of `BuiltInSourceArchive`, beyond what `SourceArchive`
/// already declares.
pub trait BuiltInSourceArchive: SourceArchive {
    /// Returns the pathname of the associated data type archive. Always empty for the built-in
    /// archive, mirroring `BuiltInSourceArchive.getPathname()`.
    fn pathname(&self) -> String;

    /// Sets the pathname of the associated data type archive. A no-op, mirroring
    /// `BuiltInSourceArchive.setPathname(String)`.
    fn set_pathname(&mut self, pathname: String);
}

/// The concrete singleton implementation, mirroring `BuiltInSourceArchive`'s private constructor
/// plus its single instance. Reached only through [`INSTANCE`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BuiltInSourceArchiveImpl;

/// Shared singleton, mirroring `BuiltInSourceArchive.INSTANCE`.
pub static INSTANCE: BuiltInSourceArchiveImpl = BuiltInSourceArchiveImpl;

impl SourceArchive for BuiltInSourceArchiveImpl {
    fn source_archive_id(&self) -> UniversalID {
        built_in_archive_universal_id()
    }

    fn domain_file_id(&self) -> String {
        String::new()
    }

    fn archive_type(&self) -> ArchiveType {
        ArchiveType::BuiltIn
    }

    fn name(&self) -> String {
        BUILT_IN_DATA_TYPES_NAME.to_string()
    }

    fn last_sync_time(&self) -> i64 {
        0
    }

    fn is_dirty(&self) -> bool {
        false
    }

    fn set_last_sync_time(&mut self, _time: i64) {}

    fn set_name(&mut self, _name: String) {}

    fn set_dirty_flag(&mut self, _dirty: bool) {}
}

impl BuiltInSourceArchive for BuiltInSourceArchiveImpl {
    fn pathname(&self) -> String {
        String::new()
    }

    fn set_pathname(&mut self, _pathname: String) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_matches_java_singleton_behavior() {
        let mut archive = INSTANCE;
        assert_eq!(archive.archive_type(), ArchiveType::BuiltIn);
        assert_eq!(archive.domain_file_id(), "");
        assert_eq!(archive.last_sync_time(), 0);
        assert_eq!(archive.name(), BUILT_IN_DATA_TYPES_NAME);
        assert_eq!(archive.source_archive_id(), built_in_archive_universal_id());
        assert!(!archive.is_dirty());
        assert_eq!(archive.pathname(), "");

        // Setters are no-ops, mirroring the Java singleton's empty overrides.
        archive.set_last_sync_time(99);
        archive.set_name("changed".to_string());
        archive.set_dirty_flag(true);
        archive.set_pathname("changed".to_string());
        assert_eq!(archive.last_sync_time(), 0);
        assert_eq!(archive.name(), BUILT_IN_DATA_TYPES_NAME);
        assert!(!archive.is_dirty());
        assert_eq!(archive.pathname(), "");
    }

    #[test]
    fn usable_as_trait_object() {
        let dyn_archive: &dyn BuiltInSourceArchive = &INSTANCE;
        assert_eq!(dyn_archive.name(), BUILT_IN_DATA_TYPES_NAME);

        let dyn_source: &dyn SourceArchive = &INSTANCE;
        assert_eq!(dyn_source.archive_type(), ArchiveType::BuiltIn);
        assert_eq!(dyn_source.source_archive_id(), built_in_archive_universal_id());
    }
}
