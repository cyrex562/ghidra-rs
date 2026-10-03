//! Port of `ghidra.program.database.data.SourceArchiveUpgradeMap`.
//!
//! Builds a lookup of old, now-obsolete built-in archive [`UniversalID`]s to the current
//! [`SourceArchive`] each was consolidated into (or, for archives removed outright, a stand-in
//! "removed" archive), used when upgrading data types whose `SourceArchive` reference predates a
//! reorganization of Ghidra's built-in archives.
//!
//! ## Known simplifications
//!
//! - The Java class declares a `private CompilerSpecID WINDOWS_CSPEC_ID` field that is
//!   constructed but never read by any method -- genuinely dead state in the original. It is
//!   omitted here rather than ported as an unused field.
//! - [`SourceArchive::domain_file_id`] returns `String` (not `Option<String>`) on this crate's
//!   already-ported trait (see `program::model::data::source_archive`), so `SourceArchiveImpl`'s
//!   `getDomainFileID() -> null` becomes an empty string, matching the established substitution
//!   used elsewhere for this same trait mismatch.
//!
//! ## A faithfully-preserved quirk
//!
//! The Java constructor's `HashMap.put` calls silently overwrite three of their own entries:
//! `OLD_CLIB_ARCHIVE_ID` is first mapped to `newWindowsArchive`, then immediately remapped to
//! `newDefaultClibArchive`; `OLD_WINDOWS_ARCHIVE_ID`/`OLD_NTDDK_ARCHIVE_ID` are first mapped to
//! `newWindowsArchive`, then immediately remapped to `removedSourceArchive`. The net effect --
//! `newWindowsArchive` ends up referenced by *no* map entry at all -- looks like a bug in the
//! original (probably intended to keep the first `OLD_WINDOWS_ARCHIVE_ID`/`OLD_NTDDK_ARCHIVE_ID`
//! mappings), but this port reproduces the observed behavior rather than "fixing" it: the
//! `HashMap::insert` calls below run in the same order as Java's `put` calls, so the same
//! overwrites happen naturally.

use std::collections::HashMap;
use std::sync::Arc;

use crate::program::model::data::archive_type::ArchiveType;
use crate::program::model::data::data_type_manager::local_archive_universal_id;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::UniversalID;

const OLD_CLIB_ARCHIVE_ID: i64 = 2585014296036210369;
const OLD_WINDOWS_ARCHIVE_ID: i64 = 2592694847825635591;
const OLD_NTDDK_ARCHIVE_ID: i64 = 2585014353215059675;

const OLD_ARCHIVE_IDS: [i64; 3] = [
    OLD_CLIB_ARCHIVE_ID,
    OLD_NTDDK_ARCHIVE_ID,
    OLD_WINDOWS_ARCHIVE_ID,
];

/// Maps old, obsolete built-in archive IDs to the current [`SourceArchive`] each was folded
/// into.
///
/// Port of `ghidra.program.database.data.SourceArchiveUpgradeMap`.
pub struct SourceArchiveUpgradeMap {
    old_archive_remappings: HashMap<UniversalID, Arc<dyn SourceArchive>>,
}

impl SourceArchiveUpgradeMap {
    /// Builds the upgrade map. See the module docs for the faithfully-preserved overwrite quirk
    /// in the resulting mappings.
    pub fn new() -> Self {
        let new_windows_super_archive_id = UniversalID::new(2644092282468053077);
        let new_default_clib_archive_id = UniversalID::new(2644097909188870631);

        let new_windows_super_archive_name = "windows_vs12_32";
        let new_default_clib_archive_name = "generic_clib";

        let new_windows_archive: Arc<dyn SourceArchive> = Arc::new(SourceArchiveImpl::new(
            new_windows_super_archive_id,
            new_windows_super_archive_name.to_string(),
        ));
        let new_default_clib_archive: Arc<dyn SourceArchive> = Arc::new(SourceArchiveImpl::new(
            new_default_clib_archive_id,
            new_default_clib_archive_name.to_string(),
        ));

        let mut old_archive_remappings: HashMap<UniversalID, Arc<dyn SourceArchive>> =
            HashMap::new();

        // create mappings for old Windows archives
        old_archive_remappings.insert(
            UniversalID::new(OLD_CLIB_ARCHIVE_ID),
            new_windows_archive.clone(),
        );
        old_archive_remappings.insert(
            UniversalID::new(OLD_WINDOWS_ARCHIVE_ID),
            new_windows_archive.clone(),
        );
        old_archive_remappings.insert(
            UniversalID::new(OLD_NTDDK_ARCHIVE_ID),
            new_windows_archive.clone(),
        );

        // create mappings for old default archives
        old_archive_remappings.insert(
            UniversalID::new(OLD_CLIB_ARCHIVE_ID),
            new_default_clib_archive.clone(),
        );

        // create mappings for old removed archives
        let removed_source_archive: Arc<dyn SourceArchive> =
            Arc::new(SourceArchiveImpl::removed());
        old_archive_remappings.insert(
            UniversalID::new(OLD_WINDOWS_ARCHIVE_ID),
            removed_source_archive.clone(),
        );
        old_archive_remappings.insert(
            UniversalID::new(OLD_NTDDK_ARCHIVE_ID),
            removed_source_archive.clone(),
        );

        SourceArchiveUpgradeMap {
            old_archive_remappings,
        }
    }

    /// Get the current archive that `source_archive`'s ID was remapped to, or `None` if
    /// `source_archive` is not one of the obsolete archives this map knows about.
    pub fn get_mapped_source_archive(
        &self,
        source_archive: &dyn SourceArchive,
    ) -> Option<Arc<dyn SourceArchive>> {
        self.old_archive_remappings
            .get(&source_archive.source_archive_id())
            .cloned()
    }

    /// Returns `true` if `id` is one of the (now-obsolete) archive IDs replaced by this map.
    pub fn is_replaced_source_archive(id: i64) -> bool {
        OLD_ARCHIVE_IDS.contains(&id)
    }

    /// Built-in typedef base type names that may need replacement after this archive upgrade.
    pub fn get_typedef_replacements() -> Vec<&'static str> {
        vec!["short", "int", "long", "longlong", "wchar_t", "bool"]
    }
}

impl Default for SourceArchiveUpgradeMap {
    fn default() -> Self {
        Self::new()
    }
}

/// A minimal, immutable [`SourceArchive`] used as a stand-in for archives consolidated or
/// removed by [`SourceArchiveUpgradeMap`]; all setters are no-ops.
struct SourceArchiveImpl {
    id: UniversalID,
    archive_name: String,
}

impl SourceArchiveImpl {
    fn new(id: UniversalID, archive_name: String) -> Self {
        SourceArchiveImpl { id, archive_name }
    }

    /// Stand-in for an archive that was removed outright (rather than consolidated into another
    /// archive), matching Java's no-arg constructor.
    fn removed() -> Self {
        SourceArchiveImpl {
            id: local_archive_universal_id(),
            archive_name: String::new(),
        }
    }
}

impl SourceArchive for SourceArchiveImpl {
    fn source_archive_id(&self) -> UniversalID {
        self.id
    }

    fn domain_file_id(&self) -> String {
        String::new()
    }

    fn archive_type(&self) -> ArchiveType {
        ArchiveType::File
    }

    fn name(&self) -> String {
        self.archive_name.clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_replaced_source_archive_matches_known_ids() {
        assert!(SourceArchiveUpgradeMap::is_replaced_source_archive(
            OLD_CLIB_ARCHIVE_ID
        ));
        assert!(SourceArchiveUpgradeMap::is_replaced_source_archive(
            OLD_WINDOWS_ARCHIVE_ID
        ));
        assert!(SourceArchiveUpgradeMap::is_replaced_source_archive(
            OLD_NTDDK_ARCHIVE_ID
        ));
        assert!(!SourceArchiveUpgradeMap::is_replaced_source_archive(12345));
    }

    #[test]
    fn get_typedef_replacements_matches_known_list() {
        assert_eq!(
            SourceArchiveUpgradeMap::get_typedef_replacements(),
            vec!["short", "int", "long", "longlong", "wchar_t", "bool"]
        );
    }

    #[test]
    fn clib_archive_remaps_to_default_clib_due_to_overwrite() {
        let map = SourceArchiveUpgradeMap::new();
        let query = SourceArchiveImpl::new(UniversalID::new(OLD_CLIB_ARCHIVE_ID), String::new());
        let mapped = map
            .get_mapped_source_archive(&query)
            .expect("clib archive should be remapped");
        assert_eq!(mapped.name(), "generic_clib");
    }

    #[test]
    fn windows_and_ntddk_archives_remap_to_removed_due_to_overwrite() {
        let map = SourceArchiveUpgradeMap::new();

        let windows_query =
            SourceArchiveImpl::new(UniversalID::new(OLD_WINDOWS_ARCHIVE_ID), String::new());
        let windows_mapped = map
            .get_mapped_source_archive(&windows_query)
            .expect("windows archive should be remapped");
        assert_eq!(windows_mapped.name(), "");
        assert_eq!(windows_mapped.source_archive_id(), local_archive_universal_id());

        let ntddk_query =
            SourceArchiveImpl::new(UniversalID::new(OLD_NTDDK_ARCHIVE_ID), String::new());
        let ntddk_mapped = map
            .get_mapped_source_archive(&ntddk_query)
            .expect("ntddk archive should be remapped");
        assert_eq!(ntddk_mapped.name(), "");

        // Both obsolete Windows-family IDs collapse to the *same* shared removed-archive
        // instance.
        assert!(Arc::ptr_eq(&windows_mapped, &ntddk_mapped));
    }

    #[test]
    fn unknown_archive_is_not_mapped() {
        let map = SourceArchiveUpgradeMap::new();
        let query = SourceArchiveImpl::new(UniversalID::new(999_999), String::new());
        assert!(map.get_mapped_source_archive(&query).is_none());
    }

    #[test]
    fn source_archive_impl_setters_are_no_ops() {
        let mut archive =
            SourceArchiveImpl::new(UniversalID::new(1), "orig".to_string());
        archive.set_name("renamed".to_string());
        archive.set_last_sync_time(42);
        archive.set_dirty_flag(true);

        assert_eq!(archive.name(), "orig");
        assert_eq!(archive.last_sync_time(), 0);
        assert!(!archive.is_dirty());
        assert_eq!(archive.archive_type(), ArchiveType::File);
        assert_eq!(archive.domain_file_id(), "");
    }
}
