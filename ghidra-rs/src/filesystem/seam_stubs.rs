//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::filesystem::gfilesystem::factory::file_system_info_rec::FileSystemInfoRec;

/// Placeholder for `ghidra.formats.gfilesystem.fileinfo.FileAttributeType`, needed by
/// [`crate::filesystem::gfilesystem::fileinfo::file_attribute::FileAttributeLike`].
///
/// Only exposes the display name lookup that `FileAttribute` needs; the full enum (value-type
/// validation, category grouping, ordinal display ordering) is ported separately.
pub trait FileAttributeTypeLike {
    fn display_name(&self) -> &str;
}

/// Placeholder for `docking.widgets.SelectFromListDialog`, needed by
/// [`crate::filesystem::gfilesystem::file_system_probe_conflict_resolver::GuiPickerResolver`]
/// (the Rust equivalent of `FileSystemProbeConflictResolver.GUI_PICKER`) to prompt the user to
/// choose a filesystem from a GUI list.
///
/// The Java static method takes an arbitrary list plus a `Function` reference used to extract
/// a display label; since `FileSystemInfoRec` already exposes `get_description` for that
/// purpose, this seam only needs the candidate list itself.
pub trait SelectFromListDialogLike {
    fn select_from_list<'a>(
        &self,
        choices: &[&'a FileSystemInfoRec],
        title: &str,
        message: &str,
    ) -> Option<&'a FileSystemInfoRec>;
}
