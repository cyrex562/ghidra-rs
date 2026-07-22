//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::filesystem::gfilesystem::factory::file_system_info_rec::FileSystemInfoRec;
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;

/// Placeholder for `ghidra.formats.gfilesystem.GFileSystem`, needed by
/// [`crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory`].
///
/// `GFileSystemFactory` is an empty marker interface whose only use of `GFileSystem` is as a
/// generic bound (`FSTYPE extends GFileSystem`); no methods are ever called on it here, so
/// this is a marker trait until the real `GFileSystem` is ported.
pub trait GFileSystemLike {}

/// Placeholder for `ghidra.formats.gfilesystem.fileinfo.FileAttributeType`, needed by
/// [`crate::filesystem::gfilesystem::fileinfo::file_attribute::FileAttributeLike`].
///
/// Only exposes the display name lookup that `FileAttribute` needs; the full enum (value-type
/// validation, category grouping, ordinal display ordering) is ported separately.
pub trait FileAttributeTypeLike {
    fn display_name(&self) -> &str;
}

/// Placeholder for `ghidra.formats.gfilesystem.FSRLRoot`, needed by
/// [`crate::filesystem::gfilesystem::g_file_system::GFileSystem::get_fsrl`].
///
/// `GFileSystem` never calls a method on the `FSRLRoot` it returns -- it only stores and
/// hands the value back to callers -- so this is an empty marker trait until the real
/// `FSRLRoot` is ported.
pub trait FsrlRootLike {}

/// Placeholder for `ghidra.formats.gfilesystem.FileSystemRefManager`, needed by
/// [`crate::filesystem::gfilesystem::g_file_system::GFileSystem::get_ref_manager`].
///
/// Like [`FsrlRootLike`], `GFileSystem` only returns this value to callers and never calls a
/// method on it itself, so this is an empty marker trait.
pub trait FileSystemRefManagerLike {}

/// Placeholder for `ghidra.formats.gfilesystem.fileinfo.FileAttributes`, needed by
/// [`crate::filesystem::gfilesystem::g_file_system::GFileSystem::get_file_attributes`].
///
/// Only exposes the single lookup that `GFileSystem`'s default `getFileType()` needs
/// (`attrs.get(FileAttributeType.FILE_TYPE_ATTR, FileType.class, ...)`); the full attribute
/// container (arbitrary keyed values, merging, read-only wrapping) is ported separately.
pub trait FileAttributesLike {
    /// The explicit `FileType` attribute, if the filesystem recorded one.
    fn file_type_attr(&self) -> Option<FileType>;
}

/// Placeholder for `ghidra.formats.gfilesystem.FileSystemRef`, needed by
/// [`crate::filesystem::gfilesystem::file_system_ref_manager::FileSystemRefManager`]'s
/// `create`/`release`/`can_close`.
///
/// Those methods never call a method on the refs they hand out, only compare identity
/// (Java uses `==`), so this seam requires nothing beyond [`PartialEq`] until the real
/// `FileSystemRef` (with its `dup()`/`close()` callbacks into the owning ref manager) is
/// ported.
pub trait FileSystemRefLike: PartialEq {}

/// Placeholder for `ghidra.formats.gfilesystem.FileSystemService`, needed by
/// [`crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider::create`].
///
/// `create()` only forwards this value to the filesystem being constructed; it never calls a
/// method on it itself, so this is an empty marker trait until the real `FileSystemService` is
/// ported.
pub trait FileSystemServiceLike {}

/// Placeholder for `docking.widgets.SelectFromListDialog`, needed by
/// [`crate::filesystem::gfilesystem::file_system_probe_conflict_resolver::GuiPickerResolver`]
/// (the Rust equivalent of `FileSystemProbeConflictResolver.GUI_PICKER`) to prompt the user to
/// choose a filesystem from a GUI list.
///
/// The Java static method takes an arbitrary list plus a `Function` reference used to extract
/// a display label; since `FileSystemInfoRec` already exposes `get_description` for that
/// purpose, this seam only needs the candidate list itself.
pub trait SelectFromListDialogLike<FSTYPE: GFileSystemLike> {
    fn select_from_list<'a>(
        &self,
        choices: &[&'a dyn FileSystemInfoRec<FSTYPE>],
        title: &str,
        message: &str,
    ) -> Option<&'a dyn FileSystemInfoRec<FSTYPE>>;
}

/// Placeholder for `ghidra.formats.gfilesystem.FSRL`, needed by
/// [`crate::filesystem::gfilesystem::crypto::crypto_session::CryptoSession`].
///
/// `CryptoSession` only ever passes the `FSRL` through as an opaque lookup/cache key -- it
/// never calls a method on it -- so this is an empty marker trait until the real `FSRL` is
/// ported.
pub trait FsrlLike {}
