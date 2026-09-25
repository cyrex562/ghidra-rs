//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::filesystem::gfilesystem::factory::file_system_info_rec::FileSystemInfoRec;
use crate::filesystem::gfilesystem::fsrl::Fsrl;

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

/// Placeholder for `ghidra.formats.gfilesystem.FileSystemRefManager`, needed by
/// [`crate::filesystem::gfilesystem::g_file_system::GFileSystem::get_ref_manager`].
///
/// `GFileSystem` only returns this value to callers and never calls a
/// method on it itself, so this is an empty marker trait.
pub trait FileSystemRefManagerLike {}

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

/// Placeholder for `ghidra.formats.gfilesystem.FSRL`, needed by
/// [`crate::filesystem::gfilesystem::crypto::cached_password_provider::CachedPasswordProvider`].
///
/// Unlike [`FsrlLike`]'s opaque-key usage elsewhere, `CachedPasswordProvider` actually calls
/// `toString()`, `toPrettyString()`, `getName()` and `getMD5()` on the `FSRL` to index cached
/// passwords under multiple aliases. Rather than widen `FsrlLike` (and break its existing
/// empty-impl callers), this extends it with just the four accessors this type needs.
pub trait CachedFsrlLike: FsrlLike {
    /// Mirrors `FSRL.toString()`.
    fn fsrl_string(&self) -> String;
    /// Mirrors `FSRL.toPrettyString()`.
    fn fsrl_pretty_string(&self) -> String;
    /// Mirrors `FSRL.getName()`.
    fn fsrl_name(&self) -> String;
    /// Mirrors `FSRL.getMD5()`.
    fn fsrl_md5(&self) -> Option<String>;
}

/// The real [`Fsrl`] is usable wherever the opaque [`FsrlLike`] key seam is still threaded as a
/// generic parameter.
impl FsrlLike for Fsrl {}

/// The real [`Fsrl`] supplies the accessors [`CachedFsrlLike`] models.
impl CachedFsrlLike for Fsrl {
    fn fsrl_string(&self) -> String {
        self.to_string()
    }
    fn fsrl_pretty_string(&self) -> String {
        self.to_pretty_string()
    }
    fn fsrl_name(&self) -> String {
        self.name().unwrap_or_default()
    }
    fn fsrl_md5(&self) -> Option<String> {
        self.md5().map(str::to_owned)
    }
}

/// Placeholder for `ghidra.formats.gfilesystem.LocalFileSystem` (distinct from the unrelated,
/// already-ported `ghidra.framework.store.local.LocalFileSystem`), needed by
/// [`crate::filesystem::gfilesystem::file_system_service::FileSystemService::get_local_fs`].
///
/// `FileSystemService` only ever hands this value back to its own caller
/// (`getLocalFS()`); it never calls a method on it internally (its own `isLocal`/
/// `getLocalFSRL` are ported as separate trait methods, not as default bodies that delegate
/// through this seam), so the only member modeled is the one an outside caller reaches for.
pub trait LocalFileSystemLike {
    /// Mirrors `LocalFileSystem.getLocalFile(FSRL)`: the local file `fsrl` names.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`AbstractOrdinalSupportLoader`](crate::app::util::opinion::abstract_ordinal_support_loader::AbstractOrdinalSupportLoader)'s
    /// port of `processLibrary`, which timestamp-matches a loaded library against its cached
    /// `.exports` file.
    ///
    /// # Errors
    /// Returns `Err` if `fsrl` does not name a file on the local filesystem, mirroring Java's
    /// `throws IOException`. The default implementation always does, since a placeholder knows
    /// of no local files.
    fn get_local_file(&self, fsrl: &Fsrl) -> std::io::Result<std::path::PathBuf> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{fsrl} is not a local file"),
        ))
    }
}

/// Placeholder for `ghidra.formats.gfilesystem.FileCache.FileCacheEntry`, needed by
/// [`crate::filesystem::gfilesystem::file_system_service::FileSystemService::get_named_temp_file`].
///
/// Only ever passed through as an opaque handle to a previously-created temp file, so this is
/// an empty marker trait until the real `FileCache`/`FileCacheEntry` are ported.
pub trait FileCacheEntryLike {}

/// Placeholder for `ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder`, needed by
/// [`crate::filesystem::gfilesystem::file_system_service::FileSystemService::create_temp_file`].
///
/// Only ever returned to the caller to be filled in and finished, so this is an empty marker
/// trait until the real `FileCache`/`FileCacheEntryBuilder` are ported.
pub trait FileCacheEntryBuilderLike {}
