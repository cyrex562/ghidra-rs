//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::filesystem::gfilesystem::factory::file_system_info_rec::FileSystemInfoRec;
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
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

/// Placeholder for `ghidra.formats.gfilesystem.FSRLRoot`, needed by
/// [`crate::filesystem::gfilesystem::g_file_system::GFileSystem::get_fsrl`] (which never calls
/// a method on it, only stores and hands the value back to callers) and, since the real
/// `FSRL` port, by [`crate::filesystem::gfilesystem::fsrl::Fsrl`]'s default methods, which
/// need to walk and render the container chain a `FSRLRoot` sits at the top of.
///
/// Every method here has a default body so the pre-existing empty `impl FsrlRootLike for X {}`
/// marker usages elsewhere keep compiling unchanged (as a "no container, empty protocol" root);
/// a real `FSRLRoot` port should override all of them. `protocol`/`has_container`/
/// `get_container` mirror `FSRLRoot.getProtocol`/`hasContainer`/`getContainer`;
/// `append_to_string` mirrors `FSRLRoot`'s override of `FSRL.appendToStringBuilder`;
/// `root_equals`/`root_hash` mirror `FSRLRoot`'s inherited (not overridden in Java)
/// `FSRL.equals`/`hashCode`, simplified to ignore MD5 since a real `FSRLRoot` never carries one
/// (its constructor only ever calls `FSRL`'s 2-arg, MD5-less constructor).
pub trait FsrlRootLike {
    /// The "protocol" portion, eg. `"file"` for a FSRLRoot rendering as `"file://"`.
    fn protocol(&self) -> &str {
        ""
    }

    /// `true` if there is a parent container file, `false` for a root-level filesystem.
    fn has_container(&self) -> bool {
        false
    }

    /// The parent container FSRL, or `None` for a root-level filesystem.
    fn get_container(&self) -> Option<&dyn Fsrl> {
        None
    }

    /// Appends this root's string representation (and, if `recurse`, its container's) to `out`.
    fn append_to_string(
        &self,
        out: &mut String,
        recurse: bool,
        include_params: bool,
        include_fs_root: bool,
    ) {
        if self.has_container() && recurse {
            if let Some(container) = self.get_container() {
                container.append_to_string_builder(out, recurse, include_params, include_fs_root);
                out.push('|');
            }
        }
        if include_fs_root {
            out.push_str(self.protocol());
            out.push_str("://");
        }
    }

    /// Value equality against another root: same protocol and (recursively) equivalent
    /// containers.
    fn root_equals(&self, other: &dyn FsrlRootLike) -> bool {
        self.protocol() == other.protocol()
            && match (self.get_container(), other.get_container()) {
                (None, None) => true,
                (Some(a), Some(b)) => a.is_equivalent(b),
                _ => false,
            }
    }

    /// A hash consistent with [`FsrlRootLike::root_equals`].
    fn root_hash(&self) -> u64 {
        let mut h: u64 = 17;
        for b in self.protocol().as_bytes() {
            h = h.wrapping_mul(31).wrapping_add(*b as u64);
        }
        if let Some(c) = self.get_container() {
            h = h.wrapping_mul(31).wrapping_add(c.fsrl_hash());
        }
        h
    }
}

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

/// Placeholder for `ghidra.formats.gfilesystem.LocalFileSystem` (distinct from the unrelated,
/// already-ported `ghidra.framework.store.local.LocalFileSystem`), needed by
/// [`crate::filesystem::gfilesystem::file_system_service::FileSystemService::get_local_fs`].
///
/// `FileSystemService` only ever hands this value back to its own caller
/// (`getLocalFS()`); it never calls a method on it internally (its own `isLocal`/
/// `getLocalFSRL` are ported as separate trait methods, not as default bodies that delegate
/// through this seam), so this is an empty marker trait until the real `LocalFileSystem` is
/// ported.
pub trait LocalFileSystemLike {}

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
