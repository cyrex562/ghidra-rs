//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `ghidra.formats.gfilesystem.GFileSystem`, needed by
/// [`crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory`].
///
/// `GFileSystemFactory` is an empty marker interface whose only use of `GFileSystem` is as a
/// generic bound (`FSTYPE extends GFileSystem`); no methods are ever called on it here, so
/// this is a marker trait until the real `GFileSystem` is ported.
pub trait GFileSystemLike {}
