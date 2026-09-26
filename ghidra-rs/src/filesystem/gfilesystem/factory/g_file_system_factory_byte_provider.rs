//! Port of `ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider`.

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::util::task::TaskMonitor;

use super::g_file_system_factory::GFileSystemFactory;

/// A [`GFileSystemFactory`] that creates filesystem instances from a [`ByteProvider`].
///
/// Mirrors `ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider<FSTYPE>`; the
/// created filesystem is returned as a shared, type-erased [`FsHandle`] (see
/// [`GFileSystemFactory`] for why `FSTYPE` is not carried).
pub trait GFileSystemFactoryByteProvider: GFileSystemFactory {
    /// Constructs a new filesystem instance using `byte_provider`, which the new filesystem
    /// (or this method, on error) becomes responsible for closing.
    ///
    /// `target_fsrl` is the FSRL of the filesystem being created; `fs_service` is the service
    /// requesting it.
    ///
    /// # Errors
    /// On I/O errors, unrecognized contents, or cancellation.
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError>;
}
