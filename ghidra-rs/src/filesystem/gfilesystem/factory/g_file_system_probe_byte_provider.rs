//! Port of `ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider`.

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::util::task::TaskMonitor;

use super::g_file_system_probe::GFileSystemProbe;

/// A [`GFileSystemProbe`] interface for filesystems that need to examine a [`ByteProvider`].
///
/// Mirrors `ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider`.
pub trait GFileSystemProbeByteProvider: GFileSystemProbe {
    /// Probes `byte_provider` to determine if this filesystem implementation can handle the
    /// file. The provider must not be closed.
    ///
    /// # Errors
    /// On I/O errors or cancellation.
    fn probe(
        &self,
        byte_provider: &dyn ByteProvider,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError>;
}
