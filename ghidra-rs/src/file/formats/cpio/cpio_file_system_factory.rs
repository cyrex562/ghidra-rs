//! Port of `ghidra.file.formats.cpio.CpioFileSystemFactory`.

use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::util::task::TaskMonitor;

use super::cpio_archive;
use super::cpio_file_system::CpioFileSystem;

/// Creates [`CpioFileSystem`]s, recognizing cpio archives by their magic bytes.
///
/// Mirrors `ghidra.file.formats.cpio.CpioFileSystemFactory`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CpioFileSystemFactory;

impl CpioFileSystemFactory {
    /// The number of start bytes the probe needs. `CpioArchiveInputStream` doesn't have a
    /// value that can be used, so Java hard codes it.
    pub const BYTES_REQUIRED: usize = 6;
}

impl GFileSystemFactory for CpioFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_bytes_only(&self) -> Option<&dyn GFileSystemProbeBytesOnly> {
        Some(self)
    }
}

impl GFileSystemFactoryByteProvider for CpioFileSystemFactory {
    /// Mirrors `create(FSRLRoot, ByteProvider, FileSystemService, TaskMonitor)`: the new
    /// filesystem takes ownership of the archive provider.
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let provider: Rc<dyn ByteProvider> = Rc::from(byte_provider);
        let fs = CpioFileSystem::new(target_fsrl.clone(), provider, fs_service, monitor)?;
        Ok(Rc::new(fs))
    }
}

impl GFileSystemProbe for CpioFileSystemFactory {}

impl GFileSystemProbeBytesOnly for CpioFileSystemFactory {
    fn bytes_required(&self) -> usize {
        Self::BYTES_REQUIRED
    }

    /// Mirrors `probeStartBytes`, which defers to `CpioArchiveInputStream.matches`.
    fn probe_start_bytes(&self, _container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool {
        cpio_archive::matches(start_bytes, start_bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::cpio::cpio_archive::test_archives::{newc_archive, odc_member};
    use crate::file::formats::cpio::cpio_archive::C_ISREG;

    #[test]
    fn probe_uses_cpio_magic() {
        let f = CpioFileSystemFactory;
        let fsrl = Fsrl::from_string("file:///a.cpio").unwrap();
        assert_eq!(f.bytes_required(), 6);
        assert!(f.probe_start_bytes(&fsrl, &newc_archive(&[("a", C_ISREG, b"1")])[..6]));
        assert!(f.probe_start_bytes(&fsrl, &odc_member("a", C_ISREG, b"1")[..6]));
        assert!(!f.probe_start_bytes(&fsrl, b"\x1f\x8b\x08\0\0\0"));
        assert!(!f.probe_start_bytes(&fsrl, b"0707"));
    }

    #[test]
    fn capabilities() {
        let f = CpioFileSystemFactory;
        assert!(f.as_byte_provider_factory().is_some());
        assert!(f.as_probe_bytes_only().is_some());
        assert!(f.as_probe_byte_provider().is_none());
    }
}
