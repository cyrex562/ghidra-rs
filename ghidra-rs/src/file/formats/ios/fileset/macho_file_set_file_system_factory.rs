//! Port of `ghidra.file.formats.ios.fileset.MachoFileSetFileSystemFactory`.

use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::opinion::macho_prelink_utils;
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_byte_provider::GFileSystemProbeByteProvider;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::util::task::TaskMonitor;

use super::macho_file_set_file_system::MachoFileSetFileSystem;

/// Creates [`MachoFileSetFileSystem`]s for Mach-O file sets.
///
/// Port of `ghidra.file.formats.ios.fileset.MachoFileSetFileSystemFactory`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MachoFileSetFileSystemFactory;

impl GFileSystemFactory for MachoFileSetFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_byte_provider(&self) -> Option<&dyn GFileSystemProbeByteProvider> {
        Some(self)
    }
}

impl GFileSystemFactoryByteProvider for MachoFileSetFileSystemFactory {
    /// Java `create(FSRLRoot, ByteProvider, FileSystemService, TaskMonitor)`: a new, mounted
    /// filesystem that takes ownership of the container provider.
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let provider: Rc<dyn ByteProvider> = Rc::from(byte_provider);
        let mut fs = MachoFileSetFileSystem::new(target_fsrl.clone(), provider, fs_service);
        fs.mount(monitor)?;
        Ok(Rc::new(fs))
    }
}

impl GFileSystemProbe for MachoFileSetFileSystemFactory {}

impl GFileSystemProbeByteProvider for MachoFileSetFileSystemFactory {
    /// Java `probe(ByteProvider, FileSystemService, TaskMonitor)`:
    /// `MachoPrelinkUtils.isMachoFileset(byteProvider)`.
    fn probe(
        &self,
        byte_provider: &dyn ByteProvider,
        _fs_service: &FileSystemService,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError> {
        Ok(macho_prelink_utils::is_macho_fileset(byte_provider))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::file::formats::ios::fileset::macho_file_set_file_system::test_support::fileset_image;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::util::task::DummyMonitor;

    #[test]
    fn probes_and_creates() {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        let f = MachoFileSetFileSystemFactory;
        assert!(f.as_byte_provider_factory().is_some());
        assert!(f.as_probe_byte_provider().is_some());
        assert!(f.as_probe_bytes_only().is_none());

        let image = fileset_image();
        assert!(f.probe(&ByteArrayProvider::new(image.clone()), &svc, &DummyMonitor).unwrap());
        assert!(!f.probe(&ByteArrayProvider::new(vec![0u8; 64]), &svc, &DummyMonitor).unwrap());

        let container = Fsrl::from_string("file:///kernelcache").unwrap();
        let fs = f
            .create(
                &container.make_nested("machofileset"),
                Box::new(ByteArrayProvider::with_fsrl(image, Some(container.clone()))),
                &svc,
                &DummyMonitor,
            )
            .unwrap();
        assert_eq!(fs.get_type(), "machofileset");
        // root + kext + BRANCH_STUBS
        assert_eq!(fs.get_file_count(), 3);
    }
}
