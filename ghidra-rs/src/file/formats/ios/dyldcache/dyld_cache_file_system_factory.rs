//! Port of `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystemFactory`.

use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::opinion::dyld_cache_utils;
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_byte_provider::GFileSystemProbeByteProvider;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::format::macho::dyld::dyld_cache_header::DyldCacheHeader;
use crate::util::task::TaskMonitor;

use super::dyld_cache_file_system::DyldCacheFileSystem;

/// Creates [`DyldCacheFileSystem`]s for (base) DYLD caches.
///
/// Port of `ghidra.file.formats.ios.dyldcache.DyldCacheFileSystemFactory`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DyldCacheFileSystemFactory;

/// How much of the cache the probe copies to parse the header from: the header itself is far
/// smaller (see the probe's docs).
const PROBE_HEADER_BYTES: u64 = 0x1000;

impl GFileSystemFactory for DyldCacheFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_byte_provider(&self) -> Option<&dyn GFileSystemProbeByteProvider> {
        Some(self)
    }
}

impl GFileSystemFactoryByteProvider for DyldCacheFileSystemFactory {
    /// Java `create(FSRLRoot, ByteProvider, FileSystemService, TaskMonitor)`: a new, mounted
    /// filesystem that takes ownership of the cache provider (a `MachException` while mounting
    /// surfaces as an I/O error, as in Java).
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let provider: Rc<dyn ByteProvider> = Rc::from(byte_provider);
        let mut fs = DyldCacheFileSystem::new(target_fsrl.clone(), provider, fs_service);
        fs.mount(monitor)?;
        Ok(Rc::new(fs))
    }
}

impl GFileSystemProbe for DyldCacheFileSystemFactory {}

impl GFileSystemProbeByteProvider for DyldCacheFileSystemFactory {
    /// Java `probe(ByteProvider, FileSystemService, TaskMonitor)`: a DYLD cache that is not a
    /// sub-cache.
    ///
    /// Java builds the `DyldCacheHeader` directly over the provider; the header constructor only
    /// reads the fixed-size header fields, so this parses them from a copy of the provider's
    /// first [`PROBE_HEADER_BYTES`] (a `DyldCacheHeader` reader needs an owned provider).
    fn probe(
        &self,
        byte_provider: &dyn ByteProvider,
        _fs_service: &FileSystemService,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError> {
        if !dyld_cache_utils::is_dyld_cache_provider(byte_provider) {
            return Ok(false);
        }
        let head = byte_provider.read_bytes(0, PROBE_HEADER_BYTES.min(byte_provider.length()))?;
        let reader = BinaryReader::new(Rc::new(ByteArrayProvider::new(head)), true);
        match DyldCacheHeader::new(&reader) {
            Ok(header) => Ok(!header.is_subcache()),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::ios::dyldcache::dyld_cache_file_system::test_support::dyld_cache;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::util::task::DummyMonitor;

    #[test]
    fn probes_and_creates() {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        let f = DyldCacheFileSystemFactory;
        assert!(f.as_byte_provider_factory().is_some());
        assert!(f.as_probe_byte_provider().is_some());

        let cache = dyld_cache();
        assert!(f.probe(&ByteArrayProvider::new(cache.clone()), &svc, &DummyMonitor).unwrap());
        assert!(!f.probe(&ByteArrayProvider::new(vec![0u8; 0x100]), &svc, &DummyMonitor).unwrap());

        let container = Fsrl::from_string("file:///dyld_shared_cache_x86_64").unwrap();
        let fs = f
            .create(
                &container.make_nested("dyldcachev1"),
                Box::new(ByteArrayProvider::with_fsrl(cache, Some(container.clone()))),
                &svc,
                &DummyMonitor,
            )
            .unwrap();
        assert_eq!(fs.get_type(), "dyldcachev1");
        // root + libA.dylib + /usr + /usr/lib + /DYLD + /DYLD/<cache> + the mapping chunk
        assert_eq!(fs.get_file_count(), 7);
    }
}
