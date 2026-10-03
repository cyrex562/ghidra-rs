//! Port of `ghidra.file.formats.sparseimage.SparseImageFileSystemFactory`.

use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;

use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_byte_provider::GFileSystemProbeByteProvider;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::{
    FileAttributeValue, FileAttributes,
};
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::util::task::TaskMonitor;

use super::sparse_constants::SPARSE_HEADER_MAGIC;
use super::sparse_header::SparseHeader;
use super::sparse_image_decompressor::SparseImageDecompressor;
use super::sparse_image_file_system::SparseImageFileSystem;

/// Size of a [`SparseHeader`] on disk.
const SPARSE_HEADER_SIZE: u64 = 28;

/// Creates [`SparseImageFileSystem`]s: recognizes an Android sparse image by its header magic
/// and exposes the expanded raw image (cached by the [`FileSystemService`]) as the single
/// file `<container name>.raw`.
///
/// Mirrors `ghidra.file.formats.sparseimage.SparseImageFileSystemFactory`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SparseImageFileSystemFactory;

impl SparseImageFileSystemFactory {
    fn create_fs(
        target_fsrl: &FsrlRoot,
        byte_provider: &Rc<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let container_fsrl = byte_provider
            .get_fsrl()
            .ok_or_else(|| io::Error::other("sparse image container has no FSRL"))?;
        let mut pusher = |os: &mut dyn Write| -> Result<(), GFileSystemError> {
            let mut reader = BinaryReader::new(Rc::clone(byte_provider), true);
            let mut sid = SparseImageDecompressor::new(&mut reader, os);
            sid.decompress(monitor)
        };
        let payload_provider = fs_service.get_derived_byte_provider_push(
            container_fsrl,
            None,
            "sparse",
            -1,
            &mut pusher,
            monitor,
        )?;

        let payload_attrs = FileAttributes::of([
            (
                FileAttributeType::SizeAttr,
                Some(FileAttributeValue::Long(payload_provider.length() as i64)),
            ),
            (
                FileAttributeType::CompressedSizeAttr,
                Some(FileAttributeValue::Long(byte_provider.length() as i64)),
            ),
        ]);
        let container_name = target_fsrl
            .container()
            .and_then(Fsrl::name)
            .unwrap_or_default();
        let payload_name = format!("{container_name}.raw");

        let fs = SparseImageFileSystem::new(
            target_fsrl.clone(),
            Rc::from(payload_provider),
            &payload_name,
            payload_attrs,
        );
        Ok(Rc::new(fs))
    }
}

impl GFileSystemFactory for SparseImageFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_byte_provider(&self) -> Option<&dyn GFileSystemProbeByteProvider> {
        Some(self)
    }
}

impl GFileSystemFactoryByteProvider for SparseImageFileSystemFactory {
    /// Mirrors `create(FSRLRoot, ByteProvider, FileSystemService, TaskMonitor)`.
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let mut byte_provider: Rc<dyn ByteProvider> = Rc::from(byte_provider);
        let result = Self::create_fs(target_fsrl, &byte_provider, fs_service, monitor);
        // Mirrors `finally { FSUtilities.uncheckedClose(byteProvider, null); }`: the payload
        // lives in the file cache.
        if let Some(p) = Rc::get_mut(&mut byte_provider) {
            let _ = p.close();
        }
        result
    }
}

impl GFileSystemProbe for SparseImageFileSystemFactory {}

impl GFileSystemProbeByteProvider for SparseImageFileSystemFactory {
    /// Mirrors `probe(ByteProvider, FileSystemService, TaskMonitor)`: reads a little-endian
    /// [`SparseHeader`] and checks its magic.
    ///
    /// # Errors
    /// If the provider is too short to hold a header (Java's `EOFException`).
    fn probe(
        &self,
        byte_provider: &dyn ByteProvider,
        _fs_service: &FileSystemService,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError> {
        let len = SPARSE_HEADER_SIZE.min(byte_provider.length());
        let header_bytes = byte_provider.read_bytes(0, len)?;
        let mut reader = BinaryReader::from_bytes(header_bytes, true);
        let header = SparseHeader::new(&mut reader)?;
        Ok(header.magic as u32 == SPARSE_HEADER_MAGIC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
    use crate::util::task::DummyMonitor;

    #[test]
    fn probe_checks_little_endian_magic_and_rejects_short_input() {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(dir.path(), FileSystemFactoryMgr::new()).unwrap();
        let f = SparseImageFileSystemFactory;
        let mut header = SPARSE_HEADER_MAGIC.to_le_bytes().to_vec();
        header.resize(28, 0);
        assert!(f
            .probe(&ByteArrayProvider::new(header.clone()), &svc, &DummyMonitor)
            .unwrap());
        header[0] ^= 1;
        assert!(!f
            .probe(&ByteArrayProvider::new(header), &svc, &DummyMonitor)
            .unwrap());
        let short = SPARSE_HEADER_MAGIC.to_le_bytes().to_vec();
        assert!(f
            .probe(&ByteArrayProvider::new(short), &svc, &DummyMonitor)
            .is_err());
        assert!(f.as_probe_bytes_only().is_none());
        assert!(f.as_probe_byte_provider().is_some());
    }
}
