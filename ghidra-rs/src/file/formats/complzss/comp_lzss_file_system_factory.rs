//! Port of `ghidra.file.formats.complzss.CompLzssFileSystemFactory`.

use std::io::{self, Write};
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::file::formats::lzss::lzss_codec;
use crate::file::formats::lzss::lzss_compression_header::LzssCompressionHeader;
use crate::file::formats::lzss::lzss_constants::HEADER_LENGTH;
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributes;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::util::task::TaskMonitor;

use super::comp_lzss_file_system::CompLzssFileSystem;

/// Creates [`CompLzssFileSystem`]s: recognizes an [`LzssCompressionHeader`] and exposes the
/// LZSS-decompressed remainder (cached by the [`FileSystemService`]) as the single file.
///
/// Mirrors `ghidra.file.formats.complzss.CompLzssFileSystemFactory`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CompLzssFileSystemFactory;

impl CompLzssFileSystemFactory {
    /// The name of the decompressed payload file.
    pub const PAYLOAD_FILENAME: &'static str = "lzss_decompressed";

    fn create_fs(
        target_fsrl: &FsrlRoot,
        provider: &dyn ByteProvider,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        // Java: a ByteProviderWrapper over everything after the header.
        if provider.length() < HEADER_LENGTH as u64 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "LZSS container shorter than its header").into());
        }
        let container_fsrl = provider
            .get_fsrl()
            .ok_or_else(|| io::Error::other("LZSS container has no FSRL"))?;
        let mut pusher = |os: &mut dyn Write| -> Result<(), GFileSystemError> {
            let mut tmp_is = provider.get_input_stream(HEADER_LENGTH as u64)?;
            let mut os = os;
            lzss_codec::decompress(&mut os, &mut tmp_is)?;
            Ok(())
        };
        let payload_provider = fs_service.get_derived_byte_provider_push(
            container_fsrl,
            None,
            "decompressed lzss",
            -1,
            &mut pusher,
            monitor,
        )?;
        let fs = CompLzssFileSystem::new(
            target_fsrl.clone(),
            Rc::from(payload_provider),
            Self::PAYLOAD_FILENAME,
            FileAttributes::new(),
        );
        Ok(Rc::new(fs))
    }
}

impl GFileSystemFactory for CompLzssFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_bytes_only(&self) -> Option<&dyn GFileSystemProbeBytesOnly> {
        Some(self)
    }
}

impl GFileSystemFactoryByteProvider for CompLzssFileSystemFactory {
    /// Mirrors `create(FSRLRoot, ByteProvider, FileSystemService, TaskMonitor)`.
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        mut provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let result = Self::create_fs(target_fsrl, &*provider, fs_service, monitor);
        // Mirrors `finally { FSUtilities.uncheckedClose(provider, null); }`: the payload lives
        // in the file cache.
        let _ = provider.close();
        result
    }
}

impl GFileSystemProbe for CompLzssFileSystemFactory {}

impl GFileSystemProbeBytesOnly for CompLzssFileSystemFactory {
    fn bytes_required(&self) -> usize {
        LzssCompressionHeader::PROBE_BYTES_NEEDED
    }

    fn probe_start_bytes(&self, _container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool {
        LzssCompressionHeader::probe(start_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_defers_to_header() {
        let f = CompLzssFileSystemFactory;
        let fsrl = Fsrl::from_string("file:///kernel.lzss").unwrap();
        assert_eq!(f.bytes_required(), 8);
        assert!(f.probe_start_bytes(&fsrl, b"lzsscomp"));
        assert!(!f.probe_start_bytes(&fsrl, b"\x1f\x8b\x08\0\0\0\0\0"));
        assert!(f.as_byte_provider_factory().is_some());
        assert!(f.as_probe_byte_provider().is_none());
    }
}
