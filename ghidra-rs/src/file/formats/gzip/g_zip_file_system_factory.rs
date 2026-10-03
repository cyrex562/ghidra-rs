//! Port of `ghidra.file.formats.gzip.GZipFileSystemFactory`.

use std::io::{self, Read};
use std::rc::Rc;

use flate2::read::GzDecoder;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::{FileAttributeValue, FileAttributes};
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fs_utilities;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::util::task::unknown_progress_wrapping_task_monitor::UnknownProgressWrappingTaskMonitor;
use crate::util::task::TaskMonitor;

use super::g_zip_constants::MAGIC_BYTES_COUNT;
use super::g_zip_file_system::GZipFileSystem;
use super::g_zip_util;

/// Creates [`GZipFileSystem`]s: probes for the gzip magic bytes and exposes the decompressed
/// contents (cached by the [`FileSystemService`]) as the filesystem's single file.
///
/// Mirrors `ghidra.file.formats.gzip.GZipFileSystemFactory`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GZipFileSystemFactory;

impl GZipFileSystemFactory {
    /// Mirrors `PROBE_BYTES_REQUIRED`.
    pub const PROBE_BYTES_REQUIRED: usize = MAGIC_BYTES_COUNT as usize;
    /// The payload name used when the gzip header records none. Mirrors
    /// `GZIP_PAYLOAD_FILENAME`.
    pub const GZIP_PAYLOAD_FILENAME: &'static str = "gzip_decompressed";

    fn get_gz_file_attributes(provider: &dyn ByteProvider, container_name: &str) -> io::Result<FileAttributes> {
        let mut gzcis = GzDecoder::new(provider.get_input_stream(0)?);
        // The header is parsed by the first read.
        let mut probe = [0u8; 1];
        let _ = gzcis.read(&mut probe)?;
        let header = gzcis
            .header()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Not a gzip stream"))?;
        // gzip header strings are ISO-8859-1.
        let latin1 = |b: &[u8]| b.iter().map(|&c| c as char).collect::<String>();
        let payload_filename = match header.filename() {
            None => {
                if container_name.to_lowercase().ends_with(".gz") {
                    remove_extension(container_name).to_string()
                } else {
                    Self::GZIP_PAYLOAD_FILENAME.to_string()
                }
            }
            Some(name) => fs_utilities::get_safe_filename(&latin1(name)),
        };
        let orig_comment = header.comment().map(latin1);
        // commons-compress reports the modification time in milliseconds.
        let orig_date = i64::from(header.mtime()) * 1000;
        Ok(FileAttributes::of([
            (FileAttributeType::NameAttr, Some(FileAttributeValue::Str(payload_filename))),
            (
                FileAttributeType::CompressedSizeAttr,
                Some(FileAttributeValue::Long(provider.length() as i64)),
            ),
            (
                FileAttributeType::ModifiedDateAttr,
                (orig_date != 0).then_some(FileAttributeValue::Date(orig_date)),
            ),
            (FileAttributeType::CommentAttr, orig_comment.map(FileAttributeValue::Str)),
        ]))
    }

    fn create_fs(
        target_fsrl: &FsrlRoot,
        provider: &dyn ByteProvider,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let container_name = target_fsrl.container().and_then(Fsrl::name).unwrap_or_default();
        let mut payload_attrs = Self::get_gz_file_attributes(provider, &container_name)?;
        let payload_name =
            payload_attrs.get_str(FileAttributeType::NameAttr, Self::GZIP_PAYLOAD_FILENAME).to_string();
        let upwtm = UnknownProgressWrappingTaskMonitor::new(monitor, provider.length() as i64);
        let container_fsrl = provider
            .get_fsrl()
            .ok_or_else(|| io::Error::other("gzip container has no FSRL"))?;
        let mut producer = || -> Result<Box<dyn Read>, GFileSystemError> {
            Ok(Box::new(GzDecoder::new(provider.get_input_stream(0)?)))
        };
        let payload_provider = fs_service.get_derived_byte_provider(
            container_fsrl,
            None,
            &format!("uncompressed {payload_name}"),
            -1,
            &mut producer,
            &upwtm,
        )?;
        payload_attrs.add(
            FileAttributeType::SizeAttr,
            Some(FileAttributeValue::Long(payload_provider.length() as i64)),
        );
        let fs = GZipFileSystem::new(
            target_fsrl.clone(),
            Rc::from(payload_provider),
            &payload_name,
            payload_attrs,
        );
        Ok(Rc::new(fs))
    }
}

/// `FilenameUtils.removeExtension`: drops the text after the last `.` of the final path
/// element.
fn remove_extension(name: &str) -> &str {
    let last_sep = name.rfind(['/', '\\']).map_or(0, |i| i + 1);
    match name[last_sep..].rfind('.') {
        Some(dot) => &name[..last_sep + dot],
        None => name,
    }
}

impl GFileSystemFactory for GZipFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_bytes_only(&self) -> Option<&dyn GFileSystemProbeBytesOnly> {
        Some(self)
    }
}

impl GFileSystemFactoryByteProvider for GZipFileSystemFactory {
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        mut provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let result = Self::create_fs(target_fsrl, &*provider, fs_service, monitor);
        // Mirrors `finally { FSUtilities.uncheckedClose(provider, null); }`: the payload lives
        // in the file cache, so the container is no longer needed.
        let _ = provider.close();
        result
    }
}

impl GFileSystemProbe for GZipFileSystemFactory {}

impl GFileSystemProbeBytesOnly for GZipFileSystemFactory {
    fn bytes_required(&self) -> usize {
        Self::PROBE_BYTES_REQUIRED
    }

    fn probe_start_bytes(&self, _container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool {
        g_zip_util::is_gzip(start_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_extension_matches_commons_io() {
        assert_eq!(remove_extension("a.tar.gz"), "a.tar");
        assert_eq!(remove_extension("dir.d/file"), "dir.d/file");
        assert_eq!(remove_extension("noext"), "noext");
    }

    #[test]
    fn probe_uses_magic_bytes() {
        let f = GZipFileSystemFactory;
        let fsrl = Fsrl::from_string("file:///a.gz").unwrap();
        assert_eq!(f.bytes_required(), 2);
        assert!(f.probe_start_bytes(&fsrl, &[0x1f, 0x8b]));
        assert!(!f.probe_start_bytes(&fsrl, b"PK"));
    }
}
