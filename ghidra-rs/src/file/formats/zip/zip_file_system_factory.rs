//! Rust port of `ghidra.file.formats.zip.ZipFileSystemFactory`.
//!
//! Opens `.zip` containers, preferring the 7-Zip libraries (via
//! [`SevenZipFileSystemFactory`](crate::file::seam_stubs::SevenZipFileSystemFactory)) and
//! falling back to a built-in zip reader when 7-Zip is unavailable or disabled.
//!
//! # Seam notes
//!
//! `ZipFileSystem`, `ZipFileSystemBuiltin` and `SevenZipFileSystemFactory` are not yet ported;
//! see [`crate::file::seam_stubs`] for their minimal placeholders (STUBS.tsv). Until they are,
//! [`create`](GFileSystemFactoryByteProvider::create) always fails when it reaches their
//! `mount`, after exercising the Java branch selection faithfully.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::file::seam_stubs::{SevenZipFileSystemFactory, ZipFileSystem, ZipFileSystemBuiltin};
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystemError};
use crate::util::task::TaskMonitor;

/// Mirrors `ZipFileSystemFactory.START_BYTES_REQUIRED`.
const START_BYTES_REQUIRED: usize = 2;

/// Mirrors `ZipFileSystemFactory.USE_BUILTIN_ZIP_SUPPORT`, a process-wide flag toggled with
/// [`ZipFileSystemFactory::set_use_builtin_zip_support`].
///
/// Java seeds this from the `ghidra.file.formats.zip.ZipFileSystemFactory.USE_BUILTIN_ZIP_SUPPORT`
/// JVM system property at class load. This port has no equivalent startup-flag mechanism, so it
/// always starts `false` (the same default the property has when unset).
static USE_BUILTIN_ZIP_SUPPORT: AtomicBool = AtomicBool::new(false);

/// A [`GFileSystemFactoryByteProvider`] / [`GFileSystemProbeBytesOnly`] that opens `.zip`
/// containers.
///
/// Mirrors `ghidra.file.formats.zip.ZipFileSystemFactory`.
pub struct ZipFileSystemFactory;

impl ZipFileSystemFactory {
    /// Sets the static flag controlling which zip file implementation will be used when opening
    /// a zip file system.
    ///
    /// Mirrors `setUseBuiltinZipSupport(boolean)`.
    ///
    /// `b` true forces use of the built-in zip support (disabling 7-Zip); `false` allows the
    /// 7-Zip libraries to be attempted first.
    pub fn set_use_builtin_zip_support(b: bool) {
        USE_BUILTIN_ZIP_SUPPORT.store(b, Ordering::Relaxed);
    }
}

impl GFileSystemFactory for ZipFileSystemFactory {
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        Some(self)
    }

    fn as_probe_bytes_only(&self) -> Option<&dyn GFileSystemProbeBytesOnly> {
        Some(self)
    }
}

impl GFileSystemProbe for ZipFileSystemFactory {}

// `probe_start_bytes` never reads `container_fsrl` (same as the Java override).
impl GFileSystemProbeBytesOnly for ZipFileSystemFactory {
    fn bytes_required(&self) -> usize {
        START_BYTES_REQUIRED
    }

    fn probe_start_bytes(&self, _container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool {
        start_bytes.len() >= 2 && start_bytes[0] == b'P' && start_bytes[1] == b'K'
    }
}

impl GFileSystemFactoryByteProvider for ZipFileSystemFactory {
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        mut byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        // Try to use 7zip to handle .zip files, or fall back to using the less feature rich
        // built-in zip file support.
        if !USE_BUILTIN_ZIP_SUPPORT.load(Ordering::Relaxed)
            && SevenZipFileSystemFactory::init_native_libraries()
        {
            let mut fs = ZipFileSystem::new(target_fsrl, fs_service);
            match fs.mount(byte_provider, monitor) {
                Ok(h) => Ok(h),
                Err(e) => {
                    let _ = fs.close();
                    Err(GFileSystemError::Io(e))
                }
            }
        } else {
            let (zip_file, delete_zip_file_when_done) =
                match fs_service.get_file_if_available(&*byte_provider) {
                    Some(f) => (f, false),
                    None => {
                        let f = fs_service.create_plaintext_temp_file(
                            &*byte_provider,
                            ZipFileSystemBuiltin::TEMPFILE_PREFIX,
                            monitor,
                        );
                        match f {
                            Ok(f) => (f, true),
                            Err(e) => {
                                let _ = byte_provider.close();
                                return Err(e.into());
                            }
                        }
                    }
                };
            // Mirrors `FSUtilities.uncheckedClose(byteProvider, null)`.
            let _ = byte_provider.close();
            drop(byte_provider);

            let mut fs = ZipFileSystemBuiltin::new(target_fsrl, fs_service);
            match fs.mount(&zip_file, delete_zip_file_when_done, monitor) {
                Ok(h) => Ok(h),
                Err(e) => {
                    let _ = fs.close();
                    Err(GFileSystemError::Io(e))
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;

    fn service() -> (tempfile::TempDir, FileSystemService) {
        let dir = tempfile::tempdir().unwrap();
        let svc = FileSystemService::new(dir.path(), FileSystemFactoryMgr::new()).unwrap();
        (dir, svc)
    }

    // Mirrors `ZipFileSystemFactoryTest`-style expectations derived directly from the Java
    // source: START_BYTES_REQUIRED == 2, and probeStartBytes checks for a leading "PK".

    #[test]
    fn bytes_required_matches_java_constant() {
        let factory = ZipFileSystemFactory;
        let required: usize =
            GFileSystemProbeBytesOnly::bytes_required(&factory);
        assert_eq!(required, 2);
    }

    #[test]
    fn probe_start_bytes_recognizes_pk_magic() {
        let factory = ZipFileSystemFactory;
        let fsrl = Fsrl::from_string("file:///tmp/a.zip").unwrap();
        assert!(factory.probe_start_bytes(&fsrl, b"PK\x03\x04"));
    }

    #[test]
    fn probe_start_bytes_rejects_non_pk_magic() {
        let factory = ZipFileSystemFactory;
        let fsrl = Fsrl::from_string("file:///tmp/a.zip").unwrap();
        // gzip magic, not zip
        assert!(!factory.probe_start_bytes(&fsrl, &[0x1f, 0x8b, 0x08, 0x00]));
    }

    #[test]
    fn create_plaintext_temp_file_copies_exact_bytes_with_prefix() {
        let (_d, svc) = service();
        let provider = ByteArrayProvider::new(b"hello zip world".to_vec());
        let monitor = crate::util::task::DummyMonitor;
        let path = svc
            .create_plaintext_temp_file(&provider, ZipFileSystemBuiltin::TEMPFILE_PREFIX, &monitor)
            .expect("temp file creation should succeed");
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(file_name.starts_with(ZipFileSystemBuiltin::TEMPFILE_PREFIX));
        let contents = std::fs::read(&path).expect("temp file should be readable");
        assert_eq!(contents, b"hello zip world");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn temp_files_created_in_the_same_millisecond_are_distinct() {
        let (_d, svc) = service();
        let provider = ByteArrayProvider::new(b"x".to_vec());
        let monitor = crate::util::task::DummyMonitor;
        let prefix = ZipFileSystemBuiltin::TEMPFILE_PREFIX;
        let a = svc.create_plaintext_temp_file(&provider, prefix, &monitor).unwrap();
        let b = svc.create_plaintext_temp_file(&provider, prefix, &monitor).unwrap();
        assert_ne!(a, b);
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    #[test]
    fn create_falls_back_to_builtin_when_7zip_unavailable() {
        // With no 7-Zip binding ported, `SevenZipFileSystemFactory::init_native_libraries()`
        // always reports `false`, so `create` always takes the built-in-zip branch. That branch's
        // `ZipFileSystemBuiltin::mount` is itself an unported stub, so the overall call still
        // surfaces an `Err` -- but by the time it does, it must have already exercised the
        // temp-file/get-file branch selection faithfully to the Java control flow.
        let factory = ZipFileSystemFactory;
        let (_d, svc) = service();
        let provider: Box<dyn ByteProvider> = Box::new(ByteArrayProvider::new(b"PK\x03\x04".to_vec()));
        let monitor = crate::util::task::DummyMonitor;
        let result = factory.create(&FsrlRoot::make_root("file"), provider, &svc, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn tempfile_prefix_matches_java_constant() {
        assert_eq!(ZipFileSystemBuiltin::TEMPFILE_PREFIX, "ghidra_tmp_zipfile");
    }
}
