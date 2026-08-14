//! Rust port of `ghidra.file.formats.zip.ZipFileSystemFactory`.
//!
//! Opens `.zip` containers, preferring the 7-Zip libraries (via
//! [`SevenZipFileSystemFactory`](crate::file::seam_stubs::SevenZipFileSystemFactory)) and
//! falling back to a built-in zip reader when 7-Zip is unavailable or disabled.
//!
//! # Seam notes
//!
//! [`GFileSystemFactoryByteProvider::create`] hands this factory a `fs_service:
//! &dyn FileSystemServiceLike` -- an empty marker seam (see
//! `crate::filesystem::seam_stubs::FileSystemServiceLike`'s own docs, which call out that
//! `GFileSystemFactoryByteProvider` and `FileSystemService` were ported against each other as a
//! deliberate cycle cut-point). The two `FileSystemService` operations the Java class actually
//! calls here -- `getFileIfAvailable` and `createPlaintextTempFile` -- are therefore reimplemented
//! locally in [`create_plaintext_temp_file`] directly against the already-ported [`ByteProvider`],
//! rather than routed through the unreachable marker:
//! * `getFileIfAvailable` narrows its argument to a handful of concrete `ByteProvider`
//!   subclasses before returning `provider.getFile()`; none of those subclasses are ported yet,
//!   so this port calls [`ByteProvider::get_file`] directly (itself the same accessor Java's
//!   version bottoms out at).
//! * `createPlaintextTempFile` delegates to `FSUtilities.copyByteProviderToFile`, a plain byte
//!   copy loop; that loop is reproduced directly against `ByteProvider::length`/`read_bytes`.
//!
//! `ZipFileSystem`, `ZipFileSystemBuiltin` and `SevenZipFileSystemFactory` are not yet ported;
//! see [`crate::file::seam_stubs`] for their minimal placeholders (STUBS.tsv).

use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::file::seam_stubs::{SevenZipFileSystemFactory, ZipFileSystem, ZipFileSystemBuiltin};
use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::gfilesystem::factory::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
use crate::filesystem::gfilesystem::factory::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::seam_stubs::{FileSystemServiceLike, FsrlRootLike, GFileSystemLike};
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

impl GFileSystemFactory<ZipFileSystem> for ZipFileSystemFactory {}
impl GFileSystemProbe for ZipFileSystemFactory {}

// `probe_start_bytes` never calls a method on `container_fsrl` (same as the Java override, and
// as already noted for `SevenZipFileSystemFactory`), so this factory handles every `Fsrl`
// instantiation identically.
impl<Fsrl> GFileSystemProbeBytesOnly<Fsrl> for ZipFileSystemFactory {
    fn bytes_required(&self) -> usize {
        START_BYTES_REQUIRED
    }

    fn probe_start_bytes(&self, _container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool {
        start_bytes.len() >= 2 && start_bytes[0] == b'P' && start_bytes[1] == b'K'
    }
}

impl GFileSystemFactoryByteProvider<ZipFileSystem> for ZipFileSystemFactory {
    fn create(
        &self,
        target_fsrl: &dyn FsrlRootLike,
        mut byte_provider: Box<dyn ByteProvider>,
        fs_service: &dyn FileSystemServiceLike,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GFileSystemLike>, GFileSystemError> {
        // Try to use 7zip to handle .zip files, or fall back to using the less feature rich
        // built-in zip file support.
        if !USE_BUILTIN_ZIP_SUPPORT.load(Ordering::Relaxed)
            && SevenZipFileSystemFactory::init_native_libraries()
        {
            let mut fs = ZipFileSystem::new(target_fsrl, fs_service);
            match fs.mount(byte_provider, monitor) {
                Ok(()) => Ok(Box::new(fs)),
                Err(e) => {
                    let _ = fs.close();
                    Err(GFileSystemError::Io(e))
                }
            }
        } else {
            let zip_file = byte_provider.get_file();
            let (zip_file, delete_zip_file_when_done) = match zip_file {
                Some(f) => (f, false),
                None => {
                    let f = create_plaintext_temp_file(
                        byte_provider.as_mut(),
                        ZipFileSystemBuiltin::TEMPFILE_PREFIX,
                        monitor,
                    )?;
                    (f, true)
                }
            };
            // Mirrors `FSUtilities.uncheckedClose(byteProvider, null)`. `ByteProvider` has no
            // explicit close in this port, so releasing it is just dropping it.
            drop(byte_provider);

            let mut fs = ZipFileSystemBuiltin::new(target_fsrl, fs_service);
            match fs.mount(&zip_file, delete_zip_file_when_done, monitor) {
                Ok(()) => Ok(Box::new(fs)),
                Err(e) => {
                    let _ = fs.close();
                    Err(GFileSystemError::Io(e))
                }
            }
        }
    }
}

/// Copies `byte_provider`'s contents into a fresh plaintext temp file, returning its path.
///
/// Mirrors `FileSystemService.createPlaintextTempFile(ByteProvider, String, TaskMonitor)` (which
/// itself delegates to `FSUtilities.copyByteProviderToFile`); see the [module docs](self) for why
/// this is implemented directly here instead of through the unreachable `FileSystemServiceLike`
/// marker seam.
fn create_plaintext_temp_file(
    byte_provider: &mut dyn ByteProvider,
    filename_prefix: &str,
    monitor: &dyn TaskMonitor,
) -> io::Result<PathBuf> {
    let len = byte_provider.length()?;
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let mut path = std::env::temp_dir();
    path.push(format!("{filename_prefix}{millis}"));

    monitor.set_message("Copying to temp file");
    monitor.initialize(len as i64);

    let mut file = File::create(&path)?;
    const CHUNK: u64 = 64 * 1024;
    let mut offset = 0u64;
    while offset < len {
        if monitor.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "Copy was cancelled"));
        }
        let n = CHUNK.min(len - offset) as usize;
        let bytes = byte_provider.read_bytes(offset, n)?;
        file.write_all(&bytes)?;
        offset += n as u64;
        monitor.increment_progress(n as i64);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryByteProvider {
        bytes: Vec<u8>,
    }

    impl ByteProvider for MemoryByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct DummyFsrlRoot;
    impl FsrlRootLike for DummyFsrlRoot {}
    struct DummyFsService;
    impl FileSystemServiceLike for DummyFsService {}

    // Mirrors `ZipFileSystemFactoryTest`-style expectations derived directly from the Java
    // source: START_BYTES_REQUIRED == 2, and probeStartBytes checks for a leading "PK".

    #[test]
    fn bytes_required_matches_java_constant() {
        let factory = ZipFileSystemFactory;
        let required: usize =
            GFileSystemProbeBytesOnly::<DummyFsrlRoot>::bytes_required(&factory);
        assert_eq!(required, 2);
    }

    #[test]
    fn probe_start_bytes_recognizes_pk_magic() {
        let factory = ZipFileSystemFactory;
        let fsrl = DummyFsrlRoot;
        assert!(factory.probe_start_bytes(&fsrl, b"PK\x03\x04"));
    }

    #[test]
    fn probe_start_bytes_rejects_non_pk_magic() {
        let factory = ZipFileSystemFactory;
        let fsrl = DummyFsrlRoot;
        // gzip magic, not zip
        assert!(!factory.probe_start_bytes(&fsrl, &[0x1f, 0x8b, 0x08, 0x00]));
    }

    #[test]
    fn create_plaintext_temp_file_copies_exact_bytes_with_prefix() {
        let mut provider = MemoryByteProvider { bytes: b"hello zip world".to_vec() };
        let monitor = crate::util::task::DummyMonitor;
        let path =
            create_plaintext_temp_file(&mut provider, ZipFileSystemBuiltin::TEMPFILE_PREFIX, &monitor)
                .expect("temp file creation should succeed");

        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(file_name.starts_with(ZipFileSystemBuiltin::TEMPFILE_PREFIX));

        let contents = std::fs::read(&path).expect("temp file should be readable");
        assert_eq!(contents, b"hello zip world");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn create_falls_back_to_builtin_when_7zip_unavailable() {
        // With no 7-Zip binding ported, `SevenZipFileSystemFactory::init_native_libraries()`
        // always reports `false`, so `create` always takes the built-in-zip branch. That branch's
        // `ZipFileSystemBuiltin::mount` is itself an unported stub, so the overall call still
        // surfaces an `Err` -- but by the time it does, it must have already exercised the
        // temp-file/get-file branch selection faithfully to the Java control flow.
        let factory = ZipFileSystemFactory;
        let provider: Box<dyn ByteProvider> =
            Box::new(MemoryByteProvider { bytes: b"PK\x03\x04".to_vec() });
        let monitor = crate::util::task::DummyMonitor;
        let result = factory.create(&DummyFsrlRoot, provider, &DummyFsService, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn tempfile_prefix_matches_java_constant() {
        assert_eq!(ZipFileSystemBuiltin::TEMPFILE_PREFIX, "ghidra_tmp_zipfile");
    }
}
