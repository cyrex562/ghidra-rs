use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::filesystem::seam_stubs::FileSystemServiceLike;
use crate::util::task::TaskMonitor;

use super::g_file_system_probe::GFileSystemProbe;

/// A [`GFileSystemProbe`] for filesystems that need to examine a [`ByteProvider`].
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider`.
pub trait GFileSystemProbeByteProvider: GFileSystemProbe {
    /// Probes `byte_provider` to determine if this filesystem implementation can handle the
    /// file.
    ///
    /// Implementors must NOT close `byte_provider`. `monitor` should be polled to see if the
    /// user has requested to cancel the operation, and updated with progress information.
    ///
    /// Returns `true` if the specified file is handled by this filesystem implementation,
    /// `false` if not.
    fn probe(
        &self,
        byte_provider: &mut dyn ByteProvider,
        fs_service: &dyn FileSystemServiceLike,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct DummyFsService;
    impl FileSystemServiceLike for DummyFsService {}

    struct RecordingByteProvider {
        length: u64,
    }

    impl ByteProvider for RecordingByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.length)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.length
        }
        fn read_byte(&mut self, _index: u64) -> io::Result<u8> {
            Ok(0x7f)
        }
        fn read_bytes(&mut self, _index: u64, length: usize) -> io::Result<Vec<u8>> {
            Ok(vec![0x7f; length])
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
    }

    /// Probes for the ELF magic byte at offset 0, mirroring a typical
    /// `GFileSystemProbeByteProvider` implementation.
    struct ElfMagicProbe;
    impl GFileSystemProbe for ElfMagicProbe {}
    impl GFileSystemProbeByteProvider for ElfMagicProbe {
        fn probe(
            &self,
            byte_provider: &mut dyn ByteProvider,
            _fs_service: &dyn FileSystemServiceLike,
            _monitor: &dyn TaskMonitor,
        ) -> Result<bool, GFileSystemError> {
            if !byte_provider.is_valid_index(0) {
                return Ok(false);
            }
            Ok(byte_provider.read_byte(0)? == 0x7f)
        }
    }

    #[test]
    fn probe_matches_expected_magic_byte() {
        let probe = ElfMagicProbe;
        let mut bp = RecordingByteProvider { length: 4 };
        let fs_service = DummyFsService;
        let monitor = crate::util::task::DummyMonitor;

        let result = probe.probe(&mut bp, &fs_service, &monitor).unwrap();
        assert!(result);
    }

    #[test]
    fn probe_rejects_empty_byte_provider() {
        let probe = ElfMagicProbe;
        let mut bp = RecordingByteProvider { length: 0 };
        let fs_service = DummyFsService;
        let monitor = crate::util::task::DummyMonitor;

        let result = probe.probe(&mut bp, &fs_service, &monitor).unwrap();
        assert!(!result);
    }

    #[test]
    fn boxed_dyn_probe_is_accepted() {
        let probe: Box<dyn GFileSystemProbeByteProvider> = Box::new(ElfMagicProbe);
        let mut bp: Box<dyn ByteProvider> = Box::new(RecordingByteProvider { length: 1 });
        let fs_service = DummyFsService;
        let monitor = crate::util::task::DummyMonitor;

        let result = probe.probe(bp.as_mut(), &fs_service, &monitor).unwrap();
        assert!(result);
    }
}
