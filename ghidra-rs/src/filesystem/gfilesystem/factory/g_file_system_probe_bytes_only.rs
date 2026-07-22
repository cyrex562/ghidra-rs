use super::g_file_system_probe::GFileSystemProbe;

/// Maximum that any [`GFileSystemProbeBytesOnly`] is allowed to specify as its
/// [`GFileSystemProbeBytesOnly::bytes_required`].
pub const MAX_BYTES_REQUIRED: usize = 64 * 1024;

/// A [`GFileSystemProbe`] for filesystems that can be detected using just a few bytes from
/// the beginning of the containing file.
///
/// Filesystem probes of this type are given precedence when possible since they tend to be
/// simpler and quicker.
///
/// `Fsrl` is the same free type parameter used elsewhere in this crate (e.g.
/// [`crate::filesystem::gfilesystem::g_file::GFile`]) to stand in for the concrete `FSRL`
/// type once `FSRL.java` is ported. No implementation of `probeStartBytes` in the original
/// codebase calls a method on `containerFSRL`, so `Fsrl` carries no trait bound here.
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly`.
pub trait GFileSystemProbeBytesOnly<Fsrl>: GFileSystemProbe {
    /// The minimum number of bytes needed to be supplied to [`Self::probe_start_bytes`].
    fn bytes_required(&self) -> usize;

    /// Probes the supplied `start_bytes` to determine if this filesystem implementation can
    /// handle the file.
    ///
    /// `container_fsrl` is the FSRL of the file containing the bytes being probed.
    /// `start_bytes` has a length of at least [`Self::bytes_required`], containing bytes from
    /// the beginning (ie. offset 0) of the probed file.
    ///
    /// Returns `true` if the specified file is handled by this filesystem implementation,
    /// `false` if not.
    fn probe_start_bytes(&self, container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFsrl {
        name: String,
    }

    /// Recognizes the gzip magic bytes at offset 0, mirroring a typical
    /// `GFileSystemProbeBytesOnly` implementation (e.g. `GZipFileSystemFactory`).
    struct GzipMagicProbe;
    impl GFileSystemProbe for GzipMagicProbe {}
    impl GFileSystemProbeBytesOnly<MockFsrl> for GzipMagicProbe {
        fn bytes_required(&self) -> usize {
            2
        }

        fn probe_start_bytes(&self, _container_fsrl: &MockFsrl, start_bytes: &[u8]) -> bool {
            start_bytes.len() >= 2 && start_bytes[0] == 0x1f && start_bytes[1] == 0x8b
        }
    }

    #[test]
    fn probe_matches_expected_magic_bytes() {
        let probe = GzipMagicProbe;
        let fsrl = MockFsrl { name: "archive.gz".to_owned() };

        assert_eq!(probe.bytes_required(), 2);
        assert!(probe.probe_start_bytes(&fsrl, &[0x1f, 0x8b, 0x08, 0x00]));
    }

    #[test]
    fn probe_rejects_mismatched_bytes() {
        let probe = GzipMagicProbe;
        let fsrl = MockFsrl { name: "archive.tar".to_owned() };

        assert!(!probe.probe_start_bytes(&fsrl, &[0x50, 0x4b, 0x03, 0x04]));
    }

    #[test]
    fn probe_rejects_short_byte_slice() {
        let probe = GzipMagicProbe;
        let fsrl = MockFsrl { name: "empty".to_owned() };

        assert!(!probe.probe_start_bytes(&fsrl, &[0x1f]));
    }

    #[test]
    fn boxed_dyn_probe_is_accepted() {
        let probe: Box<dyn GFileSystemProbeBytesOnly<MockFsrl>> = Box::new(GzipMagicProbe);
        let fsrl = MockFsrl { name: "archive.gz".to_owned() };

        assert!(probe.probe_start_bytes(&fsrl, &[0x1f, 0x8b]));
    }

    #[test]
    fn max_bytes_required_matches_java_constant() {
        assert_eq!(MAX_BYTES_REQUIRED, 64 * 1024);
    }
}
