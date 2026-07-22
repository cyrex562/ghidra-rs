use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::filesystem::seam_stubs::{FileSystemServiceLike, FsrlRootLike, GFileSystemLike};
use crate::util::task::TaskMonitor;

use super::g_file_system_factory::GFileSystemFactory;

/// A [`GFileSystemFactory`] for filesystem implementations that use a [`ByteProvider`].
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider`.
///
/// The Java method returns the base `GFileSystem` type rather than `FSTYPE` (despite the
/// generic bound), so `create` here returns `Box<dyn GFileSystemLike>` -- the same
/// placeholder seam already used by [`GFileSystemFactory`]'s `FSTYPE` bound -- rather than
/// pulling in the real, four-parameter `GFileSystem` trait and its generic explosion.
pub trait GFileSystemFactoryByteProvider<FSTYPE: GFileSystemLike>:
    GFileSystemFactory<FSTYPE>
{
    /// Constructs a new filesystem instance that handles the specified file.
    ///
    /// `byte_provider` contains the contents of the file being probed; this method is
    /// responsible for closing it. `monitor` should be polled to see if the user has
    /// requested to cancel the operation, and updated with progress information.
    fn create(
        &self,
        target_fsrl: &dyn FsrlRootLike,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &dyn FileSystemServiceLike,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GFileSystemLike>, GFileSystemError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct DummyFileSystem;
    impl GFileSystemLike for DummyFileSystem {}

    struct DummyFsrlRoot;
    impl FsrlRootLike for DummyFsrlRoot {}

    struct DummyFsService;
    impl FileSystemServiceLike for DummyFsService {}

    struct RecordingByteProvider;

    impl ByteProvider for RecordingByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(0)
        }
        fn is_valid_index(&mut self, _index: u64) -> bool {
            false
        }
        fn read_byte(&mut self, _index: u64) -> io::Result<u8> {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty"))
        }
        fn read_bytes(&mut self, _index: u64, _length: usize) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
    }

    struct MockFactory;

    impl GFileSystemFactory<DummyFileSystem> for MockFactory {}

    impl GFileSystemFactoryByteProvider<DummyFileSystem> for MockFactory {
        fn create(
            &self,
            _target_fsrl: &dyn FsrlRootLike,
            mut byte_provider: Box<dyn ByteProvider>,
            _fs_service: &dyn FileSystemServiceLike,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn GFileSystemLike>, GFileSystemError> {
            // Exercise the byte provider (Java requires implementors to close it) before
            // handing back the constructed filesystem.
            let _ = byte_provider.length()?;
            Ok(Box::new(DummyFileSystem))
        }
    }

    #[test]
    fn create_reads_byte_provider_and_returns_filesystem() {
        let factory = MockFactory;
        let bp: Box<dyn ByteProvider> = Box::new(RecordingByteProvider);
        let monitor = crate::util::task::DummyMonitor;
        let result = factory.create(&DummyFsrlRoot, bp, &DummyFsService, &monitor);
        assert!(result.is_ok());
    }

    #[test]
    fn boxed_dyn_factory_is_accepted() {
        let factory: Box<dyn GFileSystemFactoryByteProvider<DummyFileSystem>> = Box::new(MockFactory);
        let bp: Box<dyn ByteProvider> = Box::new(RecordingByteProvider);
        let monitor = crate::util::task::DummyMonitor;
        let fs = factory.create(&DummyFsrlRoot, bp, &DummyFsService, &monitor).unwrap();
        let _: Box<dyn GFileSystemLike> = fs;
    }
}
