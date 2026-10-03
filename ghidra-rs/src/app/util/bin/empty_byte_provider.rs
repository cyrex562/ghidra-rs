//! Port of `ghidra.app.util.bin.EmptyByteProvider`.
//!
//! A [`ByteProvider`] that has no contents. Used, in the real Java, as `ByteProvider`'s own
//! static `EMPTY_BYTEPROVIDER` constant.
//!
//! `ByteProvider.EMPTY_BYTEPROVIDER = new EmptyByteProvider()` is a forward reference from the
//! interface back to this concrete type -- the dependency-cycle cut point this file was ported
//! ahead of [`ByteProvider`] to break. Implements the real
//! [`ByteProvider`](crate::app::util::bin::byte_provider::ByteProvider) trait directly.

use std::io;
use std::path::PathBuf;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::fsrl::Fsrl;

/// A [`ByteProvider`] that has no contents.
///
/// Mirrors `ghidra.app.util.bin.EmptyByteProvider`.
pub struct EmptyByteProvider {
    fsrl: Option<Fsrl>,
}

impl EmptyByteProvider {
    /// Creates an instance with no identity.
    ///
    /// Mirrors `EmptyByteProvider()`.
    pub fn new() -> Self {
        EmptyByteProvider { fsrl: None }
    }

    /// Creates an instance with the given [`Fsrl`] identity.
    ///
    /// Mirrors `EmptyByteProvider(FSRL fsrl)`.
    pub fn with_fsrl(fsrl: Option<Fsrl>) -> Self {
        EmptyByteProvider { fsrl }
    }
}

impl Default for EmptyByteProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteProvider for EmptyByteProvider {
    /// Mirrors `getFile()`.
    fn get_file(&self) -> Option<PathBuf> {
        None
    }

    /// Mirrors `getName()`.
    fn get_name(&self) -> Option<String> {
        self.fsrl.as_ref().and_then(|f| f.name())
    }

    /// Mirrors `getAbsolutePath()`.
    fn get_absolute_path(&self) -> Option<String> {
        self.fsrl.as_ref().and_then(|f| f.path().map(str::to_string))
    }

    /// Mirrors `length()`.
    fn length(&self) -> u64 {
        0
    }

    /// Mirrors `isValidIndex(long)`.
    fn is_valid_index(&self, _index: u64) -> bool {
        false
    }

    /// Mirrors `close()`: does nothing.
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Mirrors `readByte(long)`: always unsupported.
    fn read_byte(&self, _index: u64) -> io::Result<u8> {
        Err(io::Error::other("Not supported"))
    }

    /// Mirrors `readBytes(long, long)`: only the (trivial) empty read at index 0 succeeds.
    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        if index != 0 || length != 0 {
            return Err(io::Error::other("Not supported"));
        }
        Ok(Vec::new())
    }

    /// Mirrors `getFSRL()`.
    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.fsrl.as_ref()
    }

    /// Mirrors `isEmpty()`.
    fn is_empty(&self) -> bool {
        true
    }

    /// Mirrors `getInputStream(long)`: an empty stream at index 0, an error otherwise.
    fn get_input_stream(&self, index: u64) -> io::Result<Box<dyn io::Read>> {
        if index != 0 {
            return Err(io::Error::other("Invalid offset"));
        }
        Ok(Box::new(io::Cursor::new(Vec::<u8>::new())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_instance_has_null_identity() {
        let p = EmptyByteProvider::new();
        assert!(p.get_fsrl().is_none());
        assert!(p.get_file().is_none());
        assert!(p.get_name().is_none());
        assert!(p.get_absolute_path().is_none());
    }

    #[test]
    fn is_always_empty_with_zero_length() {
        let p = EmptyByteProvider::new();
        assert_eq!(p.length(), 0);
        assert!(p.is_empty());
    }

    #[test]
    fn no_index_is_valid() {
        let p = EmptyByteProvider::new();
        assert!(!p.is_valid_index(0));
        assert!(!p.is_valid_index(1));
    }

    #[test]
    fn read_byte_is_never_supported() {
        let p = EmptyByteProvider::new();
        assert!(p.read_byte(0).is_err());
    }

    #[test]
    fn read_bytes_zero_zero_succeeds_with_empty_result() {
        let p = EmptyByteProvider::new();
        assert_eq!(p.read_bytes(0, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn read_bytes_nonzero_fails() {
        let p = EmptyByteProvider::new();
        assert!(p.read_bytes(0, 1).is_err());
        assert!(p.read_bytes(1, 0).is_err());
    }

    #[test]
    fn close_is_a_no_op() {
        let mut p = EmptyByteProvider::new();
        assert!(p.close().is_ok());
    }

    #[test]
    fn get_input_stream_at_zero_is_empty() {
        let p = EmptyByteProvider::new();
        let mut stream = p.get_input_stream(0).unwrap();
        let mut buf = Vec::new();
        io::Read::read_to_end(&mut stream, &mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn get_input_stream_at_nonzero_index_errors() {
        let p = EmptyByteProvider::new();
        assert!(p.get_input_stream(1).is_err());
    }
}
