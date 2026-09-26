//! Port of `ghidra.app.util.bin.ByteArrayProvider`.
//!
//! A [`ByteProvider`] backed by an in-memory byte array.
//!
//! PROMOTE: this replaces the minimal placeholder previously at
//! `crate::file::seam_stubs::ByteArrayProvider`, which only implemented the legacy
//! [`GByteStore`] trait. That trait is still what a handful of older filesystem ports consume
//! (`AndroidXmlFileSystem`, `MachoFileSetExtractor`, the XCOFF header tests), so this type also
//! implements [`GByteStore`] as a read-only bridge; new code should use it as a
//! [`ByteProvider`].
//!
//! The backing bytes are held as a shared `Arc<[u8]>` so that callers that already own a shared
//! buffer (e.g. the file cache's in-memory entries) can hand it out without copying, matching
//! Java, where the array is shared by reference.

use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;

use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::filesystem::gfilesystem::fsrl::Fsrl;

use super::byte_provider::ByteProvider;

/// An array-backed [`ByteProvider`].
///
/// Mirrors `ghidra.app.util.bin.ByteArrayProvider`.
#[derive(Clone)]
pub struct ByteArrayProvider {
    src_bytes: Arc<[u8]>,
    name: Option<String>,
    fsrl: Option<Fsrl>,
}

impl ByteArrayProvider {
    /// Constructs a provider using the specified byte array. Mirrors
    /// `ByteArrayProvider(byte[])`.
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self::with_fsrl(bytes, None)
    }

    /// Constructs a provider using the specified byte array and FSRL identity. Mirrors
    /// `ByteArrayProvider(byte[], FSRL)`.
    pub fn with_fsrl(bytes: impl Into<Arc<[u8]>>, fsrl: Option<Fsrl>) -> Self {
        ByteArrayProvider { src_bytes: bytes.into(), name: None, fsrl }
    }

    /// Constructs a provider using the specified byte array and name. Mirrors
    /// `ByteArrayProvider(String, byte[])`.
    pub fn with_name(name: &str, bytes: impl Into<Arc<[u8]>>) -> Self {
        ByteArrayProvider { src_bytes: bytes.into(), name: Some(name.to_string()), fsrl: None }
    }

    /// Releases the byte storage of this instance. Mirrors `hardClose()`.
    ///
    /// This is separate from [`ByteProvider::close`], which (as in Java) does nothing, so that
    /// callers that cannot know whether a provider is array-backed do not lose its data.
    pub fn hard_close(&mut self) {
        self.src_bytes = Arc::from(Vec::new());
    }

    fn assert_valid_index(&self, index: u64, inclusive_max: bool) -> io::Result<()> {
        let len = self.src_bytes.len() as u64;
        if index > len || (!inclusive_max && index == len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid position, index: {index}, max is: {len}"),
            ));
        }
        Ok(())
    }
}

impl ByteProvider for ByteArrayProvider {
    fn get_file(&self) -> Option<PathBuf> {
        None
    }

    fn get_name(&self) -> Option<String> {
        match &self.fsrl {
            Some(fsrl) => fsrl.name(),
            None => self.name.clone(),
        }
    }

    fn get_absolute_path(&self) -> Option<String> {
        match &self.fsrl {
            Some(fsrl) => fsrl.path().map(str::to_string),
            None => Some(String::new()),
        }
    }

    fn length(&self) -> u64 {
        self.src_bytes.len() as u64
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index < self.length()
    }

    /// Does nothing, matching Java; see [`hard_close`](ByteArrayProvider::hard_close).
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.assert_valid_index(index, false)?;
        Ok(self.src_bytes[index as usize])
    }

    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        self.assert_valid_index(index, true)?;
        if index + length > self.length() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Attempt to read beyond end of byte data",
            ));
        }
        Ok(self.src_bytes[index as usize..(index + length) as usize].to_vec())
    }

    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.fsrl.as_ref()
    }

    fn get_input_stream(&self, index: u64) -> io::Result<Box<dyn Read>> {
        self.assert_valid_index(index, true)?;
        let bytes = Arc::clone(&self.src_bytes);
        let mut cursor = io::Cursor::new(ArcBytes(bytes));
        cursor.set_position(index);
        Ok(Box::new(cursor))
    }
}

/// `AsRef<[u8]>` adapter so a shared buffer can back an [`io::Cursor`] without copying.
struct ArcBytes(Arc<[u8]>);

impl AsRef<[u8]> for ArcBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Read-only bridge to the legacy [`GByteStore`] trait (see the module docs).
impl GByteStore for ByteArrayProvider {
    fn length(&mut self) -> io::Result<u64> {
        Ok(ByteProvider::length(self))
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        ByteProvider::is_valid_index(self, index)
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        ByteProvider::read_byte(self, index)
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        ByteProvider::read_bytes(self, index, length as u64)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ByteArrayProvider is read-only"))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ByteArrayProvider is read-only"))
    }

    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.fsrl.as_ref()
    }

    fn get_file(&self) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bytes_and_bounds() {
        let p = ByteArrayProvider::new(vec![1u8, 2, 3, 4]);
        assert_eq!(ByteProvider::length(&p), 4);
        assert_eq!(ByteProvider::read_byte(&p, 3).unwrap(), 4);
        assert!(ByteProvider::read_byte(&p, 4).is_err());
        assert_eq!(ByteProvider::read_bytes(&p, 1, 2).unwrap(), vec![2, 3]);
        // Java: index == length is a valid (empty) read position for readBytes.
        assert_eq!(ByteProvider::read_bytes(&p, 4, 0).unwrap(), Vec::<u8>::new());
        assert!(ByteProvider::read_bytes(&p, 3, 2).is_err());
        assert!(ByteProvider::read_bytes(&p, 5, 0).is_err());
    }

    #[test]
    fn name_and_path_come_from_fsrl_when_present() {
        let fsrl = Fsrl::from_string("file:///tmp/abc.bin").unwrap();
        let p = ByteArrayProvider::with_fsrl(vec![0u8], Some(fsrl.clone()));
        assert_eq!(ByteProvider::get_name(&p).as_deref(), Some("abc.bin"));
        assert_eq!(p.get_absolute_path().as_deref(), Some("/tmp/abc.bin"));
        assert_eq!(ByteProvider::get_fsrl(&p), Some(&fsrl));

        let named = ByteArrayProvider::with_name("nm", vec![0u8]);
        assert_eq!(ByteProvider::get_name(&named).as_deref(), Some("nm"));
        assert_eq!(named.get_absolute_path().as_deref(), Some(""));
    }

    #[test]
    fn close_keeps_data_hard_close_drops_it() {
        let mut p = ByteArrayProvider::new(vec![9u8; 8]);
        ByteProvider::close(&mut p).unwrap();
        assert_eq!(ByteProvider::length(&p), 8);
        p.hard_close();
        assert_eq!(ByteProvider::length(&p), 0);
    }

    #[test]
    fn input_stream_starts_at_index() {
        let p = ByteArrayProvider::new(vec![10u8, 20, 30]);
        let mut s = p.get_input_stream(1).unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, vec![20, 30]);
        assert!(p.get_input_stream(4).is_err());
    }

    #[test]
    fn g_byte_store_bridge_is_read_only() {
        let mut p = ByteArrayProvider::new(vec![1u8, 2]);
        assert_eq!(GByteStore::read_bytes(&mut p, 0, 2).unwrap(), vec![1, 2]);
        assert!(GByteStore::write_byte(&mut p, 0, 5).is_err());
    }
}
