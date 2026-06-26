use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::app::util::bin::mutable_byte_provider::MutableByteProvider;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// A [`MutableByteProvider`] backed by a random-access file.
///
/// Mirrors `ghidra.app.util.bin.RandomAccessMutableByteProvider` from the
/// original Ghidra source (itself extending the deprecated
/// `RandomAccessByteProvider`). In Rust there is no inheritance; this struct
/// directly implements [`ByteProvider`] and [`MutableByteProvider`] using
/// [`std::fs::File`].
///
/// The file length is cached at open time, matching the Java behaviour of
/// `RandomAccessByteProvider`.
///
/// Note: not thread-safe — do not share across threads without external
/// synchronisation.
pub struct RandomAccessMutableByteProvider {
    file: File,
    file_length: u64,
}

impl RandomAccessMutableByteProvider {
    /// Opens `path` for both reading and writing.
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let file_length = file.metadata()?.len();
        Ok(Self { file, file_length })
    }

    /// Opens `path` with the mode string used by Java's `RandomAccessFile`:
    /// `"r"` for read-only, `"rw"` / `"rws"` / `"rwd"` for read-write.
    ///
    /// Mirrors the `RandomAccessMutableByteProvider(File, String)` constructor.
    pub fn with_permissions<P: AsRef<Path>>(path: P, permissions: &str) -> io::Result<Self> {
        let write = permissions.contains('w');
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .open(path)?;
        let file_length = file.metadata()?.len();
        Ok(Self { file, file_length })
    }
}

impl ByteProvider for RandomAccessMutableByteProvider {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.file_length)
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        index < self.file_length
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        self.file.seek(SeekFrom::Start(index))?;
        let mut buf = [0u8; 1];
        self.file.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        if index > self.file_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Invalid file offset {index}"),
            ));
        }
        if index + length as u64 > self.file_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("EOF: unable to read {length} bytes at {index}"),
            ));
        }
        self.file.seek(SeekFrom::Start(index))?;
        let mut buf = vec![0u8; length];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(index))?;
        self.file.write_all(&[value])
    }

    fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(index))?;
        self.file.write_all(values)
    }
}

impl MutableByteProvider for RandomAccessMutableByteProvider {}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_temp_file(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn length_matches_file_size() {
        let f = make_temp_file(b"hello");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        assert_eq!(p.length().unwrap(), 5);
    }

    #[test]
    fn is_valid_index_within_bounds() {
        let f = make_temp_file(b"abc");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        assert!(p.is_valid_index(0));
        assert!(p.is_valid_index(2));
        assert!(!p.is_valid_index(3));
    }

    #[test]
    fn read_byte_returns_correct_value() {
        let f = make_temp_file(b"XYZ");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        assert_eq!(p.read_byte(0).unwrap(), b'X');
        assert_eq!(p.read_byte(2).unwrap(), b'Z');
    }

    #[test]
    fn read_bytes_returns_slice() {
        let f = make_temp_file(b"hello world");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        assert_eq!(p.read_bytes(6, 5).unwrap(), b"world");
    }

    #[test]
    fn read_bytes_at_invalid_offset_errors() {
        let f = make_temp_file(b"hi");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        assert!(p.read_bytes(10, 1).is_err());
    }

    #[test]
    fn read_bytes_past_eof_errors() {
        let f = make_temp_file(b"hi");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        assert!(p.read_bytes(1, 5).is_err());
    }

    #[test]
    fn write_byte_mutates_file() {
        let f = make_temp_file(b"aaa");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        p.write_byte(1, b'Z').unwrap();
        assert_eq!(p.read_byte(1).unwrap(), b'Z');
        assert_eq!(p.read_byte(0).unwrap(), b'a');
        assert_eq!(p.read_byte(2).unwrap(), b'a');
    }

    #[test]
    fn write_bytes_mutates_file() {
        let f = make_temp_file(b"00000");
        let mut p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        p.write_bytes(1, b"ABC").unwrap();
        assert_eq!(p.read_bytes(0, 5).unwrap(), b"0ABC0");
    }

    #[test]
    fn with_permissions_rw_allows_writes() {
        let f = make_temp_file(b"test");
        let mut p =
            RandomAccessMutableByteProvider::with_permissions(f.path(), "rw").unwrap();
        p.write_byte(0, b'X').unwrap();
        assert_eq!(p.read_byte(0).unwrap(), b'X');
    }

    #[test]
    fn implements_mutable_byte_provider() {
        fn accept(_: &impl MutableByteProvider) {}
        let f = make_temp_file(b"data");
        let p = RandomAccessMutableByteProvider::new(f.path()).unwrap();
        accept(&p);
    }
}
