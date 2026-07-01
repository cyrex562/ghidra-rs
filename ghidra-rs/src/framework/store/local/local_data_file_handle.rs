use crate::framework::store::DataFileHandle;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Provides random access to a local file.
pub struct LocalDataFileHandle {
    file: File,
    read_only: bool,
}

impl LocalDataFileHandle {
    /// Constructs and opens a local `LocalDataFileHandle`.
    ///
    /// - `file`: file to be opened
    /// - `read_only`: if true the resulting handle may only be read.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file was not found or another I/O error occurs.
    pub fn new(file: impl AsRef<Path>, read_only: bool) -> io::Result<Self> {
        let opened = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(file.as_ref())?;
        Ok(Self {
            file: opened,
            read_only,
        })
    }
}

impl DataFileHandle for LocalDataFileHandle {
    fn is_read_only(&mut self) -> io::Result<bool> {
        Ok(self.read_only)
    }

    fn read(&mut self, b: &mut [u8]) -> io::Result<()> {
        self.file.read_exact(b)
    }

    fn read_at(&mut self, b: &mut [u8], off: usize, len: usize) -> io::Result<()> {
        self.file.read_exact(&mut b[off..off + len])
    }

    fn skip_bytes(&mut self, n: i32) -> io::Result<i32> {
        if n <= 0 {
            return Ok(0);
        }
        let pos = self.file.stream_position()? as i64;
        let len = self.file.metadata()?.len() as i64;
        let mut new_pos = pos + n as i64;
        if new_pos > len {
            new_pos = len;
        }
        self.file.seek(SeekFrom::Start(new_pos as u64))?;
        Ok((new_pos - pos) as i32)
    }

    fn write(&mut self, b: i32) -> io::Result<()> {
        self.file.write_all(&[(b & 0xFF) as u8])
    }

    fn write_bytes(&mut self, b: &[u8]) -> io::Result<()> {
        self.file.write_all(b)
    }

    fn write_at(&mut self, b: &[u8], off: usize, len: usize) -> io::Result<()> {
        self.file.write_all(&b[off..off + len])
    }

    fn seek(&mut self, pos: i64) -> io::Result<()> {
        if pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "position cannot be negative",
            ));
        }
        self.file.seek(SeekFrom::Start(pos as u64))?;
        Ok(())
    }

    fn length(&mut self) -> io::Result<i64> {
        Ok(self.file.metadata()?.len() as i64)
    }

    fn set_length(&mut self, new_length: i64) -> io::Result<()> {
        self.file.set_len(new_length as u64)?;
        let pos = self.file.stream_position()? as i64;
        if pos > new_length {
            self.file.seek(SeekFrom::Start(new_length as u64))?;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_file(data: &[u8]) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "local_data_file_handle_test_{}_{}",
            std::process::id(),
            id
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(data).unwrap();
        path
    }

    #[test]
    fn test_open_read_only() {
        let path = tmp_file(b"hello");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        assert!(handle.is_read_only().unwrap());
        let mut buf = [0u8; 5];
        handle.read(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_write_read_roundtrip() {
        let path = tmp_file(b"");
        let mut handle = LocalDataFileHandle::new(&path, false).unwrap();
        assert!(!handle.is_read_only().unwrap());
        handle.write_bytes(b"test data").unwrap();
        handle.seek(0).unwrap();
        let mut buf = vec![0u8; 9];
        handle.read(&mut buf).unwrap();
        assert_eq!(&buf, b"test data");
    }

    #[test]
    fn test_read_at_offset() {
        let path = tmp_file(b"abcdef");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        let mut buf = vec![0u8; 10];
        handle.read_at(&mut buf, 2, 4).unwrap();
        assert_eq!(&buf[2..6], b"abcd");
    }

    #[test]
    fn test_write_at_offset() {
        let path = tmp_file(b"");
        let mut handle = LocalDataFileHandle::new(&path, false).unwrap();
        handle.write_bytes(b"hello").unwrap();
        handle.seek(5).unwrap();
        handle.write_at(b" world", 0, 6).unwrap();
        assert_eq!(handle.length().unwrap(), 11);
    }

    #[test]
    fn test_write_single_byte() {
        let path = tmp_file(b"");
        let mut handle = LocalDataFileHandle::new(&path, false).unwrap();
        handle.write(65).unwrap();
        assert_eq!(handle.length().unwrap(), 1);
        handle.seek(0).unwrap();
        let mut buf = [0u8; 1];
        handle.read(&mut buf).unwrap();
        assert_eq!(buf[0], b'A');
    }

    #[test]
    fn test_skip_bytes_partial() {
        let path = tmp_file(b"abcdef");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        let skipped = handle.skip_bytes(4).unwrap();
        assert_eq!(skipped, 4);
        let mut buf = [0u8; 2];
        handle.read(&mut buf).unwrap();
        assert_eq!(&buf, b"ef");
    }

    #[test]
    fn test_skip_bytes_past_eof() {
        let path = tmp_file(b"abc");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        let skipped = handle.skip_bytes(100).unwrap();
        assert_eq!(skipped, 3);
    }

    #[test]
    fn test_skip_bytes_non_positive() {
        let path = tmp_file(b"abc");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        assert_eq!(handle.skip_bytes(0).unwrap(), 0);
        assert_eq!(handle.skip_bytes(-5).unwrap(), 0);
    }

    #[test]
    fn test_seek_negative_fails() {
        let path = tmp_file(b"abc");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        assert!(handle.seek(-1).is_err());
    }

    #[test]
    fn test_set_length_truncate() {
        let path = tmp_file(b"hello world");
        let mut handle = LocalDataFileHandle::new(&path, false).unwrap();
        assert_eq!(handle.length().unwrap(), 11);
        handle.set_length(5).unwrap();
        assert_eq!(handle.length().unwrap(), 5);
    }

    #[test]
    fn test_set_length_adjusts_position() {
        let path = tmp_file(b"hello world");
        let mut handle = LocalDataFileHandle::new(&path, false).unwrap();
        handle.seek(10).unwrap();
        handle.set_length(5).unwrap();
        // position was clamped to new length; writing here should append at offset 5
        handle.write(b'!' as i32).unwrap();
        assert_eq!(handle.length().unwrap(), 6);
    }

    #[test]
    fn test_close_is_ok() {
        let path = tmp_file(b"abc");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        assert!(handle.close().is_ok());
    }

    #[test]
    fn test_read_exact_failure() {
        let path = tmp_file(b"abc");
        let mut handle = LocalDataFileHandle::new(&path, true).unwrap();
        let mut buf = vec![0u8; 10];
        let result = handle.read(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
