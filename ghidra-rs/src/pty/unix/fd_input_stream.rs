//! Port of `ghidra.pty.unix.FdInputStream` (rule R14a-concrete-leaf -> struct).

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::posix_c::PosixC;

/// An input stream that wraps a native POSIX file descriptor (port of `FdInputStream`).
///
/// Cheap to [`Clone`] -- every clone shares the same `closed` flag and reads the same fd, which
/// is how [`super::super::PtyEndpoint::get_input_stream`] hands out a fresh `Box<dyn Read>` per
/// call while still behaving like Java's single cached `inputStream` field: closing one handle
/// closes them all.
///
/// Java's `read` catches `LastErrorException` and rethrows EIO/EBADF as a checked `IOException`,
/// anything else as-is. There is no checked/unchecked distinction in Rust -- every POSIX error
/// already surfaces as an [`io::Error`] via [`PosixC::read`] -- so that branch has nothing left
/// to do and is not carried over.
///
/// The `Pty` (not this stream) owns the underlying fd, so [`Self::close`] only stops further
/// reads; it never closes the fd itself.
#[derive(Clone)]
pub struct FdInputStream {
    fd: i32,
    closed: Arc<AtomicBool>,
    posix: Arc<dyn PosixC>,
}

impl FdInputStream {
    /// Wraps the given file descriptor in an input stream.
    pub fn new(fd: i32, posix: Arc<dyn PosixC>) -> Self {
        FdInputStream {
            fd,
            closed: Arc::new(AtomicBool::new(false)),
            posix,
        }
    }

    /// Marks the stream closed. Further reads return an error. Does not close the fd itself --
    /// the owning `Pty` is responsible for that.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl Read for FdInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Other, "Stream closed"));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.posix.read(self.fd, buf)?;
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::unix::posix_c::PosixCImpl;

    fn open_temp_file_with(contents: &[u8], name: &str) -> (i32, Arc<dyn PosixC>, std::path::PathBuf) {
        let posix: Arc<dyn PosixC> = Arc::new(PosixCImpl);
        let path = std::env::temp_dir().join(name);
        let fd = posix.open(path.to_str().unwrap(), 0o1101, 0o644).unwrap(); // O_WRONLY|O_CREAT|O_TRUNC
        posix.write(fd, contents).unwrap();
        posix.close(fd).unwrap();
        let fd = posix.open(path.to_str().unwrap(), 0, 0).unwrap(); // O_RDONLY
        (fd, posix, path)
    }

    #[test]
    fn reads_bytes_written_to_the_underlying_fd() {
        let (fd, posix, path) =
            open_temp_file_with(b"hello", "ghidra_rs_fd_input_stream_test_a");
        let mut stream = FdInputStream::new(fd, posix.clone());
        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).unwrap();
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn empty_buffer_reads_zero_without_touching_the_fd() {
        let (fd, posix, path) =
            open_temp_file_with(b"hello", "ghidra_rs_fd_input_stream_test_b");
        let mut stream = FdInputStream::new(fd, posix.clone());
        let mut buf: [u8; 0] = [];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_after_close_is_an_error() {
        let (fd, posix, path) =
            open_temp_file_with(b"hello", "ghidra_rs_fd_input_stream_test_c");
        let mut stream = FdInputStream::new(fd, posix.clone());
        stream.close();
        let mut buf = [0u8; 5];
        assert!(stream.read(&mut buf).is_err());
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn clones_share_the_closed_flag() {
        let (fd, posix, path) =
            open_temp_file_with(b"hello", "ghidra_rs_fd_input_stream_test_d");
        let stream = FdInputStream::new(fd, posix.clone());
        let mut clone = stream.clone();
        stream.close();
        let mut buf = [0u8; 5];
        assert!(clone.read(&mut buf).is_err());
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
