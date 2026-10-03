//! Port of `ghidra.pty.unix.FdOutputStream` (rule R14a-concrete-leaf -> struct).

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::posix_c::PosixC;

/// An output stream that wraps a native POSIX file descriptor (port of `FdOutputStream`).
///
/// See [`super::fd_input_stream::FdInputStream`] for why this is cheaply [`Clone`], why the
/// checked/unchecked `LastErrorException` distinction has nothing to carry over, and why
/// [`Self::close`] never closes the underlying fd.
///
/// Java's `write` loops `LIB_POSIX.write` until every byte is written (a single `write(2)` call
/// is not guaranteed to consume the whole buffer); this port does the same.
#[derive(Clone)]
pub struct FdOutputStream {
    fd: i32,
    closed: Arc<AtomicBool>,
    posix: Arc<dyn PosixC>,
}

impl FdOutputStream {
    /// Wraps the given file descriptor in an output stream.
    pub fn new(fd: i32, posix: Arc<dyn PosixC>) -> Self {
        FdOutputStream {
            fd,
            closed: Arc::new(AtomicBool::new(false)),
            posix,
        }
    }

    /// Marks the stream closed. Further writes return an error. Does not close the fd itself --
    /// the owning `Pty` is responsible for that.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl Write for FdOutputStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Other, "Stream closed"));
        }
        let mut total = 0usize;
        while total < buf.len() {
            let n = self.posix.write(self.fd, &buf[total..])?;
            total += n as usize;
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::unix::posix_c::PosixCImpl;

    fn open_temp_file_for_write(name: &str) -> (i32, Arc<dyn PosixC>, std::path::PathBuf) {
        let posix: Arc<dyn PosixC> = Arc::new(PosixCImpl);
        let path = std::env::temp_dir().join(name);
        let fd = posix.open(path.to_str().unwrap(), 0o1101, 0o644).unwrap(); // O_WRONLY|O_CREAT|O_TRUNC
        (fd, posix, path)
    }

    #[test]
    fn writes_bytes_to_the_underlying_fd() {
        let (fd, posix, path) = open_temp_file_for_write("ghidra_rs_fd_output_stream_test_a");
        {
            let mut stream = FdOutputStream::new(fd, posix.clone());
            let n = stream.write(b"hello").unwrap();
            assert_eq!(n, 5);
        }
        posix.close(fd).unwrap();
        let contents = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(contents, b"hello");
    }

    #[test]
    fn write_after_close_is_an_error() {
        let (fd, posix, path) = open_temp_file_for_write("ghidra_rs_fd_output_stream_test_b");
        let mut stream = FdOutputStream::new(fd, posix.clone());
        stream.close();
        assert!(stream.write(b"hello").is_err());
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn clones_share_the_closed_flag() {
        let (fd, posix, path) = open_temp_file_for_write("ghidra_rs_fd_output_stream_test_c");
        let stream = FdOutputStream::new(fd, posix.clone());
        let mut clone = stream.clone();
        stream.close();
        assert!(clone.write(b"hello").is_err());
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
