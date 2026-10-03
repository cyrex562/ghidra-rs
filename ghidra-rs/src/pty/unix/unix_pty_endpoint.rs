//! Port of `ghidra.pty.unix.UnixPtyEndpoint`.
//!
//! # Shape
//!
//! `shape_rules.py` flags this R14c-concrete-small-hierarchy (2 in-repo extenders --
//! `UnixPtyParent`, `UnixPtyChild` -- so "both instantiable and a base"), which normally means a
//! struct for shared state plus a trait for overridable behaviour. Neither Java subclass
//! actually overrides any `UnixPtyEndpoint` method, though -- `UnixPtyParent` adds nothing,
//! `UnixPtyChild` only adds its own new [`crate::pty::PtyChild`] methods -- so there is no
//! overridable behaviour for a trait to carry. This is pure code reuse, the same shape as
//! `ghidra.pty.windows.ConPtyEndpoint`/`ConPtyParent`, which the existing port
//! ([`crate::pty::windows::ConPtyParent`]) already resolved with plain composition and no trait.
//! Following that established precedent here instead of introducing an empty trait.

use std::io::{Read, Write};
use std::sync::Arc;

use crate::pty::PtyEndpoint;

use super::fd_input_stream::FdInputStream;
use super::fd_output_stream::FdOutputStream;
use super::posix_c::PosixC;
use super::Ioctls;

/// One end of a UNIX pseudo-terminal (port of `UnixPtyEndpoint`).
pub struct UnixPtyEndpoint {
    ioctls: Arc<dyn Ioctls>,
    fd: i32,
    output_stream: FdOutputStream,
    input_stream: FdInputStream,
}

impl UnixPtyEndpoint {
    /// Wraps the given file descriptor as one end of a pty.
    pub fn new(ioctls: Arc<dyn Ioctls>, fd: i32, posix: Arc<dyn PosixC>) -> Self {
        UnixPtyEndpoint {
            ioctls,
            fd,
            output_stream: FdOutputStream::new(fd, posix.clone()),
            input_stream: FdInputStream::new(fd, posix),
        }
    }

    /// The platform ioctl command numbers for this endpoint's pty.
    pub fn ioctls(&self) -> &Arc<dyn Ioctls> {
        &self.ioctls
    }

    /// The raw file descriptor for this endpoint.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Closes this endpoint's streams. Mirrors `UnixPtyEndpoint.closeStreams()`; does not close
    /// the fd itself -- the owning `Pty` does that.
    pub fn close_streams(&self) {
        self.output_stream.close();
        self.input_stream.close();
    }
}

impl PtyEndpoint for UnixPtyEndpoint {
    fn get_output_stream(&self) -> std::io::Result<Box<dyn Write>> {
        Ok(Box::new(self.output_stream.clone()))
    }

    fn get_input_stream(&self) -> std::io::Result<Box<dyn Read>> {
        Ok(Box::new(self.input_stream.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::unix::posix_c::PosixCImpl;
    use std::io::Write as _;

    struct FakeIoctls;
    impl Ioctls for FakeIoctls {
        fn tiocsctty(&self) -> libc::c_ulong {
            0
        }
        fn tiocswinsz(&self) -> libc::c_ulong {
            0
        }
    }

    fn open_temp_fd(name: &str) -> (i32, Arc<dyn PosixC>, std::path::PathBuf) {
        let posix: Arc<dyn PosixC> = Arc::new(PosixCImpl);
        let path = std::env::temp_dir().join(name);
        let fd = posix.open(path.to_str().unwrap(), 0o1101, 0o644).unwrap();
        (fd, posix, path)
    }

    #[test]
    fn exposes_ioctls_and_fd() {
        let (fd, posix, path) = open_temp_fd("ghidra_rs_unix_pty_endpoint_test_a");
        let endpoint = UnixPtyEndpoint::new(Arc::new(FakeIoctls), fd, posix.clone());
        assert_eq!(endpoint.fd(), fd);
        assert_eq!(endpoint.ioctls().tiocsctty(), 0);
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn output_stream_writes_to_the_fd() {
        let (fd, posix, path) = open_temp_fd("ghidra_rs_unix_pty_endpoint_test_b");
        let endpoint = UnixPtyEndpoint::new(Arc::new(FakeIoctls), fd, posix.clone());
        {
            let mut out = endpoint.get_output_stream().unwrap();
            out.write_all(b"hi").unwrap();
        }
        posix.close(fd).unwrap();
        let contents = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(contents, b"hi");
    }

    #[test]
    fn close_streams_makes_further_writes_fail() {
        let (fd, posix, path) = open_temp_fd("ghidra_rs_unix_pty_endpoint_test_c");
        let endpoint = UnixPtyEndpoint::new(Arc::new(FakeIoctls), fd, posix.clone());
        endpoint.close_streams();
        let mut out = endpoint.get_output_stream().unwrap();
        assert!(out.write_all(b"hi").is_err());
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
