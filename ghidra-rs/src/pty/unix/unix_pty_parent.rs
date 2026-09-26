//! Port of `ghidra.pty.unix.UnixPtyParent` (rule R14a-concrete-leaf -> struct).
//!
//! Wraps a [`UnixPtyEndpoint`] by composition and implements the [`PtyParent`] marker trait,
//! mirroring `class UnixPtyParent extends UnixPtyEndpoint implements PtyParent` -- the same
//! pattern already established by [`crate::pty::windows::ConPtyParent`].

use std::io::{Read, Write};
use std::sync::Arc;

use crate::pty::{PtyEndpoint, PtyParent};

use super::posix_c::PosixC;
use super::unix_pty_endpoint::UnixPtyEndpoint;
use super::Ioctls;

/// The parent (UNIX "master") end of a pseudo-terminal (port of `UnixPtyParent`).
pub struct UnixPtyParent(UnixPtyEndpoint);

impl UnixPtyParent {
    /// Wraps the given file descriptor as the parent end of a pty.
    pub fn new(ioctls: Arc<dyn Ioctls>, fd: i32, posix: Arc<dyn PosixC>) -> Self {
        UnixPtyParent(UnixPtyEndpoint::new(ioctls, fd, posix))
    }

    /// The raw file descriptor for this end.
    pub fn fd(&self) -> i32 {
        self.0.fd()
    }

    /// Closes this endpoint's streams; see [`UnixPtyEndpoint::close_streams`].
    pub fn close_streams(&self) {
        self.0.close_streams();
    }
}

impl PtyEndpoint for UnixPtyParent {
    fn get_output_stream(&self) -> std::io::Result<Box<dyn Write>> {
        self.0.get_output_stream()
    }

    fn get_input_stream(&self) -> std::io::Result<Box<dyn Read>> {
        self.0.get_input_stream()
    }
}

impl PtyParent for UnixPtyParent {}

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
    fn implements_endpoint_via_delegation() {
        let (fd, posix, path) = open_temp_fd("ghidra_rs_unix_pty_parent_test_a");
        let parent = UnixPtyParent::new(Arc::new(FakeIoctls), fd, posix.clone());
        {
            let mut out = parent.get_output_stream().unwrap();
            out.write_all(b"hi").unwrap();
        }
        posix.close(fd).unwrap();
        let contents = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(contents, b"hi");
    }

    #[test]
    fn is_a_pty_parent() {
        fn accepts_parent<T: PtyParent>() {}
        accepts_parent::<UnixPtyParent>();
    }

    #[test]
    fn fd_matches_the_wrapped_endpoint() {
        let (fd, posix, path) = open_temp_fd("ghidra_rs_unix_pty_parent_test_b");
        let parent = UnixPtyParent::new(Arc::new(FakeIoctls), fd, posix.clone());
        assert_eq!(parent.fd(), fd);
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
