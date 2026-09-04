//! Port of `ghidra.pty.unix.UnixPty` (rule R14a-concrete-leaf -> struct).

use std::io;
use std::sync::Arc;

use crate::pty::{Pty, PtyChild, PtyParent};

use super::posix_c::{PosixC, PosixCImpl};
use super::unix_pty_child::UnixPtyChild;
use super::unix_pty_parent::UnixPtyParent;
use super::util::{Util, UtilImpl};
use super::Ioctls;

/// A UNIX pseudo-terminal, owning both ends (port of `UnixPty`).
pub struct UnixPty {
    aparent: i32,
    achild: i32,
    closed: bool,
    parent: UnixPtyParent,
    child: UnixPtyChild,
    posix: Arc<dyn PosixC>,
}

impl UnixPty {
    /// Opens a new pseudo-terminal pair, mirroring the static `UnixPty.openpty(Ioctls)` factory.
    pub fn openpty(ioctls: Arc<dyn Ioctls>) -> io::Result<Self> {
        let util = UtilImpl;
        let (aparent, achild, name) = util.openpty()?;
        Ok(Self::new(ioctls, aparent, achild, name, Arc::new(PosixCImpl)))
    }

    /// Wraps an already-open pseudo-terminal pair.
    pub fn new(
        ioctls: Arc<dyn Ioctls>,
        aparent: i32,
        achild: i32,
        name: String,
        posix: Arc<dyn PosixC>,
    ) -> Self {
        UnixPty {
            aparent,
            achild,
            closed: false,
            parent: UnixPtyParent::new(ioctls.clone(), aparent, posix.clone()),
            child: UnixPtyChild::new(ioctls, achild, name, posix.clone()),
            posix,
        }
    }
}

impl Pty for UnixPty {
    fn get_parent(&self) -> &dyn PtyParent {
        &self.parent
    }

    fn get_child(&self) -> &dyn PtyChild {
        &self.child
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.child.close_streams();
        self.parent.close_streams();
        self.posix.close(self.achild)?;
        self.posix.close(self.aparent)?;
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::PtyEndpoint;

    struct FakeIoctls;
    impl Ioctls for FakeIoctls {
        fn tiocsctty(&self) -> libc::c_ulong {
            0x540e
        }
        fn tiocswinsz(&self) -> libc::c_ulong {
            0x5414
        }
    }

    #[test]
    fn openpty_creates_a_working_pty_pair() {
        let mut pty = UnixPty::openpty(Arc::new(FakeIoctls)).unwrap();
        {
            let mut out = pty.get_child().get_output_stream().unwrap();
            use std::io::Write;
            out.write_all(b"hi").unwrap();
        }
        let mut buf = [0u8; 2];
        use std::io::Read;
        pty.get_parent()
            .get_input_stream()
            .unwrap()
            .read_exact(&mut buf)
            .unwrap();
        assert_eq!(&buf, b"hi");
        pty.close().unwrap();
    }

    #[test]
    fn close_is_idempotent() {
        let mut pty = UnixPty::openpty(Arc::new(FakeIoctls)).unwrap();
        pty.close().unwrap();
        assert!(pty.close().is_ok());
    }

    #[test]
    fn close_stops_further_reads_and_writes() {
        let mut pty = UnixPty::openpty(Arc::new(FakeIoctls)).unwrap();
        pty.close().unwrap();
        let mut out = pty.get_child().get_output_stream().unwrap();
        use std::io::Write;
        assert!(out.write_all(b"x").is_err());
    }
}
