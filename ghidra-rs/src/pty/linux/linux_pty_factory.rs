//! Port of `ghidra.pty.linux.LinuxPtyFactory` (rule R1-java-enum -> enum; single-constant,
//! matching [`super::LinuxIoctls`]'s own port).

use std::io;
use std::sync::Arc;

use crate::pty::unix::UnixPty;
use crate::pty::{Pty, PtyFactory};

use super::LinuxIoctls;

/// Opens local ptys on Linux via [`UnixPty`], selecting [`LinuxIoctls`] as the platform ioctl
/// numbers.
pub enum LinuxPtyFactory {
    /// The one instance, mirroring Java's `INSTANCE` enum constant.
    Instance,
}

impl PtyFactory for LinuxPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let pty = UnixPty::openpty(Arc::new(LinuxIoctls::Instance))?;
        if cols != 0 && rows != 0 {
            pty.get_child().set_window_size(cols, rows);
        }
        Ok(Box::new(pty))
    }

    fn description(&self) -> String {
        "local (Linux)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_identifies_linux() {
        assert_eq!(LinuxPtyFactory::Instance.description(), "local (Linux)");
    }

    #[test]
    fn openpty_creates_a_working_pty() {
        let mut pty = LinuxPtyFactory::Instance.openpty(80, 24).unwrap();
        assert!(pty.get_parent().get_output_stream().is_ok());
        pty.close().unwrap();
    }

    #[test]
    fn openpty_with_zero_dimensions_skips_the_resize() {
        // Mirrors Java: cols/rows of 0 means "let the system decide", so no resize ioctl is
        // attempted -- this must not error even though nothing observable distinguishes it from
        // the non-zero case (set_window_size logs rather than returning a Result).
        let mut pty = LinuxPtyFactory::Instance.openpty(0, 0).unwrap();
        pty.close().unwrap();
    }
}
