//! Port of `ghidra.pty.macos.MacosPtyFactory` (rule R1-java-enum -> enum; single-constant,
//! matching [`super::MacosIoctls`]'s own port).

use std::io;
use std::sync::Arc;

use crate::pty::unix::UnixPty;
use crate::pty::{Pty, PtyFactory};

use super::MacosIoctls;

/// Opens local ptys on macOS via [`UnixPty`], selecting [`MacosIoctls`] as the platform ioctl
/// numbers.
pub enum MacosPtyFactory {
    /// The one instance, mirroring Java's `INSTANCE` enum constant.
    Instance,
}

impl PtyFactory for MacosPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let pty = UnixPty::openpty(Arc::new(MacosIoctls::Instance))?;
        if cols != 0 && rows != 0 {
            pty.get_child().set_window_size(cols, rows);
        }
        Ok(Box::new(pty))
    }

    fn description(&self) -> String {
        "local (macOS)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_identifies_macos() {
        assert_eq!(MacosPtyFactory::Instance.description(), "local (macOS)");
    }

    #[test]
    fn openpty_creates_a_working_pty() {
        let mut pty = MacosPtyFactory::Instance.openpty(80, 24).unwrap();
        assert!(pty.get_parent().get_output_stream().is_ok());
        pty.close().unwrap();
    }

    #[test]
    fn openpty_with_zero_dimensions_skips_the_resize() {
        let mut pty = MacosPtyFactory::Instance.openpty(0, 0).unwrap();
        pty.close().unwrap();
    }
}
