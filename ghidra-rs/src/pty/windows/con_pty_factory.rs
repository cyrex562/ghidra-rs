//! Port of `ghidra.pty.windows.ConPtyFactory` (rule R1-java-enum -> enum; single-constant).

use std::io;

use crate::pty::{Pty, PtyFactory};

use super::ConPty;

/// Opens local ptys on Windows via [`ConPty`].
pub enum ConPtyFactory {
    /// The one instance, mirroring Java's `INSTANCE` enum constant.
    Instance,
}

impl PtyFactory for ConPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        if cols == 0 || rows == 0 {
            return Ok(Box::new(ConPty::openpty(80, 25)?));
        }
        Ok(Box::new(ConPty::openpty(cols as i16, rows as i16)?))
    }

    fn description(&self) -> String {
        "local (Windows)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_identifies_windows() {
        assert_eq!(ConPtyFactory::Instance.description(), "local (Windows)");
    }

    #[test]
    fn openpty_creates_a_working_pty() {
        let mut pty = ConPtyFactory::Instance.openpty(80, 24).unwrap();
        assert!(pty.get_parent().get_output_stream().is_ok());
        pty.close().unwrap();
    }

    #[test]
    fn openpty_with_zero_dimensions_uses_the_java_default() {
        let mut pty = ConPtyFactory::Instance.openpty(0, 24).unwrap();
        pty.close().unwrap();
    }
}
