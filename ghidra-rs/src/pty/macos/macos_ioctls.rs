//! Port of `ghidra.pty.macos.MacosIoctls` (rule R1-java-enum -> enum; single-constant, mirrors
//! Java's `enum MacosIoctls implements Ioctls { INSTANCE; ... }`).
//!
//! See [`crate::pty::linux::LinuxIoctls`] for why Java's `leaderClass()` has no port here.

use crate::pty::unix::Ioctls;

/// macOS ioctl command numbers for the pty subsystem.
pub enum MacosIoctls {
    /// The one instance, mirroring Java's `INSTANCE` enum constant.
    Instance,
}

impl Ioctls for MacosIoctls {
    fn tiocsctty(&self) -> libc::c_ulong {
        0x20007461
    }

    fn tiocswinsz(&self) -> libc::c_ulong {
        0x80087467
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_the_macos_ioctl_command_numbers() {
        let ioctls = MacosIoctls::Instance;
        assert_eq!(ioctls.tiocsctty(), 0x20007461);
        assert_eq!(ioctls.tiocswinsz(), 0x80087467);
    }
}
