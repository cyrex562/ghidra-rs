//! Port of `ghidra.pty.linux.LinuxIoctls` (rule R1-java-enum -> enum; single-constant, mirrors
//! Java's `enum LinuxIoctls implements Ioctls { INSTANCE; ... }`).
//!
//! Java's `leaderClass()` (returning `LinuxPtySessionLeader.class`, used to relaunch a fresh JVM
//! running that class as a "session leader" subprocess) has no port: Rust's
//! `std::os::unix::process::CommandExt::pre_exec` runs arbitrary setup code in the forked child
//! before `execve`, so `UnixPtyChild` calls the session-leader logic directly there instead of
//! relaunching a separate process to run it. See `pty::unix::session_leader`.

use crate::pty::unix::Ioctls;

/// Linux ioctl command numbers for the pty subsystem.
pub enum LinuxIoctls {
    /// The one instance, mirroring Java's `INSTANCE` enum constant.
    Instance,
}

impl Ioctls for LinuxIoctls {
    fn tiocsctty(&self) -> libc::c_ulong {
        0x540e
    }

    fn tiocswinsz(&self) -> libc::c_ulong {
        0x5414
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_the_linux_ioctl_command_numbers() {
        let ioctls = LinuxIoctls::Instance;
        assert_eq!(ioctls.tiocsctty(), 0x540e);
        assert_eq!(ioctls.tiocswinsz(), 0x5414);
    }
}
