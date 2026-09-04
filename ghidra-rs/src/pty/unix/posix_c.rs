//! Port of `ghidra.pty.unix.PosixC`.
//!
//! # Shape
//!
//! An interface with 11 abstract methods (rule R9-open-interface -> trait). Java keeps two
//! implementations: `BARE` (raw, unchecked, loaded once via JNA) and `INSTANCE` (wraps every
//! `BARE` call in `Err.checkLt0`). Nothing outside this file ever calls `BARE` directly -- every
//! real caller in this codebase (`UnixPtySessionLeader`, `FdInputStream`/`FdOutputStream`,
//! `UnixPtyChild`, `UnixPty`) uses `PosixC.INSTANCE` -- so this port collapses the two into one
//! [`PosixCImpl`] that calls the raw `libc` function and checks its result inline. There is
//! nothing left over to port as a separate "bare" type.
//!
//! Java's nested `Winsize`/`Termios` JNA `Structure` types have the identical field layout to
//! `libc::winsize`/`libc::termios`, so they are not re-declared here -- see the type aliases
//! below. `ControllingTty` (a one-`int` struct used only to carry `TIOCSCTTY`'s "steal" flag)
//! is not carried over as a type at all; [`PosixC::ioctl_ctty`] takes that `i32` directly.
//! Java's generic `ioctl(fd, cmd, Pointer...)` is split into [`PosixC::ioctl_winsize`] and
//! [`PosixC::ioctl_ctty`], the two (and only two) argument shapes any caller in this tree
//! actually passes -- typed methods instead of a raw-pointer varargs sink.

use std::ffi::CString;
use std::io;

use super::err::check_lt0;

/// Port of nested `PosixC.Winsize` -- identical layout to `libc::winsize`.
pub type Winsize = libc::winsize;

/// Port of nested `PosixC.Ioctls` -- platform-specific ioctl command numbers, plus the leader
/// class for each POSIX platform. Implemented once per platform (`LinuxIoctls`, `MacosIoctls`),
/// matching Java's per-platform `enum... implements Ioctls`.
pub trait Ioctls: Send + Sync {
    /// `TIOCSCTTY` -- "set controlling tty" ioctl command number for this platform.
    fn tiocsctty(&self) -> libc::c_ulong;
    /// `TIOCSWINSZ` -- "set window size" ioctl command number for this platform.
    fn tiocswinsz(&self) -> libc::c_ulong;
}

/// Interface for POSIX functions in libc (port of `PosixC`).
///
/// The functions are not documented here. Instead see the POSIX manual pages.
pub trait PosixC: Send + Sync {
    /// `strerror(3)`.
    fn strerror(&self, errnum: i32) -> String;
    /// `close(2)`.
    fn close(&self, fd: i32) -> io::Result<i32>;
    /// `read(2)`.
    fn read(&self, fd: i32, buf: &mut [u8]) -> io::Result<i32>;
    /// `write(2)`.
    fn write(&self, fd: i32, buf: &[u8]) -> io::Result<i32>;
    /// `setsid(2)`.
    fn setsid(&self) -> io::Result<i32>;
    /// `open(2)`.
    fn open(&self, path: &str, mode: i32, flags: i32) -> io::Result<i32>;
    /// `dup2(2)`.
    fn dup2(&self, oldfd: i32, newfd: i32) -> io::Result<i32>;
    /// `execv(3)`. On success this does not return to the caller; the process image is
    /// replaced. It only returns (with an error) on failure.
    fn execv(&self, path: &str, argv: &[String]) -> io::Result<i32>;
    /// `ioctl(2)` with a [`Winsize`] argument, e.g. `TIOCSWINSZ`.
    fn ioctl_winsize(&self, fd: i32, cmd: libc::c_ulong, ws: &Winsize) -> io::Result<i32>;
    /// `ioctl(2)` with a single `int` argument, e.g. `TIOCSCTTY`'s "steal" flag.
    fn ioctl_ctty(&self, fd: i32, cmd: libc::c_ulong, steal: i32) -> io::Result<i32>;
    /// `tcgetattr(3)`.
    fn tcgetattr(&self, fd: i32) -> io::Result<libc::termios>;
    /// `tcsetattr(3)`.
    fn tcsetattr(
        &self,
        fd: i32,
        optional_actions: i32,
        termios: &libc::termios,
    ) -> io::Result<i32>;
}

/// The one production implementor of [`PosixC`] (port of `PosixC.INSTANCE`).
pub struct PosixCImpl;

impl PosixC for PosixCImpl {
    fn strerror(&self, errnum: i32) -> String {
        // SAFETY: strerror(3) returns a pointer to a static, NUL-terminated string owned by
        // libc; we copy it out immediately and never retain the pointer.
        unsafe {
            let ptr = libc::strerror(errnum);
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    fn close(&self, fd: i32) -> io::Result<i32> {
        // SAFETY: close(2) accepts any int; an invalid fd is reported via errno, not UB.
        check_lt0(unsafe { libc::close(fd) })
    }

    fn read(&self, fd: i32, buf: &mut [u8]) -> io::Result<i32> {
        // SAFETY: buf is a valid, appropriately-sized slice for the duration of the call.
        let ret = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        check_lt0(ret as i32)
    }

    fn write(&self, fd: i32, buf: &[u8]) -> io::Result<i32> {
        // SAFETY: buf is a valid, appropriately-sized slice for the duration of the call.
        let ret = unsafe {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
        };
        check_lt0(ret as i32)
    }

    fn setsid(&self) -> io::Result<i32> {
        // SAFETY: setsid(2) takes no arguments.
        check_lt0(unsafe { libc::setsid() })
    }

    fn open(&self, path: &str, mode: i32, flags: i32) -> io::Result<i32> {
        let c_path = CString::new(path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: c_path is a valid NUL-terminated string for the duration of the call.
        check_lt0(unsafe { libc::open(c_path.as_ptr(), mode, flags as libc::mode_t) })
    }

    fn dup2(&self, oldfd: i32, newfd: i32) -> io::Result<i32> {
        // SAFETY: dup2(2) accepts any two ints; invalid fds are reported via errno.
        check_lt0(unsafe { libc::dup2(oldfd, newfd) })
    }

    fn execv(&self, path: &str, argv: &[String]) -> io::Result<i32> {
        let c_path = CString::new(path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let c_argv: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<Result<_, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut argv_ptrs: Vec<*const libc::c_char> =
            c_argv.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        // SAFETY: c_path and every element of c_argv outlive this call, and argv_ptrs is
        // NUL-terminated as execv(3) requires.
        check_lt0(unsafe { libc::execv(c_path.as_ptr(), argv_ptrs.as_ptr()) })
    }

    fn ioctl_winsize(&self, fd: i32, cmd: libc::c_ulong, ws: &Winsize) -> io::Result<i32> {
        // SAFETY: ws is a valid, appropriately-typed struct for the ioctl commands this is used
        // with (TIOCSWINSZ / TIOCGWINSZ).
        check_lt0(unsafe { libc::ioctl(fd, cmd as _, ws as *const Winsize) })
    }

    fn ioctl_ctty(&self, fd: i32, cmd: libc::c_ulong, steal: i32) -> io::Result<i32> {
        // SAFETY: TIOCSCTTY's argument is a single int (the "steal" flag) on the platforms this
        // is used on.
        check_lt0(unsafe { libc::ioctl(fd, cmd as _, &steal as *const i32) })
    }

    fn tcgetattr(&self, fd: i32) -> io::Result<libc::termios> {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: termios is a valid, zero-initialized out-param for tcgetattr(3).
        check_lt0(unsafe { libc::tcgetattr(fd, &mut termios) })?;
        Ok(termios)
    }

    fn tcsetattr(
        &self,
        fd: i32,
        optional_actions: i32,
        termios: &libc::termios,
    ) -> io::Result<i32> {
        // SAFETY: termios is a valid, initialized struct for the duration of the call.
        check_lt0(unsafe { libc::tcsetattr(fd, optional_actions, termios) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_returns_a_nonempty_message() {
        let posix = PosixCImpl;
        // errno 2 is ENOENT on every POSIX platform this crate targets.
        assert!(!posix.strerror(2).is_empty());
    }

    #[test]
    fn close_of_an_invalid_fd_is_an_error() {
        let posix = PosixCImpl;
        assert!(posix.close(-1).is_err());
    }

    #[test]
    fn open_of_a_nonexistent_path_is_an_error() {
        let posix = PosixCImpl;
        let result = posix.open("/nonexistent/path/for/pty/tests", 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn open_read_write_close_round_trips_through_a_real_file() {
        let posix = PosixCImpl;
        let path = std::env::temp_dir().join("ghidra_rs_posix_c_test");
        let path_str = path.to_str().unwrap();

        // O_WRONLY | O_CREAT | O_TRUNC, mode 0o644
        let fd = posix.open(path_str, 0o1101, 0o644).unwrap();
        posix.write(fd, b"hello").unwrap();
        posix.close(fd).unwrap();

        // O_RDONLY
        let fd = posix.open(path_str, 0, 0).unwrap();
        let mut buf = [0u8; 5];
        let n = posix.read(fd, &mut buf).unwrap();
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn dup2_of_an_invalid_fd_is_an_error() {
        let posix = PosixCImpl;
        assert!(posix.dup2(-1, -1).is_err());
    }

    #[test]
    fn tcgetattr_on_a_non_tty_is_an_error() {
        let posix = PosixCImpl;
        // stdin during `cargo test` is not a controlling tty.
        let path = std::env::temp_dir().join("ghidra_rs_posix_c_tcgetattr_test");
        let fd = posix.open(path.to_str().unwrap(), 0o1101, 0o644).unwrap();
        let result = posix.tcgetattr(fd);
        posix.close(fd).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
    }

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
    fn ioctls_trait_reports_its_command_numbers() {
        let ioctls = FakeIoctls;
        assert_eq!(ioctls.tiocsctty(), 0x540e);
        assert_eq!(ioctls.tiocswinsz(), 0x5414);
    }
}
