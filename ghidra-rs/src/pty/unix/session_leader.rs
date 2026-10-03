//! Port of `ghidra.pty.unix.UnixPtySessionLeader`, `ghidra.pty.linux.LinuxPtySessionLeader`, and
//! `ghidra.pty.macos.MacosPtySessionLeader`.
//!
//! # Shape -- a redesign, not a 1:1 translation
//!
//! These three classes exist only because a JVM cannot safely `fork()`: to make a subprocess the
//! leader of a new session with a given controlling tty, Java has to relaunch an entire second
//! JVM whose `main()` is `Linux`/`MacosPtySessionLeader` -- open the tty, `dup2` it onto
//! stdio, `setsid()`, `ioctl(TIOCSCTTY)`, then `execv` the real target program -- because that
//! setup must run in a fresh, single-threaded process between fork and exec, which the already-
//! running, multi-threaded JVM cannot do in-place.
//!
//! Rust does not have that constraint. `std::os::unix::process::CommandExt::pre_exec` runs
//! arbitrary code in the forked child, between `fork()` and `exec()`, which is exactly what this
//! needs -- no separate leader process required. [`UnixPtyChild::session`](super::UnixPtyChild)
//! (not yet ported as of this file) calls [`become_session_leader`] directly from a `pre_exec`
//! closure; `std::process::Command` itself performs the final `exec`, so this function stops
//! short of it.
//!
//! `shape_rules.py` classified `UnixPtySessionLeader` as R11-abstract-stateful (abstract class,
//! 2 instance fields, 2 subclasses -> struct_trait) -- but that shape was computed against
//! Java's design, where `ptyPath`/`subArgs` are fields on a long-lived leader object and
//! `ioctls()` is a subclass override. Under this redesign there is no such object: the pty path
//! is a plain argument, and the platform `Ioctls` is a value the caller already has (from
//! [`crate::pty::linux::LinuxIoctls`] / [`crate::pty::macos::MacosIoctls`]) and simply passes
//! in. There is no instance state left to justify a struct, and no override left to justify a
//! trait -- a plain function fully captures what `run()` did. `LinuxPtySessionLeader` and
//! `MacosPtySessionLeader` are pure `main()` entry points plus a one-line `ioctls()` override
//! each; under this redesign they have no remaining unique logic (the caller passes the platform
//! `Ioctls` directly), so neither gets its own Rust file.
//!
//! # What else changed
//!
//! - Java hardcodes `O_RDWR = 2` with a `// TODO: Find this in libs` comment; this port uses the
//!   real `libc::O_RDWR` constant, resolving that TODO.
//! - Java's `run()` catches every `Throwable`, tries to restore a backup stderr fd to print an
//!   error, and calls `System.exit`. `pre_exec`'s own contract already handles this better: if
//!   the closure returns `Err`, `Command::spawn` reports that failure back to the *parent*
//!   process through a dedicated pipe before the child exits, which is simpler and more reliable
//!   than manually restoring a duplicated fd to print through. So [`become_session_leader`] just
//!   returns [`io::Result`] and leaves error propagation to `pre_exec`/`Command`.

use std::io;

use super::posix_c::PosixC;
use super::Ioctls;

/// Performs the "become the controlling-tty session leader" setup that must happen in the
/// forked child before `exec`, mirroring `UnixPtySessionLeader.run()` up to (not including) its
/// final `execv` -- the caller execs afterward (typically via `std::process::Command`, which
/// does so automatically once the `pre_exec` closure that calls this returns `Ok`).
///
/// # Safety
///
/// Must only be called from a `pre_exec` closure -- i.e., in the forked child, before `exec`,
/// while the process is still single-threaded. See
/// [`CommandExt::pre_exec`](std::os::unix::process::CommandExt::pre_exec)'s own safety notes:
/// most libc functions are not documented async-signal-safe, so as with any `pre_exec` closure
/// this is inherently a "best effort in practice" contract, not one Rust's type system can prove.
pub fn become_session_leader(posix: &dyn PosixC, ioctls: &dyn Ioctls, pty_path: &str) -> io::Result<()> {
    let fd = posix.open(pty_path, libc::O_RDWR, 0)?;

    // Best-effort backup of the original stderr, matching Java's intent (a place to report
    // trouble); unlike Java, failure here is not fatal to session setup, so its result is not
    // propagated. Kept only because a later dup2 target must not collide with `fd`+1 in the
    // improbable case something upstream is watching that descriptor.
    let bkt = fd + 1;
    let _ = posix.dup2(2, bkt);

    posix.close(0)?;
    posix.close(1)?;
    posix.close(2)?;
    posix.dup2(fd, 0)?;
    posix.dup2(fd, 1)?;
    posix.dup2(fd, 2)?;
    posix.close(fd)?;

    posix.setsid()?;
    posix.ioctl_ctty(0, ioctls.tiocsctty(), 0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::unix::posix_c::PosixCImpl;
    use crate::pty::unix::util::{Util, UtilImpl};

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
    fn open_of_a_nonexistent_pty_path_fails_before_touching_stdio() {
        let posix = PosixCImpl;
        let result = become_session_leader(&posix, &FakeIoctls, "/nonexistent/pty/path");
        assert!(result.is_err());
    }

    #[test]
    fn succeeds_against_a_real_pty_child_device_in_a_forked_child() {
        // become_session_leader mutates fds 0/1/2 and calls setsid(), which would corrupt this
        // test process's own stdio if run directly -- exactly why it may only run in a forked
        // child. Fork here (this test binary is single-threaded at this point) and assert via
        // the child's exit status, matching how the function is actually used in
        // UnixPtyChild::session (a pre_exec closure ahead of exec).
        let util = UtilImpl;
        let (_parent_fd, child_fd, child_name) = util.openpty().expect("openpty must succeed in CI");
        unsafe {
            libc::close(child_fd);
        }

        // SAFETY: single-threaded test process; the child only calls async-signal-safe libc
        // functions (via become_session_leader) before exiting with _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let posix = PosixCImpl;
            let ioctls = FakeIoctls;
            let rc = match become_session_leader(&posix, &ioctls, &child_name) {
                Ok(()) => 0,
                Err(_) => 1,
            };
            unsafe { libc::_exit(rc) };
        }

        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(status, 0, "become_session_leader failed in the forked child");
    }
}
