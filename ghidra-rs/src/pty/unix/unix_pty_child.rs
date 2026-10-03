//! Port of `ghidra.pty.unix.UnixPtyChild`.
//!
//! # Shape
//!
//! `shape_rules.py` classifies this R14a-concrete-leaf -> struct (nothing extends it). Wraps a
//! [`UnixPtyEndpoint`] by composition, matching the established `UnixPtyParent`/`ConPtyParent`
//! pattern.
//!
//! # `session()` -- no leader process
//!
//! Java's `sessionUsingJavaLeader` builds a `java -cp <classpath> <LeaderClass> <args...>`
//! command and lets the relaunched JVM's leader `main()` set up the session before `execv`-ing
//! the real target. This port has no leader process at all: [`std::process::Command`]'s
//! `pre_exec` runs [`become_session_leader`] directly in the forked child ahead of the real
//! target's own `exec`. See [`super::session_leader`] for the full reasoning.

use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::pty::{Echo, PtyChild, PtyEndpoint, PtySession, TermMode};
use crate::pty::LocalProcessPtySession;

use super::posix_c::PosixC;
use super::session_leader::become_session_leader;
use super::unix_pty_endpoint::UnixPtyEndpoint;
use super::Ioctls;

/// The child (UNIX "slave") end of a pseudo-terminal (port of `UnixPtyChild`).
pub struct UnixPtyChild {
    endpoint: UnixPtyEndpoint,
    posix: Arc<dyn PosixC>,
    name: String,
}

impl UnixPtyChild {
    /// Wraps the given file descriptor as the child end of a pty, with `name` as the device
    /// path handed back by [`PtyChild::null_session`].
    pub fn new(ioctls: Arc<dyn Ioctls>, fd: i32, name: String, posix: Arc<dyn PosixC>) -> Self {
        UnixPtyChild {
            endpoint: UnixPtyEndpoint::new(ioctls, fd, posix.clone()),
            posix,
            name,
        }
    }

    /// The raw file descriptor for this end.
    pub fn fd(&self) -> i32 {
        self.endpoint.fd()
    }

    /// Closes this endpoint's streams; see [`UnixPtyEndpoint::close_streams`].
    pub fn close_streams(&self) {
        self.endpoint.close_streams();
    }

    fn apply_mode(&self, mode: &[Box<dyn TermMode>]) {
        let echo_off = mode
            .iter()
            .any(|m| m.as_any().downcast_ref::<Echo>() == Some(&Echo::Off));
        if echo_off {
            let _ = self.disable_echo();
        }
    }

    fn disable_echo(&self) -> io::Result<()> {
        let mut termios = self.posix.tcgetattr(self.endpoint.fd())?;
        termios.c_lflag &= !(libc::ECHO as libc::tcflag_t);
        self.posix.tcsetattr(self.endpoint.fd(), libc::TCSANOW, &termios)?;
        Ok(())
    }
}

impl PtyEndpoint for UnixPtyChild {
    fn get_output_stream(&self) -> io::Result<Box<dyn std::io::Write>> {
        self.endpoint.get_output_stream()
    }

    fn get_input_stream(&self) -> io::Result<Box<dyn std::io::Read>> {
        self.endpoint.get_input_stream()
    }
}

impl PtyChild for UnixPtyChild {
    fn session(
        &self,
        args: &[String],
        env: &HashMap<String, String>,
        working_directory: Option<&Path>,
        mode: &[Box<dyn TermMode>],
    ) -> io::Result<Box<dyn PtySession>> {
        if args.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session requires at least a program path",
            ));
        }

        self.apply_mode(mode);

        let mut command = Command::new(&args[0]);
        command.args(&args[1..]);
        command.envs(env);
        if let Some(dir) = working_directory {
            command.current_dir(dir);
        }

        let posix = self.posix.clone();
        let ioctls = self.endpoint.ioctls().clone();
        let pty_path = self.name.clone();
        // SAFETY: become_session_leader only calls async-signal-safe-in-practice libc
        // functions (open/dup2/close/setsid/ioctl), matching pre_exec's own safety contract.
        unsafe {
            command.pre_exec(move || become_session_leader(&*posix, &*ioctls, &pty_path));
        }

        let child = command.spawn()?;
        Ok(Box::new(LocalProcessPtySession::new(child, self.name.clone())))
    }

    fn null_session(&self, mode: &[Box<dyn TermMode>]) -> io::Result<String> {
        self.apply_mode(mode);
        Ok(self.name.clone())
    }

    fn set_window_size(&self, cols: u16, rows: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if let Err(e) = self
            .posix
            .ioctl_winsize(self.endpoint.fd(), self.endpoint.ioctls().tiocswinsz(), &ws)
        {
            tracing::error!("Could not set terminal window size: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::unix::posix_c::PosixCImpl;
    use crate::pty::unix::util::{Util, UtilImpl};
    use crate::pty::PtySession;
    use std::io::Read;
    use std::os::fd::FromRawFd;

    struct FakeIoctls;
    impl Ioctls for FakeIoctls {
        fn tiocsctty(&self) -> libc::c_ulong {
            0x540e
        }
        fn tiocswinsz(&self) -> libc::c_ulong {
            0x5414
        }
    }

    /// Opens a real pty pair and wraps the child fd, using the pty's real device path as the
    /// child's `name` -- `become_session_leader` opens that path by name, so a fake path (as an
    /// earlier version of this test used) fails session spawning with a confusing error.
    fn open_child() -> (UnixPtyChild, i32) {
        let posix: Arc<dyn PosixC> = Arc::new(PosixCImpl);
        let util = UtilImpl;
        let (parent_fd, child_fd, name) = util.openpty().unwrap();
        let child = UnixPtyChild::new(Arc::new(FakeIoctls), child_fd, name, posix);
        (child, parent_fd)
    }

    #[test]
    fn null_session_returns_the_configured_name() {
        let (child, parent_fd) = open_child();
        let mode: Vec<Box<dyn TermMode>> = vec![];
        let name = child.null_session(&mode).unwrap();
        assert!(name.starts_with("/dev/"));
        unsafe {
            libc::close(parent_fd);
        }
    }

    #[test]
    fn null_session_with_echo_off_does_not_error() {
        let (child, parent_fd) = open_child();
        let mode: Vec<Box<dyn TermMode>> = vec![Box::new(Echo::Off)];
        assert!(child.null_session(&mode).is_ok());
        unsafe {
            libc::close(parent_fd);
        }
    }

    #[test]
    fn set_window_size_does_not_panic() {
        let (child, parent_fd) = open_child();
        child.set_window_size(80, 24);
        unsafe {
            libc::close(parent_fd);
        }
    }

    #[test]
    fn session_spawns_the_requested_program_as_the_pty_session_leader() {
        let (child, parent_fd) = open_child();
        let args = vec!["/bin/echo".to_string(), "hello".to_string()];
        let env = HashMap::new();
        let mode: Vec<Box<dyn TermMode>> = vec![];

        let session = child.session(&args, &env, None, &mode).unwrap();
        let exit_code = session.wait_exited().unwrap();
        assert_eq!(exit_code, 0);

        // The child's output went to the pty (its stdio was redirected there by
        // become_session_leader), so it should be readable from the parent end.
        let mut parent_out = std::fs::File::from(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(parent_fd)
        });
        let mut buf = [0u8; 64];
        let n = parent_out.read(&mut buf).unwrap_or(0);
        assert!(n > 0, "expected some output from the pty");
        assert!(String::from_utf8_lossy(&buf[..n]).contains("hello"));
    }

    #[test]
    fn session_with_no_program_is_an_error() {
        let (child, parent_fd) = open_child();
        let args: Vec<String> = vec![];
        let env = HashMap::new();
        let mode: Vec<Box<dyn TermMode>> = vec![];
        assert!(child.session(&args, &env, None, &mode).is_err());
        unsafe {
            libc::close(parent_fd);
        }
    }
}
