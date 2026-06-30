use std::time::Duration;

/// A session led by the child pty.
///
/// This is typically a handle to the (local or remote) process designated
/// as the "session leader".
pub trait PtySession {
    /// Wait for the session leader to exit, returning its exit status code.
    ///
    /// # Errors
    ///
    /// Returns `Err` with [`std::io::ErrorKind::Interrupted`] if the wait
    /// is interrupted.
    fn wait_exited(&self) -> std::io::Result<i32>;

    /// Wait for the session leader to exit within the given `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `Err` with [`std::io::ErrorKind::Interrupted`] if the wait is
    /// interrupted, or [`std::io::ErrorKind::TimedOut`] if the timeout elapses
    /// before the session leader exits.
    fn wait_exited_timeout(&self, timeout: Duration) -> std::io::Result<i32>;

    /// Take the greatest efforts to terminate the session (leader and descendants).
    ///
    /// If this represents a remote session, this should strive to release the
    /// remote resources consumed by this session. If that is not possible, this
    /// should at the very least release whatever local resources are used in
    /// maintaining and controlling the remote session.
    fn destroy_forcibly(&self);

    /// Returns a human-readable description of the session.
    fn description(&self) -> String;

    /// Returns the process ID of the session leader.
    fn handle(&self) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};

    struct ImmediateSession {
        exit_code: i32,
        pid: u32,
        desc: &'static str,
    }

    impl PtySession for ImmediateSession {
        fn wait_exited(&self) -> io::Result<i32> {
            Ok(self.exit_code)
        }

        fn wait_exited_timeout(&self, _timeout: Duration) -> io::Result<i32> {
            Ok(self.exit_code)
        }

        fn destroy_forcibly(&self) {}

        fn description(&self) -> String {
            self.desc.to_string()
        }

        fn handle(&self) -> u32 {
            self.pid
        }
    }

    struct InterruptedSession;

    impl PtySession for InterruptedSession {
        fn wait_exited(&self) -> io::Result<i32> {
            Err(io::Error::new(ErrorKind::Interrupted, "interrupted"))
        }

        fn wait_exited_timeout(&self, _timeout: Duration) -> io::Result<i32> {
            Err(io::Error::new(ErrorKind::Interrupted, "interrupted"))
        }

        fn destroy_forcibly(&self) {}

        fn description(&self) -> String {
            "interrupted session".to_string()
        }

        fn handle(&self) -> u32 {
            0
        }
    }

    struct TimedOutSession;

    impl PtySession for TimedOutSession {
        fn wait_exited(&self) -> io::Result<i32> {
            Ok(0)
        }

        fn wait_exited_timeout(&self, _timeout: Duration) -> io::Result<i32> {
            Err(io::Error::new(ErrorKind::TimedOut, "timed out"))
        }

        fn destroy_forcibly(&self) {}

        fn description(&self) -> String {
            "slow session".to_string()
        }

        fn handle(&self) -> u32 {
            42
        }
    }

    #[test]
    fn wait_exited_returns_exit_code() {
        let s = ImmediateSession { exit_code: 0, pid: 1, desc: "ok" };
        assert_eq!(s.wait_exited().unwrap(), 0);
    }

    #[test]
    fn wait_exited_nonzero_exit_code() {
        let s = ImmediateSession { exit_code: 1, pid: 1, desc: "fail" };
        assert_eq!(s.wait_exited().unwrap(), 1);
    }

    #[test]
    fn wait_exited_timeout_returns_exit_code() {
        let s = ImmediateSession { exit_code: 0, pid: 1, desc: "ok" };
        assert_eq!(s.wait_exited_timeout(Duration::from_secs(1)).unwrap(), 0);
    }

    #[test]
    fn wait_exited_interrupted_error() {
        let s = InterruptedSession;
        let err = s.wait_exited().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Interrupted);
    }

    #[test]
    fn wait_exited_timeout_interrupted_error() {
        let s = InterruptedSession;
        let err = s.wait_exited_timeout(Duration::from_secs(1)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Interrupted);
    }

    #[test]
    fn wait_exited_timeout_timed_out_error() {
        let s = TimedOutSession;
        let err = s.wait_exited_timeout(Duration::from_millis(1)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn destroy_forcibly_does_not_panic() {
        let s = ImmediateSession { exit_code: 0, pid: 1, desc: "ok" };
        s.destroy_forcibly();
    }

    #[test]
    fn description_returns_string() {
        let s = ImmediateSession { exit_code: 0, pid: 99, desc: "my session" };
        assert_eq!(s.description(), "my session");
    }

    #[test]
    fn handle_returns_pid() {
        let s = ImmediateSession { exit_code: 0, pid: 1234, desc: "ok" };
        assert_eq!(s.handle(), 1234);
    }
}
