use std::collections::HashMap;
use std::path::Path;

use crate::pty::{PtyEndpoint, PtySession};

/// A terminal mode flag.
pub trait TermMode: Send + Sync {}

/// Echo mode for the pseudo-terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    /// Input is echoed to output by the terminal itself.
    On,
    /// No local echo.
    Off,
}

impl TermMode for Echo {}

/// The child (UNIX "slave") end of a pseudo-terminal.
pub trait PtyChild: PtyEndpoint {
    /// Spawn a subprocess in a new session whose controlling tty is this pseudo-terminal.
    ///
    /// This method or [`nullSession`](Self::nullSession) can only be invoked once per pty.
    ///
    /// # Arguments
    ///
    /// * `args` - The image path and arguments
    /// * `env` - The environment variables
    /// * `working_directory` - The working directory (None for default)
    /// * `mode` - The terminal mode. If a mode is not implemented, it may be silently ignored.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session could not be started.
    fn session(
        &self,
        args: &[String],
        env: &HashMap<String, String>,
        working_directory: Option<&Path>,
        mode: &[Box<dyn TermMode>],
    ) -> std::io::Result<Box<dyn PtySession>>;

    /// Spawn a subprocess in a new session whose controlling tty is this pseudo-terminal (varargs).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session could not be started.
    fn session_varargs(
        &self,
        args: &[String],
        env: &HashMap<String, String>,
        working_directory: Option<&Path>,
        mode: &[Box<dyn TermMode>],
    ) -> std::io::Result<Box<dyn PtySession>> {
        self.session(args, env, working_directory, mode)
    }

    /// Start a session without a real leader, instead obtaining the pty's name.
    ///
    /// This method or any other `session` method can only be invoked once per pty.
    /// It must be called before anyone reads the parent's output stream, since
    /// obtaining the filename may be implemented by the parent sending commands to its child.
    ///
    /// If the child end of the pty is on a remote system, this should be the file
    /// (or other resource) name as it would be accessed on that remote system.
    ///
    /// # Arguments
    ///
    /// * `mode` - The terminal mode. If a mode is not implemented, it may be silently ignored.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session could not be started or the pty name could not be determined.
    fn null_session(&self, mode: &[Box<dyn TermMode>]) -> std::io::Result<String>;

    /// Resize the terminal window to the given width and height, in characters.
    fn set_window_size(&self, cols: u16, rows: u16);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    struct MockPtyChild;

    impl PtyEndpoint for MockPtyChild {
        fn get_output_stream(&self) -> std::io::Result<Box<dyn Write>> {
            Ok(Box::new(std::io::sink()))
        }

        fn get_input_stream(&self) -> std::io::Result<Box<dyn Read>> {
            Ok(Box::new(Cursor::new(vec![])))
        }
    }

    struct MockSession {
        exit_code: i32,
    }

    impl PtySession for MockSession {
        fn wait_exited(&self) -> std::io::Result<i32> {
            Ok(self.exit_code)
        }

        fn wait_exited_timeout(
            &self,
            _timeout: std::time::Duration,
        ) -> std::io::Result<i32> {
            Ok(self.exit_code)
        }

        fn destroy_forcibly(&self) {}

        fn description(&self) -> String {
            "mock session".to_string()
        }

        fn handle(&self) -> u32 {
            0
        }
    }

    impl PtyChild for MockPtyChild {
        fn session(
            &self,
            _args: &[String],
            _env: &HashMap<String, String>,
            _working_directory: Option<&Path>,
            _mode: &[Box<dyn TermMode>],
        ) -> std::io::Result<Box<dyn PtySession>> {
            Ok(Box::new(MockSession { exit_code: 0 }))
        }

        fn null_session(&self, _mode: &[Box<dyn TermMode>]) -> std::io::Result<String> {
            Ok("/dev/pts/0".to_string())
        }

        fn set_window_size(&self, _cols: u16, _rows: u16) {}
    }

    #[test]
    fn echo_on_is_distinct() {
        assert_eq!(Echo::On, Echo::On);
        assert_ne!(Echo::On, Echo::Off);
    }

    #[test]
    fn echo_off_is_distinct() {
        assert_eq!(Echo::Off, Echo::Off);
        assert_ne!(Echo::Off, Echo::On);
    }

    #[test]
    fn echo_can_be_cloned() {
        let mode = Echo::On;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    #[test]
    fn pty_child_implements_endpoint() {
        let child = MockPtyChild;
        let output = child.get_output_stream();
        assert!(output.is_ok());
        let input = child.get_input_stream();
        assert!(input.is_ok());
    }

    #[test]
    fn pty_child_session_returns_session() {
        let child = MockPtyChild;
        let args = vec![];
        let env = HashMap::new();
        let mode: Vec<Box<dyn TermMode>> = vec![];

        let result = child.session(&args, &env, None, &mode);
        assert!(result.is_ok());

        let session = result.unwrap();
        let exit_code = session.wait_exited();
        assert_eq!(exit_code.unwrap(), 0);
    }

    #[test]
    fn pty_child_null_session_returns_path() {
        let child = MockPtyChild;
        let mode: Vec<Box<dyn TermMode>> = vec![];
        let result = child.null_session(&mode);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/dev/pts/0");
    }

    #[test]
    fn pty_child_set_window_size_succeeds() {
        let child = MockPtyChild;
        child.set_window_size(80, 24);
    }

    #[test]
    fn echo_implements_term_mode() {
        let mode: &dyn TermMode = &Echo::On;
        drop(mode);
    }

    #[test]
    fn session_with_echo_mode() {
        let child = MockPtyChild;
        let args = vec!["bash".to_string()];
        let env = HashMap::new();
        let mode: Vec<Box<dyn TermMode>> = vec![Box::new(Echo::On)];

        let result = child.session(&args, &env, None, &mode);
        assert!(result.is_ok());
    }

    #[test]
    fn null_session_with_echo_mode() {
        let child = MockPtyChild;
        let mode: Vec<Box<dyn TermMode>> = vec![Box::new(Echo::Off)];
        let result = child.null_session(&mode);

        assert!(result.is_ok());
    }
}
