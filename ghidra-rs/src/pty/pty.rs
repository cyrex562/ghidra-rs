use crate::pty::{PtyChild, PtyParent};

/// A pseudo-terminal (PTY).
///
/// A pseudo-terminal is essentially a two-way pipe where one end acts as the parent (master),
/// and the other acts as the child (slave). The process opening the pseudo-terminal is given a
/// handle to both ends. The child end is generally given to a subprocess, possibly designating
/// the pty as the controlling tty of a new session.
///
/// This is more powerful than controlling a process via standard input and standard output:
/// - Some programs detect whether or not stdin/stdout/stderr refer to the controlling tty.
///   For example, a program should avoid prompting for passwords unless stdin is the controlling tty.
///   Using a pty can provide a controlling tty that is not necessarily controlled by a user.
/// - Terminals have other properties and can, e.g., send signals to the foreground process group
///   (job) by sending special characters. Normal characters are passed to the child, but special
///   characters may be interpreted by the terminal's *line discipline*. A common case is to send
///   Ctrl-C (character 003). Using stdin, the subprocess simply reads 003. With a properly-configured
///   pty and session, the subprocess is interrupted (sent SIGINT) instead.
///
/// This trait provides access to both ends of the pseudo-terminal as individual handles.
/// The parent end simply provides an input and output stream. These are typical byte-oriented streams,
/// except that the data passes through the pty, subject to interpretation by the OS kernel.
/// On Linux, this means the pty will apply the configured line discipline.
///
/// The child end also provides the input and output streams, but it is uncommon to use them from
/// the same process. More likely, a subprocess is launched in a new session, configuring the child
/// as the controlling terminal.
pub trait Pty: Send + Sync {
    /// Get a handle to the parent side of the pty.
    ///
    /// The parent end is typically used by the process that opens the pty,
    /// and provides the main interface for controlling the child process.
    ///
    /// # Returns
    ///
    /// A trait object representing the parent end of the pseudo-terminal.
    fn get_parent(&self) -> &dyn PtyParent;

    /// Get a handle to the child side of the pty.
    ///
    /// The child end is typically given to a subprocess as its controlling tty.
    ///
    /// # Returns
    ///
    /// A trait object representing the child end of the pseudo-terminal.
    fn get_child(&self) -> &dyn PtyChild;

    /// Closes both ends of the pty.
    ///
    /// This only closes this process's handles to the pty. For the parent end, this should be the
    /// only process with a handle. The child end may be opened by any number of other processes.
    /// More than likely, however, those processes will terminate once the parent end is closed,
    /// since reads or writes on the child will produce EOF or an error.
    ///
    /// # Errors
    ///
    /// Returns `Err` if an I/O error occurs during closing.
    fn close(&mut self) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read, Write};

    struct MockPtyParent;
    impl PtyParent for MockPtyParent {}

    impl crate::pty::PtyEndpoint for MockPtyParent {
        fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
            Ok(Box::new(io::sink()))
        }

        fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
            Ok(Box::new(Cursor::new(vec![])))
        }
    }

    struct MockPtyChild;
    impl crate::pty::TermMode for MockPtyChild {}

    impl crate::pty::PtyEndpoint for MockPtyChild {
        fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
            Ok(Box::new(io::sink()))
        }

        fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
            Ok(Box::new(Cursor::new(vec![])))
        }
    }

    impl PtyChild for MockPtyChild {
        fn session(
            &self,
            _args: &[String],
            _env: &std::collections::HashMap<String, String>,
            _working_directory: Option<&std::path::Path>,
            _mode: &[Box<dyn crate::pty::TermMode>],
        ) -> io::Result<Box<dyn crate::pty::PtySession>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "mock"))
        }

        fn session_varargs(
            &self,
            _args: &[String],
            _env: &std::collections::HashMap<String, String>,
            _working_directory: Option<&std::path::Path>,
            _mode: &[Box<dyn crate::pty::TermMode>],
        ) -> io::Result<Box<dyn crate::pty::PtySession>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "mock"))
        }

        fn null_session(
            &self,
            _mode: &[Box<dyn crate::pty::TermMode>],
        ) -> io::Result<String> {
            Ok("/dev/pts/0".to_string())
        }

        fn set_window_size(&self, _cols: u16, _rows: u16) {}
    }

    struct MockPty {
        parent: MockPtyParent,
        child: MockPtyChild,
    }

    impl Pty for MockPty {
        fn get_parent(&self) -> &dyn PtyParent {
            &self.parent
        }

        fn get_child(&self) -> &dyn PtyChild {
            &self.child
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pty_provides_parent() {
        let pty = MockPty {
            parent: MockPtyParent,
            child: MockPtyChild,
        };
        let parent = pty.get_parent();
        let output = parent.get_output_stream();
        assert!(output.is_ok());
    }

    #[test]
    fn pty_provides_child() {
        let pty = MockPty {
            parent: MockPtyParent,
            child: MockPtyChild,
        };
        let child = pty.get_child();
        let output = child.get_output_stream();
        assert!(output.is_ok());
    }

    #[test]
    fn pty_close_succeeds() {
        let mut pty = MockPty {
            parent: MockPtyParent,
            child: MockPtyChild,
        };
        let result = pty.close();
        assert!(result.is_ok());
    }
}
