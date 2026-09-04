//! Port of `ghidra.pty.PtyFactory` (rule R9-open-interface -> trait).

use std::io;

use crate::pty::Pty;

/// Default pty width in characters, mirroring `PtyFactory.DEFAULT_COLS`.
pub const DEFAULT_COLS: u16 = 80;
/// Default pty height in characters, mirroring `PtyFactory.DEFAULT_ROWS`.
pub const DEFAULT_ROWS: u16 = 25;

/// A mechanism for opening pseudo-terminals.
pub trait PtyFactory: Send + Sync {
    /// Opens a new pseudo-terminal of the given size, or lets the system decide both
    /// dimensions if either is `0`.
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>>;

    /// Opens a new pseudo-terminal of the default size ([`DEFAULT_COLS`] x [`DEFAULT_ROWS`]).
    fn openpty_default(&self) -> io::Result<Box<dyn Pty>> {
        self.openpty(DEFAULT_COLS, DEFAULT_ROWS)
    }

    /// A human-readable description of the factory.
    fn description(&self) -> String;
}

/// Chooses a factory of local ptys for the host operating system, mirroring the static
/// `PtyFactory.local()`.
///
/// Java makes this choice at runtime, from `OperatingSystem.CURRENT_OPERATING_SYSTEM` -- a
/// single JVM build runs on any host. A native Rust build is compiled for one target, and the
/// unix/linux/macos pty backends call POSIX-only libc functions unconditionally (no `Windows`
/// dummy fallback the way the `windows` backend has for non-Windows targets), so a
/// `target_os`-selected compile-time choice is both the idiomatic Rust translation and the only
/// one that can actually build for every target -- porting `ghidra.framework.OperatingSystem`
/// just for this one runtime check would add an unrelated class for no behavioral benefit here.
pub fn local() -> Box<dyn PtyFactory> {
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::pty::linux::LinuxPtyFactory::Instance)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::pty::macos::MacosPtyFactory::Instance)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(crate::pty::windows::ConPtyFactory::Instance)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        compile_error!("PtyFactory::local() has no implementation for this target OS");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockPtyFactory {
        calls: Mutex<Vec<(u16, u16)>>,
    }

    struct MockPty;
    impl crate::pty::PtyEndpoint for MockPty {
        fn get_output_stream(&self) -> io::Result<Box<dyn std::io::Write>> {
            Ok(Box::new(std::io::sink()))
        }
        fn get_input_stream(&self) -> io::Result<Box<dyn std::io::Read>> {
            Ok(Box::new(std::io::Cursor::new(Vec::new())))
        }
    }
    impl crate::pty::PtyParent for MockPty {}
    struct MockChild;
    impl crate::pty::PtyEndpoint for MockChild {
        fn get_output_stream(&self) -> io::Result<Box<dyn std::io::Write>> {
            Ok(Box::new(std::io::sink()))
        }
        fn get_input_stream(&self) -> io::Result<Box<dyn std::io::Read>> {
            Ok(Box::new(std::io::Cursor::new(Vec::new())))
        }
    }
    impl crate::pty::PtyChild for MockChild {
        fn session(
            &self,
            _args: &[String],
            _env: &std::collections::HashMap<String, String>,
            _working_directory: Option<&std::path::Path>,
            _mode: &[Box<dyn crate::pty::TermMode>],
        ) -> io::Result<Box<dyn crate::pty::PtySession>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "mock"))
        }
        fn null_session(&self, _mode: &[Box<dyn crate::pty::TermMode>]) -> io::Result<String> {
            Ok("mock".to_string())
        }
        fn set_window_size(&self, _cols: u16, _rows: u16) {}
    }

    struct MockPtyImpl {
        parent: MockPty,
        child: MockChild,
    }
    impl Pty for MockPtyImpl {
        fn get_parent(&self) -> &dyn crate::pty::PtyParent {
            &self.parent
        }
        fn get_child(&self) -> &dyn crate::pty::PtyChild {
            &self.child
        }
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PtyFactory for MockPtyFactory {
        fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
            self.calls.lock().unwrap().push((cols, rows));
            Ok(Box::new(MockPtyImpl {
                parent: MockPty,
                child: MockChild,
            }))
        }
        fn description(&self) -> String {
            "mock".to_string()
        }
    }

    #[test]
    fn openpty_default_uses_the_default_dimensions() {
        let factory = MockPtyFactory {
            calls: Mutex::new(Vec::new()),
        };
        factory.openpty_default().unwrap();
        assert_eq!(*factory.calls.lock().unwrap(), vec![(DEFAULT_COLS, DEFAULT_ROWS)]);
    }

    #[test]
    fn openpty_forwards_the_requested_dimensions() {
        let factory = MockPtyFactory {
            calls: Mutex::new(Vec::new()),
        };
        factory.openpty(132, 43).unwrap();
        assert_eq!(*factory.calls.lock().unwrap(), vec![(132, 43)]);
    }

    #[test]
    fn local_returns_a_factory_for_this_platform() {
        let factory = local();
        assert!(!factory.description().is_empty());
    }
}
