//! Service for creating and managing DEC VT100 (XTerm-like) terminal emulators.
//!
//! Port of `ghidra.app.services.TerminalService`. The Java `@ServiceInfo` annotation (default
//! provider `ghidra.app.plugin.core.terminal.TerminalPlugin`, not yet ported) has no Rust
//! equivalent and is omitted, matching the convention used elsewhere (e.g.
//! [`BlockModelService`](crate::app::services::BlockModelService)). `TerminalPlugin` is otherwise
//! only mentioned in Javadoc, never in a method signature, so no placeholder is needed for it.
//!
//! Java's `Charset` and `InputStream`/`OutputStream` (JDK types, not Ghidra types) are mapped to
//! a charset name string and `std::io::{Read, Write}` trait objects, respectively. Java's
//! overloaded `createNullTerminal`/`createWithStreams` methods (with/without a `Plugin` for help
//! context) are folded into a single method each, taking `Option<&dyn Plugin>`, matching the
//! convention used elsewhere (e.g.
//! [`FileImporterService::import_file`](crate::app::services::FileImporterService::import_file)).

use std::io;

use crate::app::plugin::core::terminal::vt::VtOutput;
use crate::app::services::terminal::Terminal;
use crate::framework::plugintool::Plugin;

/// A service that provides for the creation and management of DEC VT100 terminal emulators.
///
/// These are perhaps better described as XTerm clones. It seems the term "VT100" is applied to
/// any text display that interprets some number of ANSI escape codes.
pub trait TerminalService {
    /// Create a terminal not connected to any particular application.
    ///
    /// To display application output, use [`Terminal::inject_display_output`]. Application input
    /// is delivered to the given terminal output callback. If the application is connected via
    /// streams, esp. those from a pty, consider using [`Self::create_with_streams`] instead.
    ///
    /// # Arguments
    ///
    /// * `help_plugin` - the invoking plugin, which ought to provide a help topic for this
    ///   terminal. Pass `None` when no such plugin applies.
    /// * `charset` - the character set for the terminal. See note in
    ///   [`Self::create_with_streams`].
    /// * `output_cb` - callback for output from the terminal, i.e., the application's input.
    fn create_null_terminal(
        &self,
        help_plugin: Option<&dyn Plugin>,
        charset: &str,
        output_cb: Box<dyn VtOutput>,
    ) -> Box<dyn Terminal>;

    /// Create a terminal connected to the application (or pty session) via the given streams.
    ///
    /// # Arguments
    ///
    /// * `help_plugin` - the invoking plugin, which ought to provide a help topic for this
    ///   terminal. Pass `None` when no such plugin applies.
    /// * `charset` - the character set for the terminal. **NOTE:** Only US-ASCII and UTF-8 have
    ///   been tested. So long as the bytes 0x00-0x7f map one-to-one with characters with the same
    ///   code point, it'll probably work. Charsets that require more than one byte to decode
    ///   those characters will almost certainly break things.
    /// * `input` - the application's output, i.e., input for the terminal to display.
    /// * `output` - the application's input, i.e., output from the terminal's keyboard and mouse.
    fn create_with_streams(
        &self,
        help_plugin: Option<&dyn Plugin>,
        charset: &str,
        input: Box<dyn io::Read + Send>,
        output: Box<dyn io::Write + Send>,
    ) -> Box<dyn Terminal>;

    /// Remove all terminals whose sessions have terminated from the tool.
    ///
    /// This is done automatically when creating any new terminal.
    fn clean_terminated(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTerminal {
        closed: bool,
    }

    impl Terminal for FakeTerminal {
        fn add_terminal_listener(
            &mut self,
            _listener: Box<dyn crate::app::plugin::core::terminal::TerminalListener>,
        ) {
        }
        fn remove_terminal_listener(
            &mut self,
            _listener: &dyn crate::app::plugin::core::terminal::TerminalListener,
        ) {
        }
        fn inject_display_output(&mut self, _buf: &[u8]) {}
        fn set_sub_title(&mut self, _title: &str) {}
        fn get_sub_title(&self) -> String {
            String::new()
        }
        fn set_fixed_size(&mut self, _cols: i16, _rows: i16) {}
        fn set_dynamic_size(&mut self) {}
        fn set_max_scroll_back_rows(&mut self, _rows: i32) {}
        fn get_columns(&self) -> i32 {
            0
        }
        fn get_rows(&self) -> i32 {
            0
        }
        fn get_scroll_back_rows(&self) -> i32 {
            0
        }
        fn get_full_text(&self) -> String {
            String::new()
        }
        fn get_display_text(&self) -> String {
            String::new()
        }
        fn get_line_text(&self, _line: i32) -> String {
            String::new()
        }
        fn get_range_text(&self, _sc: i32, _sl: i32, _ec: i32, _el: i32) -> String {
            String::new()
        }
        fn get_cursor_row(&self) -> i32 {
            0
        }
        fn get_cursor_column(&self) -> i32 {
            0
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn terminated(&mut self, _exitcode: i32) {}
        fn set_terminate_action(&mut self, _action: Option<crate::util::function::Callback>) {}
        fn is_terminated(&self) -> bool {
            false
        }
        fn to_front(&mut self) {}
    }

    struct RecordingOutput {
        received: RefCell<Vec<u8>>,
    }

    impl VtOutput for RecordingOutput {
        fn out(&mut self, buf: &[u8]) {
            self.received.borrow_mut().extend_from_slice(buf);
        }
    }

    /// Mirrors a `TerminalPlugin`-like provider: `cleanTerminated` sweeps terminated terminals,
    /// and the two `create*` overload pairs are reachable via `Option<&dyn Plugin>` alone.
    struct FakeTerminalService {
        cleaned: RefCell<u32>,
    }

    impl TerminalService for FakeTerminalService {
        fn create_null_terminal(
            &self,
            _help_plugin: Option<&dyn Plugin>,
            _charset: &str,
            _output_cb: Box<dyn VtOutput>,
        ) -> Box<dyn Terminal> {
            Box::new(FakeTerminal { closed: false })
        }

        fn create_with_streams(
            &self,
            _help_plugin: Option<&dyn Plugin>,
            _charset: &str,
            _input: Box<dyn io::Read + Send>,
            _output: Box<dyn io::Write + Send>,
        ) -> Box<dyn Terminal> {
            Box::new(FakeTerminal { closed: false })
        }

        fn clean_terminated(&self) {
            *self.cleaned.borrow_mut() += 1;
        }
    }

    #[test]
    fn create_null_terminal_without_help_plugin_returns_terminal() {
        let service = FakeTerminalService {
            cleaned: RefCell::new(0),
        };
        let output = Box::new(RecordingOutput {
            received: RefCell::new(Vec::new()),
        });
        let mut terminal = service.create_null_terminal(None, "UTF-8", output);
        assert!(!terminal.is_terminated());
        terminal.close();
    }

    #[test]
    fn create_with_streams_reads_and_writes_via_boxed_streams() {
        let service = FakeTerminalService {
            cleaned: RefCell::new(0),
        };
        let input: Box<dyn io::Read + Send> = Box::new(io::Cursor::new(b"hello".to_vec()));
        let output: Box<dyn io::Write + Send> = Box::new(Vec::new());
        let terminal = service.create_with_streams(None, "UTF-8", input, output);
        assert!(!terminal.is_terminated());
    }

    #[test]
    fn clean_terminated_invokes_provider() {
        let service = FakeTerminalService {
            cleaned: RefCell::new(0),
        };
        service.clean_terminated();
        service.clean_terminated();
        assert_eq!(*service.cleaned.borrow(), 2);
    }
}
