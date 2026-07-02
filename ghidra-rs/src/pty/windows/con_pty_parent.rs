//! Windows pseudo-console parent (master) end implementation.

use std::io::{Read, Write};

use crate::pty::PtyEndpoint;
use crate::pty::PtyParent;

use super::con_pty_endpoint::ConPtyEndpoint;
use super::handle::Handle;
use super::pseudo_console_handle::PseudoConsoleHandle;

/// The parent (master) end of a Windows pseudo-console.
///
/// Mirrors `ghidra.pty.windows.ConPtyParent`. Wraps a [`ConPtyEndpoint`] and
/// implements the [`PtyParent`] marker trait.
pub struct ConPtyParent(ConPtyEndpoint);

impl ConPtyParent {
    /// Creates a new pseudo-console parent from read and write handles.
    ///
    /// # Arguments
    ///
    /// * `write_handle` - The write end of the pipe (becomes the output stream)
    /// * `read_handle` - The read end of the pipe (becomes the input stream)
    /// * `pseudo_console_handle` - The pseudo-console handle
    pub fn new(
        write_handle: Handle,
        read_handle: Handle,
        pseudo_console_handle: PseudoConsoleHandle,
    ) -> Self {
        ConPtyParent(ConPtyEndpoint::new(write_handle, read_handle, pseudo_console_handle))
    }

    /// Returns a reference to the underlying pseudo-console handle.
    pub fn pseudo_console_handle(&self) -> &PseudoConsoleHandle {
        self.0.pseudo_console_handle()
    }
}

impl PtyEndpoint for ConPtyParent {
    fn get_output_stream(&self) -> std::io::Result<Box<dyn Write>> {
        self.0.get_output_stream()
    }

    fn get_input_stream(&self) -> std::io::Result<Box<dyn Read>> {
        self.0.get_input_stream()
    }
}

impl PtyParent for ConPtyParent {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_parent() -> ConPtyParent {
        let write_handle = unsafe { Handle::new(ptr::null_mut()) };
        let read_handle = unsafe { Handle::new(ptr::null_mut()) };
        let pseudo_console_handle = unsafe { PseudoConsoleHandle::new(ptr::null_mut()) };

        ConPtyParent::new(write_handle, read_handle, pseudo_console_handle)
    }

    #[test]
    fn new_creates_parent() {
        let parent = null_parent();
        assert!(parent.pseudo_console_handle().as_raw().is_ok());
    }

    #[test]
    fn get_output_stream_returns_ok() {
        let parent = null_parent();
        assert!(parent.get_output_stream().is_ok());
    }

    #[test]
    fn get_input_stream_returns_ok() {
        let parent = null_parent();
        assert!(parent.get_input_stream().is_ok());
    }

    #[test]
    fn implements_pty_parent_trait() {
        let parent = null_parent();
        fn check_pty_parent<T: PtyParent>(_: &T) {}
        check_pty_parent(&parent);
    }

    #[test]
    fn implements_pty_endpoint_trait() {
        let parent = null_parent();
        fn check_pty_endpoint<T: PtyEndpoint>(_: &T) {}
        check_pty_endpoint(&parent);
    }
}
