//! Windows pseudo-console endpoint implementation.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use crate::pty::PtyEndpoint;

use super::handle::Handle;
use super::handle_input_stream::HandleInputStream;
use super::handle_output_stream::HandleOutputStream;
use super::pseudo_console_handle::PseudoConsoleHandle;

struct InputStreamBox(Arc<Mutex<HandleInputStream>>);

impl Read for InputStreamBox {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = self.0.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "stream lock poisoned")
        })?;
        stream.read(buf)
    }
}

struct OutputStreamBox(Arc<Mutex<HandleOutputStream>>);

impl Write for OutputStreamBox {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut stream = self.0.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "stream lock poisoned")
        })?;
        stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut stream = self.0.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "stream lock poisoned")
        })?;
        stream.flush()
    }
}

/// One end of a Windows pseudo-console.
///
/// Mirrors `ghidra.pty.windows.ConPtyEndpoint`: implements [`PtyEndpoint`] by
/// wrapping a read handle (as [`HandleInputStream`]), a write handle (as
/// [`HandleOutputStream`]), and a pseudo-console handle (as
/// [`PseudoConsoleHandle`]).
pub struct ConPtyEndpoint {
    input_stream: Arc<Mutex<HandleInputStream>>,
    output_stream: Arc<Mutex<HandleOutputStream>>,
    pseudo_console_handle: PseudoConsoleHandle,
}

impl ConPtyEndpoint {
    /// Creates a new pseudo-console endpoint from read and write handles.
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
        ConPtyEndpoint {
            input_stream: Arc::new(Mutex::new(HandleInputStream::new(read_handle))),
            output_stream: Arc::new(Mutex::new(HandleOutputStream::new(write_handle))),
            pseudo_console_handle,
        }
    }

    /// Returns a reference to the underlying pseudo-console handle.
    pub fn pseudo_console_handle(&self) -> &PseudoConsoleHandle {
        &self.pseudo_console_handle
    }
}

impl PtyEndpoint for ConPtyEndpoint {
    fn get_output_stream(&self) -> std::io::Result<Box<dyn Write>> {
        Ok(Box::new(OutputStreamBox(self.output_stream.clone())))
    }

    fn get_input_stream(&self) -> std::io::Result<Box<dyn Read>> {
        Ok(Box::new(InputStreamBox(self.input_stream.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_endpoint() -> ConPtyEndpoint {
        let write_handle = unsafe { Handle::new(ptr::null_mut()) };
        let read_handle = unsafe { Handle::new(ptr::null_mut()) };
        let pseudo_console_handle = unsafe { PseudoConsoleHandle::new(ptr::null_mut()) };

        ConPtyEndpoint::new(write_handle, read_handle, pseudo_console_handle)
    }

    #[test]
    fn new_creates_endpoint() {
        let ep = null_endpoint();
        assert!(ep.pseudo_console_handle().as_raw().is_ok());
    }

    #[test]
    fn get_output_stream_returns_ok() {
        let ep = null_endpoint();
        assert!(ep.get_output_stream().is_ok());
    }

    #[test]
    fn get_input_stream_returns_ok() {
        let ep = null_endpoint();
        assert!(ep.get_input_stream().is_ok());
    }

    #[test]
    fn pseudo_console_handle_accessor() {
        let write_handle = unsafe { Handle::new(ptr::null_mut()) };
        let read_handle = unsafe { Handle::new(ptr::null_mut()) };
        let pseudo_console_handle = unsafe { PseudoConsoleHandle::new(ptr::null_mut()) };

        let ep = ConPtyEndpoint::new(write_handle, read_handle, pseudo_console_handle);

        assert!(ep.pseudo_console_handle().as_raw().is_ok());
    }

    #[test]
    fn output_stream_box_implements_write() {
        let ep = null_endpoint();
        let stream = ep.get_output_stream().unwrap();
        let stream_any = stream;
        assert!(!format!("{:?}", stream_any).is_empty());
    }

    #[test]
    fn input_stream_box_implements_read() {
        let ep = null_endpoint();
        let stream = ep.get_input_stream().unwrap();
        let stream_any = stream;
        assert!(!format!("{:?}", stream_any).is_empty());
    }
}
