//! Windows kernel HANDLE input stream.

use std::io::{self, Read};

use super::handle::Handle;

/// Win32 `ERROR_BROKEN_PIPE`: the pipe's other end has gone away.
#[allow(dead_code)]
const ERROR_BROKEN_PIPE: u32 = 109;
/// Win32 `ERROR_PIPE_CONNECTED`: a client connected before we started waiting.
#[allow(dead_code)]
const ERROR_PIPE_CONNECTED: u32 = 535;
/// Win32 `ERROR_PIPE_LISTENING`: the named pipe has no client yet.
#[allow(dead_code)]
const ERROR_PIPE_LISTENING: u32 = 536;

#[cfg(target_os = "windows")]
mod ffi {
    use std::ffi::c_void;

    use crate::pty::windows::handle::RawHandle;

    extern "system" {
        pub fn ReadFile(
            h_file: RawHandle,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;

        pub fn ConnectNamedPipe(h_named_pipe: RawHandle, lp_overlapped: *mut c_void) -> i32;

        pub fn GetLastError() -> u32;
    }
}

/// An [`std::io::Read`] implementation backed by a Windows kernel HANDLE.
///
/// Mirrors `ghidra.pty.windows.HandleInputStream`: reads via the Win32
/// `ReadFile` API, transparently blocking on `ConnectNamedPipe` when the
/// underlying named pipe has no client yet, and treats `ERROR_BROKEN_PIPE`
/// as end-of-stream (`Ok(0)`).
pub struct HandleInputStream {
    handle: Handle,
    closed: bool,
}

impl HandleInputStream {
    /// Creates a new stream that reads from `handle`.
    pub fn new(handle: Handle) -> Self {
        HandleInputStream {
            handle,
            closed: false,
        }
    }

    /// Explicitly closes the stream and the underlying handle.
    ///
    /// After this call, further reads return an error. Mirrors
    /// `HandleInputStream.close()`.
    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        self.handle.close()
    }

    /// Blocks until a client connects to the underlying named pipe.
    ///
    /// Mirrors `HandleInputStream.waitPipeConnected()`.
    ///
    /// # Errors
    ///
    /// Returns the OS error if `ConnectNamedPipe` fails for any reason other
    /// than the pipe already being connected.
    #[cfg(target_os = "windows")]
    fn wait_pipe_connected(&self) -> io::Result<()> {
        let raw = self.handle.as_raw()?;
        let ok = unsafe { ffi::ConnectNamedPipe(raw, std::ptr::null_mut()) };
        if ok != 0 {
            return Ok(()); // We waited, and now we're connected
        }
        let error = unsafe { ffi::GetLastError() };
        if error == ERROR_PIPE_CONNECTED {
            return Ok(()); // We got the connection before we waited. OK
        }
        Err(io::Error::from_raw_os_error(error as i32))
    }

    #[cfg(target_os = "windows")]
    fn read_handle(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let raw = self.handle.as_raw()?;
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ffi::ReadFile(
                    raw,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0 {
                return Ok(read as usize);
            }
            let error = unsafe { ffi::GetLastError() };
            match error {
                ERROR_BROKEN_PIPE => return Ok(0),
                ERROR_PIPE_LISTENING => {
                    // Well, we know we're dealing with a listening pipe, now.
                    // Wait for a client, then try reading again.
                    self.wait_pipe_connected()?;
                    continue;
                }
                _ => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn read_handle(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HandleInputStream requires Windows",
        ))
    }
}

impl Read for HandleInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::Other, "Stream closed"));
        }
        self.read_handle(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_stream() -> HandleInputStream {
        let handle = unsafe { Handle::new(ptr::null_mut()) };
        HandleInputStream::new(handle)
    }

    #[test]
    fn read_after_close_is_error() {
        let mut s = null_stream();
        s.close().unwrap();
        let mut buf = [0u8; 4];
        let err = s.read(&mut buf).unwrap_err();
        assert!(err.to_string().contains("Stream closed"));
    }

    #[test]
    fn close_invalidates_underlying_handle() {
        let mut s = null_stream();
        s.close().unwrap();
        assert!(s.handle.as_raw().is_err());
    }

    #[test]
    fn double_close_is_idempotent() {
        let mut s = null_stream();
        s.close().unwrap();
        let result = s.close();
        assert!(result.is_ok());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn read_on_non_windows_is_unsupported() {
        let mut s = null_stream();
        let mut buf = [0u8; 4];
        let err = s.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn error_constants_match_win32() {
        assert_eq!(ERROR_BROKEN_PIPE, 109);
        assert_eq!(ERROR_PIPE_CONNECTED, 535);
        assert_eq!(ERROR_PIPE_LISTENING, 536);
    }
}
