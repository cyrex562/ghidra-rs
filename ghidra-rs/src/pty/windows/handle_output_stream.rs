//! Windows kernel HANDLE output stream.

use std::io::{self, Write};

use super::handle::Handle;

#[cfg(target_os = "windows")]
mod ffi {
    use std::ffi::c_void;

    use crate::pty::windows::handle::RawHandle;

    extern "system" {
        pub fn WriteFile(
            h_file: RawHandle,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;

        pub fn FlushFileBuffers(h_file: RawHandle) -> i32;

        pub fn GetLastError() -> u32;
    }
}

/// An [`std::io::Write`] implementation backed by a Windows kernel HANDLE.
///
/// Mirrors `ghidra.pty.windows.HandleOutputStream`: writes via the Win32
/// `WriteFile` API, looping until the entire buffer is written, and flushes
/// via `FlushFileBuffers`.
pub struct HandleOutputStream {
    handle: Handle,
    closed: bool,
}

impl HandleOutputStream {
    /// Creates a new stream that writes to `handle`.
    pub fn new(handle: Handle) -> Self {
        HandleOutputStream {
            handle,
            closed: false,
        }
    }

    /// Explicitly closes the stream.
    ///
    /// After this call, further writes return an error. Mirrors
    /// `HandleOutputStream.close()`.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Check whether this handle has buffered output.
    ///
    /// Windows can get touchy when trying to flush handles that are not
    /// actually buffered. If the wrapped handle is not buffered, this must
    /// return `false`, otherwise any attempt to flush this stream will
    /// result in `ERROR_INVALID_HANDLE`. Mirrors `HandleOutputStream.isBuffered()`.
    fn is_buffered(&self) -> bool {
        true
    }

    #[cfg(target_os = "windows")]
    fn write_handle(&mut self, buf: &[u8]) -> io::Result<()> {
        let raw = self.handle.as_raw()?;
        let mut total = 0usize;
        while total < buf.len() {
            let mut written: u32 = 0;
            let ok = unsafe {
                ffi::WriteFile(
                    raw,
                    buf[total..].as_ptr(),
                    (buf.len() - total) as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let error = unsafe { ffi::GetLastError() };
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            total += written as usize;
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn write_handle(&mut self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HandleOutputStream requires Windows",
        ))
    }

    #[cfg(target_os = "windows")]
    fn flush_handle(&self) -> io::Result<()> {
        let raw = self.handle.as_raw()?;
        if unsafe { ffi::FlushFileBuffers(raw) } == 0 {
            let error = unsafe { ffi::GetLastError() };
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn flush_handle(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HandleOutputStream requires Windows",
        ))
    }
}

impl Write for HandleOutputStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::Other, "Stream closed"));
        }
        self.write_handle(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.is_buffered() {
            return Ok(());
        }
        self.flush_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_stream() -> HandleOutputStream {
        let handle = unsafe { Handle::new(ptr::null_mut()) };
        HandleOutputStream::new(handle)
    }

    #[test]
    fn write_after_close_is_error() {
        let mut s = null_stream();
        s.close();
        let err = s.write(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("Stream closed"));
    }

    #[test]
    fn is_buffered_defaults_true() {
        let s = null_stream();
        assert!(s.is_buffered());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn write_on_non_windows_is_unsupported() {
        let mut s = null_stream();
        let err = s.write(&[1, 2, 3]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn flush_on_non_windows_is_unsupported() {
        let mut s = null_stream();
        let err = s.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
