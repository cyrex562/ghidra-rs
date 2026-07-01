//! Windows anonymous pipe creation and management.

use std::io;
use std::ptr;

use super::handle::Handle;
#[cfg(target_os = "windows")]
use super::jna::SecurityAttributes;

#[cfg(target_os = "windows")]
extern "system" {
    fn CreatePipe(
        h_read_pipe: *mut *mut std::ffi::c_void,
        h_write_pipe: *mut *mut std::ffi::c_void,
        lp_pipe_attributes: *mut SecurityAttributes,
        n_size: u32,
    ) -> i32;

    fn GetLastError() -> u32;
}

/// An anonymous Windows pipe with separate read and write ends.
///
/// Mirrors `ghidra.pty.windows.Pipe`: creates a pipe via Win32 `CreatePipe`,
/// holds ownership of both ends, and closes them on drop.
pub struct Pipe {
    read_handle: Handle,
    write_handle: Handle,
}

impl Pipe {
    /// Creates an anonymous pipe and returns a new [`Pipe`] wrapping both ends.
    ///
    /// Calls Win32 `CreatePipe` with default security attributes and no size hint.
    /// Both handles are automatically closed when the [`Pipe`] is dropped or
    /// [`Pipe::close`] is called.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if `CreatePipe` fails, with the OS error code
    /// from `GetLastError`.
    ///
    /// Mirrors `Pipe.createPipe()`.
    #[cfg(target_os = "windows")]
    pub fn create() -> io::Result<Self> {
        let mut read_handle: *mut std::ffi::c_void = ptr::null_mut();
        let mut write_handle: *mut std::ffi::c_void = ptr::null_mut();
        let mut security_attrs = SecurityAttributes::default();

        let ok = unsafe {
            CreatePipe(
                &mut read_handle,
                &mut write_handle,
                &mut security_attrs,
                0,
            )
        };

        if ok == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(err_code as i32));
        }

        let read = unsafe { Handle::new(read_handle) };
        let write = unsafe { Handle::new(write_handle) };

        Ok(Pipe {
            read_handle: read,
            write_handle: write,
        })
    }

    /// Creates a dummy pipe for testing on non-Windows platforms.
    ///
    /// On non-Windows, this always succeeds but the handles are not valid
    /// Win32 handles. Use only in tests.
    #[cfg(not(target_os = "windows"))]
    #[doc(hidden)]
    pub fn create() -> io::Result<Self> {
        let read = unsafe { Handle::new(ptr::null_mut()) };
        let write = unsafe { Handle::new(ptr::null_mut()) };
        Ok(Pipe {
            read_handle: read,
            write_handle: write,
        })
    }

    /// Returns a reference to the read end of the pipe.
    ///
    /// Mirrors `Pipe.getReadHandle()`.
    pub fn read_handle(&self) -> &Handle {
        &self.read_handle
    }

    /// Returns a reference to the write end of the pipe.
    ///
    /// Mirrors `Pipe.getWriteHandle()`.
    pub fn write_handle(&self) -> &Handle {
        &self.write_handle
    }

    /// Closes both ends of the pipe and returns the first error, if any.
    ///
    /// The write end is closed first, then the read end.
    /// Subsequent calls to this method are idempotent (each [`Handle::close`]
    /// call already handles repeated invocations).
    ///
    /// Mirrors `Pipe.close()`.
    pub fn close(&mut self) -> io::Result<()> {
        self.write_handle.close()?;
        self.read_handle.close()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_pipe_succeeds() {
        let pipe = Pipe::create();
        assert!(pipe.is_ok(), "Pipe::create should succeed");
    }

    #[test]
    fn read_handle_is_accessible() {
        let pipe = Pipe::create().expect("Pipe::create failed");
        let read = pipe.read_handle();
        assert!(read.as_raw().is_ok(), "read_handle should be valid");
    }

    #[test]
    fn write_handle_is_accessible() {
        let pipe = Pipe::create().expect("Pipe::create failed");
        let write = pipe.write_handle();
        assert!(write.as_raw().is_ok(), "write_handle should be valid");
    }

    #[test]
    fn close_is_idempotent() {
        let mut pipe = Pipe::create().expect("Pipe::create failed");
        assert!(pipe.close().is_ok(), "first close should succeed");
        assert!(pipe.close().is_ok(), "second close should also succeed");
    }

    #[test]
    fn handles_invalid_after_close() {
        let mut pipe = Pipe::create().expect("Pipe::create failed");
        let _ = pipe.close();
        assert!(pipe.read_handle().as_raw().is_err(), "read_handle should be invalid after close");
        assert!(pipe.write_handle().as_raw().is_err(), "write_handle should be invalid after close");
    }
}
