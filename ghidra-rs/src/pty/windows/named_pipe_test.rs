//! Windows named pipe testing utilities.
//!
//! Mirrors `ghidra.pty.windows.NamedPipeTest`: experiments with creating and
//! interacting with named pipes via Win32 APIs.

use std::io;

use super::handle::Handle;

#[cfg(target_os = "windows")]
mod ffi {
    use std::ffi::c_void;
    use crate::pty::windows::handle::RawHandle;

    extern "system" {
        pub fn CreateNamedPipeA(
            lp_name: *const u8,
            dw_open_mode: u32,
            dw_pipe_mode: u32,
            n_max_instances: u32,
            n_out_buffer_size: u32,
            n_in_buffer_size: u32,
            n_default_time_out: u32,
            lp_security_attributes: *mut c_void,
        ) -> RawHandle;

        pub fn GetLastError() -> u32;
    }
}

// Win32 constants for pipe creation
#[cfg(target_os = "windows")]
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
#[cfg(target_os = "windows")]
const PIPE_TYPE_BYTE: u32 = 0x00000000;
#[cfg(target_os = "windows")]
const PIPE_WAIT: u32 = 0x00000000;
#[cfg(target_os = "windows")]
const PIPE_UNLIMITED_INSTANCES: u32 = 0xFF;
#[cfg(target_os = "windows")]
const INVALID_HANDLE_VALUE: RawHandle = -1isize as *mut _;

/// Creates a named pipe and returns a `Handle` wrapping it.
///
/// Mirrors the behavior of `NamedPipeTest.checkHandle()` applied to
/// `Kernel32.CreateNamedPipe()`. Creates a duplex byte-mode named pipe
/// with unlimited instances and default timeouts.
///
/// # Errors
///
/// Returns an [`io::Error`] if `CreateNamedPipeA` fails or returns an invalid handle,
/// with the OS error code from `GetLastError`.
#[cfg(target_os = "windows")]
pub fn create_named_pipe(pipe_name: &str) -> io::Result<Handle> {
    use std::ptr;

    let pipe_name_cstr = format!("{}\0", pipe_name);
    let pipe_name_bytes = pipe_name_cstr.as_bytes();

    let handle = unsafe {
        ffi::CreateNamedPipeA(
            pipe_name_bytes.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1024, // nOutBufferSize
            1024, // nInBufferSize
            0,    // nDefaultTimeOut
            ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let error_code = unsafe { ffi::GetLastError() };
        return Err(io::Error::from_raw_os_error(error_code as i32));
    }

    Ok(unsafe { Handle::new(handle) })
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn create_named_pipe(_pipe_name: &str) -> io::Result<Handle> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "create_named_pipe requires Windows",
    ))
}

#[cfg(test)]
mod tests {
    use std::ptr;
    use super::*;
    use super::super::handle_input_stream::HandleInputStream;
    use super::super::handle_output_stream::HandleOutputStream;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_create_named_pipe_constants() {
        assert_eq!(PIPE_ACCESS_DUPLEX, 0x00000003);
        assert_eq!(PIPE_TYPE_BYTE, 0x00000000);
        assert_eq!(PIPE_WAIT, 0x00000000);
        assert_eq!(PIPE_UNLIMITED_INSTANCES, 0xFF);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_create_named_pipe_unsupported_on_non_windows() {
        let result = create_named_pipe("\\\\.\\pipe\\test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_create_iostream_from_handle() {
        let null_handle = unsafe { Handle::new(ptr::null_mut()) };
        let _input_stream = HandleInputStream::new(null_handle);

        let null_handle2 = unsafe { Handle::new(ptr::null_mut()) };
        let _output_stream = HandleOutputStream::new(null_handle2);
    }

    #[test]
    fn test_handle_input_stream_wraps_handle() {
        let handle = unsafe { Handle::new(ptr::null_mut()) };
        let stream = HandleInputStream::new(handle);
        std::mem::forget(stream);
    }

    #[test]
    fn test_handle_output_stream_wraps_handle() {
        let handle = unsafe { Handle::new(ptr::null_mut()) };
        let stream = HandleOutputStream::new(handle);
        std::mem::forget(stream);
    }

    #[test]
    fn test_handle_output_stream_close() {
        let handle = unsafe { Handle::new(ptr::null_mut()) };
        let mut stream = HandleOutputStream::new(handle);
        stream.close();
    }

    #[test]
    fn test_handle_input_stream_close() {
        let handle = unsafe { Handle::new(ptr::null_mut()) };
        let mut stream = HandleInputStream::new(handle);
        let _ = stream.close();
    }
}
