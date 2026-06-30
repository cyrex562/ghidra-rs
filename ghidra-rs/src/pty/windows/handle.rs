//! Windows kernel HANDLE wrapper with automatic cleanup.

use std::ffi::c_void;
use std::io;

/// Raw Windows HANDLE value (a kernel object reference).
pub type RawHandle = *mut c_void;

#[cfg(target_os = "windows")]
extern "system" {
    fn CloseHandle(handle: RawHandle) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(target_os = "windows")]
unsafe fn close_raw(h: RawHandle) -> io::Result<()> {
    if CloseHandle(h) == 0 {
        let err = GetLastError();
        Err(io::Error::from_raw_os_error(err as i32))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn close_raw(_h: RawHandle) -> io::Result<()> {
    Ok(())
}

/// A Windows kernel HANDLE that is automatically closed when dropped.
///
/// Mirrors `ghidra.pty.windows.Handle`: wraps a raw Win32 HANDLE, closes it
/// via `CloseHandle` on drop (the Rust equivalent of Java's `Cleaner`), and
/// offers an explicit [`Handle::close`] for callers that need to observe errors.
pub struct Handle {
    raw: Option<RawHandle>,
}

/// # Safety
///
/// Windows HANDLEs are valid kernel object references that may be transferred
/// across threads.
unsafe impl Send for Handle {}

impl Handle {
    /// Creates a new `Handle` that takes ownership of `raw`.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid, open Windows kernel handle. This value will be
    /// closed with `CloseHandle` when the `Handle` is dropped or
    /// [`Handle::close`] is called.
    pub unsafe fn new(raw: RawHandle) -> Self {
        Handle { raw: Some(raw) }
    }

    /// Returns the underlying Windows HANDLE.
    ///
    /// # Errors
    ///
    /// Returns `Err` if this handle has already been closed.
    pub fn as_raw(&self) -> io::Result<RawHandle> {
        self.raw.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "This handle is no longer valid")
        })
    }

    /// Explicitly closes the handle and returns any OS error.
    ///
    /// After this call, [`Handle::as_raw`] will return `Err`. Subsequent calls
    /// to `close` are no-ops. When the `Handle` is dropped without an explicit
    /// `close`, any OS error is silently discarded.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(h) = self.raw.take() {
            unsafe { close_raw(h) }
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.raw {
            Some(h) => write!(f, "Handle({:p})", h),
            None => write!(f, "Handle(closed)"),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(h) = self.raw.take() {
            unsafe {
                let _ = close_raw(h);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    /// Creates a Handle wrapping a null pointer for testing state logic.
    ///
    /// On non-Windows the Drop is a no-op; on Windows CloseHandle(NULL)
    /// returns an error that Drop silently discards.
    fn null_handle() -> Handle {
        unsafe { Handle::new(ptr::null_mut()) }
    }

    #[test]
    fn new_handle_as_raw_is_ok() {
        let h = null_handle();
        assert!(h.as_raw().is_ok());
        std::mem::forget(h);
    }

    #[test]
    fn as_raw_returns_stored_pointer() {
        let sentinel: RawHandle = 0x4242 as *mut _;
        let h = unsafe { Handle::new(sentinel) };
        assert_eq!(h.as_raw().unwrap(), sentinel);
        std::mem::forget(h);
    }

    #[test]
    fn close_invalidates_handle() {
        let mut h = null_handle();
        let _ = h.close();
        assert!(h.as_raw().is_err());
    }

    #[test]
    fn double_close_is_idempotent() {
        let mut h = null_handle();
        let _ = h.close();
        let result = h.close();
        assert!(result.is_ok());
    }

    #[test]
    fn as_raw_error_contains_message() {
        let mut h = null_handle();
        let _ = h.close();
        let err = h.as_raw().unwrap_err();
        assert!(err.to_string().contains("no longer valid"));
    }

    #[test]
    fn debug_open_shows_pointer() {
        let h = null_handle();
        let s = format!("{:?}", h);
        assert!(s.starts_with("Handle("));
        std::mem::forget(h);
    }

    #[test]
    fn debug_closed_shows_closed() {
        let mut h = null_handle();
        let _ = h.close();
        assert_eq!(format!("{:?}", h), "Handle(closed)");
    }
}
