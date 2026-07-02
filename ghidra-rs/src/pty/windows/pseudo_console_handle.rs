//! Pseudo-console handle with automatic cleanup via `ClosePseudoConsole`.
//!
//! Mirrors `ghidra.pty.windows.PseudoConsoleHandle`: wraps a Windows pseudo-console
//! HANDLE and closes it via `ClosePseudoConsole` on drop (rather than the generic
//! `CloseHandle` used by [`Handle`](super::handle::Handle)).

use std::io;

use super::handle::RawHandle;
use super::jna::console_api_native as cna;
use super::jna::console_api_native::Coord;

/// A Windows pseudo-console HANDLE that is closed via `ClosePseudoConsole` on drop.
///
/// Mirrors `ghidra.pty.windows.PseudoConsoleHandle`, extending the base
/// [`Handle`](super::handle::Handle) behavior to use `ClosePseudoConsole` instead
/// of the generic `CloseHandle`.
pub struct PseudoConsoleHandle {
    raw: Option<RawHandle>,
}

impl PseudoConsoleHandle {
    /// Creates a new `PseudoConsoleHandle` that takes ownership of `raw`.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid, open Windows pseudo-console handle. This handle
    /// will be closed with `ClosePseudoConsole` when the `PseudoConsoleHandle`
    /// is dropped.
    pub unsafe fn new(raw: RawHandle) -> Self {
        PseudoConsoleHandle { raw: Some(raw) }
    }

    /// Returns the underlying Windows pseudo-console HANDLE.
    ///
    /// # Errors
    ///
    /// Returns `Err` if this handle has already been closed.
    pub fn as_raw(&self) -> io::Result<RawHandle> {
        self.raw.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "This handle is no longer valid")
        })
    }

    /// Resizes the pseudo-console to the given dimensions.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the resize operation fails (including if this handle has
    /// already been closed).
    ///
    /// Mirrors `ghidra.pty.windows.PseudoConsoleHandle.resize()`.
    pub fn resize(&self, rows: i16, cols: i16) -> io::Result<()> {
        let raw = self.as_raw()?;
        let size = Coord::new(cols, rows);

        #[cfg(target_os = "windows")]
        {
            let result = unsafe { cna::ResizePseudoConsole(raw, size) };
            if result < 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (raw, size);
        }

        Ok(())
    }

    /// Explicitly closes the pseudo-console and returns any OS error.
    ///
    /// After this call, [`as_raw`](Self::as_raw) will return `Err`. Subsequent
    /// calls to `close` are no-ops. When the `PseudoConsoleHandle` is dropped
    /// without an explicit `close`, any OS error is silently discarded.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(h) = self.raw.take() {
            #[cfg(target_os = "windows")]
            unsafe {
                cna::ClosePseudoConsole(h);
            }

            #[cfg(not(target_os = "windows"))]
            {
                let _ = h;
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for PseudoConsoleHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.raw {
            Some(h) => write!(f, "PseudoConsoleHandle({:p})", h),
            None => write!(f, "PseudoConsoleHandle(closed)"),
        }
    }
}

impl Drop for PseudoConsoleHandle {
    fn drop(&mut self) {
        if let Some(h) = self.raw.take() {
            #[cfg(target_os = "windows")]
            unsafe {
                cna::ClosePseudoConsole(h);
            }

            #[cfg(not(target_os = "windows"))]
            {
                let _ = h;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_pseudo_console_handle() -> PseudoConsoleHandle {
        unsafe { PseudoConsoleHandle::new(ptr::null_mut()) }
    }

    #[test]
    fn new_handle_as_raw_is_ok() {
        let h = null_pseudo_console_handle();
        assert!(h.as_raw().is_ok());
        std::mem::forget(h);
    }

    #[test]
    fn as_raw_returns_stored_pointer() {
        let sentinel: RawHandle = 0x4242 as *mut _;
        let h = unsafe { PseudoConsoleHandle::new(sentinel) };
        assert_eq!(h.as_raw().unwrap(), sentinel);
        std::mem::forget(h);
    }

    #[test]
    fn close_invalidates_handle() {
        let mut h = null_pseudo_console_handle();
        let _ = h.close();
        assert!(h.as_raw().is_err());
    }

    #[test]
    fn double_close_is_idempotent() {
        let mut h = null_pseudo_console_handle();
        let _ = h.close();
        let result = h.close();
        assert!(result.is_ok());
    }

    #[test]
    fn as_raw_error_contains_message() {
        let mut h = null_pseudo_console_handle();
        let _ = h.close();
        let err = h.as_raw().unwrap_err();
        assert!(err.to_string().contains("no longer valid"));
    }

    #[test]
    fn debug_open_shows_pointer() {
        let h = null_pseudo_console_handle();
        let s = format!("{:?}", h);
        assert!(s.starts_with("PseudoConsoleHandle("));
        std::mem::forget(h);
    }

    #[test]
    fn debug_closed_shows_closed() {
        let mut h = null_pseudo_console_handle();
        let _ = h.close();
        assert_eq!(format!("{:?}", h), "PseudoConsoleHandle(closed)");
    }

    #[test]
    fn resize_fails_when_closed() {
        let mut h = null_pseudo_console_handle();
        let _ = h.close();
        let result = h.resize(24, 80);
        assert!(result.is_err());
    }

    #[test]
    fn resize_requires_valid_handle() {
        let h = null_pseudo_console_handle();
        let result = h.resize(24, 80);
        assert!(result.is_ok());
        std::mem::forget(h);
    }
}
