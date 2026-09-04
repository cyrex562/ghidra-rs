//! Pseudo-console handle with automatic cleanup via `ClosePseudoConsole`.
//!
//! Mirrors `ghidra.pty.windows.PseudoConsoleHandle`: wraps a Windows pseudo-console
//! HANDLE and closes it via `ClosePseudoConsole` on drop (rather than the generic
//! `CloseHandle` used by [`Handle`](super::handle::Handle)).
//!
//! # Shared ownership
//!
//! Java aliases a single `PseudoConsoleHandle` object across `ConPty`, `ConPtyParent`, and
//! `ConPtyChild` (`ConPty`'s constructor passes the same reference into both endpoints), and
//! only `ConPty.close()` ever closes it -- the endpoints only read it (`ConPtyChild.
//! setWindowSize` calls `resize()` on it directly). A naive Rust port with one owned,
//! close-on-drop `PseudoConsoleHandle` per endpoint would double-close the native handle the
//! moment more than one endpoint held one. This type is [`Clone`] and reference-counted instead
//! ([`Arc`]-backed): the real `ClosePseudoConsole` call happens exactly once, whenever the
//! *last* clone is dropped, however many clones exist or in whatever order they drop -- and
//! [`close`](Self::close) can still force it early, matching `ConPty.close()`'s explicit intent.

use std::io;
use std::sync::{Arc, Mutex};

use super::handle::RawHandle;
use super::jna::console_api_native as cna;
use super::jna::console_api_native::Coord;

struct Inner(Mutex<Option<RawHandle>>);

/// # Safety
///
/// Windows HANDLEs are valid kernel object references that may be transferred across and
/// shared between threads; access to the raw pointer itself is already serialized by the
/// `Mutex`, matching `Handle`'s own `unsafe impl Send`.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        close_raw(self.0.lock().unwrap().take());
    }
}

fn close_raw(raw: Option<RawHandle>) {
    if let Some(h) = raw {
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

/// A Windows pseudo-console HANDLE, shared (via [`Clone`]) across every part of a `ConPty` that
/// needs it, closed via `ClosePseudoConsole` exactly once when the last clone is dropped or
/// [`close`](Self::close) is called explicitly.
///
/// Mirrors `ghidra.pty.windows.PseudoConsoleHandle`, extending the base
/// [`Handle`](super::handle::Handle) behavior to use `ClosePseudoConsole` instead
/// of the generic `CloseHandle`.
#[derive(Clone)]
pub struct PseudoConsoleHandle {
    inner: Arc<Inner>,
}

impl PseudoConsoleHandle {
    /// Creates a new `PseudoConsoleHandle` that takes ownership of `raw`.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid, open Windows pseudo-console handle. It will be closed with
    /// `ClosePseudoConsole` when the last clone of the returned handle is dropped (or
    /// [`close`](Self::close) is called explicitly on any clone).
    pub unsafe fn new(raw: RawHandle) -> Self {
        PseudoConsoleHandle {
            inner: Arc::new(Inner(Mutex::new(Some(raw)))),
        }
    }

    /// Returns the underlying Windows pseudo-console HANDLE.
    ///
    /// # Errors
    ///
    /// Returns `Err` if this handle (or any clone of it) has already been closed.
    pub fn as_raw(&self) -> io::Result<RawHandle> {
        self.inner.0.lock().unwrap().ok_or_else(|| {
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

    /// Explicitly closes the pseudo-console (for every clone of this handle) and returns any OS
    /// error. After this call, [`as_raw`](Self::as_raw) returns `Err` on every clone.
    /// Subsequent calls, from any clone, are no-ops.
    pub fn close(&self) -> io::Result<()> {
        close_raw(self.inner.0.lock().unwrap().take());
        Ok(())
    }
}

impl std::fmt::Debug for PseudoConsoleHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self.inner.0.lock().unwrap() {
            Some(h) => write!(f, "PseudoConsoleHandle({:p})", h),
            None => write!(f, "PseudoConsoleHandle(closed)"),
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
    }

    #[test]
    fn as_raw_returns_stored_pointer() {
        let sentinel: RawHandle = 0x4242 as *mut _;
        let h = unsafe { PseudoConsoleHandle::new(sentinel) };
        assert_eq!(h.as_raw().unwrap(), sentinel);
    }

    #[test]
    fn close_invalidates_handle() {
        let h = null_pseudo_console_handle();
        let _ = h.close();
        assert!(h.as_raw().is_err());
    }

    #[test]
    fn double_close_is_idempotent() {
        let h = null_pseudo_console_handle();
        let _ = h.close();
        let result = h.close();
        assert!(result.is_ok());
    }

    #[test]
    fn as_raw_error_contains_message() {
        let h = null_pseudo_console_handle();
        let _ = h.close();
        let err = h.as_raw().unwrap_err();
        assert!(err.to_string().contains("no longer valid"));
    }

    #[test]
    fn debug_open_shows_pointer() {
        let h = null_pseudo_console_handle();
        let s = format!("{:?}", h);
        assert!(s.starts_with("PseudoConsoleHandle("));
    }

    #[test]
    fn debug_closed_shows_closed() {
        let h = null_pseudo_console_handle();
        let _ = h.close();
        assert_eq!(format!("{:?}", h), "PseudoConsoleHandle(closed)");
    }

    #[test]
    fn resize_fails_when_closed() {
        let h = null_pseudo_console_handle();
        let _ = h.close();
        let result = h.resize(24, 80);
        assert!(result.is_err());
    }

    #[test]
    fn resize_requires_valid_handle() {
        let h = null_pseudo_console_handle();
        let result = h.resize(24, 80);
        assert!(result.is_ok());
    }

    #[test]
    fn clones_share_the_same_handle() {
        let h = null_pseudo_console_handle();
        let clone = h.clone();
        assert_eq!(h.as_raw().unwrap(), clone.as_raw().unwrap());
    }

    #[test]
    fn closing_one_clone_closes_them_all() {
        let h = null_pseudo_console_handle();
        let clone = h.clone();
        h.close().unwrap();
        assert!(clone.as_raw().is_err());
    }

    #[test]
    fn dropping_one_clone_does_not_close_the_others() {
        let h = null_pseudo_console_handle();
        let clone = h.clone();
        drop(h);
        // The real ClosePseudoConsole only fires once the LAST clone drops; `clone` is still
        // alive here, so the handle must still be valid.
        assert!(clone.as_raw().is_ok());
    }
}
