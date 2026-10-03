//! Port of `ghidra.pty.unix.Util`.
//!
//! # Shape
//!
//! An interface with one abstract method (rule R9-open-interface -> trait), binding
//! `openpty(3)`. As with [`super::posix_c`], Java's `BARE`/`INSTANCE` split collapses into one
//! [`UtilImpl`] -- nothing outside this file calls the unchecked `BARE` form.

use std::ffi::CStr;
use std::io;

use super::err::check_lt0;

/// The interface for linking to `openpty(3)` (port of `Util`).
pub trait Util: Send + Sync {
    /// Opens a new pseudo-terminal pair.
    ///
    /// Returns `(parent_fd, child_fd, child_device_name)`, mirroring
    /// `Util.INSTANCE.openpty(amaster, aslave, name, termp, winp)` with `termp`/`winp` left
    /// null, as every caller in this codebase does.
    fn openpty(&self) -> io::Result<(i32, i32, String)>;
}

/// The one production implementor of [`Util`] (port of `Util.INSTANCE`).
pub struct UtilImpl;

impl Util for UtilImpl {
    fn openpty(&self) -> io::Result<(i32, i32, String)> {
        let mut amaster: libc::c_int = -1;
        let mut aslave: libc::c_int = -1;
        // openpty(3) writes the child's device path (NUL-terminated) into this buffer; POSIX
        // guarantees paths fit well within this size.
        let mut name_buf = [0u8; 1024];
        // SAFETY: amaster/aslave/name_buf are valid, appropriately-sized out-params; termp/winp
        // are optional and passed null, matching every caller in this codebase.
        let ret = unsafe {
            libc::openpty(
                &mut amaster,
                &mut aslave,
                name_buf.as_mut_ptr() as *mut libc::c_char,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        check_lt0(ret)?;
        // SAFETY: openpty(3) NUL-terminates the name on success, and name_buf outlives this use.
        let name = unsafe { CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char) }
            .to_string_lossy()
            .into_owned();
        Ok((amaster, aslave, name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openpty_returns_distinct_valid_fds_and_a_device_name() {
        let util = UtilImpl;
        let (parent_fd, child_fd, name) = util.openpty().expect("openpty should succeed in CI");
        assert!(parent_fd >= 0);
        assert!(child_fd >= 0);
        assert_ne!(parent_fd, child_fd);
        assert!(!name.is_empty());
        assert!(name.starts_with("/dev/"));
        unsafe {
            libc::close(parent_fd);
            libc::close(child_fd);
        }
    }
}
