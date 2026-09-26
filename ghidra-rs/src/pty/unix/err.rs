//! Port of `ghidra.pty.unix.Err`.
//!
//! # Shape
//!
//! An interface with one static method and one static field, both existing only to build a
//! `LastErrorException` message (rule R8d-constants-module: a Java constant-interface with no
//! dispatch ports as a plain module, not a trait). `std::io::Error::last_os_error()` already
//! reads the OS's `errno` and formats its own message, so there is nothing left for the port to
//! carry from `Err.BARE_POSIX`/`strerror` -- [`check_lt0`] is the one thing that mattered.

use std::io;

/// Checks a POSIX-style return value (`< 0` means failure, with the reason in `errno`) and
/// turns it into an [`io::Result`], mirroring `Err.checkLt0`.
pub fn check_lt0(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_negative_result_passes_through() {
        assert_eq!(check_lt0(0).unwrap(), 0);
        assert_eq!(check_lt0(42).unwrap(), 42);
    }

    #[test]
    fn negative_result_becomes_an_os_error() {
        let err = check_lt0(-1).unwrap_err();
        // errno is whatever the last failing libc call in this thread set; we only assert
        // that a negative result is reliably turned into an error, not any particular errno.
        assert!(err.raw_os_error().is_some());
    }
}
