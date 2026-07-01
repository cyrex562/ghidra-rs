//! Rust FFI bindings for Windows Kernel32 job object APIs.
//!
//! Mirrors `ghidra.pty.windows.jna.JobApiNative`: type definitions and
//! function declarations for `CreateJobObjectW`, `AssignProcessToJobObject`,
//! and `TerminateJobObject`.

#[cfg(target_os = "windows")]
use crate::pty::windows::handle::RawHandle;

/// Type alias for bool return values from Win32 APIs.
pub type Bool = i32;

/// Win32 `FALSE` sentinel for failed boolean-result API calls.
pub const FALSE: Bool = 0;

// ── FFI declarations (Windows only) ──────────────────────────────────────────

#[cfg(target_os = "windows")]
extern "system" {
    /// Creates a named or anonymous job object.
    ///
    /// Maps to Win32 `CreateJobObjectW` from kernel32.dll.
    pub fn CreateJobObjectW(
        lp_job_attributes: *mut std::ffi::c_void,
        lp_name: *const u16,
    ) -> RawHandle;

    /// Assigns a process to a job object.
    ///
    /// Maps to Win32 `AssignProcessToJobObject` from kernel32.dll.
    pub fn AssignProcessToJobObject(
        h_job: RawHandle,
        h_process: RawHandle,
    ) -> Bool;

    /// Terminates all processes in a job object.
    ///
    /// Maps to Win32 `TerminateJobObject` from kernel32.dll.
    pub fn TerminateJobObject(h_job: RawHandle, u_exit_code: u32) -> Bool;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn false_constant_is_zero() {
        assert_eq!(FALSE, 0);
    }
}
