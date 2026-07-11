//! Windows native-process pty session, controlled directly by handle (no ConPTY).

use std::io;
use std::time::Duration;

use super::handle::Handle;
#[cfg(target_os = "windows")]
use super::jna::job_api_native;
use crate::pty::PtySession;

/// Win32 `INFINITE`: block [`ffi::WaitForSingleObject`] until the object is signaled.
#[allow(dead_code)]
const INFINITE: u32 = 0xFFFF_FFFF;
/// Win32 `WAIT_OBJECT_0`: the wait completed because the object was signaled.
#[allow(dead_code)]
const WAIT_OBJECT_0: u32 = 0x0000_0000;
/// Win32 `WAIT_ABANDONED`: the wait completed because a mutex was abandoned.
#[allow(dead_code)]
const WAIT_ABANDONED: u32 = 0x0000_0080;
/// Win32 `WAIT_TIMEOUT`: the wait timed out before the object was signaled.
#[allow(dead_code)]
const WAIT_TIMEOUT: u32 = 0x0000_0102;
/// Win32 `WAIT_FAILED`: the wait call itself failed; consult `GetLastError`.
#[allow(dead_code)]
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
/// Win32 `STILL_ACTIVE`: the exit code reported for a process that has not exited.
#[allow(dead_code)]
const STILL_ACTIVE: u32 = 259;

#[cfg(target_os = "windows")]
mod ffi {
    use crate::pty::windows::handle::RawHandle;

    extern "system" {
        pub fn WaitForSingleObject(h_handle: RawHandle, dw_milliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(h_process: RawHandle, lp_exit_code: *mut u32) -> i32;
        pub fn GetLastError() -> u32;
    }
}

/// A pty session led by a native Windows process, managed via a job object.
///
/// Mirrors `ghidra.pty.local.LocalWindowsNativeProcessPtySession`: waits on and
/// terminates the session leader using the raw Win32 process and job handles,
/// rather than Rust's [`std::process::Child`].
pub struct LocalWindowsNativeProcessPtySession {
    pid: u32,
    #[allow(dead_code)]
    process_handle: Handle,
    pty_name: String,
    #[allow(dead_code)]
    job_handle: Handle,
}

impl LocalWindowsNativeProcessPtySession {
    /// Creates a new session for the process identified by `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID of the session leader
    /// * `tid` - The thread ID of the session leader's initial thread (unused; kept for parity with the Java constructor)
    /// * `process_handle` - An open handle to the session leader process
    /// * `thread_handle` - An open handle to the session leader's initial thread (unused; closed immediately)
    /// * `pty_name` - The name of the pseudo-terminal
    /// * `job_handle` - An open handle to the job object containing the session leader and its descendants
    pub fn new(
        pid: u32,
        _tid: u32,
        process_handle: Handle,
        _thread_handle: Handle,
        pty_name: String,
        job_handle: Handle,
    ) -> Self {
        tracing::info!("local Windows Pty session. PID = {}", pid);
        Self {
            pid,
            process_handle,
            pty_name,
            job_handle,
        }
    }

    #[cfg(target_os = "windows")]
    fn do_wait_exited(&self, millis: u32) -> io::Result<i32> {
        loop {
            let raw = self.process_handle.as_raw()?;
            let wait_result = unsafe { ffi::WaitForSingleObject(raw, millis) };
            if wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED {
                let mut exit_code: u32 = 0;
                unsafe { ffi::GetExitCodeProcess(raw, &mut exit_code) };
                if exit_code != STILL_ACTIVE {
                    return Ok(exit_code as i32);
                }
                // Signaled, but the process is somehow still active: falls through
                // to the timeout case, mirroring the Java switch's fallthrough.
                return Err(io::Error::new(io::ErrorKind::TimedOut, "wait timed out"));
            }
            if wait_result == WAIT_TIMEOUT {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "wait timed out"));
            }
            if wait_result == WAIT_FAILED {
                let err = unsafe { ffi::GetLastError() };
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            // Unrecognized result: retry, matching the Java `while (true)` loop.
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn do_wait_exited(&self, _millis: u32) -> io::Result<i32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "LocalWindowsNativeProcessPtySession requires Windows",
        ))
    }
}

impl PtySession for LocalWindowsNativeProcessPtySession {
    fn wait_exited(&self) -> io::Result<i32> {
        match self.do_wait_exited(INFINITE) {
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                panic!("infinite wait timed out unexpectedly: {e}")
            }
            other => other,
        }
    }

    fn wait_exited_timeout(&self, timeout: Duration) -> io::Result<i32> {
        let millis = timeout.as_millis();
        if millis > u32::MAX as u128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Too long a timeout"));
        }
        self.do_wait_exited(millis as u32)
    }

    fn destroy_forcibly(&self) {
        #[cfg(target_os = "windows")]
        {
            if let Ok(raw) = self.job_handle.as_raw() {
                if unsafe { job_api_native::TerminateJobObject(raw, 1) } == job_api_native::FALSE {
                    let err = unsafe { ffi::GetLastError() };
                    tracing::warn!(
                        "failed to terminate job object: {}",
                        io::Error::from_raw_os_error(err as i32)
                    );
                }
            }
        }
    }

    fn description(&self) -> String {
        format!("process {} on {}", self.pid, self.pty_name)
    }

    fn handle(&self) -> u32 {
        self.pid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_session() -> LocalWindowsNativeProcessPtySession {
        let process_handle = unsafe { Handle::new(ptr::null_mut()) };
        let thread_handle = unsafe { Handle::new(ptr::null_mut()) };
        let job_handle = unsafe { Handle::new(ptr::null_mut()) };
        LocalWindowsNativeProcessPtySession::new(
            4242,
            1,
            process_handle,
            thread_handle,
            "test_pty".to_string(),
            job_handle,
        )
    }

    #[test]
    fn description_returns_formatted_string() {
        let session = null_session();
        assert_eq!(session.description(), "process 4242 on test_pty");
    }

    #[test]
    fn handle_returns_pid() {
        let session = null_session();
        assert_eq!(session.handle(), 4242);
    }

    #[test]
    fn destroy_forcibly_does_not_panic() {
        let session = null_session();
        session.destroy_forcibly();
    }

    #[test]
    fn wait_exited_timeout_rejects_overlong_timeout() {
        let session = null_session();
        let err = session
            .wait_exited_timeout(Duration::from_millis(u32::MAX as u64 + 1))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn wait_exited_timeout_unsupported_on_non_windows() {
        let session = null_session();
        let err = session
            .wait_exited_timeout(Duration::from_millis(10))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn wait_exited_unsupported_on_non_windows() {
        let session = null_session();
        let err = session.wait_exited().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn win32_constants_match_expected_values() {
        assert_eq!(INFINITE, 0xFFFF_FFFF);
        assert_eq!(WAIT_OBJECT_0, 0);
        assert_eq!(WAIT_ABANDONED, 0x80);
        assert_eq!(WAIT_TIMEOUT, 0x102);
        assert_eq!(WAIT_FAILED, 0xFFFF_FFFF);
        assert_eq!(STILL_ACTIVE, 259);
    }
}
