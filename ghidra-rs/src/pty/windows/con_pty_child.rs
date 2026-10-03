//! Port of `ghidra.pty.windows.ConPtyChild` (rule R14a-concrete-leaf -> struct).
//!
//! Wraps a [`ConPtyEndpoint`] by composition, matching the [`ConPtyParent`] pattern. `session()`
//! attaches a freshly created process to the pseudo-console directly via the Win32
//! `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` startup-info attribute -- unlike the UNIX side, there
//! is no `pre_exec`-style hook needed here; the pseudo-console attachment happens as part of
//! `CreateProcessW` itself, exactly mirroring the Java source.
//!
//! Real ConPTY process creation is a Windows-only API surface with no equivalent on this
//! project's Linux dev/CI machine, so (matching the existing precedent in
//! [`super::local_windows_native_process_pty_session`]) the real path is `#[cfg(target_os =
//! "windows")]`-gated and only compile-checked here; non-Windows targets get a stub that
//! returns `io::ErrorKind::Unsupported`.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use crate::pty::{PtyChild, PtyEndpoint, PtySession, TermMode};

use super::con_pty_endpoint::ConPtyEndpoint;
use super::handle::Handle;
use super::pseudo_console_handle::PseudoConsoleHandle;

/// The child end of a Windows pseudo-console (port of `ConPtyChild`).
pub struct ConPtyChild(ConPtyEndpoint);

impl ConPtyChild {
    /// Creates a new pseudo-console child from read and write handles.
    pub fn new(
        write_handle: Handle,
        read_handle: Handle,
        pseudo_console_handle: PseudoConsoleHandle,
    ) -> Self {
        ConPtyChild(ConPtyEndpoint::new(write_handle, read_handle, pseudo_console_handle))
    }

    /// Returns a reference to the underlying pseudo-console handle.
    pub fn pseudo_console_handle(&self) -> &PseudoConsoleHandle {
        self.0.pseudo_console_handle()
    }

    /// Closes this endpoint's underlying handles; see [`ConPtyEndpoint::close_streams`].
    pub fn close_streams(&self) -> io::Result<()> {
        self.0.close_streams()
    }
}

impl PtyEndpoint for ConPtyChild {
    fn get_output_stream(&self) -> io::Result<Box<dyn std::io::Write>> {
        self.0.get_output_stream()
    }

    fn get_input_stream(&self) -> io::Result<Box<dyn std::io::Read>> {
        self.0.get_input_stream()
    }
}

impl PtyChild for ConPtyChild {
    fn session(
        &self,
        args: &[String],
        env: &HashMap<String, String>,
        working_directory: Option<&Path>,
        _mode: &[Box<dyn TermMode>],
    ) -> io::Result<Box<dyn PtySession>> {
        // TODO (matches the Java source's own TODOs): local echo is not controllable through
        // ConPTY the way UnixPtyChild's disable_echo is; `_mode` is accepted for API parity but
        // unused, same as upstream.
        #[cfg(target_os = "windows")]
        {
            windows_impl::spawn(args, env, working_directory, self.pseudo_console_handle())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (args, env, working_directory);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ConPTY session spawning is only available on Windows",
            ))
        }
    }

    fn null_session(&self, _mode: &[Box<dyn TermMode>]) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConPTY does not have a name",
        ))
    }

    fn set_window_size(&self, cols: u16, rows: u16) {
        if let Err(e) = self.pseudo_console_handle().resize(rows as i16, cols as i16) {
            tracing::error!("Could not set terminal window size: {e}");
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::HashMap;
    use std::io;
    use std::path::Path;

    use crate::pty::windows::handle::Handle;
    use crate::pty::windows::jna::console_api_native as cna;
    use crate::pty::windows::jna::job_api_native as jna_job;
    use crate::pty::windows::local_windows_native_process_pty_session::LocalWindowsNativeProcessPtySession;
    use crate::pty::windows::pseudo_console_handle::PseudoConsoleHandle;
    use crate::pty::shell_utils;
    use crate::pty::PtySession;

    const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x20016;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;

    fn to_wide(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn last_error() -> io::Error {
        io::Error::last_os_error()
    }

    pub(super) fn spawn(
        args: &[String],
        env: &HashMap<String, String>,
        working_directory: Option<&Path>,
        pseudo_console_handle: &PseudoConsoleHandle,
    ) -> io::Result<Box<dyn PtySession>> {
        // SAFETY: every raw pointer passed to these Win32 calls is either null (explicitly
        // allowed by the API) or points into a local that outlives the call.
        unsafe {
            let h_job = jna_job::CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if h_job.is_null() {
                return Err(last_error());
            }

            let mut si = cna::StartupInfoEx::default();
            si.startup_info.dw_flags = STARTF_USESTDHANDLES;

            let mut bytes_required: usize = 0;
            // First call deliberately fails; it only reports the required allocation size.
            let _ = cna::InitializeProcThreadAttributeList(
                std::ptr::null_mut(),
                1,
                0,
                &mut bytes_required,
            );
            let mut attr_list_buf = vec![0u8; bytes_required];
            let lp_attribute_list = attr_list_buf.as_mut_ptr() as *mut std::ffi::c_void;
            if cna::InitializeProcThreadAttributeList(lp_attribute_list, 1, 0, &mut bytes_required)
                == 0
            {
                jna_job::TerminateJobObject(h_job, 1);
                return Err(last_error());
            }

            let pc_raw = pseudo_console_handle.as_raw()?;
            if cna::UpdateProcThreadAttribute(
                lp_attribute_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                pc_raw as *mut std::ffi::c_void,
                std::mem::size_of::<*mut std::ffi::c_void>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                jna_job::TerminateJobObject(h_job, 1);
                return Err(last_error());
            }
            si.lp_attribute_list = lp_attribute_list;

            let mut command_line = to_wide(&shell_utils::generate_line(args));
            let env_block = if env.is_empty() {
                None
            } else {
                Some(to_wide(&shell_utils::generate_env_block(env)))
            };
            let work_dir = working_directory
                .map(|p| to_wide(&p.to_string_lossy()));

            let mut pi = cna::ProcessInformation::default();
            let ok = cna::CreateProcessW(
                std::ptr::null(),
                command_line.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env_block
                    .as_ref()
                    .map(|b| b.as_ptr() as *mut std::ffi::c_void)
                    .unwrap_or(std::ptr::null_mut()),
                work_dir
                    .as_ref()
                    .map(|w| w.as_ptr())
                    .unwrap_or(std::ptr::null()),
                &mut si,
                &mut pi,
            );
            if ok == 0 {
                jna_job::TerminateJobObject(h_job, 1);
                return Err(last_error());
            }

            if jna_job::AssignProcessToJobObject(h_job, pi.h_process) == 0 {
                return Err(last_error());
            }

            Ok(Box::new(LocalWindowsNativeProcessPtySession::new(
                pi.dw_process_id,
                pi.dw_thread_id,
                Handle::new(pi.h_process),
                Handle::new(pi.h_thread),
                "ConPTY".to_string(),
                Handle::new(h_job),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn null_child() -> ConPtyChild {
        let write_handle = unsafe { Handle::new(ptr::null_mut()) };
        let read_handle = unsafe { Handle::new(ptr::null_mut()) };
        let pseudo_console_handle = unsafe { PseudoConsoleHandle::new(ptr::null_mut()) };
        ConPtyChild::new(write_handle, read_handle, pseudo_console_handle)
    }

    #[test]
    fn implements_endpoint() {
        let child = null_child();
        assert!(child.get_output_stream().is_ok());
        assert!(child.get_input_stream().is_ok());
    }

    #[test]
    fn null_session_is_unsupported() {
        let child = null_child();
        let mode: Vec<Box<dyn TermMode>> = vec![];
        let err = child.null_session(&mode).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn session_is_unsupported_on_non_windows() {
        let child = null_child();
        let args = vec!["cmd.exe".to_string()];
        let env = HashMap::new();
        let mode: Vec<Box<dyn TermMode>> = vec![];
        match child.session(&args, &env, None, &mode) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected Unsupported on non-Windows"),
        }
    }

    #[test]
    fn set_window_size_does_not_panic_when_handle_is_closed() {
        let child = null_child();
        child.pseudo_console_handle().close().unwrap();
        // resize() on a closed handle errors; set_window_size only logs, never panics.
        child.set_window_size(80, 24);
    }
}
