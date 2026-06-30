//! Rust FFI bindings for Windows Kernel32 console/pseudo-console APIs.
//!
//! Mirrors `ghidra.pty.windows.jna.ConsoleApiNative`: type definitions and
//! function declarations for `CreatePseudoConsole`, `ResizePseudoConsole`,
//! `ClosePseudoConsole`, `CreateProcessW`, and related Win32 helpers.

use std::ffi::c_void;

use crate::pty::windows::handle::RawHandle;

// ── Type aliases ──────────────────────────────────────────────────────────────

pub type Bool = i32;
pub type DWord = u32;
pub type ULong = u32;
pub type ULongLong = u64;
pub type HResult = i32;

/// Win32 `FALSE` sentinel returned by boolean-result API functions.
pub const FALSE: Bool = 0;

// ── Structures ────────────────────────────────────────────────────────────────

/// Console screen-buffer coordinate (column, row).
///
/// Maps to Win32 `COORD` and `ConsoleApiNative.COORD` in the Java source.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Coord {
    pub x: i16,
    pub y: i16,
}

impl Coord {
    /// Creates a coordinate from column `x` and row `y`.
    pub fn new(x: i16, y: i16) -> Self {
        Coord { x, y }
    }
}

/// Win32 `SECURITY_ATTRIBUTES` as modelled by the JNA binding.
///
/// `lp_security_descriptor` is stored as `u64` (matching the Java source's
/// `ULONGLONG` field) so the layout is stable on 64-bit Windows.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityAttributes {
    pub n_length: DWord,
    pub lp_security_descriptor: ULongLong,
    pub b_inherited_handle: Bool,
}

/// Internal layout of a `PROC_THREAD_ATTRIBUTE_LIST` allocation.
///
/// The Win32 type is opaque; these fields mirror the JNA binding in the Java
/// source (`ConsoleApiNative.PROC_THREAD_ATTRIBUTE_LIST`). The FFI functions
/// accept the allocation as `*mut c_void`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcThreadAttributeList {
    pub dw_flags: DWord,
    pub size: ULong,
    pub count: ULong,
    pub reserved: ULong,
    pub unknown: ULongLong,
}

/// Win32 `STARTUPINFOW` structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StartupInfoW {
    pub cb: DWord,
    pub lp_reserved: *mut u16,
    pub lp_desktop: *mut u16,
    pub lp_title: *mut u16,
    pub dw_x: DWord,
    pub dw_y: DWord,
    pub dw_x_size: DWord,
    pub dw_y_size: DWord,
    pub dw_x_count_chars: DWord,
    pub dw_y_count_chars: DWord,
    pub dw_fill_attribute: DWord,
    pub dw_flags: DWord,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: RawHandle,
    pub h_std_output: RawHandle,
    pub h_std_error: RawHandle,
}

impl Default for StartupInfoW {
    fn default() -> Self {
        StartupInfoW {
            cb: std::mem::size_of::<StartupInfoW>() as DWord,
            lp_reserved: std::ptr::null_mut(),
            lp_desktop: std::ptr::null_mut(),
            lp_title: std::ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: std::ptr::null_mut(),
            h_std_input: std::ptr::null_mut(),
            h_std_output: std::ptr::null_mut(),
            h_std_error: std::ptr::null_mut(),
        }
    }
}

/// Win32 `STARTUPINFOEXW` structure.
///
/// Extends `StartupInfoW` with a pointer to a process-thread attribute list.
/// Maps to `ConsoleApiNative.STARTUPINFOEX` in the Java source.
///
/// The `startup_info.cb` field is initialised to `size_of::<StartupInfoEx>()`
/// by [`Default`] — required when passing `EXTENDED_STARTUPINFO_PRESENT`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StartupInfoEx {
    pub startup_info: StartupInfoW,
    pub lp_attribute_list: *mut c_void,
}

impl Default for StartupInfoEx {
    fn default() -> Self {
        let mut s = StartupInfoEx {
            startup_info: StartupInfoW::default(),
            lp_attribute_list: std::ptr::null_mut(),
        };
        s.startup_info.cb = std::mem::size_of::<StartupInfoEx>() as DWord;
        s
    }
}

/// Win32 `PROCESS_INFORMATION` structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessInformation {
    pub h_process: RawHandle,
    pub h_thread: RawHandle,
    pub dw_process_id: DWord,
    pub dw_thread_id: DWord,
}

// ── FFI declarations (Windows only) ──────────────────────────────────────────

#[cfg(target_os = "windows")]
extern "system" {
    /// Creates an anonymous pipe; fills `*h_read_pipe` and `*h_write_pipe`.
    pub fn CreatePipe(
        h_read_pipe: *mut RawHandle,
        h_write_pipe: *mut RawHandle,
        lp_pipe_attributes: *mut SecurityAttributes,
        n_size: DWord,
    ) -> Bool;

    /// Allocates a new pseudo-console of the given dimensions.
    pub fn CreatePseudoConsole(
        size: Coord,
        h_input: RawHandle,
        h_output: RawHandle,
        dw_flags: DWord,
        ph_pc: *mut RawHandle,
    ) -> HResult;

    /// Resizes an existing pseudo-console.
    pub fn ResizePseudoConsole(h_pc: RawHandle, size: Coord) -> HResult;

    /// Closes a pseudo-console and frees its resources.
    pub fn ClosePseudoConsole(h_pc: RawHandle);

    /// Initialises a process-thread attribute list.
    ///
    /// Pass `lp_attribute_list` as null and `*lp_size` as 0 on the first call
    /// to obtain the required allocation size; then allocate and call again.
    pub fn InitializeProcThreadAttributeList(
        lp_attribute_list: *mut c_void,
        dw_attribute_count: DWord,
        dw_flags: DWord,
        lp_size: *mut usize,
    ) -> Bool;

    /// Adds or updates an attribute in a process-thread attribute list.
    pub fn UpdateProcThreadAttribute(
        lp_attribute_list: *mut c_void,
        dw_flags: DWord,
        attribute: usize,
        lp_value: *mut c_void,
        cb_size: usize,
        lp_previous_value: *mut c_void,
        lp_return_size: *mut usize,
    ) -> Bool;

    /// Creates a new process and its primary thread.
    ///
    /// When `lp_startup_info` points to a [`StartupInfoEx`], include
    /// `EXTENDED_STARTUPINFO_PRESENT` (0x00080000) in `dw_creation_flags`.
    pub fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut SecurityAttributes,
        lp_thread_attributes: *mut SecurityAttributes,
        b_inherit_handles: Bool,
        dw_creation_flags: DWord,
        lp_environment: *mut c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *mut StartupInfoEx,
        lp_process_information: *mut ProcessInformation,
    ) -> Bool;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn coord_default_is_origin() {
        let c = Coord::default();
        assert_eq!(c.x, 0);
        assert_eq!(c.y, 0);
    }

    #[test]
    fn coord_new_stores_fields() {
        let c = Coord::new(80, 24);
        assert_eq!(c.x, 80);
        assert_eq!(c.y, 24);
    }

    #[test]
    fn coord_size_is_four_bytes() {
        assert_eq!(mem::size_of::<Coord>(), 4);
    }

    #[test]
    fn coord_equality() {
        assert_eq!(Coord::new(1, 2), Coord::new(1, 2));
        assert_ne!(Coord::new(1, 2), Coord::new(3, 4));
    }

    #[test]
    fn security_attributes_default_is_zeroed() {
        let s = SecurityAttributes::default();
        assert_eq!(s.n_length, 0);
        assert_eq!(s.lp_security_descriptor, 0);
        assert_eq!(s.b_inherited_handle, 0);
    }

    #[test]
    fn proc_thread_attribute_list_default_is_zeroed() {
        let p = ProcThreadAttributeList::default();
        assert_eq!(p.dw_flags, 0);
        assert_eq!(p.size, 0);
        assert_eq!(p.count, 0);
        assert_eq!(p.reserved, 0);
        assert_eq!(p.unknown, 0);
    }

    #[test]
    fn startup_info_w_default_cb_matches_struct_size() {
        let s = StartupInfoW::default();
        assert_eq!(s.cb as usize, mem::size_of::<StartupInfoW>());
        assert!(s.lp_reserved.is_null());
        assert!(s.lp_desktop.is_null());
        assert!(s.lp_title.is_null());
        assert!(s.lp_reserved2.is_null());
        assert!(s.h_std_input.is_null());
        assert!(s.h_std_output.is_null());
        assert!(s.h_std_error.is_null());
    }

    #[test]
    fn startup_info_ex_default_cb_matches_extended_size() {
        let s = StartupInfoEx::default();
        assert_eq!(
            s.startup_info.cb as usize,
            mem::size_of::<StartupInfoEx>()
        );
        assert!(s.lp_attribute_list.is_null());
    }

    #[test]
    fn process_information_default_handles_are_null() {
        let p = ProcessInformation::default();
        assert!(p.h_process.is_null());
        assert!(p.h_thread.is_null());
        assert_eq!(p.dw_process_id, 0);
        assert_eq!(p.dw_thread_id, 0);
    }

    #[test]
    fn false_constant_is_zero() {
        assert_eq!(FALSE, 0);
    }

    /// Verify the `#[repr(C)]` layouts match documented Win32 sizes on x86-64.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn struct_sizes_on_64bit() {
        assert_eq!(mem::size_of::<Coord>(), 4);
        assert_eq!(mem::size_of::<SecurityAttributes>(), 24);
        assert_eq!(mem::size_of::<ProcThreadAttributeList>(), 24);
        assert_eq!(mem::size_of::<StartupInfoW>(), 104);
        assert_eq!(mem::size_of::<StartupInfoEx>(), 112);
        assert_eq!(mem::size_of::<ProcessInformation>(), 24);
    }
}
