//! Constants for ELF program header segment types and flags.
//!
//! Ported from `ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants`.

// Segment Types

/// Unused/Undefined segment.
pub const PT_NULL: u32 = 0;
/// Loadable segment.
pub const PT_LOAD: u32 = 1;
/// Dynamic linking information (.dynamic section).
pub const PT_DYNAMIC: u32 = 2;
/// Interpreter path name.
pub const PT_INTERP: u32 = 3;
/// Auxiliary information location.
pub const PT_NOTE: u32 = 4;
/// Unused.
pub const PT_SHLIB: u32 = 5;
/// Program header table.
pub const PT_PHDR: u32 = 6;
/// Thread-local storage segment.
pub const PT_TLS: u32 = 7;

/// GCC .eh_frame_hdr segment.
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
/// Indicates stack executability.
pub const PT_GNU_STACK: u32 = 0x6474e551;
/// Specifies segments which may be read-only after relocation.
pub const PT_GNU_RELRO: u32 = 0x6474e552;
/// Sun Specific segment.
pub const PT_SUNWBSS: u32 = 0x6ffffffa;
/// Stack segment.
pub const PT_SUNWSTACK: u32 = 0x6ffffffb;

// Segment Permission Flags

/// Segment is executable.
pub const PF_X: u32 = 1 << 0;
/// Segment is writable.
pub const PF_W: u32 = 1 << 1;
/// Segment is readable.
pub const PF_R: u32 = 1 << 2;
/// OS-specific flag mask.
pub const PF_MASKOS: u32 = 0x0ff00000;
/// Processor-specific flag mask.
pub const PF_MASKPROC: u32 = 0xf0000000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pt_standard_segment_types() {
        assert_eq!(PT_NULL, 0);
        assert_eq!(PT_LOAD, 1);
        assert_eq!(PT_DYNAMIC, 2);
        assert_eq!(PT_INTERP, 3);
        assert_eq!(PT_NOTE, 4);
        assert_eq!(PT_SHLIB, 5);
        assert_eq!(PT_PHDR, 6);
        assert_eq!(PT_TLS, 7);
    }

    #[test]
    fn pt_gnu_segment_types() {
        assert_eq!(PT_GNU_EH_FRAME, 0x6474e550);
        assert_eq!(PT_GNU_STACK, 0x6474e551);
        assert_eq!(PT_GNU_RELRO, 0x6474e552);
    }

    #[test]
    fn pt_sun_segment_types() {
        assert_eq!(PT_SUNWBSS, 0x6ffffffa);
        assert_eq!(PT_SUNWSTACK, 0x6ffffffb);
    }

    #[test]
    fn pf_flag_bits() {
        assert_eq!(PF_X, 0x1);
        assert_eq!(PF_W, 0x2);
        assert_eq!(PF_R, 0x4);
    }

    #[test]
    fn pf_masks() {
        assert_eq!(PF_MASKOS, 0x0ff00000);
        assert_eq!(PF_MASKPROC, 0xf0000000);
    }

    #[test]
    fn pf_maskos_and_maskproc_do_not_overlap() {
        assert_eq!(PF_MASKOS & PF_MASKPROC, 0);
    }

    #[test]
    fn pf_rwx_flags_are_disjoint() {
        assert_eq!(PF_R & PF_W, 0);
        assert_eq!(PF_R & PF_X, 0);
        assert_eq!(PF_W & PF_X, 0);
    }

    #[test]
    fn pt_gnu_eh_frame_sequential() {
        assert_eq!(PT_GNU_STACK, PT_GNU_EH_FRAME + 1);
        assert_eq!(PT_GNU_RELRO, PT_GNU_EH_FRAME + 2);
    }
}
