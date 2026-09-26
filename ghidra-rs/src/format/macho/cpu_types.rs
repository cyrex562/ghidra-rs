//! Port of `ghidra.app.util.bin.format.macho.CpuTypes`.
//!
//! Mach-O `cputype`/`cpusubtype` constants (mirroring
//! `osfmk/mach/machine.h`) plus three small lookup helpers. Unlike the extensible named-constant
//! registries elsewhere in this crate (e.g.
//! [`ElfDynamicType`](crate::format::elf::elf_dynamic_type::ElfDynamicType)), Java never subclasses
//! or extends this set at runtime -- `CpuTypes` is a `final` class of plain `int` constants plus
//! `static` helper methods, so it is ported the same way: `pub const i32` values plus free
//! functions, matching the sibling [`cpu_sub_types`](super::cpu_sub_types) module's established
//! convention in this same directory.

use crate::program::model::lang::Processor;

/// Mask for architecture bits.
pub const CPU_ARCH_MASK: i32 = 0xff000000u32 as i32;
/// 64 bit ABI.
pub const CPU_ARCH_ABI64: i32 = 0x01000000;
/// ABI for 64-bit hardware with 32-bit types; LP32.
pub const CPU_ARCH_ABI64_32: i32 = 0x02000000;

pub const CPU_TYPE_ANY: i32 = -1;
pub const CPU_TYPE_VAX: i32 = 0x1;
// UNUSED                     0x2
// UNUSED                     0x3
// UNUSED                     0x4
// UNUSED                     0x5
pub const CPU_TYPE_MC680X0: i32 = 0x6;
pub const CPU_TYPE_X86: i32 = 0x7;
/// Compatibility alias for [`CPU_TYPE_X86`].
pub const CPU_TYPE_I386: i32 = CPU_TYPE_X86;
// CPU_TYPE_MIPS               0x8
// UNUSED                      0x9
pub const CPU_TYPE_MC98000: i32 = 0xa;
pub const CPU_TYPE_HPPA: i32 = 0xb;
pub const CPU_TYPE_ARM: i32 = 0xc;
pub const CPU_TYPE_MC88000: i32 = 0xd;
pub const CPU_TYPE_SPARC: i32 = 0xe;
pub const CPU_TYPE_I860: i32 = 0xf;
// CPU_TYPE_ALPHA               0x10
// UNUSED                       0x11
pub const CPU_TYPE_POWERPC: i32 = 0x12;

pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM_64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;

/// `CpuTypes.getProcessor(int, int)`.
///
/// Returns the [`Processor`] name of the given CPU type value. `cpu_subtype` is accepted for
/// parity with the Java signature but unused, exactly as in Java (every branch of the real
/// `switch` ignores it).
///
/// # Panics
/// Panics (standing in for Java's unconditional `throw new RuntimeException(...)` reached when no
/// `switch` arm matches) if `cpu_type` is not one of the recognized `CPU_TYPE_*` values.
pub fn get_processor(cpu_type: i32, _cpu_subtype: i32) -> Processor {
    match cpu_type {
        CPU_TYPE_X86 => Processor::find_or_possibly_create_processor("x86"),
        CPU_TYPE_X86_64 => Processor::find_or_possibly_create_processor("x86"),
        CPU_TYPE_POWERPC => Processor::find_or_possibly_create_processor("PowerPC"),
        CPU_TYPE_POWERPC64 => Processor::find_or_possibly_create_processor("PowerPC"),
        CPU_TYPE_I860 => Processor::find_or_possibly_create_processor("i860"),
        CPU_TYPE_SPARC => Processor::find_or_possibly_create_processor("Sparc"),
        CPU_TYPE_ARM => Processor::find_or_possibly_create_processor("ARM"),
        CPU_TYPE_ARM_64 => Processor::find_or_possibly_create_processor("AARCH64"),
        CPU_TYPE_ARM64_32 => Processor::find_or_possibly_create_processor("AARCH64"),
        _ => panic!("Unrecognized CPU type: 0x{:x}", cpu_type),
    }
}

/// `CpuTypes.getProcessorBitSize(int)`.
///
/// # Panics
/// Panics (standing in for Java's `throw new RuntimeException(...)` in the `switch`'s `default`
/// arm) if `cpu_type` is not one of the recognized `CPU_TYPE_*` values.
pub fn get_processor_bit_size(cpu_type: i32) -> i32 {
    match cpu_type {
        CPU_TYPE_ARM | CPU_TYPE_SPARC | CPU_TYPE_I860 | CPU_TYPE_POWERPC | CPU_TYPE_X86
        | CPU_TYPE_ARM64_32 => 32,
        CPU_TYPE_ARM_64 | CPU_TYPE_POWERPC64 | CPU_TYPE_X86_64 => 64,
        _ => panic!("Unrecognized CPU type: 0x{:x}", cpu_type),
    }
}

/// `CpuTypes.getMagicString(int, int)`.
///
/// For [`CPU_TYPE_ARM`], includes the subtype (`"cpuType.cpuSubtype"`); every other CPU type
/// ignores `cpu_subtype` entirely, exactly matching Java's `switch` expression (which has no other
/// case besides `ARM` and `default`).
pub fn get_magic_string(cpu_type: i32, cpu_subtype: i32) -> String {
    match cpu_type {
        CPU_TYPE_ARM => format!("{cpu_type}.{cpu_subtype}"),
        _ => format!("{cpu_type}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i386_is_an_alias_for_x86() {
        assert_eq!(CPU_TYPE_I386, CPU_TYPE_X86);
    }

    #[test]
    fn combined_64_bit_constants_or_in_the_abi64_bit() {
        assert_eq!(CPU_TYPE_POWERPC64, CPU_TYPE_POWERPC | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_X86_64, CPU_TYPE_X86 | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_ARM_64, CPU_TYPE_ARM | CPU_ARCH_ABI64);
        assert_eq!(CPU_TYPE_ARM64_32, CPU_TYPE_ARM | CPU_ARCH_ABI64_32);
    }

    #[test]
    fn arch_mask_covers_the_high_byte() {
        assert_eq!(CPU_ARCH_MASK as u32, 0xff000000);
        assert_eq!(CPU_TYPE_X86_64 & (CPU_ARCH_MASK as u32 as i32), CPU_ARCH_ABI64);
    }

    #[test]
    fn get_processor_maps_every_documented_cpu_type() {
        assert_eq!(get_processor(CPU_TYPE_X86, 0).to_string(), "x86");
        assert_eq!(get_processor(CPU_TYPE_X86_64, 0).to_string(), "x86");
        assert_eq!(get_processor(CPU_TYPE_POWERPC, 0).to_string(), "PowerPC");
        assert_eq!(get_processor(CPU_TYPE_POWERPC64, 0).to_string(), "PowerPC");
        assert_eq!(get_processor(CPU_TYPE_I860, 0).to_string(), "i860");
        assert_eq!(get_processor(CPU_TYPE_SPARC, 0).to_string(), "Sparc");
        assert_eq!(get_processor(CPU_TYPE_ARM, 0).to_string(), "ARM");
        assert_eq!(get_processor(CPU_TYPE_ARM_64, 0).to_string(), "AARCH64");
        assert_eq!(get_processor(CPU_TYPE_ARM64_32, 0).to_string(), "AARCH64");
    }

    #[test]
    fn get_processor_panics_on_unrecognized_cpu_type() {
        // CPU_TYPE_VAX and CPU_TYPE_MC680X0 are real, named cputype constants, but Java's
        // getProcessor switch has no case for them, so it falls through to the trailing
        // `throw new RuntimeException(...)` -- faithfully reproduced as a panic here.
        let result = std::panic::catch_unwind(|| get_processor(CPU_TYPE_VAX, 0));
        assert!(result.is_err());
    }

    #[test]
    fn get_processor_bit_size_groups_32_and_64_bit_types() {
        for cpu_type in [
            CPU_TYPE_ARM,
            CPU_TYPE_SPARC,
            CPU_TYPE_I860,
            CPU_TYPE_POWERPC,
            CPU_TYPE_X86,
            CPU_TYPE_ARM64_32,
        ] {
            assert_eq!(get_processor_bit_size(cpu_type), 32);
        }
        for cpu_type in [CPU_TYPE_ARM_64, CPU_TYPE_POWERPC64, CPU_TYPE_X86_64] {
            assert_eq!(get_processor_bit_size(cpu_type), 64);
        }
    }

    #[test]
    fn get_processor_bit_size_panics_on_unrecognized_cpu_type() {
        let result = std::panic::catch_unwind(|| get_processor_bit_size(CPU_TYPE_VAX));
        assert!(result.is_err());
    }

    #[test]
    fn get_magic_string_includes_subtype_only_for_arm() {
        assert_eq!(get_magic_string(CPU_TYPE_ARM, 9), "12.9");
        assert_eq!(get_magic_string(CPU_TYPE_X86, 3), "7");
        assert_eq!(get_magic_string(CPU_TYPE_POWERPC, 5), "18");
    }

    #[test]
    fn get_magic_string_never_panics_on_unrecognized_type() {
        // Unlike getProcessor/getProcessorBitSize, Java's getMagicString `default` arm returns a
        // value instead of throwing.
        assert_eq!(get_magic_string(CPU_TYPE_VAX, 0), "1");
    }
}
