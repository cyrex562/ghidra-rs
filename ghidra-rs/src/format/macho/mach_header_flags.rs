/// Constants for the `flags` field of the `mach_header`.
///
/// See `EXTERNAL_HEADERS/mach-o/loader.h` in the XNU source.

/// The object file has no undefined references.
pub const MH_NOUNDEFS: u32 = 0x1;

/// The object file is the output of an incremental link against a base file and
/// cannot be link-edited again.
pub const MH_INCRLINK: u32 = 0x2;

/// The object file is input for the dynamic linker and cannot be statically
/// link-edited again.
pub const MH_DYLDLINK: u32 = 0x4;

/// The object file's undefined references are bound by the dynamic linker when
/// loaded.
pub const MH_BINDATLOAD: u32 = 0x8;

/// The file has its dynamic undefined references prebound.
pub const MH_PREBOUND: u32 = 0x10;

/// The file has its read-only and read-write segments split.
pub const MH_SPLIT_SEGS: u32 = 0x20;

/// The shared library init routine is to be run lazily via catching memory
/// faults to its writeable segments (obsolete).
pub const MH_LAZY_INIT: u32 = 0x40;

/// The image is using two-level name space bindings.
pub const MH_TWOLEVEL: u32 = 0x80;

/// The executable is forcing all images to use flat name space bindings.
pub const MH_FORCE_FLAT: u32 = 0x100;

/// This umbrella guarantees no multiple definitions of symbols in its
/// sub-images so the two-level namespace hints can always be used.
pub const MH_NOMULTIDEFS: u32 = 0x200;

/// Do not have dyld notify the prebinding agent about this executable.
pub const MH_NOFIXPREBINDING: u32 = 0x400;

/// The binary is not prebound but can have its prebinding redone. Only used
/// when `MH_PREBOUND` is not set.
pub const MH_PREBINDABLE: u32 = 0x800;

/// Indicates that this binary binds to all two-level namespace modules of its
/// dependent libraries. Only used when both `MH_PREBINDABLE` and `MH_TWOLEVEL`
/// are set.
pub const MH_ALLMODSBOUND: u32 = 0x1000;

/// Safe to divide up the sections into sub-sections via symbols for dead code
/// stripping.
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;

/// The binary has been canonicalized via the unprebind operation.
pub const MH_CANONICAL: u32 = 0x4000;

/// The final linked image contains external weak symbols.
pub const MH_WEAK_DEFINES: u32 = 0x8000;

/// The final linked image uses weak symbols.
pub const MH_BINDS_TO_WEAK: u32 = 0x10000;

/// When set, all stacks in the task will be given stack execution privilege.
/// Only used in `MH_EXECUTE` file types.
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;

/// The binary declares it is safe for use in processes with uid zero.
pub const MH_ROOT_SAFE: u32 = 0x40000;

/// The binary declares it is safe for use in processes when `issetugid()` is
/// true.
pub const MH_SETUID_SAFE: u32 = 0x80000;

/// When set on a dylib, the static linker does not need to examine dependent
/// dylibs to see if any are re-exported.
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x100000;

/// When set, the OS will load the main executable at a random address. Only
/// used in `MH_EXECUTE` file types.
pub const MH_PIE: u32 = 0x200000;

/// Only for use on dylibs. When linking against a dylib that has this bit set,
/// the static linker will automatically not create a `LC_LOAD_DYLIB` load
/// command to the dylib if no symbols are being referenced from the dylib.
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x400000;

/// Contains a section of type `S_THREAD_LOCAL_VARIABLES`.
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x800000;

/// When set, the OS will run the main executable with a non-executable heap
/// even on platforms that don't require it. Only used in `MH_EXECUTE` file
/// types.
pub const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;

/// The code was linked for use in an application extension.
pub const MH_APP_EXTENSION_SAFE: u32 = 0x2000000;

/// The external symbols listed in the nlist symbol table do not include all the
/// symbols listed in the dyld info.
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x04000000;

/// Allow `LC_MIN_VERSION_MACOS` and `LC_BUILD_VERSION` load commands with the
/// platforms macOS, iOSMac, iOSSimulator, tvOSSimulator and
/// watchOSSimulator.
pub const MH_SIM_SUPPORT: u32 = 0x08000000;

/// Only for use on dylibs. When set, the dylib is part of the dyld shared
/// cache, rather than loose in the filesystem.
pub const MH_DYLIB_IN_CACHE: u32 = 0x80000000;

/// All known flags in declaration order, paired with the short name returned by
/// [`get_flags`] (i.e. the `MH_` prefix is stripped).
static FLAG_TABLE: &[(u32, &str)] = &[
    (MH_NOUNDEFS, "NOUNDEFS"),
    (MH_INCRLINK, "INCRLINK"),
    (MH_DYLDLINK, "DYLDLINK"),
    (MH_BINDATLOAD, "BINDATLOAD"),
    (MH_PREBOUND, "PREBOUND"),
    (MH_SPLIT_SEGS, "SPLIT_SEGS"),
    (MH_LAZY_INIT, "LAZY_INIT"),
    (MH_TWOLEVEL, "TWOLEVEL"),
    (MH_FORCE_FLAT, "FORCE_FLAT"),
    (MH_NOMULTIDEFS, "NOMULTIDEFS"),
    (MH_NOFIXPREBINDING, "NOFIXPREBINDING"),
    (MH_PREBINDABLE, "PREBINDABLE"),
    (MH_ALLMODSBOUND, "ALLMODSBOUND"),
    (MH_SUBSECTIONS_VIA_SYMBOLS, "SUBSECTIONS_VIA_SYMBOLS"),
    (MH_CANONICAL, "CANONICAL"),
    (MH_WEAK_DEFINES, "WEAK_DEFINES"),
    (MH_BINDS_TO_WEAK, "BINDS_TO_WEAK"),
    (MH_ALLOW_STACK_EXECUTION, "ALLOW_STACK_EXECUTION"),
    (MH_ROOT_SAFE, "ROOT_SAFE"),
    (MH_SETUID_SAFE, "SETUID_SAFE"),
    (MH_NO_REEXPORTED_DYLIBS, "NO_REEXPORTED_DYLIBS"),
    (MH_PIE, "PIE"),
    (MH_DEAD_STRIPPABLE_DYLIB, "DEAD_STRIPPABLE_DYLIB"),
    (MH_HAS_TLV_DESCRIPTORS, "HAS_TLV_DESCRIPTORS"),
    (MH_NO_HEAP_EXECUTION, "NO_HEAP_EXECUTION"),
    (MH_APP_EXTENSION_SAFE, "APP_EXTENSION_SAFE"),
    (MH_NLIST_OUTOFSYNC_WITH_DYLDINFO, "NLIST_OUTOFSYNC_WITH_DYLDINFO"),
    (MH_SIM_SUPPORT, "SIM_SUPPORT"),
    (MH_DYLIB_IN_CACHE, "DYLIB_IN_CACHE"),
];

/// Returns the short names (without the `MH_` prefix) of every flag bit that
/// is set in `flags`.
///
/// The names are returned in the same declaration order as the Java source,
/// preserving parity with `MachHeaderFlags.getFlags(int)`.
pub fn get_flags(flags: u32) -> Vec<&'static str> {
    FLAG_TABLE
        .iter()
        .filter(|(value, _)| flags & value != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(MH_NOUNDEFS, 0x1);
        assert_eq!(MH_INCRLINK, 0x2);
        assert_eq!(MH_DYLDLINK, 0x4);
        assert_eq!(MH_BINDATLOAD, 0x8);
        assert_eq!(MH_PREBOUND, 0x10);
        assert_eq!(MH_SPLIT_SEGS, 0x20);
        assert_eq!(MH_LAZY_INIT, 0x40);
        assert_eq!(MH_TWOLEVEL, 0x80);
        assert_eq!(MH_FORCE_FLAT, 0x100);
        assert_eq!(MH_NOMULTIDEFS, 0x200);
        assert_eq!(MH_NOFIXPREBINDING, 0x400);
        assert_eq!(MH_PREBINDABLE, 0x800);
        assert_eq!(MH_ALLMODSBOUND, 0x1000);
        assert_eq!(MH_SUBSECTIONS_VIA_SYMBOLS, 0x2000);
        assert_eq!(MH_CANONICAL, 0x4000);
        assert_eq!(MH_WEAK_DEFINES, 0x8000);
        assert_eq!(MH_BINDS_TO_WEAK, 0x10000);
        assert_eq!(MH_ALLOW_STACK_EXECUTION, 0x20000);
        assert_eq!(MH_ROOT_SAFE, 0x40000);
        assert_eq!(MH_SETUID_SAFE, 0x80000);
        assert_eq!(MH_NO_REEXPORTED_DYLIBS, 0x100000);
        assert_eq!(MH_PIE, 0x200000);
        assert_eq!(MH_DEAD_STRIPPABLE_DYLIB, 0x400000);
        assert_eq!(MH_HAS_TLV_DESCRIPTORS, 0x800000);
        assert_eq!(MH_NO_HEAP_EXECUTION, 0x1000000);
        assert_eq!(MH_APP_EXTENSION_SAFE, 0x2000000);
        assert_eq!(MH_NLIST_OUTOFSYNC_WITH_DYLDINFO, 0x04000000);
        assert_eq!(MH_SIM_SUPPORT, 0x08000000);
        assert_eq!(MH_DYLIB_IN_CACHE, 0x80000000);
    }

    #[test]
    fn get_flags_zero_returns_empty() {
        assert!(get_flags(0).is_empty());
    }

    #[test]
    fn get_flags_single_bit() {
        assert_eq!(get_flags(MH_NOUNDEFS), vec!["NOUNDEFS"]);
        assert_eq!(get_flags(MH_PIE), vec!["PIE"]);
        assert_eq!(get_flags(MH_DYLIB_IN_CACHE), vec!["DYLIB_IN_CACHE"]);
    }

    #[test]
    fn get_flags_multiple_bits() {
        let flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
        let names = get_flags(flags);
        assert_eq!(names, vec!["NOUNDEFS", "DYLDLINK", "TWOLEVEL", "PIE"]);
    }

    #[test]
    fn get_flags_all_flags_set() {
        let all: u32 = FLAG_TABLE.iter().map(|(v, _)| v).fold(0, |acc, &v| acc | v);
        let names = get_flags(all);
        assert_eq!(names.len(), FLAG_TABLE.len());
    }

    #[test]
    fn get_flags_order_matches_declaration() {
        let flags = MH_PIE | MH_NOUNDEFS;
        let names = get_flags(flags);
        // NOUNDEFS declared before PIE, so it must appear first.
        assert_eq!(names[0], "NOUNDEFS");
        assert_eq!(names[1], "PIE");
    }
}
