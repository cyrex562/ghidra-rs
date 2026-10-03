/// Constants and lookups for the `filetype` field of the `mach_header`.

/// Relocatable object file.
pub const MH_OBJECT: u32 = 0x1;

/// Demand paged executable file.
pub const MH_EXECUTE: u32 = 0x2;

/// Fixed VM shared library file.
pub const MH_FVMLIB: u32 = 0x3;

/// Core file.
pub const MH_CORE: u32 = 0x4;

/// Preloaded executable file.
pub const MH_PRELOAD: u32 = 0x5;

/// Dynamically bound shared library.
pub const MH_DYLIB: u32 = 0x6;

/// Dynamic link editor.
pub const MH_DYLINKER: u32 = 0x7;

/// Dynamically bound bundle file.
pub const MH_BUNDLE: u32 = 0x8;

/// Shared library stub for static linking only, no section contents.
pub const MH_DYLIB_STUB: u32 = 0x9;

/// Linking only, no section contents, companion file with only debug sections.
pub const MH_DSYM: u32 = 0xa;

/// x86_64 kexts.
pub const MH_KEXT_BUNDLE: u32 = 0xb;

/// Kernel cache fileset.
pub const MH_FILESET: u32 = 0xc;

/// All known file types in declaration order, paired with the short name
/// returned by [`get_file_type_name`] (i.e. the `MH_` prefix is stripped).
static FILE_TYPE_TABLE: &[(u32, &str)] = &[
    (MH_OBJECT, "OBJECT"),
    (MH_EXECUTE, "EXECUTE"),
    (MH_FVMLIB, "FVMLIB"),
    (MH_CORE, "CORE"),
    (MH_PRELOAD, "PRELOAD"),
    (MH_DYLIB, "DYLIB"),
    (MH_DYLINKER, "DYLINKER"),
    (MH_BUNDLE, "BUNDLE"),
    (MH_DYLIB_STUB, "DYLIB_STUB"),
    (MH_DSYM, "DSYM"),
    (MH_KEXT_BUNDLE, "KEXT_BUNDLE"),
    (MH_FILESET, "FILESET"),
];

/// Returns the short name (without the `MH_` prefix) of `file_type`, or a
/// message describing it as unrecognized.
pub fn get_file_type_name(file_type: u32) -> String {
    FILE_TYPE_TABLE
        .iter()
        .find(|(value, _)| *value == file_type)
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| format!("Unrecognized file type: {:#x}", file_type))
}

/// Returns a human-readable description of `file_type`, or a message
/// describing it as unrecognized.
pub fn get_file_type_description(file_type: u32) -> String {
    match file_type {
        MH_OBJECT => "Relocatable Object File",
        MH_EXECUTE => "Demand Paged Executable File",
        MH_FVMLIB => "Fixed VM Shared Library File",
        MH_CORE => "Core File",
        MH_PRELOAD => "Preloaded Executable File",
        MH_DYLIB => "Dynamically Bound Shared Library",
        MH_DYLINKER => "Dynamic Link Editor",
        MH_BUNDLE => "Dynamically Bound Bundle File",
        MH_DYLIB_STUB => "Shared Library Stub for Static Linking Only",
        MH_DSYM => "Companion file with only debug sections",
        MH_KEXT_BUNDLE => "x86 64 Kernel Extension",
        MH_FILESET => "Kernel Cache Fileset",
        _ => return format!("Unrecognized file type: {:#x}", file_type),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(MH_OBJECT, 0x1);
        assert_eq!(MH_EXECUTE, 0x2);
        assert_eq!(MH_FVMLIB, 0x3);
        assert_eq!(MH_CORE, 0x4);
        assert_eq!(MH_PRELOAD, 0x5);
        assert_eq!(MH_DYLIB, 0x6);
        assert_eq!(MH_DYLINKER, 0x7);
        assert_eq!(MH_BUNDLE, 0x8);
        assert_eq!(MH_DYLIB_STUB, 0x9);
        assert_eq!(MH_DSYM, 0xa);
        assert_eq!(MH_KEXT_BUNDLE, 0xb);
        assert_eq!(MH_FILESET, 0xc);
    }

    #[test]
    fn get_file_type_name_known_values() {
        assert_eq!(get_file_type_name(MH_OBJECT), "OBJECT");
        assert_eq!(get_file_type_name(MH_EXECUTE), "EXECUTE");
        assert_eq!(get_file_type_name(MH_FILESET), "FILESET");
    }

    #[test]
    fn get_file_type_name_unrecognized() {
        assert_eq!(
            get_file_type_name(0xdead),
            "Unrecognized file type: 0xdead"
        );
    }

    #[test]
    fn get_file_type_description_known_values() {
        assert_eq!(get_file_type_description(MH_OBJECT), "Relocatable Object File");
        assert_eq!(
            get_file_type_description(MH_EXECUTE),
            "Demand Paged Executable File"
        );
        assert_eq!(
            get_file_type_description(MH_KEXT_BUNDLE),
            "x86 64 Kernel Extension"
        );
        assert_eq!(
            get_file_type_description(MH_FILESET),
            "Kernel Cache Fileset"
        );
    }

    #[test]
    fn get_file_type_description_unrecognized() {
        assert_eq!(
            get_file_type_description(0xdead),
            "Unrecognized file type: 0xdead"
        );
    }
}
