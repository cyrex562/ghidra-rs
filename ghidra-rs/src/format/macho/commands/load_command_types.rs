/// After macOS X 10.1, new load commands required to be understood by the
/// dynamic linker have this bit OR'd into their constant. If the dynamic
/// linker encounters such a command it does not understand, it refuses to
/// execute the image. Load commands without this bit that are not understood
/// are simply ignored.
pub const LC_REQ_DYLD: u32 = 0x80000000;

/// Segment of this file to be mapped.
pub const LC_SEGMENT: u32 = 0x1;
/// Link-edit stab symbol table info.
pub const LC_SYMTAB: u32 = 0x2;
/// Link-edit gdb symbol table info (obsolete).
pub const LC_SYMSEG: u32 = 0x3;
/// Thread.
pub const LC_THREAD: u32 = 0x4;
/// Unix thread (includes a stack).
pub const LC_UNIXTHREAD: u32 = 0x5;
/// Load a specified fixed VM shared library.
pub const LC_LOADFVMLIB: u32 = 0x6;
/// Fixed VM shared library identification.
pub const LC_IDFVMLIB: u32 = 0x7;
/// Object identification info (obsolete).
pub const LC_IDENT: u32 = 0x8;
/// Fixed VM file inclusion (internal use).
pub const LC_FVMFILE: u32 = 0x9;
/// Prepage command (internal use).
pub const LC_PREPAGE: u32 = 0xa;
/// Dynamic link-edit symbol table info.
pub const LC_DYSYMTAB: u32 = 0xb;
/// Load a dynamically linked shared library.
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// Dynamically linked shared lib ident.
pub const LC_ID_DYLIB: u32 = 0xd;
/// Load a dynamic linker.
pub const LC_LOAD_DYLINKER: u32 = 0xe;
/// Dynamic linker identification.
pub const LC_ID_DYLINKER: u32 = 0xf;
/// Modules prebound for a dynamically linked shared library.
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
/// Image routines.
pub const LC_ROUTINES: u32 = 0x11;
/// Sub framework.
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
/// Sub umbrella.
pub const LC_SUB_UMBRELLA: u32 = 0x13;
/// Sub client.
pub const LC_SUB_CLIENT: u32 = 0x14;
/// Sub library.
pub const LC_SUB_LIBRARY: u32 = 0x15;
/// Two-level namespace lookup hints.
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
/// Prebind checksum.
pub const LC_PREBIND_CKSUM: u32 = 0x17;
/// Load a dynamically linked shared library that is allowed to be missing
/// (all symbols are weak imported).
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
/// 64-bit segment of this file to be mapped.
pub const LC_SEGMENT_64: u32 = 0x19;
/// 64-bit image routines.
pub const LC_ROUTINES_64: u32 = 0x1a;
/// Specifies the 128-bit UUID for an image.
pub const LC_UUID: u32 = 0x1b;
/// Run path additions.
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
/// Location of code signature.
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// Location of info to split segments.
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
/// Load and re-export dylib.
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
/// Delay load of dylib until first use.
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// Encrypted segment information.
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
/// Compressed dyld information.
pub const LC_DYLD_INFO: u32 = 0x22;
/// Compressed dyld information only.
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
/// Load upward dylib.
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
/// Build for macOS minimum OS version.
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// Build for iPhoneOS minimum OS version.
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
/// Compressed table of function start addresses.
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// String for dyld to treat as an environment variable.
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
/// Replacement for LC_UNIXTHREAD.
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
/// Table of non-instructions in `__text`.
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// Source version used to build binary.
pub const LC_SOURCE_VERSION: u32 = 0x2a;
/// Code signing DRs copied from linked dylibs.
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
/// 64-bit encrypted segment information.
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
/// Linker options in MH_OBJECT files.
pub const LC_LINKER_OPTIONS: u32 = 0x2d;
/// Optimization hints in MH_OBJECT files.
pub const LC_OPTIMIZATION_HINT: u32 = 0x2e;
/// Build for AppleTV minimum OS version.
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
/// Build for Watch minimum OS version.
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// Arbitrary data included within a Mach-O file.
pub const LC_NOTE: u32 = 0x31;
/// Build for platform minimum OS version.
pub const LC_BUILD_VERSION: u32 = 0x32;
/// Used with linkedit_data_command; payload is a trie.
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
/// Used with linkedit_data_command.
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
/// Used with fileset_entry_command.
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

/// Returns the name of the given load command type, or
/// `"LC_UNKNOWN_<HEX>"` if the type is not recognized.
pub fn get_load_command_name(load_type: u32) -> String {
    match load_type {
        LC_SEGMENT => "LC_SEGMENT",
        LC_SYMTAB => "LC_SYMTAB",
        LC_SYMSEG => "LC_SYMSEG",
        LC_THREAD => "LC_THREAD",
        LC_UNIXTHREAD => "LC_UNIXTHREAD",
        LC_LOADFVMLIB => "LC_LOADFVMLIB",
        LC_IDFVMLIB => "LC_IDFVMLIB",
        LC_IDENT => "LC_IDENT",
        LC_FVMFILE => "LC_FVMFILE",
        LC_PREPAGE => "LC_PREPAGE",
        LC_DYSYMTAB => "LC_DYSYMTAB",
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_ID_DYLIB => "LC_ID_DYLIB",
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
        LC_ID_DYLINKER => "LC_ID_DYLINKER",
        LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB",
        LC_ROUTINES => "LC_ROUTINES",
        LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK",
        LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA",
        LC_SUB_CLIENT => "LC_SUB_CLIENT",
        LC_SUB_LIBRARY => "LC_SUB_LIBRARY",
        LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS",
        LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_ROUTINES_64 => "LC_ROUTINES_64",
        LC_UUID => "LC_UUID",
        LC_RPATH => "LC_RPATH",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_DYLD_INFO => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT",
        LC_MAIN => "LC_MAIN",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_LINKER_OPTIONS => "LC_LINKER_OPTIONS",
        LC_OPTIMIZATION_HINT => "LC_OPTIMIZATION_HINT",
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        LC_NOTE => "LC_NOTE",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        LC_FILESET_ENTRY => "LC_FILESET_ENTRY",
        _ => return format!("LC_UNKNOWN_{:X}", load_type),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lc_req_dyld_flag() {
        assert_eq!(LC_REQ_DYLD, 0x80000000);
    }

    #[test]
    fn plain_constants() {
        assert_eq!(LC_SEGMENT, 0x1);
        assert_eq!(LC_SYMTAB, 0x2);
        assert_eq!(LC_SYMSEG, 0x3);
        assert_eq!(LC_THREAD, 0x4);
        assert_eq!(LC_UNIXTHREAD, 0x5);
        assert_eq!(LC_LOADFVMLIB, 0x6);
        assert_eq!(LC_IDFVMLIB, 0x7);
        assert_eq!(LC_IDENT, 0x8);
        assert_eq!(LC_FVMFILE, 0x9);
        assert_eq!(LC_PREPAGE, 0xa);
        assert_eq!(LC_DYSYMTAB, 0xb);
        assert_eq!(LC_LOAD_DYLIB, 0xc);
        assert_eq!(LC_ID_DYLIB, 0xd);
        assert_eq!(LC_LOAD_DYLINKER, 0xe);
        assert_eq!(LC_ID_DYLINKER, 0xf);
        assert_eq!(LC_PREBOUND_DYLIB, 0x10);
        assert_eq!(LC_ROUTINES, 0x11);
        assert_eq!(LC_SUB_FRAMEWORK, 0x12);
        assert_eq!(LC_SUB_UMBRELLA, 0x13);
        assert_eq!(LC_SUB_CLIENT, 0x14);
        assert_eq!(LC_SUB_LIBRARY, 0x15);
        assert_eq!(LC_TWOLEVEL_HINTS, 0x16);
        assert_eq!(LC_PREBIND_CKSUM, 0x17);
        assert_eq!(LC_SEGMENT_64, 0x19);
        assert_eq!(LC_ROUTINES_64, 0x1a);
        assert_eq!(LC_UUID, 0x1b);
        assert_eq!(LC_CODE_SIGNATURE, 0x1d);
        assert_eq!(LC_SEGMENT_SPLIT_INFO, 0x1e);
        assert_eq!(LC_LAZY_LOAD_DYLIB, 0x20);
        assert_eq!(LC_ENCRYPTION_INFO, 0x21);
        assert_eq!(LC_DYLD_INFO, 0x22);
        assert_eq!(LC_VERSION_MIN_MACOSX, 0x24);
        assert_eq!(LC_VERSION_MIN_IPHONEOS, 0x25);
        assert_eq!(LC_FUNCTION_STARTS, 0x26);
        assert_eq!(LC_DYLD_ENVIRONMENT, 0x27);
        assert_eq!(LC_DATA_IN_CODE, 0x29);
        assert_eq!(LC_SOURCE_VERSION, 0x2a);
        assert_eq!(LC_DYLIB_CODE_SIGN_DRS, 0x2b);
        assert_eq!(LC_ENCRYPTION_INFO_64, 0x2c);
        assert_eq!(LC_LINKER_OPTIONS, 0x2d);
        assert_eq!(LC_OPTIMIZATION_HINT, 0x2e);
        assert_eq!(LC_VERSION_MIN_TVOS, 0x2f);
        assert_eq!(LC_VERSION_MIN_WATCHOS, 0x30);
        assert_eq!(LC_NOTE, 0x31);
        assert_eq!(LC_BUILD_VERSION, 0x32);
    }

    #[test]
    fn req_dyld_constants() {
        assert_eq!(LC_LOAD_WEAK_DYLIB, 0x18 | LC_REQ_DYLD);
        assert_eq!(LC_RPATH, 0x1c | LC_REQ_DYLD);
        assert_eq!(LC_REEXPORT_DYLIB, 0x1f | LC_REQ_DYLD);
        assert_eq!(LC_DYLD_INFO_ONLY, 0x22 | LC_REQ_DYLD);
        assert_eq!(LC_LOAD_UPWARD_DYLIB, 0x23 | LC_REQ_DYLD);
        assert_eq!(LC_MAIN, 0x28 | LC_REQ_DYLD);
        assert_eq!(LC_DYLD_EXPORTS_TRIE, 0x33 | LC_REQ_DYLD);
        assert_eq!(LC_DYLD_CHAINED_FIXUPS, 0x34 | LC_REQ_DYLD);
        assert_eq!(LC_FILESET_ENTRY, 0x35 | LC_REQ_DYLD);
    }

    #[test]
    fn get_load_command_name_known() {
        assert_eq!(get_load_command_name(LC_SEGMENT), "LC_SEGMENT");
        assert_eq!(get_load_command_name(LC_SYMTAB), "LC_SYMTAB");
        assert_eq!(get_load_command_name(LC_DYLD_INFO), "LC_DYLD_INFO");
        assert_eq!(get_load_command_name(LC_DYLD_INFO_ONLY), "LC_DYLD_INFO_ONLY");
        assert_eq!(get_load_command_name(LC_MAIN), "LC_MAIN");
        assert_eq!(get_load_command_name(LC_FILESET_ENTRY), "LC_FILESET_ENTRY");
    }

    #[test]
    fn get_load_command_name_unknown() {
        assert_eq!(get_load_command_name(0xFF), "LC_UNKNOWN_FF");
        assert_eq!(get_load_command_name(0x0), "LC_UNKNOWN_0");
        assert_eq!(get_load_command_name(0xDEAD), "LC_UNKNOWN_DEAD");
    }
}
