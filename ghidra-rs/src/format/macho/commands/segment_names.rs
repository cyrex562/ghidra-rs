/// Well-known Mach-O segment name strings.
///
/// Corresponds to `SegmentNames.java` in the Ghidra source.

/// The pagezero segment — no protections; catches NULL dereferences in `MH_EXECUTE` files.
pub const PAGEZERO: &str = "__PAGEZERO";
/// The traditional UNIX text segment.
pub const TEXT: &str = "__TEXT";
/// The traditional UNIX data segment.
pub const DATA: &str = "__DATA";
/// The Objective-C runtime segment.
pub const OBJC: &str = "__OBJC";
/// The icon segment.
pub const ICON: &str = "__ICON";
/// Contains all structs created and maintained by the link editor.
///
/// Created with `-seglinkedit` option to `ld(1)` for `MH_EXECUTE` and `FVMLIB` file types only.
pub const LINKEDIT: &str = "__LINKEDIT";
/// The UNIX stack segment.
pub const UNIXSTACK: &str = "__UNIXSTACK";
/// The segment for self-modifying (dyld) code stubs; has read, write, and execute permissions.
pub const IMPORT: &str = "__IMPORT";
/// Executable text segment used by some kernels (e.g. arm64 XNU).
pub const TEXT_EXEC: &str = "__TEXT_EXEC";
/// Pre-linked kernel extension text segment.
pub const PRELINK_TEXT: &str = "__PRELINK_TEXT";
/// Arm64e branch stubs segment.
pub const BRANCH_STUBS: &str = "__BRANCH_STUBS";
/// Arm64e branch GOTs segment.
pub const BRANCH_GOTS: &str = "__BRANCH_GOTS";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_segment_names() {
        assert_eq!(PAGEZERO, "__PAGEZERO");
        assert_eq!(TEXT, "__TEXT");
        assert_eq!(DATA, "__DATA");
        assert_eq!(OBJC, "__OBJC");
        assert_eq!(ICON, "__ICON");
        assert_eq!(LINKEDIT, "__LINKEDIT");
        assert_eq!(UNIXSTACK, "__UNIXSTACK");
        assert_eq!(IMPORT, "__IMPORT");
    }

    #[test]
    fn extended_segment_names() {
        assert_eq!(TEXT_EXEC, "__TEXT_EXEC");
        assert_eq!(PRELINK_TEXT, "__PRELINK_TEXT");
        assert_eq!(BRANCH_STUBS, "__BRANCH_STUBS");
        assert_eq!(BRANCH_GOTS, "__BRANCH_GOTS");
    }

    #[test]
    fn all_names_start_with_double_underscore() {
        let names = [
            PAGEZERO, TEXT, DATA, OBJC, ICON, LINKEDIT, UNIXSTACK, IMPORT,
            TEXT_EXEC, PRELINK_TEXT, BRANCH_STUBS, BRANCH_GOTS,
        ];
        for name in &names {
            assert!(name.starts_with("__"), "{name} should start with '__'");
        }
    }
}
