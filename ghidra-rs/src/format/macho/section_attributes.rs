/// Constants for the `attributes` field of a Mach-O section header.
///
/// Corresponds to `SectionAttributes.java` in the Ghidra source.

/// Mask covering all 24 section-attribute bits.
pub const SECTION_ATTRIBUTES_MASK: u32 = 0xffff_ff00;

/// Mask for user-settable attribute bits.
pub const SECTION_ATTRIBUTES_USR: u32 = 0xff00_0000;

/// Mask for system-settable attribute bits.
pub const SECTION_ATTRIBUTES_SYS: u32 = 0x00ff_ff00;

/// Section contains only true machine instructions.
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;

/// Section contains coalesced symbols that are not to be in a ranlib table of
/// contents.
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;

/// OK to strip static symbols in this section in files with the
/// `MH_DYLDLINK` flag.
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;

/// Section must not be dead-stripped.
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;

/// Section is live — used with i386 code stubs written by dyld (live support).
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;

/// Used with i386 code stubs written on by dyld (self-modifying code).
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;

/// Section contains some machine instructions.
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

/// Section has external relocation entries.
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;

/// Section has local relocation entries.
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

/// All `S_ATTR_*` constants in declaration order, paired with the short name
/// returned by [`get_attribute_names`] (i.e. the `S_ATTR_` prefix stripped).
static ATTR_TABLE: &[(u32, &str)] = &[
    (S_ATTR_PURE_INSTRUCTIONS, "PURE_INSTRUCTIONS"),
    (S_ATTR_NO_TOC, "NO_TOC"),
    (S_ATTR_STRIP_STATIC_SYMS, "STRIP_STATIC_SYMS"),
    (S_ATTR_NO_DEAD_STRIP, "NO_DEAD_STRIP"),
    (S_ATTR_LIVE_SUPPORT, "LIVE_SUPPORT"),
    (S_ATTR_SELF_MODIFYING_CODE, "SELF_MODIFYING_CODE"),
    (S_ATTR_SOME_INSTRUCTIONS, "SOME_INSTRUCTIONS"),
    (S_ATTR_EXT_RELOC, "EXT_RELOC"),
    (S_ATTR_LOC_RELOC, "LOC_RELOC"),
];

/// Returns the short names (without the `S_ATTR_` prefix) of every attribute
/// bit that is set in `attributes`.
///
/// Preserves parity with `SectionAttributes.getAttributeNames(int)`.
pub fn get_attribute_names(attributes: u32) -> Vec<&'static str> {
    ATTR_TABLE
        .iter()
        .filter(|(value, _)| attributes & value != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(SECTION_ATTRIBUTES_MASK, 0xffff_ff00);
        assert_eq!(SECTION_ATTRIBUTES_USR, 0xff00_0000);
        assert_eq!(SECTION_ATTRIBUTES_SYS, 0x00ff_ff00);
        assert_eq!(S_ATTR_PURE_INSTRUCTIONS, 0x8000_0000);
        assert_eq!(S_ATTR_NO_TOC, 0x4000_0000);
        assert_eq!(S_ATTR_STRIP_STATIC_SYMS, 0x2000_0000);
        assert_eq!(S_ATTR_NO_DEAD_STRIP, 0x1000_0000);
        assert_eq!(S_ATTR_LIVE_SUPPORT, 0x0800_0000);
        assert_eq!(S_ATTR_SELF_MODIFYING_CODE, 0x0400_0000);
        assert_eq!(S_ATTR_SOME_INSTRUCTIONS, 0x0000_0400);
        assert_eq!(S_ATTR_EXT_RELOC, 0x0000_0200);
        assert_eq!(S_ATTR_LOC_RELOC, 0x0000_0100);
    }

    #[test]
    fn get_attribute_names_zero_returns_empty() {
        assert!(get_attribute_names(0).is_empty());
    }

    #[test]
    fn get_attribute_names_single_bits() {
        assert_eq!(get_attribute_names(S_ATTR_PURE_INSTRUCTIONS), vec!["PURE_INSTRUCTIONS"]);
        assert_eq!(get_attribute_names(S_ATTR_LOC_RELOC), vec!["LOC_RELOC"]);
        assert_eq!(get_attribute_names(S_ATTR_EXT_RELOC), vec!["EXT_RELOC"]);
        assert_eq!(get_attribute_names(S_ATTR_SOME_INSTRUCTIONS), vec!["SOME_INSTRUCTIONS"]);
    }

    #[test]
    fn get_attribute_names_multiple_bits() {
        let attrs = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_EXT_RELOC | S_ATTR_LOC_RELOC;
        let names = get_attribute_names(attrs);
        assert_eq!(names, vec!["PURE_INSTRUCTIONS", "EXT_RELOC", "LOC_RELOC"]);
    }

    #[test]
    fn get_attribute_names_order_matches_declaration() {
        // LOC_RELOC is declared after EXT_RELOC, so EXT_RELOC must appear first.
        let attrs = S_ATTR_LOC_RELOC | S_ATTR_EXT_RELOC;
        let names = get_attribute_names(attrs);
        assert_eq!(names[0], "EXT_RELOC");
        assert_eq!(names[1], "LOC_RELOC");
    }

    #[test]
    fn get_attribute_names_all_attrs_set() {
        let all: u32 = ATTR_TABLE.iter().fold(0, |acc, (v, _)| acc | v);
        let names = get_attribute_names(all);
        assert_eq!(names.len(), ATTR_TABLE.len());
    }

    #[test]
    fn masks_cover_attr_bits() {
        // Every S_ATTR_* bit must be within SECTION_ATTRIBUTES_MASK.
        for &(value, _) in ATTR_TABLE {
            assert_eq!(value & SECTION_ATTRIBUTES_MASK, value);
        }
    }
}
