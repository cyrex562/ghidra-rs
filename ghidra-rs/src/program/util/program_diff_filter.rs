/// Filter for program context (register) differences.
pub const PROGRAM_CONTEXT_DIFFS: u32 = 1 << 0;
/// Filter for byte differences.
pub const BYTE_DIFFS: u32 = 1 << 1;
/// Filter for code unit differences.
pub const CODE_UNIT_DIFFS: u32 = 1 << 2;
/// Filter for end-of-line comment differences.
pub const EOL_COMMENT_DIFFS: u32 = 1 << 3;
/// Filter for pre-comment differences.
pub const PRE_COMMENT_DIFFS: u32 = 1 << 4;
/// Filter for post-comment differences.
pub const POST_COMMENT_DIFFS: u32 = 1 << 5;
/// Filter for plate comment differences.
pub const PLATE_COMMENT_DIFFS: u32 = 1 << 6;
/// Filter for repeatable comment differences.
pub const REPEATABLE_COMMENT_DIFFS: u32 = 1 << 7;
/// Filter for memory, variable, and external reference differences.
pub const REFERENCE_DIFFS: u32 = 1 << 8;
/// Filter for equate differences.
pub const EQUATE_DIFFS: u32 = 1 << 9;
/// Filter for symbol differences.
pub const SYMBOL_DIFFS: u32 = 1 << 10;
/// Filter for function differences.
pub const FUNCTION_DIFFS: u32 = 1 << 11;
/// Filter for bookmark differences.
pub const BOOKMARK_DIFFS: u32 = 1 << 12;
/// Filter for user-defined property differences.
pub const USER_DEFINED_DIFFS: u32 = 1 << 13;
/// Filter for function tag differences.
pub const FUNCTION_TAG_DIFFS: u32 = 1 << 14;
/// Filter for source map differences.
pub const SOURCE_MAP_DIFFS: u32 = 1 << 15;

const NUM_PRIMARY_TYPES: usize = 16;

/// All comment-related difference filters combined.
pub const COMMENT_DIFFS: u32 = EOL_COMMENT_DIFFS
    | PRE_COMMENT_DIFFS
    | POST_COMMENT_DIFFS
    | REPEATABLE_COMMENT_DIFFS
    | PLATE_COMMENT_DIFFS;

/// All defined difference filters combined.
pub const ALL_DIFFS: u32 = BYTE_DIFFS
    | CODE_UNIT_DIFFS
    | COMMENT_DIFFS
    | REFERENCE_DIFFS
    | USER_DEFINED_DIFFS
    | SYMBOL_DIFFS
    | EQUATE_DIFFS
    | FUNCTION_DIFFS
    | BOOKMARK_DIFFS
    | FUNCTION_TAG_DIFFS
    | PROGRAM_CONTEXT_DIFFS
    | SOURCE_MAP_DIFFS;

/// Used when determining or working with differences between two programs.
///
/// Each difference type bit can be toggled independently. Combine types with `|`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProgramDiffFilter {
    filter_flags: u32,
}

impl ProgramDiffFilter {
    /// Creates a new filter with no diff types selected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new filter with the specified diff types selected.
    ///
    /// `type_flags` is one or more diff type constants OR-ed together,
    /// e.g. `CODE_UNIT_DIFFS | SYMBOL_DIFFS`. Bits outside `ALL_DIFFS` are masked off.
    pub fn with_type(type_flags: u32) -> Self {
        Self {
            filter_flags: ALL_DIFFS & type_flags,
        }
    }

    /// Returns `true` if any of the bits in `type_flags` are set in this filter.
    pub fn get_filter(&self, type_flags: u32) -> bool {
        (type_flags & self.filter_flags) != 0
    }

    /// Adds the diff types from `other` to this filter.
    pub fn add_to_filter(&mut self, other: &ProgramDiffFilter) {
        self.filter_flags |= other.filter_flags;
    }

    /// Sets or clears the specified diff type bits.
    ///
    /// When `enabled` is `true`, the bits in `type_flags` are set; when `false`, they are cleared.
    pub fn set_filter(&mut self, type_flags: u32, enabled: bool) {
        if enabled {
            self.filter_flags |= type_flags;
        } else {
            self.filter_flags &= !type_flags;
        }
    }

    /// Clears all diff type flags.
    pub fn clear_all(&mut self) {
        self.set_filter(ALL_DIFFS, false);
    }

    /// Sets all diff type flags.
    pub fn select_all(&mut self) {
        self.set_filter(ALL_DIFFS, true);
    }

    /// Returns an array of all primary (single-bit) diff type values.
    pub fn get_primary_types() -> [u32; NUM_PRIMARY_TYPES] {
        let mut pt = [0u32; NUM_PRIMARY_TYPES];
        for i in 0..NUM_PRIMARY_TYPES {
            pt[i] = 1 << i;
        }
        pt
    }

    /// Returns the name of a predefined diff type constant, or an empty string for unknown values.
    pub fn type_to_name(type_flags: u32) -> &'static str {
        match type_flags {
            BYTE_DIFFS => "BYTE_DIFFS",
            CODE_UNIT_DIFFS => "CODE_UNIT_DIFFS",
            COMMENT_DIFFS => "COMMENT_DIFFS",
            EOL_COMMENT_DIFFS => "EOL_COMMENT_DIFFS",
            PRE_COMMENT_DIFFS => "PRE_COMMENT_DIFFS",
            POST_COMMENT_DIFFS => "POST_COMMENT_DIFFS",
            PLATE_COMMENT_DIFFS => "PLATE_COMMENT_DIFFS",
            REPEATABLE_COMMENT_DIFFS => "REPEATABLE_COMMENT_DIFFS",
            REFERENCE_DIFFS => "REFERENCE_DIFFS",
            USER_DEFINED_DIFFS => "USER_DEFINED_DIFFS",
            SYMBOL_DIFFS => "SYMBOL_DIFFS",
            EQUATE_DIFFS => "EQUATE_DIFFS",
            FUNCTION_DIFFS => "FUNCTION_DIFFS",
            BOOKMARK_DIFFS => "BOOKMARK_DIFFS",
            PROGRAM_CONTEXT_DIFFS => "PROGRAM_CONTEXT_DIFFS",
            ALL_DIFFS => "ALL_DIFFS",
            FUNCTION_TAG_DIFFS => "FUNCTION_TAG_DIFFS",
            SOURCE_MAP_DIFFS => "SOURCE_MAP_DIFFS",
            _ => "",
        }
    }
}

impl std::fmt::Display for ProgramDiffFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProgramDiffFilter:\n")?;
        for i in 0..NUM_PRIMARY_TYPES {
            let t = 1u32 << i;
            writeln!(f, "  {}={}", Self::type_to_name(t), self.get_filter(t))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_filter_has_no_flags() {
        let f = ProgramDiffFilter::new();
        assert!(!f.get_filter(ALL_DIFFS));
        assert!(!f.get_filter(BYTE_DIFFS));
    }

    #[test]
    fn with_type_masks_to_all_diffs() {
        let f = ProgramDiffFilter::with_type(0xFFFF_FFFF);
        assert_eq!(f, ProgramDiffFilter::with_type(ALL_DIFFS));
    }

    #[test]
    fn with_type_sets_requested_bits() {
        let f = ProgramDiffFilter::with_type(CODE_UNIT_DIFFS | SYMBOL_DIFFS);
        assert!(f.get_filter(CODE_UNIT_DIFFS));
        assert!(f.get_filter(SYMBOL_DIFFS));
        assert!(!f.get_filter(BYTE_DIFFS));
    }

    #[test]
    fn get_filter_matches_any_set_bit() {
        let f = ProgramDiffFilter::with_type(BYTE_DIFFS);
        assert!(f.get_filter(BYTE_DIFFS | SYMBOL_DIFFS));
        assert!(!f.get_filter(SYMBOL_DIFFS));
    }

    #[test]
    fn set_filter_enables_and_disables() {
        let mut f = ProgramDiffFilter::new();
        f.set_filter(BYTE_DIFFS, true);
        assert!(f.get_filter(BYTE_DIFFS));
        f.set_filter(BYTE_DIFFS, false);
        assert!(!f.get_filter(BYTE_DIFFS));
    }

    #[test]
    fn add_to_filter_merges_flags() {
        let mut f1 = ProgramDiffFilter::with_type(BYTE_DIFFS);
        let f2 = ProgramDiffFilter::with_type(SYMBOL_DIFFS);
        f1.add_to_filter(&f2);
        assert!(f1.get_filter(BYTE_DIFFS));
        assert!(f1.get_filter(SYMBOL_DIFFS));
    }

    #[test]
    fn clear_all_removes_all_flags() {
        let mut f = ProgramDiffFilter::with_type(ALL_DIFFS);
        f.clear_all();
        assert!(!f.get_filter(ALL_DIFFS));
    }

    #[test]
    fn select_all_sets_all_flags() {
        let mut f = ProgramDiffFilter::new();
        f.select_all();
        assert!(f.get_filter(BYTE_DIFFS));
        assert!(f.get_filter(SYMBOL_DIFFS));
        assert!(f.get_filter(FUNCTION_TAG_DIFFS));
        assert!(f.get_filter(SOURCE_MAP_DIFFS));
    }

    #[test]
    fn get_primary_types_returns_sixteen_single_bits() {
        let pt = ProgramDiffFilter::get_primary_types();
        assert_eq!(pt.len(), 16);
        for (i, &v) in pt.iter().enumerate() {
            assert_eq!(v, 1u32 << i);
        }
    }

    #[test]
    fn type_to_name_known_types() {
        assert_eq!(ProgramDiffFilter::type_to_name(BYTE_DIFFS), "BYTE_DIFFS");
        assert_eq!(ProgramDiffFilter::type_to_name(ALL_DIFFS), "ALL_DIFFS");
        assert_eq!(ProgramDiffFilter::type_to_name(COMMENT_DIFFS), "COMMENT_DIFFS");
        assert_eq!(ProgramDiffFilter::type_to_name(SOURCE_MAP_DIFFS), "SOURCE_MAP_DIFFS");
        assert_eq!(ProgramDiffFilter::type_to_name(0), "");
    }

    #[test]
    fn equality_based_on_flags() {
        let f1 = ProgramDiffFilter::with_type(BYTE_DIFFS | SYMBOL_DIFFS);
        let mut f2 = ProgramDiffFilter::new();
        f2.set_filter(BYTE_DIFFS, true);
        f2.set_filter(SYMBOL_DIFFS, true);
        assert_eq!(f1, f2);
    }

    #[test]
    fn display_lists_all_primary_types() {
        let mut f = ProgramDiffFilter::new();
        f.set_filter(BYTE_DIFFS, true);
        let s = f.to_string();
        assert!(s.starts_with("ProgramDiffFilter:\n"));
        assert!(s.contains("BYTE_DIFFS=true"));
        assert!(s.contains("SYMBOL_DIFFS=false"));
    }

    #[test]
    fn comment_diffs_is_combination_of_comment_types() {
        assert_eq!(
            COMMENT_DIFFS,
            EOL_COMMENT_DIFFS
                | PRE_COMMENT_DIFFS
                | POST_COMMENT_DIFFS
                | REPEATABLE_COMMENT_DIFFS
                | PLATE_COMMENT_DIFFS
        );
    }

    #[test]
    fn all_diffs_includes_all_primary_types() {
        for t in ProgramDiffFilter::get_primary_types() {
            assert_ne!(ALL_DIFFS & t, 0, "ALL_DIFFS missing bit {t:#010x}");
        }
    }
}
