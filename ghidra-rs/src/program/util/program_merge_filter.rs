use crate::util::msg::Msg;

/// Indicates the merge filter difference type specified was not valid.
pub const INVALID: i32 = -1;
/// A **filter value** indicating that the type of difference isn't to be changed in the merged
/// program.
pub const IGNORE: i32 = 0;
/// A **filter value** indicating that the type of difference in program1 should be replaced with
/// the difference from program2.
pub const REPLACE: i32 = 1;
/// A **filter value** indicating that the type of difference should be merged from program2 with
/// what is already in program1 (the property type should be taken from both program1 and
/// program2).
pub const MERGE: i32 = 2;

/// Indicates the **merge filter** for the program context differences.
pub const PROGRAM_CONTEXT: u32 = 1 << 0;
/// Indicates the **merge filter** for the byte differences.
pub const BYTES: u32 = 1 << 1;
/// Indicates the **merge filter** for the instruction code unit differences. This includes
/// mnemonic, operand, and value references, and equates.
pub const INSTRUCTIONS: u32 = 1 << 2;
/// Indicates the **merge filter** for the data code unit differences.
pub const DATA: u32 = 1 << 3;
/// Indicates the **merge filter** for the memory, variable, and external reference differences.
pub const REFERENCES: u32 = 1 << 4;
/// Indicates the **merge filter** for the plate comment differences.
pub const PLATE_COMMENTS: u32 = 1 << 5;
/// Indicates the **merge filter** for the pre comment differences.
pub const PRE_COMMENTS: u32 = 1 << 6;
/// Indicates the **merge filter** for the eol comment differences.
pub const EOL_COMMENTS: u32 = 1 << 7;
/// Indicates the **merge filter** for the repeatable comment differences.
pub const REPEATABLE_COMMENTS: u32 = 1 << 8;
/// Indicates the **merge filter** for the post comment differences.
pub const POST_COMMENTS: u32 = 1 << 9;
/// Indicates the **merge filter** for the label differences.
pub const SYMBOLS: u32 = 1 << 10;
/// Indicates the **merge filter** for bookmark differences.
pub const BOOKMARKS: u32 = 1 << 11;
/// Indicates the **merge filter** for the user defined property differences.
pub const PROPERTIES: u32 = 1 << 12;
/// Indicates the **merge filter** for the functions differences.
pub const FUNCTIONS: u32 = 1 << 13;
/// Indicates the **merge filter** for the equates differences.
pub const EQUATES: u32 = 1 << 14;
/// Indicates the **merge filter** for replacing the primary symbol with the one from program 2
/// when merging labels.
pub const PRIMARY_SYMBOL: u32 = 1 << 15;
/// Indicates the **merge filter** for function tags.
pub const FUNCTION_TAGS: u32 = 1 << 16;
/// Indicates the **merge filter** for source map information.
pub const SOURCE_MAP: u32 = 1 << 17;

/// The total number of primary merge difference types.
const NUM_PRIMARY_TYPES: usize = 18;

/// Indicates to merge code unit differences. This includes instructions, data, and equates.
pub const CODE_UNITS: u32 = INSTRUCTIONS | DATA;

/// Indicates to merge all comment differences.
pub const COMMENTS: u32 =
    PLATE_COMMENTS | PRE_COMMENTS | EOL_COMMENTS | REPEATABLE_COMMENTS | POST_COMMENTS;

/// Indicates all **merge filters** for all types of differences.
pub const ALL: u32 = PROGRAM_CONTEXT
    | BYTES
    | CODE_UNITS
    | EQUATES
    | REFERENCES
    | COMMENTS
    | SYMBOLS
    | PRIMARY_SYMBOL
    | BOOKMARKS
    | PROPERTIES
    | FUNCTIONS
    | FUNCTION_TAGS
    | SOURCE_MAP;

/// Used to specify which portions of a program should be merged into another program.
///
/// It indicates the types of program differences to merge. Each merge type can have its filter
/// set to [`IGNORE`] or [`REPLACE`]. [`IGNORE`] indicates no interest in replacing or merging
/// that type of difference. [`REPLACE`] indicates to replace differences in program1 with
/// differences of that type from program2. Some merge types (for example, `COMMENTS` and
/// `SYMBOLS`) allow the filter to be set to [`MERGE`]. [`MERGE`] indicates that the type should
/// be taken from Program2 and merged into Program1 with whatever is already there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramMergeFilter {
    filter_flags: [i32; NUM_PRIMARY_TYPES],
}

impl Default for ProgramMergeFilter {
    fn default() -> Self {
        Self {
            filter_flags: [IGNORE; NUM_PRIMARY_TYPES],
        }
    }
}

impl ProgramMergeFilter {
    /// Creates a new `ProgramMergeFilter` with none of the merge types selected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new `ProgramMergeFilter` with the specified merge types selected.
    ///
    /// `filter` is [`IGNORE`], [`REPLACE`], or [`MERGE`]. It indicates which program difference
    /// to include of the specified type. If a particular type cannot be set to [`MERGE`] then it
    /// will be set to [`REPLACE`].
    pub fn with_type(type_flags: u32, filter: i32) -> Self {
        let mut result = Self::new();
        result.set_filter(type_flags, filter);
        result
    }

    /// Determines whether or not the specified type of filter is set.
    ///
    /// Valid types are: [`BYTES`], [`INSTRUCTIONS`], [`DATA`], [`SOURCE_MAP`], [`SYMBOLS`],
    /// [`PRIMARY_SYMBOL`], [`COMMENTS`], [`PROGRAM_CONTEXT`], [`PROPERTIES`], [`BOOKMARKS`],
    /// [`FUNCTIONS`]. [`INVALID`] is returned if combinations of merge types (e.g. [`ALL`]) are
    /// passed in.
    pub fn get_filter(&self, type_flags: u32) -> i32 {
        if !Self::is_individual_type(type_flags) {
            return INVALID;
        }
        for bit_pos in 0..NUM_PRIMARY_TYPES {
            if (type_flags >> bit_pos) & 1 == 1 {
                return self.filter_flags[bit_pos];
            }
        }
        INVALID
    }

    /// Determines whether or not the indicated type of filter item is a valid predefined type.
    ///
    /// Valid types are: [`BYTES`], [`INSTRUCTIONS`], [`DATA`], [`SYMBOLS`], [`PRIMARY_SYMBOL`],
    /// [`COMMENTS`], [`PROGRAM_CONTEXT`], [`PROPERTIES`], [`BOOKMARKS`], [`FUNCTIONS`],
    /// [`SOURCE_MAP`], [`ALL`].
    pub fn validate_predefined_type(type_flags: u32) -> bool {
        Self::is_individual_type(type_flags)
            || matches!(type_flags, CODE_UNITS | COMMENTS | ALL)
    }

    /// Determines if at least one of the filter types is set to [`REPLACE`] or [`MERGE`].
    pub fn is_set(&self) -> bool {
        self.filter_flags.iter().any(|&f| f != IGNORE)
    }

    /// Determines whether or not the indicated type of filter item is valid.
    ///
    /// Valid types are: [`BYTES`], [`INSTRUCTIONS`], [`DATA`], [`REFERENCES`], [`SYMBOLS`],
    /// [`PRIMARY_SYMBOL`], [`COMMENTS`], [`PROGRAM_CONTEXT`], [`PROPERTIES`], [`BOOKMARKS`],
    /// [`FUNCTIONS`], [`ALL`]. The type can also be any of the predefined types "OR"ed together.
    fn validate_type(type_flags: u32) -> bool {
        (type_flags as u64) < (1u64 << NUM_PRIMARY_TYPES)
    }

    /// Determines whether or not the filter is one of the valid predefined values.
    ///
    /// Valid filter values are: [`IGNORE`], [`REPLACE`], or [`MERGE`].
    fn validate_filter(filter: i32) -> bool {
        if filter < IGNORE || filter > MERGE {
            Msg::error(
                "ProgramMergeFilter",
                &format!("setFilter: Invalid filter: {filter}"),
            );
            return false;
        }
        true
    }

    /// Determines whether or not the [`MERGE`] filter is valid for the indicated primary merge
    /// type.
    ///
    /// Possible types are: [`BYTES`], [`INSTRUCTIONS`], [`DATA`], [`REFERENCES`], [`SYMBOLS`],
    /// [`PRIMARY_SYMBOL`], [`COMMENTS`], [`PROGRAM_CONTEXT`], [`PROPERTIES`], [`BOOKMARKS`],
    /// [`FUNCTIONS`], [`SOURCE_MAP`], [`ALL`].
    ///
    /// # Panics
    ///
    /// Panics if `type_flags` isn't a predefined individual merge type.
    fn is_merge_valid_for_filter(type_flags: u32) -> bool {
        match type_flags {
            // The following can be MERGE.
            PLATE_COMMENTS | PRE_COMMENTS | EOL_COMMENTS | REPEATABLE_COMMENTS | POST_COMMENTS
            | SYMBOLS | FUNCTION_TAGS => true,
            // The following cannot be MERGE.
            PROGRAM_CONTEXT | BYTES | INSTRUCTIONS | DATA | REFERENCES | BOOKMARKS | PROPERTIES
            | FUNCTIONS | EQUATES | PRIMARY_SYMBOL | SOURCE_MAP => false,
            _ => panic!(
                "Parameter to method isMergeValidForFilter() must be an individual merge type."
            ),
        }
    }

    /// Specifies whether or not the indicated type of item will not be included by the filter
    /// ([`IGNORE`]), replaced in the first program using the type of item in the second program
    /// ([`REPLACE`]), or included from both programs ([`MERGE`]).
    ///
    /// Valid types are: [`BYTES`], [`INSTRUCTIONS`], [`DATA`], [`REFERENCES`], [`SYMBOLS`],
    /// [`PRIMARY_SYMBOL`], [`COMMENTS`], [`PROPERTIES`], [`BOOKMARKS`], [`FUNCTIONS`], [`ALL`],
    /// or combinations of these "OR"ed together. If [`MERGE`] is not valid for an included
    /// primary type, then it will be set to [`REPLACE`] instead for that primary type.
    pub fn set_filter(&mut self, type_flags: u32, filter: i32) {
        if !Self::validate_type(type_flags) {
            Msg::error("ProgramMergeFilter", &"setFilter: Invalid type.");
            return;
        }
        if !Self::validate_filter(filter) {
            return;
        }

        for (bit_pos, &primary_type) in Self::get_primary_types().iter().enumerate() {
            if type_flags & primary_type != 0 {
                let mut tmp_filter = filter;
                if filter == MERGE && !Self::is_merge_valid_for_filter(primary_type) {
                    tmp_filter = REPLACE;
                }
                self.filter_flags[bit_pos] = tmp_filter;
            }
        }
    }

    /// Gets all the valid individual types of differences for this filter.
    ///
    /// Returns an array containing all the currently defined primary difference types.
    pub fn get_primary_types() -> [u32; NUM_PRIMARY_TYPES] {
        let mut pt = [0u32; NUM_PRIMARY_TYPES];
        for (i, slot) in pt.iter_mut().enumerate() {
            *slot = 1 << i;
        }
        pt
    }

    /// Returns the name of a predefined merge type.
    ///
    /// Only predefined types, as specified on `ProgramMergeFilter`, will return a name.
    /// Otherwise, an empty string is returned.
    pub fn type_to_name(type_flags: u32) -> &'static str {
        match type_flags {
            PROGRAM_CONTEXT => "PROGRAM CONTEXT",
            BYTES => "BYTES",
            INSTRUCTIONS => "INSTRUCTIONS",
            DATA => "DATA",
            REFERENCES => "REFERENCES",
            PLATE_COMMENTS => "PLATE_COMMENTS",
            PRE_COMMENTS => "PRE_COMMENTS",
            EOL_COMMENTS => "EOL_COMMENTS",
            REPEATABLE_COMMENTS => "REPEATABLE_COMMENTS",
            POST_COMMENTS => "POST_COMMENTS",
            SYMBOLS => "SYMBOLS",
            PRIMARY_SYMBOL => "PRIMARY_SYMBOL",
            BOOKMARKS => "BOOKMARKS",
            PROPERTIES => "PROPERTIES",
            FUNCTIONS => "FUNCTIONS",
            FUNCTION_TAGS => "FUNCTION TAGS",
            EQUATES => "EQUATES",
            CODE_UNITS => "CODE_UNITS",
            COMMENTS => "COMMENTS",
            ALL => "ALL",
            SOURCE_MAP => "SOURCE_MAP",
            _ => "",
        }
    }

    /// Returns the string associated with an individual (primary) merge difference setting.
    ///
    /// Valid types are: [`IGNORE`], [`REPLACE`], [`MERGE`].
    pub fn filter_to_name(filter: i32) -> &'static str {
        match filter {
            IGNORE => "IGNORE",
            REPLACE => "REPLACE",
            MERGE => "MERGE",
            _ => "",
        }
    }

    fn is_individual_type(type_flags: u32) -> bool {
        matches!(
            type_flags,
            PROGRAM_CONTEXT
                | BYTES
                | INSTRUCTIONS
                | DATA
                | SYMBOLS
                | PRIMARY_SYMBOL
                | REFERENCES
                | PLATE_COMMENTS
                | PRE_COMMENTS
                | EOL_COMMENTS
                | REPEATABLE_COMMENTS
                | POST_COMMENTS
                | BOOKMARKS
                | PROPERTIES
                | FUNCTIONS
                | FUNCTION_TAGS
                | EQUATES
                | SOURCE_MAP
        )
    }
}

impl std::fmt::Display for ProgramMergeFilter {
    /// A printable string indicating the current settings of this filter.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ProgramMergeFilter:")?;
        for type_flags in Self::get_primary_types() {
            let filter = self.get_filter(type_flags);
            writeln!(
                f,
                "  {}={}",
                Self::type_to_name(type_flags),
                Self::filter_to_name(filter)
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_filter_has_no_flags_set() {
        let f = ProgramMergeFilter::new();
        assert!(!f.is_set());
        assert_eq!(f.get_filter(BYTES), IGNORE);
    }

    #[test]
    fn with_type_sets_requested_type() {
        let f = ProgramMergeFilter::with_type(BYTES, REPLACE);
        assert_eq!(f.get_filter(BYTES), REPLACE);
        assert_eq!(f.get_filter(SYMBOLS), IGNORE);
        assert!(f.is_set());
    }

    #[test]
    fn clone_copies_flags() {
        let f1 = ProgramMergeFilter::with_type(SYMBOLS, MERGE);
        let f2 = f1.clone();
        assert_eq!(f1, f2);
    }

    #[test]
    fn get_filter_returns_invalid_for_combined_types() {
        let f = ProgramMergeFilter::with_type(ALL, REPLACE);
        assert_eq!(f.get_filter(CODE_UNITS), INVALID);
        assert_eq!(f.get_filter(COMMENTS), INVALID);
        assert_eq!(f.get_filter(ALL), INVALID);
    }

    #[test]
    fn get_filter_returns_invalid_for_unknown_type() {
        let f = ProgramMergeFilter::new();
        assert_eq!(f.get_filter(0), INVALID);
        assert_eq!(f.get_filter(1 << 30), INVALID);
    }

    #[test]
    fn validate_predefined_type_accepts_individual_and_combined_types() {
        assert!(ProgramMergeFilter::validate_predefined_type(BYTES));
        assert!(ProgramMergeFilter::validate_predefined_type(CODE_UNITS));
        assert!(ProgramMergeFilter::validate_predefined_type(COMMENTS));
        assert!(ProgramMergeFilter::validate_predefined_type(ALL));
        assert!(!ProgramMergeFilter::validate_predefined_type(0));
        assert!(!ProgramMergeFilter::validate_predefined_type(1 << 30));
    }

    #[test]
    fn set_filter_ignores_invalid_type() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(1 << 30, REPLACE);
        assert!(!f.is_set());
    }

    #[test]
    fn set_filter_ignores_invalid_filter_value() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(BYTES, 99);
        assert_eq!(f.get_filter(BYTES), IGNORE);
    }

    #[test]
    fn set_filter_downgrades_merge_to_replace_when_invalid() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(BYTES, MERGE);
        assert_eq!(f.get_filter(BYTES), REPLACE);
    }

    #[test]
    fn set_filter_allows_merge_for_symbols() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(SYMBOLS, MERGE);
        assert_eq!(f.get_filter(SYMBOLS), MERGE);
    }

    #[test]
    fn set_filter_applies_to_combined_types() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(COMMENTS, MERGE);
        assert_eq!(f.get_filter(PLATE_COMMENTS), MERGE);
        assert_eq!(f.get_filter(PRE_COMMENTS), MERGE);
        assert_eq!(f.get_filter(EOL_COMMENTS), MERGE);
        assert_eq!(f.get_filter(REPEATABLE_COMMENTS), MERGE);
        assert_eq!(f.get_filter(POST_COMMENTS), MERGE);
    }

    #[test]
    fn set_filter_applies_replace_for_non_mergeable_combined_types() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(CODE_UNITS, MERGE);
        assert_eq!(f.get_filter(INSTRUCTIONS), REPLACE);
        assert_eq!(f.get_filter(DATA), REPLACE);
    }

    #[test]
    fn is_set_reflects_any_non_ignore_flag() {
        let mut f = ProgramMergeFilter::new();
        assert!(!f.is_set());
        f.set_filter(BOOKMARKS, REPLACE);
        assert!(f.is_set());
    }

    #[test]
    fn get_primary_types_returns_eighteen_single_bits() {
        let pt = ProgramMergeFilter::get_primary_types();
        assert_eq!(pt.len(), 18);
        for (i, &v) in pt.iter().enumerate() {
            assert_eq!(v, 1u32 << i);
        }
    }

    #[test]
    fn type_to_name_known_types() {
        assert_eq!(ProgramMergeFilter::type_to_name(BYTES), "BYTES");
        assert_eq!(ProgramMergeFilter::type_to_name(ALL), "ALL");
        assert_eq!(ProgramMergeFilter::type_to_name(COMMENTS), "COMMENTS");
        assert_eq!(ProgramMergeFilter::type_to_name(SOURCE_MAP), "SOURCE_MAP");
        assert_eq!(ProgramMergeFilter::type_to_name(0), "");
    }

    #[test]
    fn filter_to_name_known_filters() {
        assert_eq!(ProgramMergeFilter::filter_to_name(IGNORE), "IGNORE");
        assert_eq!(ProgramMergeFilter::filter_to_name(REPLACE), "REPLACE");
        assert_eq!(ProgramMergeFilter::filter_to_name(MERGE), "MERGE");
        assert_eq!(ProgramMergeFilter::filter_to_name(INVALID), "");
    }

    #[test]
    fn equality_based_on_flags() {
        let f1 = ProgramMergeFilter::with_type(BYTES | SYMBOLS, REPLACE);
        let mut f2 = ProgramMergeFilter::new();
        f2.set_filter(BYTES, REPLACE);
        f2.set_filter(SYMBOLS, REPLACE);
        assert_eq!(f1, f2);
    }

    #[test]
    fn display_lists_all_primary_types() {
        let mut f = ProgramMergeFilter::new();
        f.set_filter(BYTES, REPLACE);
        let s = f.to_string();
        assert!(s.starts_with("ProgramMergeFilter:\n"));
        assert!(s.contains("BYTES=REPLACE"));
        assert!(s.contains("SYMBOLS=IGNORE"));
    }

    #[test]
    fn all_diffs_includes_all_primary_types() {
        for t in ProgramMergeFilter::get_primary_types() {
            assert_ne!(ALL & t, 0, "ALL missing bit {t:#010x}");
        }
    }
}
