//! Port of `ghidra.program.model.data.DataTypeNameComparator`.
//!
//! The Java class is a stateless `Comparator<String>` singleton (`DataTypeNameComparator.INSTANCE`).
//! Mirroring [`CaseInsensitiveDuplicateStringComparator`](crate::util::datastruct::case_insensitive_duplicate_string_comparator::CaseInsensitiveDuplicateStringComparator)
//! -- the established convention in this crate for a stateless Java `Comparator` -- this is
//! ported as a unit struct with an associated `compare` function returning
//! [`std::cmp::Ordering`], plus an `INSTANCE` constant mirroring the Java static field.
//!
//! `compare(String, String)` calls two static helpers on `ghidra.program.database.data.
//! DataTypeUtilities`: `getNameWithoutConflict(String)` and `getConflictValue(String)`. That
//! class as a whole is still genuinely `TODO` (its `PORT_MANIFEST.tsv` row says so, and its
//! partial Rust port at `program/database/data/data_type_utilities.rs` is not even wired into
//! the module tree -- it imports merger placeholder types that do not exist, per that file's own
//! `program::seam_stubs::DataTypeUtilities` placeholder-doc comment). Rather than depend on that
//! non-compiling module, the two `(String)`-only overloads these need are ported here directly
//! as self-contained private free functions ([`name_without_conflict`]/[`conflict_value`], and
//! their shared [`pointer_array_decorations`]/[`base_conflict_value`] helpers) -- a narrow,
//! faithful re-derivation of just those four static methods from `DataTypeUtilities.java`,
//! **not** a claim that the class itself is ported (its `DataType`-typed overloads, its
//! `getBaseDataType`/`canHaveConflictName` machinery, and everything else on that 1300+ line
//! class remain untouched and still `TODO`).
//!
//! Java `char`/`Character.toLowerCase` operate on UTF-16 code units; this port instead walks
//! `char::to_ascii_lowercase()` over Rust `char`s (Unicode scalar values). Data type names in
//! practice are ASCII, so this is behaviorally equivalent for all real inputs while avoiding a
//! UTF-16 surrogate-pair translation layer that nothing in this crate needs.

use std::cmp::Ordering;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::program::model::data::data_type::CONFLICT_SUFFIX;

/// Port of the private `DataTypeUtilities.DATATYPE_POINTER_ARRAY_PATTERN` field.
static DATATYPE_POINTER_ARRAY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(( \*\d*)|(\[\d+\]))+$").unwrap());

/// Port of the private `DataTypeUtilities.BASE_DATATYPE_CONFLICT_PATTERN` field.
static BASE_DATATYPE_CONFLICT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!("{}([_]{{0,1}}\\d+){{0,1}}$", regex::escape(CONFLICT_SUFFIX))).unwrap()
});

/// Port of the private `DataTypeUtilities.getPointerArrayDecorations(String)` helper.
fn pointer_array_decorations(data_type_name: &str) -> Option<String> {
    // Use of this preliminary check greatly speeds up the check for cases not involving a
    // pointer or array.
    if !data_type_name.contains('*') && !data_type_name.contains('[') {
        return None;
    }
    let m = DATATYPE_POINTER_ARRAY_PATTERN.find(data_type_name)?;
    Some(data_type_name[m.start()..].to_string())
}

/// Port of the `DataTypeUtilities.getNameWithoutConflict(String)` overload: gets the name of a
/// data type name string with all conflict naming patterns removed.
fn name_without_conflict(data_type_name: &str) -> String {
    let decorations = pointer_array_decorations(data_type_name);
    let base = match &decorations {
        Some(d) => &data_type_name[..data_type_name.len() - d.len()],
        None => data_type_name,
    };
    let stripped = BASE_DATATYPE_CONFLICT_PATTERN.replace_all(base, "");
    match decorations {
        Some(d) => format!("{stripped}{d}"),
        None => stripped.into_owned(),
    }
}

/// Port of the private `DataTypeUtilities.getBaseConflictValue(String)` helper.
fn base_conflict_value(base_data_type_name: &str) -> i32 {
    let Some(m) = BASE_DATATYPE_CONFLICT_PATTERN.find(base_data_type_name) else {
        return -1;
    };
    let mut start_ix = m.start() + CONFLICT_SUFFIX.len();
    if start_ix < base_data_type_name.len() && base_data_type_name.as_bytes()[start_ix] == b'_' {
        start_ix += 1;
    }
    let value_str = &base_data_type_name[start_ix..];
    if value_str.is_empty() {
        return 0;
    }
    value_str.parse::<i32>().unwrap_or(-1)
}

/// Port of the `DataTypeUtilities.getConflictValue(String)` overload: gets the conflict value
/// associated with a conflict datatype name string.
fn conflict_value(data_type_name: &str) -> i32 {
    let decorations = pointer_array_decorations(data_type_name);
    let base = match &decorations {
        Some(d) => &data_type_name[..data_type_name.len() - d.len()],
        None => data_type_name,
    };
    base_conflict_value(base)
}

/// Provides the preferred name-based comparison of [`DataType`](crate::program::model::data::data_type::DataType)
/// names, handling both some degree of case-insensitivity as well as proper grouping and
/// ordering of conflict datatype names.
///
/// Port of `ghidra.program.model.data.DataTypeNameComparator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataTypeNameComparator;

impl DataTypeNameComparator {
    /// Mirrors the Java `public static final DataTypeNameComparator INSTANCE` singleton field.
    pub const INSTANCE: Self = Self;

    /// Port of `DataTypeNameComparator.compare(String, String)`.
    pub fn compare(dt1_name: &str, dt2_name: &str) -> Ordering {
        let name1 = name_without_conflict(dt1_name);
        let name2 = name_without_conflict(dt2_name);

        let chars1: Vec<char> = name1.chars().collect();
        let chars2: Vec<char> = name2.chars().collect();
        let len1 = chars1.len();
        let len2 = chars2.len();

        let len = len1.min(len2); // overlapping length
        let mut base_name_len = len; // length of overlapping portion of base-name (no decorations)

        // Case-insensitive compare of significant overlapping portion of name.
        let mut base_case_compare = Ordering::Equal;
        for i in 0..len {
            let c1 = chars1[i];
            let c2 = chars2[i];
            let lc1 = c1.to_ascii_lowercase();
            let lc2 = c2.to_ascii_lowercase();
            // First space treated as end of base-name.
            if lc1 == ' ' {
                if lc2 == ' ' {
                    base_name_len = i;
                    break;
                }
                return Ordering::Less;
            }
            if lc2 == ' ' {
                return Ordering::Greater;
            }
            if lc1 != lc2 {
                return lc1.cmp(&lc2);
            }
            if base_case_compare == Ordering::Equal {
                base_case_compare = c1.cmp(&c2);
            }
        }

        if len1 > base_name_len && chars1[base_name_len] != ' ' {
            return Ordering::Greater; // first name has longer base-name
        }
        if len2 > base_name_len && chars2[base_name_len] != ' ' {
            return Ordering::Less; // second name has longer base-name
        }

        if base_case_compare != Ordering::Equal {
            return base_case_compare;
        }

        // Same base-name, order by conflict.
        let conflict1 = conflict_value(dt1_name);
        let conflict2 = conflict_value(dt2_name);
        if conflict1 != conflict2 {
            return conflict1.cmp(&conflict2);
        }

        name1.cmp(&name2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_names_are_equal() {
        assert_eq!(DataTypeNameComparator::compare("int", "int"), Ordering::Equal);
        assert_eq!(DataTypeNameComparator::INSTANCE, DataTypeNameComparator);
    }

    #[test]
    fn case_insensitive_compare_orders_by_lowercase_first() {
        assert_eq!(DataTypeNameComparator::compare("abc", "xyz"), Ordering::Less);
        assert_eq!(DataTypeNameComparator::compare("xyz", "abc"), Ordering::Greater);
    }

    #[test]
    fn case_insensitive_equal_names_fall_back_to_case_sensitive_order() {
        // "Foo" vs "foo": case-insensitively equal, so falls back to the raw char compare
        // ('F' = 0x46 < 'f' = 0x66).
        assert_eq!(DataTypeNameComparator::compare("Foo", "foo"), Ordering::Less);
        assert_eq!(DataTypeNameComparator::compare("foo", "Foo"), Ordering::Greater);
    }

    #[test]
    fn shorter_name_that_is_a_space_terminated_prefix_sorts_first() {
        // "foo" is a space-terminated prefix of "foo bar" -> "foo" sorts before "foo bar".
        assert_eq!(DataTypeNameComparator::compare("foo", "foo bar"), Ordering::Less);
        assert_eq!(DataTypeNameComparator::compare("foo bar", "foo"), Ordering::Greater);
    }

    #[test]
    fn longer_base_name_without_space_boundary_sorts_after() {
        // "foobar" is NOT a space-terminated extension of "foo" (no space at index 3), so it
        // is treated as having a "longer base-name" and sorts after.
        assert_eq!(DataTypeNameComparator::compare("foo", "foobar"), Ordering::Less);
        assert_eq!(DataTypeNameComparator::compare("foobar", "foo"), Ordering::Greater);
    }

    #[test]
    fn conflict_values_order_numerically_when_base_names_match() {
        assert_eq!(
            DataTypeNameComparator::compare("Foo.conflict", "Foo.conflict2"),
            Ordering::Less
        );
        assert_eq!(
            DataTypeNameComparator::compare("Foo.conflict2", "Foo.conflict"),
            Ordering::Greater
        );
    }

    #[test]
    fn conflict_values_order_numerically_not_lexicographically() {
        // Lexicographically ".conflict10" < ".conflict9" (since '1' < '9'), but the conflict
        // value is compared numerically (9 < 10), so ".conflict9" must sort first.
        assert_eq!(
            DataTypeNameComparator::compare("Foo.conflict9", "Foo.conflict10"),
            Ordering::Less
        );
        assert_eq!(
            DataTypeNameComparator::compare("Foo.conflict10", "Foo.conflict9"),
            Ordering::Greater
        );
    }

    #[test]
    fn non_conflict_name_sorts_before_conflict_name_with_same_base() {
        // getConflictValue("Foo") == -1, getConflictValue("Foo.conflict") == 0.
        assert_eq!(DataTypeNameComparator::compare("Foo", "Foo.conflict"), Ordering::Less);
    }

    #[test]
    fn pointer_decoration_is_preserved_around_conflict_stripping() {
        // "Foo.conflict *" and "Foo *" share the same base name once the conflict suffix and
        // pointer decoration are both accounted for.
        assert_eq!(
            DataTypeNameComparator::compare("Foo.conflict *", "Foo.conflict2 *"),
            Ordering::Less
        );
    }

    #[test]
    fn empty_strings_are_equal() {
        assert_eq!(DataTypeNameComparator::compare("", ""), Ordering::Equal);
    }
}
