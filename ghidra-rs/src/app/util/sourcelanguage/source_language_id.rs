//! An identifier for a [`SourceLanguage`](super::source_language::SourceLanguage).
//!
//! Port of `ghidra.app.util.sourcelanguage.SourceLanguageID`. The concrete Java class is mapped
//! to an object-safe trait (this was selected as a dependency-cycle cut point), with
//! [`SourceLanguageIdValue`] as the reference implementation used by the free constructor.

use std::cmp::Ordering;
use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

/// Errors produced constructing a [`SourceLanguageIdValue`] from a string.
///
/// Combines the `IllegalArgumentException` cases thrown by `SourceLanguageID(String)`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SourceLanguageIdError {
    #[error("Source language 'id' cannot be null or blank")]
    Blank,
    #[error("Source language 'id' does not match regex: {pattern}")]
    InvalidFormat { pattern: &'static str },
}

const VALID_ID_PATTERN: &str = r"^[a-zA-Z0-9_.-]+$";

fn valid_id_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(VALID_ID_PATTERN).unwrap())
}

/// Represents a [`SourceLanguage`](super::source_language::SourceLanguage)'s ID.
///
/// Port of `ghidra.app.util.sourcelanguage.SourceLanguageID`.
pub trait SourceLanguageId {
    /// Returns the ID as a string. Stands in for `SourceLanguageID.getIdAsString()` (and
    /// `toString()`, which returns the same value -- see the `Display` impl on `dyn
    /// SourceLanguageId` below).
    fn get_id_as_string(&self) -> &str;

    /// Port of `Comparable<SourceLanguageID>.compareTo`.
    fn compare_to(&self, other: &dyn SourceLanguageId) -> Ordering {
        self.get_id_as_string().cmp(other.get_id_as_string())
    }

    /// Structural equality, matching Java's `equals(Object)`. Named `id_equals` (rather than
    /// `eq`) since trait objects cannot implement `PartialEq` directly.
    fn id_equals(&self, other: &dyn SourceLanguageId) -> bool {
        self.get_id_as_string() == other.get_id_as_string()
    }
}

impl fmt::Display for dyn SourceLanguageId + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.get_id_as_string())
    }
}

/// Reference implementation of [`SourceLanguageId`]: a validated, immutable ID string.
///
/// Port of the private `SourceLanguageID.id` field plus its constructor's validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceLanguageIdValue(String);

impl SourceLanguageIdValue {
    /// Creates a new [`SourceLanguageIdValue`].
    ///
    /// An ID must not be blank and must match `^[a-zA-Z0-9_.-]+$` (which, in particular, forbids
    /// commas).
    ///
    /// Port of `SourceLanguageID(String)`.
    ///
    /// # Errors
    /// Returns `Err` if `id` is blank, or does not match the required pattern.
    pub fn new(id: impl Into<String>) -> Result<Self, SourceLanguageIdError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(SourceLanguageIdError::Blank);
        }
        if !valid_id_regex().is_match(&id) {
            return Err(SourceLanguageIdError::InvalidFormat { pattern: VALID_ID_PATTERN });
        }
        Ok(Self(id))
    }
}

impl SourceLanguageId for SourceLanguageIdValue {
    fn get_id_as_string(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceLanguageIdValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_valid() {
        let id = SourceLanguageIdValue::new("my-lang_1.0").unwrap();
        assert_eq!(id.get_id_as_string(), "my-lang_1.0");
    }

    #[test]
    fn new_blank_returns_err() {
        assert_eq!(SourceLanguageIdValue::new("   "), Err(SourceLanguageIdError::Blank));
    }

    #[test]
    fn new_with_comma_returns_err() {
        assert!(matches!(
            SourceLanguageIdValue::new("a,b"),
            Err(SourceLanguageIdError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn display_matches_id() {
        let id = SourceLanguageIdValue::new("dwarf").unwrap();
        assert_eq!(id.to_string(), "dwarf");
    }

    #[test]
    fn equality() {
        let a = SourceLanguageIdValue::new("dwarf").unwrap();
        let b = SourceLanguageIdValue::new("dwarf").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ordering() {
        let a = SourceLanguageIdValue::new("alpha").unwrap();
        let b = SourceLanguageIdValue::new("beta").unwrap();
        assert!(a < b);
    }

    /// Minimal mock proving `SourceLanguageId` is object-safe and usable via
    /// `Box<dyn SourceLanguageId>`, and that the default `compare_to`/`id_equals` methods behave
    /// correctly across distinct implementors.
    struct MockSourceLanguageId(&'static str);

    impl SourceLanguageId for MockSourceLanguageId {
        fn get_id_as_string(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn compare_to_and_equals_work_across_implementors_via_trait_object() {
        let value = SourceLanguageIdValue::new("dwarf").unwrap();
        let mock: Box<dyn SourceLanguageId> = Box::new(MockSourceLanguageId("dwarf"));
        let other_mock: Box<dyn SourceLanguageId> = Box::new(MockSourceLanguageId("pdb"));

        assert!(value.id_equals(mock.as_ref()));
        assert_eq!(value.compare_to(mock.as_ref()), Ordering::Equal);
        assert_eq!(value.compare_to(other_mock.as_ref()), Ordering::Less);
        assert_eq!(mock.to_string(), "dwarf");
    }
}
