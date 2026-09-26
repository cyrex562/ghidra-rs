//! A query for a [`StringValidatorService`](super::StringValidatorService) to judge.
//!
//! Port of `ghidra.app.services.StringValidatorQuery`, a Java `record`.

use crate::app::plugin::core::strings::StringInfo;

/// A string to be judged, along with cached information about the characters it contains.
///
/// Port of `ghidra.app.services.StringValidatorQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringValidatorQuery {
    /// The string itself.
    pub string_value: String,
    /// Information about the characters in [`StringValidatorQuery::string_value`].
    pub string_char_info: StringInfo,
}

impl StringValidatorQuery {
    /// Creates a `StringValidatorQuery`, computing `string_char_info` from `string_value`.
    ///
    /// Mirrors the auxiliary constructor `StringValidatorQuery(String stringValue)`, which
    /// delegates to the canonical constructor via `StringInfo.fromString(stringValue)`.
    pub fn new(string_value: impl Into<String>) -> Self {
        let string_value = string_value.into();
        let string_char_info = StringInfo::from_str(&string_value);
        Self {
            string_value,
            string_char_info,
        }
    }

    /// Creates a `StringValidatorQuery` with pre-computed character info.
    ///
    /// Mirrors the canonical (record) constructor `StringValidatorQuery(String, StringInfo)`.
    pub fn with_char_info(string_value: impl Into<String>, string_char_info: StringInfo) -> Self {
        Self {
            string_value: string_value.into(),
            string_char_info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_computes_char_info_from_string_value() {
        let query = StringValidatorQuery::new("Hello");
        assert_eq!(query.string_value, "Hello");
        assert_eq!(query.string_char_info, StringInfo::from_str("Hello"));
    }

    #[test]
    fn new_on_empty_string() {
        let query = StringValidatorQuery::new("");
        assert_eq!(query.string_value, "");
        assert!(query.string_char_info.scripts.is_empty());
    }

    #[test]
    fn with_char_info_uses_the_given_info_verbatim() {
        let info = StringInfo::from_str("some other text");
        let query = StringValidatorQuery::with_char_info("Hello", info.clone());
        assert_eq!(query.string_value, "Hello");
        assert_eq!(query.string_char_info, info);
    }

    #[test]
    fn equal_values_produce_equal_queries() {
        assert_eq!(StringValidatorQuery::new("same"), StringValidatorQuery::new("same"));
        assert_ne!(StringValidatorQuery::new("same"), StringValidatorQuery::new("diff"));
    }

    #[test]
    fn clone_is_independent_but_equal() {
        let query = StringValidatorQuery::new("clone me");
        let cloned = query.clone();
        assert_eq!(query, cloned);
    }
}
