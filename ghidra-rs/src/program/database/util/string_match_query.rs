use super::query::Query;
use crate::framework::db::DBRecord;
use crate::util::user_search_utils::UserSearchUtils;
use regex::Regex;

/// Query for matching string fields with wildcard string.
///
/// Port of `ghidra.program.database.util.StringMatchQuery`.
pub struct StringMatchQuery {
    col: usize,
    /// Anchored so `is_match` behaves like Java's `Matcher.matches()` (whole-string match)
    /// rather than `Matcher.find()` (substring search). `UserSearchUtils::create_search_pattern`
    /// returns an unanchored pattern, matching the Rust crate's own `Regex` semantics, so the
    /// anchoring happens once here at construction time.
    pattern: Regex,
}

impl StringMatchQuery {
    /// Construct a new StringMatchQuery.
    ///
    /// # Parameters
    /// - `col`: column index
    /// - `search_string`: string to match
    /// - `case_sensitive`: true if the match should be case sensitive
    pub fn new(col: usize, search_string: &str, case_sensitive: bool) -> Result<Self, regex::Error> {
        let base = UserSearchUtils::create_search_pattern(search_string, case_sensitive)?;
        let pattern = Regex::new(&format!("^(?:{})$", base.as_str()))?;
        Ok(Self { col, pattern })
    }
}

impl Query for StringMatchQuery {
    fn matches(&self, record: &DBRecord) -> bool {
        // Java: `record.getString(col)` then `pattern.matcher(value).matches()`. Java's
        // `DBRecord.getString` on a null string field returns `null`, and matching a `null`
        // input against the pattern throws `NullPointerException`. This port instead treats a
        // null/absent string field as simply not matching, which is a strictly safer behavior
        // for a boolean predicate and avoids introducing a panic path.
        match record.get_string(self.col) {
            Some(value) => self.pattern.is_match(value),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::sync::Arc;

    fn make_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ))
    }

    fn record_with(value: &str) -> DBRecord {
        let schema = make_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_field(0, Field::String(Some(value.to_string())));
        record
    }

    #[test]
    fn test_exact_literal_match() {
        let query = StringMatchQuery::new(0, "bob", true).unwrap();
        assert!(query.matches(&record_with("bob")));
        assert!(!query.matches(&record_with("bobby")));
        assert!(!query.matches(&record_with("xbob")));
    }

    #[test]
    fn test_case_sensitive_mismatch() {
        let query = StringMatchQuery::new(0, "Bob", true).unwrap();
        assert!(!query.matches(&record_with("bob")));
        assert!(query.matches(&record_with("Bob")));
    }

    #[test]
    fn test_case_insensitive_match() {
        let query = StringMatchQuery::new(0, "Bob", false).unwrap();
        assert!(query.matches(&record_with("bob")));
        assert!(query.matches(&record_with("BOB")));
    }

    #[test]
    fn test_star_wildcard_matches_whole_string_only() {
        let query = StringMatchQuery::new(0, "bo*b", true).unwrap();
        assert!(query.matches(&record_with("bob")));
        assert!(query.matches(&record_with("boaab")));
        // Whole-string match: trailing/leading extra text must NOT match.
        assert!(!query.matches(&record_with("xbob")));
        assert!(!query.matches(&record_with("bobx")));
    }

    #[test]
    fn test_question_mark_wildcard_single_char() {
        let query = StringMatchQuery::new(0, "b?b", true).unwrap();
        assert!(query.matches(&record_with("bob")));
        assert!(!query.matches(&record_with("bb")));
        assert!(!query.matches(&record_with("boob")));
    }

    #[test]
    fn test_null_field_does_not_match() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = StringMatchQuery::new(0, "*", true).unwrap();
        assert!(!query.matches(&record));
    }
}
