/// QueryData represents a search/query with case sensitivity and wildcard options.
///
/// This struct encapsulates query parameters including the query string itself,
/// whether the search is case-sensitive, and whether to include dynamic labels.
/// It also provides utility methods for detecting and handling wildcard characters.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QueryData {
    query_string: String,
    case_sensitive: bool,
    include_dynamic_labels: bool,
}

impl QueryData {
    /// Wildcard character for any string.
    pub const ANY_STRING_WILDCARD: char = '*';

    /// Wildcard character for a single character.
    pub const ANY_CHAR_WILDCARD: char = '?';

    /// Creates a new QueryData with all parameters specified.
    ///
    /// # Arguments
    ///
    /// * `query_string` - The query string to search for
    /// * `case_sensitive` - Whether the search should be case-sensitive
    /// * `include_dynamic_labels` - Whether to include dynamic labels in the search
    pub fn new(
        query_string: impl Into<String>,
        case_sensitive: bool,
        include_dynamic_labels: bool,
    ) -> Self {
        QueryData {
            query_string: query_string.into(),
            case_sensitive,
            include_dynamic_labels,
        }
    }

    /// Creates a new QueryData with default include_dynamic_labels set to true.
    ///
    /// # Arguments
    ///
    /// * `query_string` - The query string to search for
    /// * `case_sensitive` - Whether the search should be case-sensitive
    pub fn with_case_sensitivity(
        query_string: impl Into<String>,
        case_sensitive: bool,
    ) -> Self {
        QueryData {
            query_string: query_string.into(),
            case_sensitive,
            include_dynamic_labels: true,
        }
    }

    /// Returns the query string.
    pub fn query_string(&self) -> &str {
        &self.query_string
    }

    /// Returns whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Returns whether dynamic labels should be included in the search.
    pub fn is_include_dynamic_labels(&self) -> bool {
        self.include_dynamic_labels
    }

    /// Returns whether this query contains wildcard characters.
    pub fn is_wildcard(&self) -> bool {
        Self::has_wildcards(&self.query_string)
    }

    /// Checks if a query string contains wildcard characters.
    ///
    /// # Arguments
    ///
    /// * `query` - The query string to check
    ///
    /// # Returns
    ///
    /// `true` if the query contains `*` or `?` wildcard characters
    pub fn has_wildcards(query: &str) -> bool {
        query.contains(Self::ANY_STRING_WILDCARD) || query.contains(Self::ANY_CHAR_WILDCARD)
    }
}

impl std::fmt::Display for QueryData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QueryData(query='{}', case_sensitive={}, include_dynamic_labels={})",
            self.query_string, self.case_sensitive, self.include_dynamic_labels
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_all_params() {
        let qd = QueryData::new("test", true, false);
        assert_eq!(qd.query_string(), "test");
        assert!(qd.is_case_sensitive());
        assert!(!qd.is_include_dynamic_labels());
    }

    #[test]
    fn test_with_case_sensitivity() {
        let qd = QueryData::with_case_sensitivity("test", false);
        assert_eq!(qd.query_string(), "test");
        assert!(!qd.is_case_sensitive());
        assert!(qd.is_include_dynamic_labels());
    }

    #[test]
    fn test_is_wildcard_with_star() {
        let qd = QueryData::new("test*", true, true);
        assert!(qd.is_wildcard());
    }

    #[test]
    fn test_is_wildcard_with_question() {
        let qd = QueryData::new("test?", true, true);
        assert!(qd.is_wildcard());
    }

    #[test]
    fn test_is_wildcard_with_both() {
        let qd = QueryData::new("te*st?", true, true);
        assert!(qd.is_wildcard());
    }

    #[test]
    fn test_is_wildcard_without_wildcards() {
        let qd = QueryData::new("test", true, true);
        assert!(!qd.is_wildcard());
    }

    #[test]
    fn test_is_wildcard_empty_string() {
        let qd = QueryData::new("", true, true);
        assert!(!qd.is_wildcard());
    }

    #[test]
    fn test_has_wildcards_static_with_star() {
        assert!(QueryData::has_wildcards("foo*bar"));
        assert!(QueryData::has_wildcards("*"));
        assert!(QueryData::has_wildcards("foo*"));
        assert!(QueryData::has_wildcards("*foo"));
    }

    #[test]
    fn test_has_wildcards_static_with_question() {
        assert!(QueryData::has_wildcards("foo?bar"));
        assert!(QueryData::has_wildcards("?"));
        assert!(QueryData::has_wildcards("foo?"));
        assert!(QueryData::has_wildcards("?foo"));
    }

    #[test]
    fn test_has_wildcards_static_without_wildcards() {
        assert!(!QueryData::has_wildcards("foobar"));
        assert!(!QueryData::has_wildcards(""));
        assert!(!QueryData::has_wildcards("test"));
        assert!(!QueryData::has_wildcards("foo bar"));
    }

    #[test]
    fn test_has_wildcards_static_multiple() {
        assert!(QueryData::has_wildcards("*?*?"));
        assert!(QueryData::has_wildcards("a*b?c*d?e"));
    }

    #[test]
    fn test_clone() {
        let qd1 = QueryData::new("test", true, false);
        let qd2 = qd1.clone();
        assert_eq!(qd1, qd2);
    }

    #[test]
    fn test_equality() {
        let qd1 = QueryData::new("test", true, false);
        let qd2 = QueryData::new("test", true, false);
        assert_eq!(qd1, qd2);
    }

    #[test]
    fn test_inequality_different_query() {
        let qd1 = QueryData::new("test", true, false);
        let qd2 = QueryData::new("different", true, false);
        assert_ne!(qd1, qd2);
    }

    #[test]
    fn test_inequality_different_case_sensitivity() {
        let qd1 = QueryData::new("test", true, false);
        let qd2 = QueryData::new("test", false, false);
        assert_ne!(qd1, qd2);
    }

    #[test]
    fn test_inequality_different_labels() {
        let qd1 = QueryData::new("test", true, true);
        let qd2 = QueryData::new("test", true, false);
        assert_ne!(qd1, qd2);
    }

    #[test]
    fn test_display() {
        let qd = QueryData::new("test", true, false);
        assert_eq!(
            qd.to_string(),
            "QueryData(query='test', case_sensitive=true, include_dynamic_labels=false)"
        );
    }

    #[test]
    fn test_debug() {
        let qd = QueryData::new("test", true, false);
        let debug_str = format!("{:?}", qd);
        assert!(debug_str.contains("QueryData"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_string_into_conversion() {
        let qd = QueryData::new("test".to_string(), true, false);
        assert_eq!(qd.query_string(), "test");
    }

    #[test]
    fn test_case_sensitive_variations() {
        let case_sensitive = QueryData::new("Test", true, true);
        let case_insensitive = QueryData::new("Test", false, true);

        assert!(case_sensitive.is_case_sensitive());
        assert!(!case_insensitive.is_case_sensitive());
        assert_ne!(case_sensitive, case_insensitive);
    }

    #[test]
    fn test_dynamic_labels_variations() {
        let with_labels = QueryData::new("test", true, true);
        let without_labels = QueryData::new("test", true, false);

        assert!(with_labels.is_include_dynamic_labels());
        assert!(!without_labels.is_include_dynamic_labels());
        assert_ne!(with_labels, without_labels);
    }

    #[test]
    fn test_wildcard_constants() {
        assert_eq!(QueryData::ANY_STRING_WILDCARD, '*');
        assert_eq!(QueryData::ANY_CHAR_WILDCARD, '?');
    }
}
