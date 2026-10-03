//! Port of `ghidra.features.base.replace.SearchAndReplaceQuery`.
//!
//! Immutable class for storing all related query information for performing a search-and-replace
//! operation: the search pattern, search pattern text, replacement text, search limit, and the
//! types of program elements to search.
//!
//! # Shape
//!
//! Java is a concrete leaf class (nothing extends it), so this becomes a plain `struct` + `impl`
//! (rule R14a-concrete-leaf).
//!
//! # Seams
//!
//! * **PROMOTE MODE.** The empty [`SearchAndReplaceQuery`](crate::feature::seam_stubs::SearchAndReplaceQuery)
//!   placeholder created while porting the previous class in this batch
//!   ([`SearchAndReplaceHandler`](super::search_and_replace_handler)) is replaced by this real
//!   struct; `SearchAndReplaceHandler::find_all`'s `query: &SearchAndReplaceQuery` parameter now
//!   points at this type.
//! * **`findAll`'s handler dispatch.** Java's `findAll` calls a private `getHandlers()` that
//!   derives the distinct handlers to invoke from `SearchType.getHandler()`. This crate's
//!   `SearchType` placeholder ([`crate::feature::seam_stubs::SearchType`]) deliberately has no
//!   handler back-reference (see that struct's own docs -- it was ported while cutting the
//!   `SearchType` <-> `SearchAndReplaceHandler` cycle), and no concrete `SearchType` exists
//!   anywhere in this crate yet: the six `*SearchAndReplaceHandler` subclasses that construct
//!   real `SearchType`s (`ghidra/features/base/replace/handler/*.java`) are not ported. So
//!   [`find_all`](SearchAndReplaceQuery::find_all) below is a documented no-op seam -- everything
//!   else on this type is fully faithful, but there is nothing to dispatch to yet, so it returns
//!   `Ok(())` without visiting `selected_types`, rather than inventing dispatch behavior with no
//!   Java original to check against. Wire the loop back in once a handler-bearing `SearchType`
//!   exists.
//! * **`Pattern`/regex construction.** Reuses
//!   [`UserSearchUtils::convert_user_input_to_regex`] exactly like Java's
//!   `UserSearchUtils.convertUserInputToRegex`. `Pattern.DOTALL` / `Pattern.CASE_INSENSITIVE` map
//!   to [`RegexBuilder::dot_matches_new_line`]/[`RegexBuilder::case_insensitive`]. Java's
//!   unchecked `PatternSyntaxException` is surfaced as a `Result<_, regex::Error>`, matching
//!   `StringMatchQuery::new`'s established convention elsewhere in this crate.

use regex::{Regex, RegexBuilder};

use crate::feature::base::quickfix::QuickFix;
use crate::feature::seam_stubs::SearchType;
use crate::program::model::listing::Program;
use crate::util::datastruct::Accumulator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use crate::util::user_search_utils::UserSearchUtils;

/// Port of `ghidra.features.base.replace.SearchAndReplaceQuery`.
pub struct SearchAndReplaceQuery {
    search_text: String,
    replacement_text: String,
    pattern: Regex,
    search_limit: i32,
    selected_types: Vec<SearchType>,
}

impl SearchAndReplaceQuery {
    /// `SearchAndReplaceQuery(String, String, Set<SearchType>, boolean, boolean, boolean, int)`.
    ///
    /// # Errors
    ///
    /// Returns `regex::Error` if the constructed pattern is not a valid regular expression. Java:
    /// `PatternSyntaxException`, an unchecked exception; see the module docs' Seams section for
    /// why this is a `Result` here instead.
    pub fn new(
        search_text: impl Into<String>,
        replacement_text: impl Into<String>,
        search_types: impl IntoIterator<Item = SearchType>,
        is_regex: bool,
        is_case_sensitive: bool,
        is_whole_word: bool,
        search_limit: i32,
    ) -> Result<Self, regex::Error> {
        let search_text = search_text.into();
        let pattern =
            Self::create_pattern(&search_text, is_regex, is_case_sensitive, is_whole_word)?;
        Ok(Self {
            replacement_text: replacement_text.into(),
            pattern,
            search_limit,
            selected_types: search_types.into_iter().collect(),
            search_text,
        })
    }

    /// Java: `private Pattern createPattern(boolean, boolean, boolean)`.
    fn create_pattern(
        search_text: &str,
        is_regex: bool,
        is_case_sensitive: bool,
        is_whole_word: bool,
    ) -> Result<Regex, regex::Error> {
        let pattern_str = if is_regex {
            search_text.to_string()
        } else {
            let converted = UserSearchUtils::convert_user_input_to_regex(search_text, false);
            if is_whole_word {
                format!(r"\b{converted}\b")
            } else {
                converted
            }
        };
        RegexBuilder::new(&pattern_str)
            .dot_matches_new_line(true)
            .case_insensitive(!is_case_sensitive)
            .build()
    }

    /// Initiates the search. See the module docs' Seams section for why this is currently a
    /// documented no-op.
    ///
    /// Mirrors `SearchAndReplaceQuery.findAll(Program, Accumulator<QuickFix>, TaskMonitor)`.
    pub fn find_all(
        &self,
        _program: &dyn Program,
        _accumulator: &mut dyn Accumulator<Box<dyn QuickFix>>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        Ok(())
    }

    /// Returns the search [`Regex`] used to search program elements.
    ///
    /// Mirrors `SearchAndReplaceQuery.getSearchPattern()`.
    pub fn search_pattern(&self) -> &Regex {
        &self.pattern
    }

    /// Returns true if the given [`SearchType`] is to be included in the search.
    ///
    /// Mirrors `SearchAndReplaceQuery.containsSearchType(SearchType)`.
    pub fn contains_search_type(&self, search_type: &SearchType) -> bool {
        self.selected_types.contains(search_type)
    }

    /// Returns the search text used to generate the pattern for this query.
    ///
    /// Mirrors `SearchAndReplaceQuery.getSearchText()`.
    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    /// Returns the replacement text that will replace matched elements.
    ///
    /// Mirrors `SearchAndReplaceQuery.getReplacementText()`.
    pub fn replacement_text(&self) -> &str {
        &self.replacement_text
    }

    /// Returns all the [`SearchType`]s to be included in this query.
    ///
    /// Mirrors `SearchAndReplaceQuery.getSelectedSearchTypes()`.
    pub fn selected_search_types(&self) -> &[SearchType] {
        &self.selected_types
    }

    /// Returns the maximum number of search matches to be found before stopping early.
    ///
    /// Mirrors `SearchAndReplaceQuery.getSearchLimit()`.
    pub fn search_limit(&self) -> i32 {
        self.search_limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_non_regex_search_escapes_metacharacters() {
        // "foo.bar" is not a regex here, so '.' is a literal dot, not "any character".
        let query = SearchAndReplaceQuery::new("foo.bar", "baz", [], false, true, false, 100)
            .expect("valid pattern");
        assert!(query.search_pattern().is_match("xxfoo.barxx"));
        assert!(!query.search_pattern().is_match("fooXbar"));
    }

    #[test]
    fn case_insensitive_matches_regardless_of_case() {
        let query = SearchAndReplaceQuery::new("Hello", "Hi", [], false, false, false, 100)
            .expect("valid pattern");
        assert!(query.search_pattern().is_match("hello"));
        assert!(query.search_pattern().is_match("HELLO"));
    }

    #[test]
    fn case_sensitive_does_not_match_other_case() {
        let query = SearchAndReplaceQuery::new("Hello", "Hi", [], false, true, false, 100)
            .expect("valid pattern");
        assert!(query.search_pattern().is_match("Hello"));
        assert!(!query.search_pattern().is_match("hello"));
    }

    #[test]
    fn whole_word_only_matches_word_boundaries() {
        let query = SearchAndReplaceQuery::new("word", "w", [], false, true, true, 100)
            .expect("valid pattern");
        assert!(query.search_pattern().is_match("a word here"));
        assert!(!query.search_pattern().is_match("wordy"));
        assert!(!query.search_pattern().is_match("password"));
    }

    #[test]
    fn regex_mode_uses_search_text_as_pattern_directly() {
        let query = SearchAndReplaceQuery::new("fo+", "f", [], true, true, false, 100)
            .expect("valid pattern");
        assert!(query.search_pattern().is_match("foooo"));
        assert!(!query.search_pattern().is_match("bar"));
    }

    #[test]
    fn invalid_regex_returns_err() {
        let result = SearchAndReplaceQuery::new("(unclosed", "x", [], true, true, false, 100);
        assert!(result.is_err());
    }

    #[test]
    fn getters_return_constructor_values() {
        let types = vec![
            SearchType::new("Symbols", "Symbol names"),
            SearchType::new("Comments", "Listing comments"),
        ];
        let query = SearchAndReplaceQuery::new(
            "abc",
            "xyz",
            types.clone(),
            false,
            true,
            false,
            42,
        )
        .expect("valid pattern");
        assert_eq!(query.search_text(), "abc");
        assert_eq!(query.replacement_text(), "xyz");
        assert_eq!(query.search_limit(), 42);
        assert_eq!(query.selected_search_types().len(), 2);
        assert!(query.contains_search_type(&types[0]));
        assert!(query.contains_search_type(&types[1]));
        assert!(!query.contains_search_type(&SearchType::new("Other", "d")));
    }

    #[test]
    fn find_all_is_a_documented_noop_ok() {
        struct TestProgram;
        impl crate::framework::model::DomainObject for TestProgram {}
        impl Program for TestProgram {
            fn get_name(&self) -> String {
                "test.bin".to_string()
            }
            fn get_language_id(&self) -> String {
                "test:LE:32:default".to_string()
            }
        }

        struct VecAccumulator {
            items: Vec<Box<dyn QuickFix>>,
        }
        impl Accumulator<Box<dyn QuickFix>> for VecAccumulator {
            fn add(&mut self, item: Box<dyn QuickFix>) {
                self.items.push(item);
            }
            fn get_progress(&self) -> usize {
                self.items.len()
            }
        }

        let query = SearchAndReplaceQuery::new("abc", "xyz", [], false, true, false, 10)
            .expect("valid pattern");
        let program = TestProgram;
        let mut acc = VecAccumulator { items: Vec::new() };
        let monitor = crate::util::task::DummyMonitor;
        let result = query.find_all(&program, &mut acc, &monitor);
        assert!(result.is_ok());
        assert_eq!(acc.items.len(), 0);
    }
}
