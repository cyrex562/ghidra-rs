use regex::{Regex, RegexBuilder};

use crate::app::services::QueryData;
use crate::program::model::symbol::{Symbol, DELIMITER};
use crate::util::UserSearchUtils;

/// Matches symbol names with or without namespace paths and wildcards.
///
/// Port of `ghidra.app.util.navigation.SymbolMatcher`.
pub struct SymbolMatcher {
    symbol_name: String,
    pattern: Regex,
    case_sensitive: bool,
    is_possible_memory_block_pattern: bool,
}

impl SymbolMatcher {
    /// Creates a new matcher for the given query string.
    ///
    /// Any whitespace in `query_string` is assumed to be a user mistake and is removed.
    pub fn new(query_string: &str, case_sensitive: bool) -> Result<Self, regex::Error> {
        let query_string = remove_whitespace(query_string);

        let is_relative_path = !query_string.starts_with(DELIMITER);
        let symbol_name = get_symbol_name(&query_string);
        let pattern = create_pattern(&query_string, is_relative_path, case_sensitive)?;
        let is_possible_memory_block_pattern = check_if_possible_memory_block_pattern(&query_string);

        Ok(SymbolMatcher {
            symbol_name,
            pattern,
            case_sensitive,
            is_possible_memory_block_pattern,
        })
    }

    /// Returns the symbol name part of the query (the portion after the last namespace
    /// delimiter, or the entire query if it has no namespace path).
    pub fn get_symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns true if the symbol name part of the query string has no wildcards and is
    /// case sensitive.
    pub fn has_fully_specified_name(&self) -> bool {
        !QueryData::has_wildcards(&self.symbol_name) && self.case_sensitive
    }

    /// Returns true if there are wildcards in the symbol name.
    pub fn has_wild_cards_in_symbol_name(&self) -> bool {
        QueryData::has_wildcards(&self.symbol_name)
    }

    /// Returns true if the given symbol matches the query specification for this matcher.
    pub fn matches(&self, symbol: &dyn Symbol) -> bool {
        let path = create_symbol_path_with_spaces(symbol);
        if self.pattern.is_match(&path) {
            return true;
        }

        // legacy feature where the query may have specified a memory block name instead of a
        // namespace path.
        self.check_memory_block_name(symbol)
    }

    fn check_memory_block_name(&self, symbol: &dyn Symbol) -> bool {
        if !self.is_possible_memory_block_pattern {
            return false;
        }

        let Some(block_name) = symbol.get_containing_memory_block_name() else {
            return false;
        };
        let block_name_path = format!("{} {}", block_name, symbol.get_name());
        self.pattern.is_match(&block_name_path)
    }
}

/// Removes every whitespace character from `input` (users entering spaces is assumed to be a
/// mistake). Matches Java's `queryString.replaceAll("\\s", "")`.
fn remove_whitespace(input: &str) -> String {
    input
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\x0B' | '\x0C' | '\r'))
        .collect()
}

fn get_symbol_name(query_string: &str) -> String {
    match query_string.rfind(DELIMITER) {
        None => query_string.to_string(),
        Some(index) => query_string[index + DELIMITER.len()..].to_string(),
    }
}

/// A legacy feature is the ability to also be able to find a label in a particular memory
/// block using the same syntax as a symbol in a namespace. So something like
/// "block::bob" would find the symbol "bob" (regardless of its namespace) if it were
/// in a memory block named "block". (Also, this only worked if there wasn't also a
/// symbol in a namespace named "block"). Now that wildcards are supported in the namespace
/// specifications, this feature becomes even more confusing. To avoid this, the legacy
/// memory block feature will not support wildcards and probably should be removed
/// at some point.
fn check_if_possible_memory_block_pattern(query_string: &str) -> bool {
    let Some(last_index_of) = query_string.rfind(DELIMITER) else {
        return false;
    };

    // if it starts with a delimiter, then it can't match a memory block
    if last_index_of < 1 {
        return false;
    }
    let qualifier_part = &query_string[..last_index_of];

    // if the qualifier is a multi part path, then it can't match a memory block
    if qualifier_part.contains(DELIMITER) {
        return false;
    }

    // we don't support wildcard when matching against memory block names
    !qualifier_part.contains('*') && !qualifier_part.contains('?')
}

fn create_pattern(
    user_input: &str,
    is_relative_path: bool,
    case_sensitive: bool,
) -> Result<Regex, regex::Error> {
    // We only support globbing characters in the query, any other regex characters need
    // to be escaped before we feed it to the regex engine. But we need to do it before we
    // begin our substitutions as we will be adding some of those characters into the query
    // string and we don't want those to be escaped.
    let mut s = UserSearchUtils::escape_non_globbing_regex_characters(user_input);
    s = replace_namespace_delimiters(&s, is_relative_path);
    s = remove_excess_stars(&s);
    s = convert_name_globing_to_regex(&s);
    s = convert_path_globing_to_regex(&s);
    s = convert_relative_path_to_regex(&s, is_relative_path);

    RegexBuilder::new(&format!("\\A(?:{})\\z", s))
        .case_insensitive(!case_sensitive)
        .build()
}

/// There is never a reason to have 3 or more stars in the query. To avoid errors creating a
/// regex pattern, replace runs of 3 or more stars with two stars. Later, the method that
/// handles path globbing (`**`) chars, will either convert `**` to a path matching expression,
/// or if not valid in its location, to a single `*` regex pattern.
fn remove_excess_stars(s: &str) -> String {
    let mut s = s.to_string();
    let mut start = s.find("***");
    while let Some(start_index) = start {
        let end = find_first_non_star(&s, start_index);
        s = format!("{}{}", &s[..start_index + 2], &s[end..]);
        start = s.find("***");
    }
    s
}

fn find_first_non_star(query: &str, index: usize) -> usize {
    let bytes = query.as_bytes();
    let mut index = index;
    while index < bytes.len() && bytes[index] == b'*' {
        index += 1;
    }
    index
}

/// To make regex processing easier, replace any namespace delimiter ("::") with a single
/// character delimiter. We chose the space character because spaces can't exist in namespace
/// names or symbol names.
fn replace_namespace_delimiters(s: &str, is_relative_path: bool) -> String {
    // also we remove any starting delimiter
    let s = if !is_relative_path {
        &s[DELIMITER.len()..]
    } else {
        s
    };

    s.replace(DELIMITER, " ")
}

/// Path globbing uses "**" to match any number of namespace elements in the symbol path.
/// Valid examples of path globbing are "a::**::b", "**::a", or "a::**".
///
/// In order to handle the case where it matches zero path elements ("a::**::b" should match
/// "a::b"), we need to remove either the starting delimiter or the ending delimiter. Also
/// note that we are doing this replacement after all "::" have been replaced by spaces.
fn convert_path_globing_to_regex(s: &str) -> String {
    // First replace " ** " with a regex pattern that matches either: a space followed by one
    // or more characters followed by another space; or a single space. The second case
    // handles when the ** matches zero elements such as "a::**::b" matches "a::b".
    let mut s = s.replace(" ** ", "( .* | )");

    // If the string starts with "** ", replace it with the regex pattern that matches either:
    // anything followed by a space; or nothing at all.
    if let Some(rest) = s.strip_prefix("** ") {
        s = format!("(.* |){}", rest);
    }

    // If the string ends with " **", replace it with the regex pattern that matches a space
    // followed by anything.
    if let Some(rest) = s.strip_suffix(" **") {
        s = format!("{} .*", rest);
    }

    // Finally, any other "**", not handled is considered a mistake and is treated as if a
    // single star was entered, which is mapped to the regex expression matching any number of
    // non-space characters.
    s.replace("**", "[^ ]*")
}

/// Name globbing here refers to using the "*" or "?" globbing characters. However, we only
/// want them to apply to a single namespace or symbol name element. In other words we can't
/// use the regex ".*" because it would match across delimiters which we don't want. The
/// alternative is to use the "match everything but" construct where we use "[^ ]*" which means
/// match anything but spaces, which is the delimiter we are using.
///
/// There is a wrinkle for this substitution. We are replacing only single "*" characters, but
/// we need to avoid doubles (**) as those are handled by path globbing, so runs of stars are
/// left untouched here based on their original (not yet substituted) neighbors.
fn convert_name_globing_to_regex(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len());
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '*' => {
                let prev_is_star = i > 0 && chars[i - 1] == '*';
                let next_is_star = chars.get(i + 1) == Some(&'*');
                if prev_is_star || next_is_star {
                    result.push('*');
                } else {
                    result.push_str("[^ ]*");
                }
            }
            '?' => result.push('.'),
            _ => result.push(c),
        }
    }
    result
}

/// If the query is relative, add a "match anything" regex pattern to the front of the query so
/// that it will match any number of parent namespaces containing the specified symbol/namespace
/// path.
fn convert_relative_path_to_regex(s: &str, is_relative_path: bool) -> String {
    if is_relative_path && !is_blank(s) {
        format!(".*{}", s)
    } else {
        s.to_string()
    }
}

fn is_blank(s: &str) -> bool {
    s.chars().all(|c| c.is_whitespace())
}

fn create_symbol_path_with_spaces(symbol: &dyn Symbol) -> String {
    let mut path: Vec<String> = symbol
        .get_parent_namespace()
        .map(|namespace| namespace.get_path_list(false))
        .unwrap_or_default();
    path.push(symbol.get_name().to_string());
    path.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Namespace, SourceType, SymbolType};
    use std::sync::Arc;

    struct TestNamespace {
        name: String,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Namespace for TestNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for these tests")
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    struct TestSymbol {
        name: String,
        parent: Option<Arc<dyn Namespace>>,
        memory_block_name: Option<String>,
    }

    impl TestSymbol {
        fn with_memory_block(mut self, block_name: &str) -> Self {
            self.memory_block_name = Some(block_name.to_string());
            self
        }
    }

    impl Symbol for TestSymbol {
        fn get_address(&self) -> crate::program::model::address::Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            space.address(0)
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn get_parent_id(&self) -> i64 {
            0
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }

        fn get_containing_memory_block_name(&self) -> Option<String> {
            self.memory_block_name.clone()
        }
    }

    fn symbol(path: &str) -> TestSymbol {
        let parts: Vec<&str> = path.split(DELIMITER).collect();
        let name = parts[parts.len() - 1].to_string();
        let mut parent: Option<Arc<dyn Namespace>> = None;
        for part in &parts[..parts.len() - 1] {
            parent = Some(Arc::new(TestNamespace {
                name: part.to_string(),
                parent,
            }));
        }
        TestSymbol {
            name,
            parent,
            memory_block_name: None,
        }
    }

    fn assert_matches(matcher: &SymbolMatcher, path: &str) {
        assert!(matcher.matches(&symbol(path)), "expected match: {path}");
    }

    fn assert_not_matches(matcher: &SymbolMatcher, path: &str) {
        assert!(!matcher.matches(&symbol(path)), "expected no match: {path}");
    }

    #[test]
    fn no_namespace_query_case_sensitive() {
        let matcher = SymbolMatcher::new("bob", true).unwrap();

        assert_matches(&matcher, "bob");
        assert_matches(&matcher, "a::bob");
        assert_matches(&matcher, "a::b::bob");
        assert_matches(&matcher, "a::b::c::bob");

        assert_not_matches(&matcher, "Bob");
        assert_not_matches(&matcher, "a::Bob");
        assert_not_matches(&matcher, "a::b::Bob");
        assert_not_matches(&matcher, "a::b::bob:joe");
    }

    #[test]
    fn no_namespace_query_case_insensitive() {
        let matcher = SymbolMatcher::new("bob", false).unwrap();

        assert_matches(&matcher, "bob");
        assert_matches(&matcher, "a::bob");
        assert_matches(&matcher, "a::b::bob");
        assert_matches(&matcher, "a::b::c::bob");
        assert_matches(&matcher, "Bob");
        assert_matches(&matcher, "a::Bob");
        assert_matches(&matcher, "a::b::Bob");
        assert_matches(&matcher, "a::b::c::Bob");
    }

    #[test]
    fn no_namespace_query_wild_cards_case_sensitive() {
        let matcher = SymbolMatcher::new("bo*", true).unwrap();

        assert_matches(&matcher, "bob");
        assert_matches(&matcher, "a::bob");
        assert_matches(&matcher, "a::b::bob");
        assert_matches(&matcher, "a::b::c::bob");

        assert_not_matches(&matcher, "Bob");
        assert_not_matches(&matcher, "a::Bob");
        assert_not_matches(&matcher, "a::b::Bob");
        assert_not_matches(&matcher, "a::b::c::Bob");
    }

    #[test]
    fn no_namespace_query_single_char_wild_cards_case_sensitive() {
        let matcher = SymbolMatcher::new("b?b", true).unwrap();

        assert_matches(&matcher, "bob");
        assert_matches(&matcher, "a::bob");

        assert_not_matches(&matcher, "Bob");
        assert_not_matches(&matcher, "a::b::c::Bob");
    }

    #[test]
    fn with_namespace() {
        let matcher = SymbolMatcher::new("apple::bob", false).unwrap();

        assert_matches(&matcher, "apple::bob");
        assert_matches(&matcher, "x::apple::bob");
        assert_matches(&matcher, "x::y::apple::bob");

        assert_not_matches(&matcher, "bob");
        assert_not_matches(&matcher, "Bob");
        assert_not_matches(&matcher, "dog::Bob");
        assert_not_matches(&matcher, "apple::x::Bob");
    }

    #[test]
    fn with_namespace_two_levels() {
        let matcher = SymbolMatcher::new("apple::car::bob", false).unwrap();

        assert_matches(&matcher, "apple::car::bob");
        assert_matches(&matcher, "x::apple::car::bob");
        assert_matches(&matcher, "x::y::apple::car::bob");

        assert_not_matches(&matcher, "bob");
        assert_not_matches(&matcher, "apple::bob");
        assert_not_matches(&matcher, "apple::x::bob");
    }

    #[test]
    fn with_full_wild_namespace() {
        let matcher = SymbolMatcher::new("*::bob", false).unwrap();

        assert_matches(&matcher, "apple::bob");
        assert_matches(&matcher, "dog::bob");
        assert_matches(&matcher, "x::y::bob");

        assert_not_matches(&matcher, "bob");
        assert_not_matches(&matcher, "joe");
        assert_not_matches(&matcher, "bo");
        assert_not_matches(&matcher, "bobby");
        assert_not_matches(&matcher, "x::boby");
    }

    #[test]
    fn with_partial_wild_namespace() {
        let matcher = SymbolMatcher::new("*a*::bob", false).unwrap();

        assert_matches(&matcher, "apple::bob");
        assert_matches(&matcher, "banana::bob");
        assert_matches(&matcher, "x::car::bob");

        assert_not_matches(&matcher, "bob");
        assert_not_matches(&matcher, "apple::bo");
        assert_not_matches(&matcher, "apple::x::bob");
    }

    #[test]
    fn with_wild_namespace_absolute_path() {
        let matcher = SymbolMatcher::new("::*::bob", false).unwrap();

        assert_matches(&matcher, "apple::bob");
        assert_matches(&matcher, "x::bob");

        assert_not_matches(&matcher, "bob");
        assert_not_matches(&matcher, "x::apple::bo");
        assert_not_matches(&matcher, "apple::x::bob");
    }

    #[test]
    fn empty_path() {
        let matcher = SymbolMatcher::new("", false).unwrap();

        assert_not_matches(&matcher, "bob");
        assert_not_matches(&matcher, "a:b");
    }

    #[test]
    fn path_globbing() {
        let matcher = SymbolMatcher::new("Apple::**::dog", false).unwrap();

        assert_matches(&matcher, "Apple::dog");
        assert_matches(&matcher, "Apple::x::dog");
        assert_matches(&matcher, "Apple::x::y::dog");
        assert_matches(&matcher, "Apple::x::Apple::dog");
        assert_matches(&matcher, "a::b::Apple::x::y::dog");

        assert_not_matches(&matcher, "dog");
        assert_not_matches(&matcher, "x::dog");
        assert_not_matches(&matcher, "Apple::x::doggy");
        assert_not_matches(&matcher, "Applebob::x::dog");
    }

    #[test]
    fn multiple_path_globbing() {
        let matcher = SymbolMatcher::new("Apple::**::cat::**::dog", false).unwrap();

        assert_matches(&matcher, "Apple::cat::dog");
        assert_matches(&matcher, "Apple::x::cat::dog");
        assert_matches(&matcher, "Apple::x::cat::y::dog");
        assert_matches(&matcher, "Apple::cat::x::Apple::dog");
        assert_matches(&matcher, "Apple::x::Apple::cat::dog");
        assert_matches(&matcher, "a::b::Apple::x::cat::dog");

        assert_not_matches(&matcher, "dog");
        assert_not_matches(&matcher, "Apple::dog");
        assert_not_matches(&matcher, "cat::dog");
    }

    #[test]
    fn path_globbing_at_end() {
        let matcher = SymbolMatcher::new("Apple::**", false).unwrap();

        assert_matches(&matcher, "Apple::dog");
        assert_matches(&matcher, "Apple::cat::dog");
        assert_matches(&matcher, "a::b::Apple::x::cat::dog");

        assert_not_matches(&matcher, "dog");
        assert_not_matches(&matcher, "Apple");
    }

    #[test]
    fn path_globbing_at_start() {
        let matcher = SymbolMatcher::new("**::dog", false).unwrap();

        assert_matches(&matcher, "dog");
        assert_matches(&matcher, "Apple::dog");
        assert_matches(&matcher, "a::b::Apple::x::cat::dog");

        assert_not_matches(&matcher, "Apple");
    }

    #[test]
    fn bad_double_star_acts_like_single_star() {
        let matcher = SymbolMatcher::new("Apple**::dog", false).unwrap();

        assert_matches(&matcher, "Apple::x::Apple::dog");
        assert_matches(&matcher, "Apple::dog");
        assert_matches(&matcher, "Applebob::dog");

        assert_not_matches(&matcher, "Apple::x::dog");
        assert_not_matches(&matcher, "Apple::x::y::dog");
        assert_not_matches(&matcher, "a::b::Apple::x::y::dog");
        assert_not_matches(&matcher, "dog");
        assert_not_matches(&matcher, "x::dog");
        assert_not_matches(&matcher, "Apple::x::doggy");
    }

    #[test]
    fn path_globbing_with_name_globbing() {
        let matcher = SymbolMatcher::new("Ap*le::**::do*", false).unwrap();

        assert_matches(&matcher, "Apple::dog");
        assert_matches(&matcher, "Apple::x::dog");
        assert_matches(&matcher, "Apple::x::y::dog");
        assert_matches(&matcher, "Apple::x::Apple::dog");
        assert_matches(&matcher, "a::b::Apple::x::y::dog");
        assert_matches(&matcher, "Apple::x::doggy");

        assert_not_matches(&matcher, "dog");
        assert_not_matches(&matcher, "x::dog");
    }

    #[test]
    fn name_globbing_after_dot_in_name() {
        // We don't support the regex ".*" directly from user input. If the user enters
        // "*.*::bob", the "." should only match the literal '.' character.
        let matcher = SymbolMatcher::new("*.*::bob", false).unwrap();

        assert_matches(&matcher, "a.a::bob");
        assert_not_matches(&matcher, "a.a::c::bob");
    }

    #[test]
    fn name_globbing_excess_stars() {
        // 3 stars is assumed to be a mistake and will be treated as though it were a single *
        let matcher = SymbolMatcher::new("a***b::bob", false).unwrap();
        assert_matches(&matcher, "axxxb::bob");
        assert_not_matches(&matcher, "a::b::bob");

        // In this context, where the extended *s are enclosed in delimiters, we assume the
        // user meant **
        let matcher = SymbolMatcher::new("a::***::bob", false).unwrap();
        assert_matches(&matcher, "a::b::bob");
        assert_not_matches(&matcher, "axxxb::bob");

        let matcher = SymbolMatcher::new("bob*****", false).unwrap();
        assert_matches(&matcher, "bobby");
    }

    #[test]
    fn block_name_matches() {
        // all symbols are stubbed to be in the ".text" block
        let matcher = SymbolMatcher::new(".text::bob", false).unwrap();

        assert!(matcher.matches(&symbol("bob").with_memory_block(".text")));
        assert!(matcher.matches(&symbol("aaa::bob").with_memory_block(".text")));
        assert!(matcher.matches(&symbol("x::y::z::bob").with_memory_block(".text")));
    }

    #[test]
    fn block_name_matches_dont_support_wilds_in_block_name() {
        let matcher = SymbolMatcher::new(".t*xt::bob", false).unwrap();
        assert!(!matcher.matches(&symbol("bob").with_memory_block(".text")));

        let matcher = SymbolMatcher::new(".t?xt::bob", false).unwrap();
        assert!(!matcher.matches(&symbol("bob").with_memory_block(".text")));
    }

    #[test]
    fn block_name_matches_support_wilds_in_symbol_name() {
        let matcher = SymbolMatcher::new(".text::bob*", false).unwrap();

        assert!(matcher.matches(&symbol("bob").with_memory_block(".text")));
        assert!(matcher.matches(&symbol("bobx").with_memory_block(".text")));
        assert!(matcher.matches(&symbol("aaa::bobz").with_memory_block(".text")));
    }

    #[test]
    fn no_memory_block_means_no_legacy_match() {
        let matcher = SymbolMatcher::new(".text::bob", false).unwrap();
        // symbol has no known memory block, so the legacy fallback can't match
        assert!(!matcher.matches(&symbol("bob")));
    }

    #[test]
    fn get_symbol_name() {
        let matcher = SymbolMatcher::new("a::b::c", false).unwrap();
        assert_eq!(matcher.get_symbol_name(), "c");
    }

    #[test]
    fn has_fully_specified_name() {
        let matcher = SymbolMatcher::new("a::b::c", false).unwrap();
        assert!(!matcher.has_fully_specified_name());

        let matcher = SymbolMatcher::new("a::b::c", true).unwrap();
        assert!(matcher.has_fully_specified_name());

        let matcher = SymbolMatcher::new("a::b::c*", true).unwrap();
        assert!(!matcher.has_fully_specified_name());

        let matcher = SymbolMatcher::new("a::b*::c", true).unwrap();
        assert!(matcher.has_fully_specified_name());
    }

    #[test]
    fn has_wild_cards_in_symbol_name() {
        let matcher = SymbolMatcher::new("a::b::c", false).unwrap();
        assert!(!matcher.has_wild_cards_in_symbol_name());

        let matcher = SymbolMatcher::new("a::b::c*", true).unwrap();
        assert!(matcher.has_wild_cards_in_symbol_name());

        let matcher = SymbolMatcher::new("a::b*::c", true).unwrap();
        assert!(!matcher.has_wild_cards_in_symbol_name());
    }

    #[test]
    fn backslash() {
        let matcher = SymbolMatcher::new("\\", false).unwrap();
        assert_matches(&matcher, "\\");

        let matcher = SymbolMatcher::new("\\bob\\", false).unwrap();
        assert_matches(&matcher, "\\bob\\");
    }
}
