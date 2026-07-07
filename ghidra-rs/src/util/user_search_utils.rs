use regex::Regex;

/// Characters that are handled similarly to command-line globbing expansion characters.
const GLOB_CHARACTERS: [char; 2] = ['*', '?'];

/// This struct converts user inputted strings and creates [`Regex`]es from them that can be
/// used to match or search text.
///
/// Note: methods on this struct will escape regex characters, which means that normal regex
/// queries will not work, but will instead be interpreted as literal string searches.
///
/// Unlike `java.util.regex.Pattern`, a [`Regex`] does not distinguish between "matches"
/// (the whole input matches) and "find" (a substring of the input matches) at compile time;
/// that distinction is made by the caller when searching. The patterns built by
/// [`UserSearchUtils::create_starts_with_pattern`], [`UserSearchUtils::create_ends_with_pattern`],
/// and [`UserSearchUtils::create_contains_pattern`] embed `.*` padding and are only meaningful
/// for whole-string matching. The patterns built by [`UserSearchUtils::create_pattern`],
/// [`UserSearchUtils::create_search_pattern`], and
/// [`UserSearchUtils::create_literal_search_pattern`] contain no such padding, so callers may
/// use them either for whole-string matching or for finding a match within a larger string.
pub struct UserSearchUtils;

impl UserSearchUtils {
    /// Wildcard string for matching 0 or more characters.
    pub const STAR: &'static str = "*";

    /// No pattern options; matching is case sensitive.
    pub const CASE_SENSITIVE: u32 = 0;

    /// Mirrors `java.util.regex.Pattern.CASE_INSENSITIVE`. Combine with other option bits
    /// using `|`. This is the only option bit honored by this struct's methods.
    pub const CASE_INSENSITIVE: u32 = 0x02;

    /// <b>
    /// Note: this is the default model of how to let users search for things in Ghidra.  This
    /// is NOT a tool to allow regex searching, but instead allows users to perform searches while
    /// using familiar globbing characters such as '*' and '?'.
    /// </b>
    ///
    /// Create a regular expression from the given input. <b>Note:</b> the regular expression
    /// created by this method is not a pure regular expression.  More specifically, many
    /// regular expression characters passed to this method will be escaped
    /// (see [`UserSearchUtils::escape_all_regex_characters`]).
    ///
    /// Also, globbing characters <b><u>will</u></b> be changed from a regular expression
    /// meaning to a command-line style glob meaning.
    ///
    /// <b>Note: </b>This method <b>will</b> escape regular expression characters, such as
    /// `.`, `$`, and many others. Thus, this method is not meant to <b>accept</b> regular
    /// expressions, but rather <b>generates</b> regular expressions.
    pub fn create_search_pattern(
        input: &str,
        case_sensitive: bool,
    ) -> Result<Regex, regex::Error> {
        let options = if case_sensitive {
            Self::CASE_SENSITIVE
        } else {
            Self::CASE_INSENSITIVE
        };

        Self::create_pattern(input, true, options)
    }

    /// Generate a compiled representation of a regular expression, ignoring regex special
    /// characters. The resulting pattern will match the literal text string.
    ///
    /// This method will <b><u>not</u></b> turn globbing characters into regex characters.
    /// If you need that, then see the other methods of this struct.
    pub fn create_literal_search_pattern(text: &str) -> Result<Regex, regex::Error> {
        Self::create_pattern(text, false, Self::CASE_SENSITIVE)
    }

    /// Creates a regular expression [`Regex`] that will <b>match</b> all strings that
    /// <b>start with</b> the given input string.
    ///
    /// # Parameters
    /// - `input`: the string that you want your matched strings to start with.
    /// - `allow_globbing`: if true, globbing characters (`*` and `?`) will be converted to
    ///   regex wildcard patterns; otherwise, they will be escaped and searched as literals.
    /// - `options`: any pattern options desired, e.g. [`UserSearchUtils::CASE_INSENSITIVE`].
    pub fn create_starts_with_pattern(
        input: &str,
        allow_globbing: bool,
        options: u32,
    ) -> Result<Regex, regex::Error> {
        if let Some(wild_card_pattern) =
            Self::create_single_star_pattern(input, allow_globbing, options)?
        {
            return Ok(wild_card_pattern);
        }

        let converted = Self::convert_user_input_to_regex(input, allow_globbing);
        Self::compile(&format!("{}.*", converted), options)
    }

    /// Creates a regular expression [`Regex`] that will <b>match</b> all strings that
    /// <b>end with</b> the given input string.
    ///
    /// # Parameters
    /// - `input`: the string that you want your matched strings to end with.
    /// - `allow_globbing`: if true, globbing characters (`*` and `?`) will be converted to
    ///   regex wildcard patterns; otherwise, they will be escaped and searched as literals.
    /// - `options`: any pattern options desired, e.g. [`UserSearchUtils::CASE_INSENSITIVE`].
    pub fn create_ends_with_pattern(
        input: &str,
        allow_globbing: bool,
        options: u32,
    ) -> Result<Regex, regex::Error> {
        if let Some(wild_card_pattern) =
            Self::create_single_star_pattern(input, allow_globbing, options)?
        {
            return Ok(wild_card_pattern);
        }

        let converted = Self::convert_user_input_to_regex(input, allow_globbing);
        Self::compile(&format!(".*{}", converted), options)
    }

    /// Creates a regular expression [`Regex`] that will <b>match</b> all strings that
    /// <b>contain</b> the given input string.
    ///
    /// # Parameters
    /// - `input`: the string that you want your matched strings to contain.
    /// - `allow_globbing`: if true, globbing characters (`*` and `?`) will be converted to
    ///   regex wildcard patterns; otherwise, they will be escaped and searched as literals.
    /// - `options`: any pattern options desired, e.g. [`UserSearchUtils::CASE_INSENSITIVE`].
    pub fn create_contains_pattern(
        input: &str,
        allow_globbing: bool,
        options: u32,
    ) -> Result<Regex, regex::Error> {
        if let Some(wild_card_pattern) =
            Self::create_single_star_pattern(input, allow_globbing, options)?
        {
            return Ok(wild_card_pattern);
        }

        let converted = Self::convert_user_input_to_regex(input, allow_globbing);
        Self::compile(&format!(".*{}.*", converted), options)
    }

    /// Creates a regular expression [`Regex`] that will match all strings that
    /// <b>match exactly</b> the given input string.
    ///
    /// # Parameters
    /// - `input`: the string that you want your matched strings to exactly match.
    /// - `allow_globbing`: if true, globbing characters (`*` and `?`) will be converted to
    ///   regex wildcard patterns; otherwise, they will be escaped and searched as literals.
    /// - `options`: any pattern options desired, e.g. [`UserSearchUtils::CASE_INSENSITIVE`].
    pub fn create_pattern(
        input: &str,
        allow_globbing: bool,
        options: u32,
    ) -> Result<Regex, regex::Error> {
        if let Some(wild_card_pattern) =
            Self::create_single_star_pattern(input, allow_globbing, options)?
        {
            return Ok(wild_card_pattern);
        }

        let converted = Self::convert_user_input_to_regex(input, allow_globbing);
        Self::compile(&converted, options)
    }

    /// Creates a regular expression string that can be used to create a pattern that will
    /// <b>match</b> all strings that match the given input string.
    ///
    /// # Parameters
    /// - `input`: the string that you want your matched strings to exactly match.
    /// - `allow_globbing`: if true, globbing characters (`*` and `?`) will be converted to
    ///   regex wildcard patterns; otherwise, they will be escaped and searched as literals.
    pub fn create_pattern_string(input: &str, allow_globbing: bool) -> String {
        if let Some(wild_card_pattern_string) =
            Self::create_single_star_pattern_string(input, allow_globbing)
        {
            return wild_card_pattern_string;
        }

        Self::convert_user_input_to_regex(input, allow_globbing)
    }

    fn create_single_star_pattern(
        input: &str,
        allow_globbing: bool,
        options: u32,
    ) -> Result<Option<Regex>, regex::Error> {
        if allow_globbing && input == Self::STAR {
            return Ok(Some(Self::compile(".+", options)?));
        }
        Ok(None)
    }

    fn create_single_star_pattern_string(input: &str, allow_globbing: bool) -> Option<String> {
        if allow_globbing && input == Self::STAR {
            return Some(".+".to_string());
        }
        None
    }

    /// Convert user entered text into a regular expression, escaping regex characters,
    /// optionally turning globbing characters into valid regex syntax.
    ///
    /// # Parameters
    /// - `input`: the user entered text to be converted to a regular expression.
    /// - `allow_globbing`: if true, `*` and `?` will be converted to equivalent regular
    ///   expression syntax for wildcard matching, otherwise they will be treated as literal
    ///   characters to be part of the search text.
    pub fn convert_user_input_to_regex(input: &str, allow_globbing: bool) -> String {
        if allow_globbing {
            // Note: Order is important! (due to how escape characters added and checked)
            let escaped = Self::escape_non_globbing_regex_characters(input);
            Self::convert_globbing_characters_to_regex(&escaped)
        } else {
            Self::escape_all_regex_characters(input)
        }
    }

    /// Will change globbing characters to work as expected in Ghidra, unless the special
    /// characters are escaped with a backslash.
    fn convert_globbing_characters_to_regex(input: &str) -> String {
        // NOTE: order is important!

        // replace all unescaped '?' chars
        let question_replaced = Self::replace_unescaped(input, '?', ".");

        // replace all unescaped '*' chars
        //
        // *? is a Reluctant Quantifier, matching zero or more.  '*' is the quantifier, '?' makes
        // it reluctant
        Self::replace_unescaped(&question_replaced, '*', ".*?")
    }

    /// Replaces every occurrence of `target` in `input` that is not immediately preceded by a
    /// `\` character with `replacement`. Mirrors the Java implementation's use of a negative
    /// lookbehind, which `regex` (the Rust crate) does not support.
    fn replace_unescaped(input: &str, target: char, replacement: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let mut result = String::with_capacity(input.len());
        for (i, &c) in chars.iter().enumerate() {
            if c == target && (i == 0 || chars[i - 1] != '\\') {
                result.push_str(replacement);
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Escapes all special regex characters so that they are treated as literal characters
    /// by the regex engine.
    fn escape_all_regex_characters(input: &str) -> String {
        regex::escape(input)
    }

    /// Escapes all special regex characters except globbing chars (`*` and `?`).
    pub fn escape_non_globbing_regex_characters(input: &str) -> String {
        Self::escape_some_regex_characters(input, &GLOB_CHARACTERS)
    }

    /// Escapes all regex characters with the `\` character, except for those in the given
    /// exclusion slice.
    ///
    /// This search utility allows users to perform globbing operations using `*` and `?`. To
    /// disable that feature, users can escape those specific characters using a backslash.
    /// Except for these special cases, backslashes are treated literally, assuming users wish
    /// to search for backslash characters.
    fn escape_some_regex_characters(input: &str, do_not_escape: &[char]) -> String {
        // Escape any '\' characters that are not followed by a globbing char. Note: this
        // check is always against the globbing characters, regardless of `do_not_escape`,
        // matching the Java implementation.
        let updated = Self::double_unescaped_backslashes(input);

        // Escape all other regex chars individually with a backslash
        let mut buffy = String::with_capacity(updated.len());
        for c in updated.chars() {
            if do_not_escape.contains(&c) {
                // a bit inefficient, but the slice should always be short
                buffy.push(c);
                continue;
            }

            match c {
                '^' => buffy.push_str("\\^"),
                '.' => buffy.push_str("\\."),
                '$' => buffy.push_str("\\$"),
                '(' => buffy.push_str("\\("),
                ')' => buffy.push_str("\\)"),
                '[' => buffy.push_str("\\["),
                ']' => buffy.push_str("\\]"),
                '+' => buffy.push_str("\\+"),
                '&' => buffy.push_str("\\&"),
                '{' => buffy.push_str("\\{"),
                '}' => buffy.push_str("\\}"),
                '*' => buffy.push_str("\\*"),
                '?' => buffy.push_str("\\?"),
                '|' => buffy.push_str("\\|"),
                _ => buffy.push(c),
            }
        }
        buffy
    }

    /// Doubles every `\` character that is not immediately followed by a globbing character
    /// (`*` or `?`), so that it survives as a literal backslash once compiled as a regex.
    fn double_unescaped_backslashes(input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let mut result = String::with_capacity(input.len());
        for (i, &c) in chars.iter().enumerate() {
            if c == '\\' {
                let next_is_glob = chars
                    .get(i + 1)
                    .is_some_and(|n| GLOB_CHARACTERS.contains(n));
                if next_is_glob {
                    result.push('\\');
                } else {
                    result.push_str("\\\\");
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Compiles `pattern`, honoring [`UserSearchUtils::CASE_INSENSITIVE`] in `options` via an
    /// inline `(?i)` flag so that the flag travels with the pattern text itself (e.g. through
    /// [`Regex::as_str`]).
    fn compile(pattern: &str, options: u32) -> Result<Regex, regex::Error> {
        if options & Self::CASE_INSENSITIVE != 0 {
            Regex::new(&format!("(?i){}", pattern))
        } else {
            Regex::new(pattern)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `java.util.regex.Matcher.matches()`: succeeds only if the whole `text` is
    /// consumed by a single match. `Regex::find` alone is not sufficient here: it returns the
    /// leftmost match for the *unanchored* pattern, which (thanks to reluctant quantifiers
    /// like the `.*?` produced for a globbed `*`) is not necessarily the longest match
    /// starting at position 0, even when a full-length match exists. Re-anchoring the pattern
    /// text with `^(?:...)$` instead asks the NFA whether *any* full-length parse exists.
    fn matches(pattern: &Regex, text: &str) -> bool {
        let anchored = Regex::new(&format!("^(?:{})$", pattern.as_str())).unwrap();
        anchored.is_match(text)
    }

    #[test]
    fn test_create_contains_pattern_no_wild_cards() {
        let pattern =
            UserSearchUtils::create_contains_pattern("bob", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "bobbob"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_contains_pattern_no_wild_cards_case_sensitive() {
        let pattern =
            UserSearchUtils::create_contains_pattern("Bob", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "bobbob"));
        assert!(!matches(&pattern, "xxbobxx"));

        assert!(matches(&pattern, "Bob"));
        assert!(matches(&pattern, "xBob"));
        assert!(matches(&pattern, "Bobx"));
        assert!(matches(&pattern, "BobBob"));
        assert!(matches(&pattern, "xxBobxx"));
    }

    #[test]
    fn test_contains_with_pattern_with_only_wild_card_case_insensitive() {
        let pattern = UserSearchUtils::create_contains_pattern(
            "*",
            true,
            UserSearchUtils::CASE_INSENSITIVE,
        )
        .unwrap();

        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_contains_with_pattern_with_only_wild_card_case_sensitive() {
        // Note: case sensitivity should not matter
        let pattern =
            UserSearchUtils::create_contains_pattern("*", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_contains_pattern_with_single_char_wild_card() {
        let pattern =
            UserSearchUtils::create_contains_pattern("b?b", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_contains_pattern_wild_card() {
        let pattern =
            UserSearchUtils::create_contains_pattern("b*b", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_contains_pattern_wild_card_at_start() {
        let pattern = UserSearchUtils::create_contains_pattern(
            "*bob",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_contains_pattern_wild_card_at_end() {
        let pattern = UserSearchUtils::create_contains_pattern(
            "bob*",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_contains_pattern_no_wildcard_escaped_regex_character() {
        // This is a regression test for a bug that was found when the user typed an escaped
        // regex character into the search string.  The utils will escape regex characters, so
        // there is no need to do this unless you need to find a literal string containing "\["
        let pattern = UserSearchUtils::create_contains_pattern(
            "\\[bob",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(matches(&pattern, "\\[bob"));
        assert!(matches(&pattern, "foo\\[bob"));
    }

    #[test]
    fn test_create_contains_single_backslash() {
        let pattern = UserSearchUtils::create_contains_pattern(
            "\\",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(matches(&pattern, "\\"));
        assert!(matches(&pattern, "\\bob"));
        assert!(matches(&pattern, "bob\\"));
        assert!(matches(&pattern, "b\\ob"));
    }

    #[test]
    fn test_starts_pattern_no_wild_cards() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "bob",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_starts_pattern_no_wild_cards_case_sensitive() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "boB",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));

        assert!(matches(&pattern, "boB"));
        assert!(matches(&pattern, "boBx"));
    }

    #[test]
    fn test_create_starts_with_pattern_with_only_wild_card_case_insensitive() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "*",
            true,
            UserSearchUtils::CASE_INSENSITIVE,
        )
        .unwrap();

        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_starts_with_pattern_with_only_wild_card_case_sensitive() {
        // Note: case sensitivity should not matter
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "*",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_starts_with_pattern_with_single_char_wild_card() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "b?b",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_starts_with_pattern_wild_card() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "b*b",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "boasdfbx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_starts_with_pattern_wild_card_at_start() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "*bob",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_starts_with_pattern_wild_card_at_end() {
        let pattern = UserSearchUtils::create_starts_with_pattern(
            "bob*",
            true,
            UserSearchUtils::CASE_SENSITIVE,
        )
        .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_pattern_no_wild_cards() {
        let pattern =
            UserSearchUtils::create_pattern("bob", true, UserSearchUtils::CASE_SENSITIVE).unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_pattern_no_wild_cards_case_sensitive() {
        let pattern =
            UserSearchUtils::create_pattern("bOb", true, UserSearchUtils::CASE_SENSITIVE).unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));

        assert!(matches(&pattern, "bOb"));
    }

    #[test]
    fn test_create_pattern_single_wild_card_match_all() {
        let pattern =
            UserSearchUtils::create_pattern("*", true, UserSearchUtils::CASE_SENSITIVE).unwrap();

        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_pattern_with_single_char_wild_card() {
        let pattern =
            UserSearchUtils::create_pattern("b?b", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boxb"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_pattern_wild_card() {
        let pattern =
            UserSearchUtils::create_pattern("b*b", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "boasdfbx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_pattern_with_single_wildcard() {
        let pattern =
            UserSearchUtils::create_pattern("*", true, UserSearchUtils::CASE_SENSITIVE).unwrap();

        assert!(!matches(&pattern, ""));
        assert!(matches(&pattern, " "));
        assert!(matches(&pattern, "b"));
        assert!(matches(&pattern, "bb"));
        assert!(matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "xxbob"));
    }

    #[test]
    fn test_create_pattern_wild_card_at_start() {
        let pattern =
            UserSearchUtils::create_pattern("*bob", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "xxbobxx"));
        assert!(!matches(&pattern, "bOb"));

        assert!(matches(&pattern, "bob"));
        assert!(matches(&pattern, "xbob"));
        assert!(matches(&pattern, "xxbob"));
    }

    #[test]
    fn test_create_pattern_wild_card_at_end() {
        let pattern =
            UserSearchUtils::create_pattern("bob*", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "boob"));
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(matches(&pattern, "bobx"));
        assert!(matches(&pattern, "bobxx"));
        assert!(!matches(&pattern, "xxbobxx"));
    }

    #[test]
    fn test_create_pattern_wild_card_as_literal_star() {
        let pattern =
            UserSearchUtils::create_pattern("b*b", false, UserSearchUtils::CASE_INSENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));

        assert!(matches(&pattern, "b*b"));
        assert!(matches(&pattern, "B*b"));
    }

    #[test]
    fn test_create_pattern_wild_card_as_literal_question() {
        let pattern =
            UserSearchUtils::create_pattern("b?b", false, UserSearchUtils::CASE_INSENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));

        assert!(matches(&pattern, "b?b"));
        assert!(matches(&pattern, "B?b"));
    }

    #[test]
    fn test_create_pattern_wild_case_sensitive() {
        let pattern =
            UserSearchUtils::create_pattern("bO?b", true, UserSearchUtils::CASE_SENSITIVE)
                .unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "bobx"));
        assert!(!matches(&pattern, "BOb"));

        assert!(matches(&pattern, "bObb"));
    }

    #[test]
    fn test_create_search_pattern_case_sensitive() {
        let pattern = UserSearchUtils::create_search_pattern("b?b?", true).unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));
        assert!(!matches(&pattern, "boBx"));

        assert!(matches(&pattern, "bobx"));
    }

    #[test]
    fn test_create_search_pattern_case_insensitive() {
        let pattern = UserSearchUtils::create_search_pattern("b?b?", false).unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bb"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "xbob"));

        assert!(matches(&pattern, "boBx"));
        assert!(matches(&pattern, "bobx"));
    }

    #[test]
    fn test_create_search_pattern_case_insensitive_contains_non_globbing_regex_char() {
        // note: this was a bug that had to be fixed in the original Java implementation
        let pattern = UserSearchUtils::create_search_pattern("Bob[*", false).unwrap();

        assert!(!matches(&pattern, "b"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "bobb["));

        assert!(matches(&pattern, "bob["));
        assert!(matches(&pattern, "Bob["));
        assert!(matches(&pattern, "Bob[2]"));
    }

    #[test]
    fn test_create_literal_exact_match_pattern() {
        // A literal pattern should only match case sensitive and no globbing expansion
        let pattern = UserSearchUtils::create_literal_search_pattern("bob").unwrap();
        assert!(matches(&pattern, "bob"));
        assert!(!matches(&pattern, "bbb"));
        assert!(!matches(&pattern, "Bob"));

        let pattern = UserSearchUtils::create_literal_search_pattern("b*b").unwrap();
        assert!(matches(&pattern, "b*b"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "Bob"));

        let pattern = UserSearchUtils::create_literal_search_pattern("b?b").unwrap();
        assert!(matches(&pattern, "b?b"));
        assert!(!matches(&pattern, "bob"));
        assert!(!matches(&pattern, "Bob"));
    }

    #[test]
    fn test_escape_all_regex_characters() {
        // RegEx Special Chars: ^.$()[]+&{}*?
        let input = "start^.$()[]+&{}*?end";
        let escaped = UserSearchUtils::escape_all_regex_characters(input);

        // Unlike Java's `Pattern.quote`, this does not produce a `\Q...\E`-wrapped string, but
        // the resulting pattern must still match the input only as a literal string.
        let pattern = Regex::new(&escaped).unwrap();
        assert!(matches(&pattern, input));
        assert!(!matches(&pattern, "startend"));
    }

    #[test]
    fn test_escape_some_regex_characters() {
        // RegEx Special Chars: ^.$()[]+&{}*?
        let to_ignore = ['(', ')'];
        let escaped =
            UserSearchUtils::escape_some_regex_characters("start^.$()[]+&{}*?end", &to_ignore);

        assert_eq!(escaped, "start\\^\\.\\$()\\[\\]\\+\\&\\{\\}\\*\\?end");

        let to_ignore = ['^', '*', '?'];
        let escaped =
            UserSearchUtils::escape_some_regex_characters("start^.$()[]+&{}*?end", &to_ignore);

        assert_eq!(escaped, "start^\\.\\$\\(\\)\\[\\]\\+\\&\\{\\}*?end");
    }

    #[test]
    fn test_create_pattern_string_no_globbing() {
        let s = UserSearchUtils::create_pattern_string("bob", true);
        assert_eq!(s, "bob");

        let s = UserSearchUtils::create_pattern_string("*", true);
        assert_eq!(s, ".+");

        let s = UserSearchUtils::create_pattern_string("b*b", false);
        assert_eq!(s, "b\\*b");
    }
}
