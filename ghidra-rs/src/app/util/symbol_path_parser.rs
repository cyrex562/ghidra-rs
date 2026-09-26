//! Port of `ghidra.app.util.SymbolPathParser`.
//!
//! A parser for breaking down namespaces in the presence of complicating factors such as
//! templates.
//! <p>
//! For example, if a `SymbolPath` is constructed with "foo&lt;int, blah::hah&gt;::bar::baz",
//! then "baz" is the name of a symbol in the "bar" namespace, which is in the
//! "foo&lt;int, blah::hah&gt;" namespace.
//!
//! Java's stateless static-utility class (no fields, only static methods) maps to a unit struct
//! with associated functions, this crate's established convention for such classes (see e.g.
//! [`DefaultSymbolUtilities`](crate::program::model::symbol::DefaultSymbolUtilities)). There is no
//! instance state to model and no need for dynamic dispatch, so `SymbolPathParser::parse` (rather
//! than a free function) is the direct namespaced port of `SymbolPathParser.parse`.
//!
//! [`crate::app::util::symbol_path`] already reproduced this exact `parse`/`skipParsing`/
//! `naiveParse` algorithm as private free functions (`parse_symbol_path`/`skip_parsing`/
//! `naive_parse`) before this class existed as its own port, because at the time
//! `SymbolPathParser` itself was still `TODO`. Now that the real class lives here,
//! `symbol_path::parse_symbol_path` delegates to [`SymbolPathParser::parse`] instead of
//! duplicating the algorithm, so there is exactly one implementation of the parsing logic.

/// A parser for breaking down namespaces in the presence of complicating factors such as
/// templates.
///
/// Port of `ghidra.app.util.SymbolPathParser`. A zero-sized unit struct, since the Java class has
/// no instance state and only static methods.
pub struct SymbolPathParser;

impl SymbolPathParser {
    /// Parses a String pathname into its constituent namespace and name components. The list
    /// does not contain the global namespace, which is implied, but then has each more deeply
    /// nested namespace contained in order in the list, followed by the trailing name.
    ///
    /// Port of `SymbolPathParser.parse(String)`, which delegates to the two-argument overload
    /// with `ignoreLeaderParens = true`.
    ///
    /// # Panics
    /// Panics if `name` is blank (empty or all whitespace), mirroring Java's
    /// `IllegalArgumentException("Pathname cannot be empty!")` (an unchecked exception, so a
    /// Rust panic is the faithful analogue; see the identical precedent in
    /// [`SymbolPathNode::parse`](crate::app::util::symbol_path::SymbolPathNode::parse), which
    /// instead surfaces this case as a `Result` since it is a constructor rather than a bare
    /// static utility method). Java's overload also accepts a null `String` and treats it the
    /// same as blank (`StringUtils.isBlank(null)` is `true`); that case has no Rust port since a
    /// `&str` cannot be null.
    pub fn parse(name: &str) -> Vec<String> {
        Self::parse_with(name, true)
    }

    /// Parses a String pathname into its constituent namespace and name components. The list
    /// does not contain the global namespace, which is implied, but then has each more deeply
    /// nested namespace contained in order in the list, followed by the trailing name.
    ///
    /// `ignore_leader_parens`: `true` signals to ignore any string that starts with a `(` char.
    /// This is useful to work around some problem characters.
    ///
    /// Port of `SymbolPathParser.parse(String, boolean)`.
    ///
    /// # Panics
    /// Panics if `name` is blank; see [`SymbolPathParser::parse`].
    pub fn parse_with(name: &str, ignore_leader_parens: bool) -> Vec<String> {
        assert!(!is_blank(name), "Pathname cannot be empty!");

        if skip_parsing(name, ignore_leader_parens) {
            return vec![name.to_string()];
        }
        naive_parse(name)
    }
}

/// Port of the private `StringUtils.isBlank` check used by `SymbolPathParser.parse`: true if the
/// string is empty or consists solely of whitespace.
fn is_blank(name: &str) -> bool {
    name.trim().is_empty()
}

/// Port of the private `SymbolPathParser.skipParsing`.
fn skip_parsing(name: &str, ignore_leader_parens: bool) -> bool {
    //	if (name.indexOf(Namespace.DELIMITER) == -1) {
    // following is temporary kludge due to struct (blah).  TODO: figure/fix
    // This particular test for starting with the open parenthesis is to work around a type
    // seen in "Rust."
    if ignore_leader_parens && name.starts_with('(') {
        return true;
    }

    !name.contains(crate::program::model::symbol::DELIMITER)
}

/// Naive parsing that assumes evenly matched angle brackets (templates) with no operator
/// overloading that contains these and no other rule breakers.
///
/// Port of the private `SymbolPathParser.naiveParse`.
fn naive_parse(name: &str) -> Vec<String> {
    // Only break on namespace delimiters that are found at templateLevel == 0.
    let chars: Vec<char> = name.chars().collect();
    let mut list: Vec<String> = Vec::new();
    let mut template_level: i32 = 0;
    let mut parentheses_level: i32 = 0;
    let mut start_index: usize = 0;
    let mut i: usize = 0;
    while i < chars.len() {
        if chars[i] == ':' && i != chars.len() - 1 && chars[i + 1] == ':' {
            if template_level == 0 && parentheses_level == 0 {
                let end_index = i; // could be 0 if i == 0.
                if end_index > start_index {
                    list.push(chars[start_index..end_index].iter().collect());
                    start_index = i + 2;
                    i += 1; // Only increment one, because the loop also has an increment.
                }
            }
        } else if chars[i] == '<' {
            template_level += 1;
        } else if chars[i] == '>' {
            template_level -= 1;
        } else if chars[i] == '(' {
            parentheses_level += 1;
        } else if chars[i] == ')' {
            parentheses_level -= 1;
        }
        i += 1;
    }

    if template_level != 0 || parentheses_level != 0 {
        // Revert to no checking template level
        start_index = 0;
        list = Vec::new();
        i = 0;
        while i < chars.len() {
            if chars[i] == ':' && i != chars.len() - 1 && chars[i + 1] == ':' {
                let end_index = i; // could be 0 if i == 0.
                if end_index > start_index {
                    list.push(chars[start_index..end_index].iter().collect());
                    start_index = i + 2;
                    i += 1; // Only increment one, because the loop also has an increment.
                }
            }
            i += 1;
        }
    }
    list.push(chars[start_index..].iter().collect());

    list
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of `SymbolPathParserTest.testJustSymbolNameNoPath`.
    #[test]
    fn just_symbol_name_no_path() {
        let list = SymbolPathParser::parse("bob");
        assert_eq!(list, vec!["bob".to_string()]);
    }

    /// Port of `SymbolPathParserTest.testSymbolPathGivenPathString`.
    #[test]
    fn symbol_path_given_path_string() {
        let list = SymbolPathParser::parse("aaa::bbb::bob");
        assert_eq!(
            list,
            vec!["aaa".to_string(), "bbb".to_string(), "bob".to_string()]
        );
    }

    /// Port of `SymbolPathParserTest.testCliArray`.
    #[test]
    fn cli_array() {
        let list = SymbolPathParser::parse(
            "namespace::ta<cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64>",
        );
        assert_eq!(
            list,
            vec![
                "namespace".to_string(),
                "ta<cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64>".to_string(),
            ]
        );
    }

    /// Port of `SymbolPathParserTest.testNamespaceInFunctionArgument`.
    #[test]
    fn namespace_in_function_argument() {
        let list = SymbolPathParser::parse("Foo7::Bar5(class Foo1d::Bar1,int)");
        assert_eq!(
            list,
            vec!["Foo7".to_string(), "Bar5(class Foo1d::Bar1,int)".to_string()]
        );
    }

    /// Port of `SymbolPathParserTest.testCliPinptrMSFTVersion_NaiveProcessing`.
    ///
    /// Testing for only doing naive processing--expecting less-than-perfect results (this is the
    /// exact same input Java's `@Ignore`d `testCliPinptrMSFTVersion_DetailedProcessing` documents
    /// a *better* expected result for, once `SymbolPathParser.detailedParse` -- itself still
    /// commented-out `// TODO: in progress.` in the real Java source -- is written; faithfully
    /// preserved here as-is, not "fixed", per this crate's policy).
    #[test]
    fn cli_pinptr_msft_version_naive_processing() {
        let name = "namespace::ta<cli::pin_ptr\
            <unsigned char * __ptr64,class System::Text::Encoding ^ __ptr64>";
        let list = SymbolPathParser::parse(name);
        assert_eq!(
            list,
            vec![
                "namespace".to_string(),
                "ta<cli".to_string(),
                "pin_ptr<unsigned char * __ptr64,class System".to_string(),
                "Text".to_string(),
                "Encoding ^ __ptr64>".to_string(),
            ]
        );
    }

    /// Port of `SymbolPathParserTest.testTemplateMoreComplicated1`.
    #[test]
    fn template_more_complicated_1() {
        let name = "E::F<class E::D::G<struct E::D::H<bool (__cdecl*const)\
            (enum C::B const &),0>,bool,enum C::B const &> >::\
            F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,\
            bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >";
        let list = SymbolPathParser::parse(name);
        assert_eq!(
            list,
            vec![
                "E".to_string(),
                "F<class E::D::G<struct E::D::H<bool (__cdecl*const)\
                    (enum C::B const &),0>,bool,enum C::B const &> >"
                    .to_string(),
                "F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,\
                    bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >"
                    .to_string(),
            ]
        );
    }

    /// Port of `SymbolPathParserTest.testSpecialCharAfterDelimiter1`.
    #[test]
    fn special_char_after_delimiter_1() {
        let name = "A::B::C<wchar_t,A::B::D<wchar_t>,A::B::E<wchar_t> >::<unnamed-tag>";
        let list = SymbolPathParser::parse(name);
        assert_eq!(
            list,
            vec![
                "A".to_string(),
                "B".to_string(),
                "C<wchar_t,A::B::D<wchar_t>,A::B::E<wchar_t> >".to_string(),
                "<unnamed-tag>".to_string(),
            ]
        );
    }

    /// Port of `SymbolPathParserTest.testUnmatchedAngleBracketFallback1`.
    ///
    /// Contrived example to test naive parsing going into fallback mode due to unmatched angle
    /// brackets. Java's own comment on this test acknowledges "the expected result here is not
    /// an accurate result that we would expect from a more sophisticated parser" -- a genuine,
    /// documented quirk of the naive fallback algorithm, faithfully reproduced (not "fixed") here.
    #[test]
    fn unmatched_angle_bracket_fallback_1() {
        let name = "A::operator<=::B<C<int>::<unnamed-tag>>::E";
        let list = SymbolPathParser::parse(name);
        assert_eq!(
            list,
            vec![
                "A".to_string(),
                "operator<=".to_string(),
                "B<C<int>".to_string(),
                "<unnamed-tag>>".to_string(),
                "E".to_string(),
            ]
        );
    }

    /// Faithful port of the blank-input `IllegalArgumentException` behavior, verified precisely
    /// at the panicking call (per this crate's testing policy: `#[should_panic]` alone only
    /// proves *a* panic happened somewhere in the test function, not *where*).
    #[test]
    fn blank_pathname_panics_with_exact_message() {
        let result = std::panic::catch_unwind(|| SymbolPathParser::parse("   "));
        let err = result.expect_err("expected SymbolPathParser::parse to panic on a blank name");
        let message = err
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| err.downcast_ref::<String>().cloned());
        assert_eq!(message.as_deref(), Some("Pathname cannot be empty!"));
    }

    /// Java's `ignoreLeaderParens` parameter: with it explicitly `false`, a leading `(` no longer
    /// short-circuits parsing via [`skip_parsing`], so the naive delimiter-splitting algorithm
    /// runs instead. Here the parentheses happen to wrap the *entire* string, so every `::`
    /// delimiter is found at `parenthesesLevel == 1` (never `0`), and none of them qualify as a
    /// split point -- the naive parser still returns the whole string as one entry, just via a
    /// different code path (`naiveParse`'s loop finding zero eligible splits) than
    /// `ignoreLeaderParens = true`'s early-return in `skipParsing`.
    #[test]
    fn parse_with_false_does_not_skip_leading_parens() {
        let list = SymbolPathParser::parse_with("(some::weird::type)", false);
        assert_eq!(list, vec!["(some::weird::type)".to_string()]);
    }

    /// Unlike the previous case, when the parenthesized region does *not* span the whole string,
    /// disabling `ignoreLeaderParens` allows the trailing delimiter (found at
    /// `parenthesesLevel == 0`, outside the parens) to actually split the name -- proving
    /// `ignore_leader_parens = false` really does run the full naive algorithm rather than always
    /// degenerating to a single entry.
    #[test]
    fn parse_with_false_splits_on_delimiters_outside_parens() {
        let list = SymbolPathParser::parse_with("(a)::b", false);
        assert_eq!(list, vec!["(a)".to_string(), "b".to_string()]);
    }

    /// The one-argument [`SymbolPathParser::parse`] must behave exactly like the two-argument
    /// [`SymbolPathParser::parse_with`] with `ignore_leader_parens = true` (its Java delegation
    /// target).
    #[test]
    fn parse_delegates_to_parse_with_ignoring_leader_parens() {
        let name = "(some::weird::type)";
        assert_eq!(SymbolPathParser::parse(name), SymbolPathParser::parse_with(name, true));
    }
}
