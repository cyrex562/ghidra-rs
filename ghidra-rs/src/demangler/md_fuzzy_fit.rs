//! Explores a symbol that cannot currently be parsed into recognizable components, by trying to
//! apply a handful of candidate grammars against every offset within the mangled string.
//!
//! Mirrors `mdemangler.MDFuzzyFit`, cut to a trait to break a dependency cycle: it is a cut-point
//! between the still-unported `MDMang` driver and the three still-unported trial types it
//! reflectively constructs and parses (`MDType`, `MDDataType` via `MDFunctionType`'s sibling
//! parse tiers, and `MDFunctionType` itself), plus the `MDTypeInfo`/`MDTypeInfoParser` and
//! `MDDataType`/`MDDataTypeParser` pairs its two private locator helpers use. As the original's own
//! doc comment notes, "This class is still not used and might be turned into a derivative of the
//! MDMang class... The details of this class are still vague and incomplete" -- it is dead,
//! exploratory code with no callers anywhere in the original codebase.
//!
//! Rather than reproduce the Java reflection (`Class<? extends MDParsableItem>` +
//! `getDeclaredConstructor`/`newInstance`) used to construct-and-parse each trial type, every
//! per-substring parse attempt (the private `createItem` plus its surrounding try/catch, and the
//! two locator helpers' own try/catch bodies) is collapsed onto a required (implementor-supplied)
//! trait method, mirroring how [`crate::demangler::md_mang_genericize::MdMangGenericize::parse_item`]
//! collapses `MDMangObjectParser.determineItemAndParse` for the same reason (the concrete types
//! constructed are not ported). The offset-scanning control flow itself -- which does not depend on
//! any unported type -- is given a real default implementation here, mirroring
//! [`crate::demangler::datatype::md_data_type_parser::MdDataTypeParser::determine_and_parse_data_type`].

use crate::util::msg::Msg;

/// Mirrors the trial classes registered (in this fixed order) in the `MDFuzzyFit()` constructor's
/// `classList`: `MDType`, `MDDataType` (`// TODO: remove; needs factory`), and `MDFunctionType`.
/// Modeled as an enum rather than per-instance mutable state (as `classList` is in the original)
/// since no `MDFuzzyFit` caller ever varies the list -- every instance ends up with the same three
/// entries in the same order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdFuzzyCandidateKind {
    /// Mirrors the `MDType` entry (`// TODO: remove`).
    Type,
    /// Mirrors the `MDDataType` entry (`// TODO: remove; needs factory`).
    DataType,
    /// Mirrors the `MDFunctionType` entry.
    FunctionType,
}

/// The fixed trial order mirroring `MDFuzzyFit()`'s `classList.add(...)` sequence.
pub const MD_FUZZY_CANDIDATE_KINDS: [MdFuzzyCandidateKind; 3] = [
    MdFuzzyCandidateKind::Type,
    MdFuzzyCandidateKind::DataType,
    MdFuzzyCandidateKind::FunctionType,
];

impl MdFuzzyCandidateKind {
    /// Returns the Java simple class name this candidate stands in for.
    ///
    /// Mirrors `tryClass.getSimpleName()`.
    pub fn class_simple_name(&self) -> &'static str {
        match self {
            MdFuzzyCandidateKind::Type => "MDType",
            MdFuzzyCandidateKind::DataType => "MDDataType",
            MdFuzzyCandidateKind::FunctionType => "MDFunctionType",
        }
    }
}

/// A successful (non-exception-throwing) parse of one [`MdFuzzyCandidateKind`] against one
/// substring.
///
/// Mirrors the local `tryItem`/`builder`/`substringDemangled` variables computed inside the
/// try-block of `fuzz(String)`, once construction and parsing succeed without throwing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdFuzzyCandidateOutcome {
    /// Whether the whole substring was consumed by the parse.
    ///
    /// Mirrors `numCharsRemaining == 0` after `tryItem.parse()`.
    pub fully_consumed: bool,
    /// The rendered (demangled) text of the parsed item.
    ///
    /// Mirrors `substringDemangled` (`tryItem.insert(builder)`, then `builder.toString()`).
    /// Populated regardless of [`Self::fully_consumed`], mirroring the original computing it
    /// unconditionally before checking `numCharsRemaining`.
    pub rendered: String,
}

/// Returns the substring of `s` starting at character offset `offset`.
///
/// Mirrors `mangledArg.substring(offset)`, indexing by character (not byte) so behavior matches
/// for any Unicode content, though in practice mangled symbols are ASCII.
fn substring_from(s: &str, offset: usize) -> String {
    s.chars().skip(offset).collect()
}

/// Returns the character length of `s`.
///
/// Mirrors `mangledArg.length()`, counting characters (not bytes) to match
/// [`substring_from`]'s indexing.
fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// Explores a symbol that cannot currently be parsed, by trying candidate grammars at every
/// offset within it.
///
/// Mirrors `mdemangler.MDFuzzyFit`. See the module docs for why the per-substring parse attempts
/// are required trait methods while the scanning loops that drive them are given real defaults.
pub trait MdFuzzyFit {
    /// Attempts to construct and parse `kind` against `substring`, starting at its beginning.
    ///
    /// Returns `None` if construction or parsing throws (mirrors the `catch (MDException e)` in
    /// `fuzz(String)`, which sets `pass = false`); otherwise `Some` with the parse's outcome
    /// (mirrors the try-block completing without throwing, i.e. `pass = true`).
    ///
    /// Mirrors the per-class body of `fuzz(String)`'s inner loop: `dmang.setMangledSymbol`,
    /// `pushContext`, `createItem` + `tryItem.parse()`, `getNumCharsRemaining`, `popContext`, and
    /// the `tryItem.insert(builder)` rendering, all folded into one call since `createItem`'s
    /// reflective construction of `MDType`/`MDDataType`/`MDFunctionType` isn't portable without
    /// those types.
    fn try_parse_candidate(
        &mut self,
        kind: MdFuzzyCandidateKind,
        substring: &str,
    ) -> Option<MdFuzzyCandidateOutcome>;

    /// Attempts to parse `substring` as an `MDTypeInfo`, starting at its beginning, reporting
    /// whether the whole substring was consumed.
    ///
    /// Mirrors the try-block body of `getBestTypeInfoLocation(String)`: `dmang.setMangledSymbol`,
    /// `pushContext`, `MDTypeInfoParser.parse(dmang, -1)` + `typeInfo.parse()`,
    /// `getNumCharsRemaining`, `popContext`, collapsed into one call (returning whether
    /// `num == 0`) since `MDTypeInfo`/`MDTypeInfoParser` aren't ported. Both `catch` clauses
    /// (`MDException`, generic `Exception`) are mirrored by simply returning `false`.
    fn try_parse_type_info_at(&mut self, substring: &str) -> bool;

    /// Attempts to parse `substring` as an `MDDataType` (with `highest = false`, the only value
    /// the original ever uses -- `highest` is declared but never reassigned in
    /// `getBestTypeLocation`), starting at its beginning, reporting whether the whole substring
    /// was consumed.
    ///
    /// Mirrors the try-block body of `getBestTypeLocation(String)`:
    /// `MDDataTypeParser.parseDataType(dmang, highest)` + `type.parse()`, collapsed the same way
    /// as [`Self::try_parse_type_info_at`] since `MDDataType`/`MDDataTypeParser` (the concrete
    /// dispatch, not the already-ported
    /// [`crate::demangler::datatype::md_data_type_parser::MdDataTypeParser`] trait) aren't
    /// reachable here.
    fn try_parse_data_type_at(&mut self, substring: &str) -> bool;

    /// Returns the smallest offset (closest to the end of `mangled_arg`) at which an `MDTypeInfo`
    /// fully parses, scanning from the end of the string down to its start; if no offset fully
    /// parses, returns `mangled_arg`'s length (the loop's initial `bestOffset`).
    ///
    /// Mirrors `getBestTypeInfoLocation(String)`. The original scans offsets from
    /// `length - 1` down to `0` without ever breaking out early, overwriting `bestOffset` on every
    /// success it finds -- so the final value is the *lowest* offset seen to fully parse, not
    /// necessarily `0` and not necessarily the first one found.
    fn best_type_info_location(&mut self, mangled_arg: &str) -> usize {
        let len = char_len(mangled_arg);
        let mut best_offset = len;
        let mut offset = len;
        while offset > 0 {
            offset -= 1;
            let substring = substring_from(mangled_arg, offset);
            if self.try_parse_type_info_at(&substring) {
                best_offset = offset;
            }
        }
        best_offset
    }

    /// Returns the smallest offset at which an `MDDataType` fully parses, with the same
    /// downward-scan-and-overwrite semantics as [`Self::best_type_info_location`].
    ///
    /// Mirrors `getBestTypeLocation(String)`.
    fn best_type_location(&mut self, mangled_arg: &str) -> usize {
        let len = char_len(mangled_arg);
        let mut best_offset = len;
        let mut offset = len;
        while offset > 0 {
            offset -= 1;
            let substring = substring_from(mangled_arg, offset);
            if self.try_parse_data_type_at(&substring) {
                best_offset = offset;
            }
        }
        best_offset
    }

    /// Explores `mangled_arg` by trying every [`MdFuzzyCandidateKind`] against every offset within
    /// it (scanning from the end down to the start), logging the best `MDTypeInfo`/`MDDataType`
    /// locations and a per-offset, per-candidate pass/fail (and, when fully consumed, rendered
    /// output) report. Always returns `true`, since -- unlike `String` in Java -- `&str` cannot be
    /// null.
    ///
    /// Mirrors `fuzz(String)`.
    fn fuzz(&mut self, mangled_arg: &str) -> bool {
        Msg::info("MDFuzzyFit", &format!("Symbol: {mangled_arg}"));
        Msg::info("MDFuzzyFit", &format!("Length: {}", char_len(mangled_arg)));

        let best_type_info_location = self.best_type_info_location(mangled_arg);
        Msg::info("MDFuzzyFit", &format!("Best type location: {best_type_info_location}"));

        let best_type_location = self.best_type_location(mangled_arg);
        Msg::info("MDFuzzyFit", &format!("Best type location: {best_type_location}"));

        let mut output = String::new();
        output.push_str("Symbol: ");
        output.push_str(mangled_arg);

        let len = char_len(mangled_arg);
        let mut offset = len;
        while offset > 0 {
            offset -= 1;
            let substring = substring_from(mangled_arg, offset);
            for kind in MD_FUZZY_CANDIDATE_KINDS {
                let pass = match self.try_parse_candidate(kind, &substring) {
                    Some(outcome) => {
                        if outcome.fully_consumed {
                            output.push_str("Offset: ");
                            output.push_str(&offset.to_string());
                            output.push_str("; Class: ");
                            output.push_str(kind.class_simple_name());
                            output.push_str("; Output:");
                            output.push_str(&outcome.rendered);
                        }
                        true
                    }
                    None => false,
                };
                output.push_str("Offset: ");
                output.push_str(&offset.to_string());
                output.push_str("; Class: ");
                output.push_str(kind.class_simple_name());
                output.push_str("; GoodResult: ");
                output.push_str(&pass.to_string());
            }
        }
        Msg::info("MDFuzzyFit", &output);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock whose candidate/locator parses are driven by simple substring-suffix rules, letting
    /// tests exercise the real scanning/overwrite control flow in the default methods rather than
    /// stubbing fixed return values.
    struct MockFuzzyFit {
        candidate_calls: Vec<(MdFuzzyCandidateKind, String)>,
        type_info_calls: Vec<String>,
        data_type_calls: Vec<String>,
    }

    impl MockFuzzyFit {
        fn new() -> Self {
            Self { candidate_calls: Vec::new(), type_info_calls: Vec::new(), data_type_calls: Vec::new() }
        }
    }

    impl MdFuzzyFit for MockFuzzyFit {
        fn try_parse_candidate(
            &mut self,
            kind: MdFuzzyCandidateKind,
            substring: &str,
        ) -> Option<MdFuzzyCandidateOutcome> {
            self.candidate_calls.push((kind, substring.to_string()));
            // Only MDDataType "fully parses" the literal substring "Pax", to exercise both the
            // Some(fully_consumed) and Some(!fully_consumed) and None branches.
            match kind {
                MdFuzzyCandidateKind::DataType if substring == "Pax" => {
                    Some(MdFuzzyCandidateOutcome { fully_consumed: true, rendered: "int".to_string() })
                }
                MdFuzzyCandidateKind::Type => {
                    Some(MdFuzzyCandidateOutcome { fully_consumed: false, rendered: String::new() })
                }
                _ => None,
            }
        }

        fn try_parse_type_info_at(&mut self, substring: &str) -> bool {
            self.type_info_calls.push(substring.to_string());
            substring == "Bar"
        }

        fn try_parse_data_type_at(&mut self, substring: &str) -> bool {
            self.data_type_calls.push(substring.to_string());
            substring.ends_with("Pax")
        }
    }

    #[test]
    fn best_type_info_location_returns_lowest_matching_offset() {
        let mut mock = MockFuzzyFit::new();

        // "FooBar": "Bar" matches at offset 3, and the scan continues past it (offsets 2..0 don't
        // match "Bar"), so the lowest (in this case only) match wins.
        let best = mock.best_type_info_location("FooBar");

        assert_eq!(best, 3);
        assert_eq!(mock.type_info_calls, vec!["r", "ar", "Bar", "oBar", "ooBar", "FooBar"]);
    }

    #[test]
    fn best_type_info_location_defaults_to_full_length_when_nothing_matches() {
        let mut mock = MockFuzzyFit::new();

        let best = mock.best_type_info_location("xyz");

        assert_eq!(best, 3);
    }

    #[test]
    fn best_type_location_keeps_overwriting_down_to_the_lowest_success() {
        let mut mock = MockFuzzyFit::new();

        // Every suffix of "PaxPax" ending in "Pax" matches: offsets 3 ("Pax") and 0 ("PaxPax").
        // The downward scan must overwrite bestOffset at each success, landing on the lowest (0).
        let best = mock.best_type_location("PaxPax");

        assert_eq!(best, 0);
    }

    #[test]
    fn fuzz_tries_every_candidate_kind_at_every_offset_in_fixed_order() {
        let mut mock = MockFuzzyFit::new();

        let result = mock.fuzz("Pax");

        assert!(result);
        // 3 offsets (2, 1, 0) x 3 candidate kinds, in classList order, none skipped despite
        // earlier successes -- mirrors the original never breaking out of either loop.
        assert_eq!(mock.candidate_calls.len(), 9);
        let expected_order = [
            (MdFuzzyCandidateKind::Type, "x"),
            (MdFuzzyCandidateKind::DataType, "x"),
            (MdFuzzyCandidateKind::FunctionType, "x"),
            (MdFuzzyCandidateKind::Type, "ax"),
            (MdFuzzyCandidateKind::DataType, "ax"),
            (MdFuzzyCandidateKind::FunctionType, "ax"),
            (MdFuzzyCandidateKind::Type, "Pax"),
            (MdFuzzyCandidateKind::DataType, "Pax"),
            (MdFuzzyCandidateKind::FunctionType, "Pax"),
        ];
        for (call, (kind, substring)) in mock.candidate_calls.iter().zip(expected_order.iter()) {
            assert_eq!(call.0, *kind);
            assert_eq!(&call.1, substring);
        }
    }

    #[test]
    fn class_simple_name_matches_java_class_names() {
        assert_eq!(MdFuzzyCandidateKind::Type.class_simple_name(), "MDType");
        assert_eq!(MdFuzzyCandidateKind::DataType.class_simple_name(), "MDDataType");
        assert_eq!(MdFuzzyCandidateKind::FunctionType.class_simple_name(), "MDFunctionType");
    }

    #[test]
    fn trait_object_is_usable() {
        let mut mock = MockFuzzyFit::new();
        let fuzzy: &mut dyn MdFuzzyFit = &mut mock;

        assert!(fuzzy.fuzz("x"));
    }
}
