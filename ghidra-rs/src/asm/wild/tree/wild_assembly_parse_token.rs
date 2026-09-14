//! Port of `ghidra.asm.wild.tree.WildAssemblyParseToken`.
//!
//! A token in a "wildcarded" assembly instruction pattern -- e.g. `ADD R0, $reg` -- where `$reg`
//! stands in for a value to be discovered later, constrained by a [`Wildcard`] spec parsed from
//! whatever follows the leading `$`/similar marker (the marker character itself isn't part of
//! this class; whatever calls [`WildAssemblyParseToken::new`] is expected to have already
//! stripped it from `spec`).
//!
//! # Shape
//!
//! Java's `WildAssemblyParseToken extends AssemblyParseToken`. This crate's
//! [`AssemblyParseToken`] was itself ported as an object-safe trait, not a concrete struct (see
//! that module's own doc comment), and deliberately drops the constructor's `AssemblyGrammar`
//! parameter since nothing `AssemblyParseToken.java` declares exposes it -- it exists only for
//! the still-unported `AssemblyParseTreeNode` superclass's `getGrammar()`. This port follows
//! that same precedent: [`WildAssemblyParseToken::new`] likewise omits the `AssemblyGrammar`
//! parameter Java's constructor takes, and this struct directly implements [`AssemblyParseToken`]
//! (holding its own `str`/`term` fields) rather than composing a base struct, since there is no
//! base struct to compose -- only the trait.
//!
//! Java's five `static`/instance nested types (`Wildcard` interface, and the `FreeWildcard`,
//! `RegexWildcard`, `NumericWildcard`, `RangesWildcard` records plus the `WildRange` record) are
//! flattened to top-level items in this module, matching this crate's general convention for
//! Java static nested types.

use std::any::Any;
use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;
use crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken;

// ---------------------------------------------------------------------------------------------
// Wildcard
// ---------------------------------------------------------------------------------------------

/// A constraint a wildcard operand's eventual value must satisfy.
///
/// Port of `WildAssemblyParseToken.Wildcard`.
pub trait Wildcard: Send + Sync {
    /// The wildcard's name (the portion of the spec before any constraint syntax).
    ///
    /// Port of `Wildcard.name()`.
    fn name(&self) -> &str;

    /// Whether `object` satisfies this wildcard's constraint.
    ///
    /// Port of `Wildcard.test(Object)`. Java's `Object` is narrowed here to `&dyn Any`; concrete
    /// [`Wildcard`] implementations downcast to whatever concrete type they actually care about
    /// (a string-like type for [`RegexWildcard`], an integer type for [`NumericWildcard`]/
    /// [`RangesWildcard`]), mirroring Java's `instanceof CharSequence`/`instanceof Number` checks.
    fn test(&self, object: &dyn Any) -> bool;
}

impl dyn Wildcard {
    /// Parses a wildcard spec into the appropriate concrete [`Wildcard`], trying (in order) the
    /// regex form (`name/regex`), the numeric form (`name[..]`), the ranges form
    /// (`name[range,range,...]`), and finally falling back to an unconstrained [`FreeWildcard`].
    ///
    /// Port of `Wildcard.parse(String)`.
    pub fn parse(spec: &str) -> Box<dyn Wildcard> {
        if let Some(caps) = REGEX_WILDCARD_PATTERN.captures(spec) {
            return Box::new(RegexWildcard::get(&caps));
        }
        if let Some(caps) = NUMERIC_WILDCARD_PATTERN.captures(spec) {
            return Box::new(NumericWildcard::get(&caps));
        }
        if let Some(caps) = RANGES_WILDCARD_PATTERN.captures(spec) {
            return Box::new(RangesWildcard::get(&caps));
        }
        Box::new(FreeWildcard { name: spec.to_string() })
    }
}

/// Extracts an integer value from `object`, if it holds one of the integer types this module's
/// [`Wildcard`]s recognize. Stands in for Java's `instanceof Number` plus `Number.longValue()`;
/// Rust has no single "any integer" trait object to downcast to, so this tries each concrete
/// integer type this crate's callers plausibly pass (offsets and the like are `i64`/`u64`
/// elsewhere in this codebase). Unlike Java's `Number`, floating-point types are not covered --
/// no caller of these wildcards passes a non-integer operand value.
fn as_i64(object: &dyn Any) -> Option<i64> {
    if let Some(v) = object.downcast_ref::<i64>() {
        return Some(*v);
    }
    if let Some(v) = object.downcast_ref::<i32>() {
        return Some(i64::from(*v));
    }
    if let Some(v) = object.downcast_ref::<u64>() {
        return i64::try_from(*v).ok();
    }
    if let Some(v) = object.downcast_ref::<u32>() {
        return Some(i64::from(*v));
    }
    if let Some(v) = object.downcast_ref::<usize>() {
        return i64::try_from(*v).ok();
    }
    None
}

/// A wildcard with no constraint: matches any value.
///
/// Port of the `WildAssemblyParseToken.FreeWildcard` record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FreeWildcard {
    pub name: String,
}

impl Wildcard for FreeWildcard {
    fn name(&self) -> &str {
        &self.name
    }
    fn test(&self, _object: &dyn Any) -> bool {
        true
    }
}

static REGEX_WILDCARD_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<name>[^/]*)/(?P<regex>.*)$").unwrap());

/// A wildcard constrained by a regular expression, tested against a string-like value.
///
/// Port of the `WildAssemblyParseToken.RegexWildcard` record.
#[derive(Debug, Clone)]
pub struct RegexWildcard {
    pub name: String,
    pub pat: Regex,
}

impl RegexWildcard {
    fn get(caps: &regex::Captures) -> RegexWildcard {
        let name = caps.name("name").unwrap().as_str().to_string();
        let pat = Regex::new(caps.name("regex").unwrap().as_str())
            .expect("invalid regex in wildcard spec");
        RegexWildcard { name, pat }
    }
}

impl Wildcard for RegexWildcard {
    fn name(&self) -> &str {
        &self.name
    }

    fn test(&self, object: &dyn Any) -> bool {
        let cs = if let Some(s) = object.downcast_ref::<String>() {
            s.as_str()
        } else if let Some(s) = object.downcast_ref::<&str>() {
            s
        } else {
            return false;
        };
        // Mirrors `Matcher.matches()`: the pattern must match the *entire* string, not merely a
        // substring of it.
        self.pat.find(cs).is_some_and(|m| m.start() == 0 && m.end() == cs.len())
    }
}

impl PartialEq for RegexWildcard {
    /// Port of `RegexWildcard.equals(Object)`: `Pattern` does not override `equals`, so Java
    /// compares `pat.toString()` instead; this compares `pat.as_str()` for the same reason.
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.pat.as_str() == other.pat.as_str()
    }
}

impl Eq for RegexWildcard {}

static NUMERIC_WILDCARD_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<name>.*)\[\.\.\]$").unwrap());

/// A wildcard constrained to any integer value (`name[..]`).
///
/// Port of the `WildAssemblyParseToken.NumericWildcard` record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NumericWildcard {
    pub name: String,
}

impl NumericWildcard {
    fn get(caps: &regex::Captures) -> NumericWildcard {
        NumericWildcard { name: caps.name("name").unwrap().as_str().to_string() }
    }
}

impl Wildcard for NumericWildcard {
    fn name(&self) -> &str {
        &self.name
    }
    fn test(&self, object: &dyn Any) -> bool {
        as_i64(object).is_some()
    }
}

/// An inclusive `[min, max]` integer range.
///
/// Port of the `WildAssemblyParseToken.WildRange` record.
///
/// # Preserved quirk
/// The Java constructor's `min > max` guard throws `new AssertionError("max > max")` -- a
/// message that (per its own contract, "max > max") reads like a copy/paste typo for what should
/// say `"min > max"`. Faithfully reproduced verbatim in [`WildRange::new`] rather than corrected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WildRange {
    pub min: i64,
    pub max: i64,
}

impl WildRange {
    /// # Panics
    /// Panics with the message `"max > max"` (see this struct's "Preserved quirk" doc) if `min >
    /// max`.
    pub fn new(min: i64, max: i64) -> WildRange {
        assert!(min <= max, "max > max");
        WildRange { min, max }
    }

    /// Parses a single range specification: either a lone integer (`"5"`, giving `[5, 5]`) or two
    /// integers separated by `".."` (`"1..5"`, giving `[1, 5]`).
    ///
    /// Port of `WildRange.parse(String)`.
    ///
    /// # Panics
    /// Panics if `str` doesn't split into exactly one or two `".."`-separated parts, or if a part
    /// isn't a decodable integer literal (mirroring Java's `IllegalArgumentException`/
    /// `NumberFormatException`).
    pub fn parse(str: &str) -> WildRange {
        let parts = java_split_on_double_dot(str);
        match parts.as_slice() {
            [only] => {
                let val = long_decode(only);
                WildRange::new(val, val)
            }
            [min, max] => WildRange::new(long_decode(min), long_decode(max)),
            _ => panic!("Invalid range specification in wildcard: {str}"),
        }
    }

    /// Every integer in this range, in ascending order.
    ///
    /// Port of `WildRange.stream()`.
    pub fn iter(&self) -> impl Iterator<Item = i64> + '_ {
        self.min..=self.max
    }
}

/// Mirrors `String.split("\\.\\.")`'s specific trailing-empty-string-removal behavior (Java's
/// zero-`limit` `split` drops trailing empty strings; Rust's [`str::split`] does not), since
/// [`WildRange::parse`]'s `parts.length == 1` vs `2` branching depends on it -- e.g. `"5.."`
/// splits to `["5"]` in Java (one part) but `["5", ""]` in a naive Rust `split` (two parts).
fn java_split_on_double_dot(s: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split("..").collect();
    while parts.len() > 1 && parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    parts
}

/// An approximation of Java's `Long.decode(String)`: accepts an optional leading sign, then
/// `0x`/`0X`-prefixed or `#`-prefixed hexadecimal, `0`-prefixed octal, or plain decimal digits.
/// Does not replicate every edge case (e.g. `Long.MIN_VALUE`'s exact overflow boundary), but
/// covers the realistic set of numeric-literal strings a wildcard range spec contains. Same
/// approximation as
/// [`PcodeOpEmitter`](crate::app::util::pcode_inject::pcode_op_emitter::PcodeOpEmitter)'s private
/// `long_decode` helper (duplicated here rather than shared, since that one is private to its own
/// module and unrelated to this one).
///
/// # Panics
/// Panics (mirroring Java's unchecked `NumberFormatException`) if `s` isn't a decodable integer
/// literal.
fn long_decode(s: &str) -> i64 {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (digits, radix) = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (hex, 16)
    } else if let Some(hex) = rest.strip_prefix('#') {
        (hex, 16)
    } else if rest.len() > 1 && rest.starts_with('0') {
        (&rest[1..], 8)
    } else {
        (rest, 10)
    };
    let value = i64::from_str_radix(digits, radix).unwrap_or_else(|_| panic!("For input string: \"{s}\""));
    if neg { -value } else { value }
}

impl PartialOrd for WildRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WildRange {
    /// Port of `WildRange.compareTo(WildRange)`: orders by [`WildRange::min`] only, ignoring
    /// [`WildRange::max`] entirely -- faithfully preserved (two ranges with the same `min` but
    /// different `max` compare equal here, even though they aren't [`PartialEq::eq`]).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.min.cmp(&other.min)
    }
}

static RANGES_WILDCARD_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<name>[^\[]*)\[(?P<ranges>[^\]]*)\]$").unwrap());

/// A wildcard constrained to a set of integer ranges (`name[1,3..5,10]`).
///
/// Port of the `WildAssemblyParseToken.RangesWildcard` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangesWildcard {
    pub name: String,
    pub ranges: Vec<WildRange>,
}

impl RangesWildcard {
    fn get(caps: &regex::Captures) -> RangesWildcard {
        let name = caps.name("name").unwrap().as_str().to_string();
        let ranges = RangesWildcard::parse_ranges(caps.name("ranges").unwrap().as_str());
        RangesWildcard { name, ranges }
    }

    /// Parses a comma-separated list of range specs, sorted by [`WildRange::min`].
    ///
    /// Port of `RangesWildcard.parseRanges(String)`.
    pub fn parse_ranges(str: &str) -> Vec<WildRange> {
        let mut ranges: Vec<WildRange> = str.split(',').map(WildRange::parse).collect();
        ranges.sort();
        ranges
    }

    /// Every integer covered by any of this wildcard's ranges, in ascending order.
    ///
    /// Port of `RangesWildcard.stream()`.
    pub fn iter(&self) -> impl Iterator<Item = i64> + '_ {
        self.ranges.iter().flat_map(WildRange::iter)
    }
}

impl Wildcard for RangesWildcard {
    fn name(&self) -> &str {
        &self.name
    }

    /// Port of `RangesWildcard.test(Object)`: binary-searches [`Self::ranges`] (sorted by
    /// [`WildRange::min`]) for the containing range.
    fn test(&self, object: &dyn Any) -> bool {
        let Some(lv) = as_i64(object) else {
            return false;
        };
        match self.ranges.binary_search_by(|range| range.min.cmp(&lv)) {
            // Exactly at one of the mins.
            Ok(_) => true,
            // `insertion_point` is the first index greater (ceiling); `insertion_point - 1` is
            // the floor. No floor exists at index 0.
            Err(0) => false,
            Err(insertion_point) => lv <= self.ranges[insertion_point - 1].max,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// WildAssemblyParseToken
// ---------------------------------------------------------------------------------------------

/// A token in a wildcarded assembly instruction pattern.
///
/// Port of `ghidra.asm.wild.tree.WildAssemblyParseToken`.
pub struct WildAssemblyParseToken {
    str: String,
    term: Arc<dyn AssemblyTerminal>,
    /// The wildcard constraint parsed from this token's spec.
    ///
    /// Port of the public final field `WildAssemblyParseToken.wild`.
    pub wild: Box<dyn Wildcard>,
}

impl WildAssemblyParseToken {
    /// Constructs a wildcard token matching `term`, covering the input `str`, with its wildcard
    /// constraint parsed from `spec`.
    ///
    /// Port of `WildAssemblyParseToken(AssemblyGrammar, AssemblyTerminal, String, String)`. See
    /// this module's doc comment for why the `AssemblyGrammar` parameter is omitted here.
    pub fn new(term: Arc<dyn AssemblyTerminal>, str: impl Into<String>, spec: &str) -> Self {
        WildAssemblyParseToken { str: str.into(), term, wild: <dyn Wildcard>::parse(spec) }
    }

    /// The wildcard's name.
    ///
    /// Port of `WildAssemblyParseToken.wildcardName()`.
    pub fn wildcard_name(&self) -> &str {
        self.wild.name()
    }
}

impl AssemblyParseToken for WildAssemblyParseToken {
    fn get_string(&self) -> &str {
        &self.str
    }

    fn get_sym(&self) -> Arc<dyn AssemblyTerminal> {
        self.term.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{AssemblyNumericSymbols, AssemblySymbol};

    #[derive(Debug)]
    struct MockTerminal(&'static str);

    impl std::fmt::Display for MockTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockTerminal {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    impl AssemblyTerminal for MockTerminal {
        fn r#match(
            &self,
            _buffer: &str,
            _pos: usize,
            _grammar: &dyn crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar,
            _symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn AssemblyParseToken>> {
            Vec::new()
        }
        fn get_suggestions(&self, _got: &str, _symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
            Vec::new()
        }
    }

    fn terminal() -> Arc<dyn AssemblyTerminal> {
        Arc::new(MockTerminal("reg"))
    }

    // ---- Wildcard::parse dispatch ----

    #[test]
    fn parse_falls_back_to_free_wildcard() {
        let w = <dyn Wildcard>::parse("reg");
        assert_eq!(w.name(), "reg");
        assert!(w.test(&"anything".to_string()));
        assert!(w.test(&42i64));
    }

    #[test]
    fn parse_recognizes_regex_form() {
        let w = <dyn Wildcard>::parse("reg/R[0-9]+");
        assert_eq!(w.name(), "reg");
        assert!(w.test(&"R1".to_string()));
        assert!(!w.test(&"X1".to_string()));
    }

    #[test]
    fn parse_recognizes_numeric_form() {
        let w = <dyn Wildcard>::parse("imm[..]");
        assert_eq!(w.name(), "imm");
        assert!(w.test(&5i64));
        assert!(!w.test(&"5".to_string()));
    }

    #[test]
    fn parse_recognizes_ranges_form() {
        let w = <dyn Wildcard>::parse("imm[0..3,10]");
        assert_eq!(w.name(), "imm");
        assert!(w.test(&2i64));
        assert!(w.test(&10i64));
        assert!(!w.test(&5i64));
    }

    // ---- RegexWildcard ----

    #[test]
    fn regex_wildcard_requires_a_full_string_match() {
        let w = <dyn Wildcard>::parse("reg/R[0-9]");
        // "R12" does not fully match "R[0-9]" (only one digit) -- a partial match should not
        // count, mirroring Java's `Matcher.matches()`.
        assert!(!w.test(&"R12".to_string()));
        assert!(w.test(&"R1".to_string()));
    }

    #[test]
    fn regex_wildcard_equality_compares_pattern_text() {
        let a = RegexWildcard::get(&REGEX_WILDCARD_PATTERN.captures("reg/R[0-9]").unwrap());
        let b = RegexWildcard::get(&REGEX_WILDCARD_PATTERN.captures("reg/R[0-9]").unwrap());
        let c = RegexWildcard::get(&REGEX_WILDCARD_PATTERN.captures("reg/X[0-9]").unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ---- NumericWildcard ----

    #[test]
    fn numeric_wildcard_accepts_only_integers() {
        let w = NumericWildcard { name: "imm".to_string() };
        assert!(w.test(&5i64));
        assert!(w.test(&5i32));
        assert!(!w.test(&"5".to_string()));
    }

    // ---- WildRange ----

    #[test]
    fn wild_range_parse_single_value() {
        let r = WildRange::parse("5");
        assert_eq!(r, WildRange::new(5, 5));
    }

    #[test]
    fn wild_range_parse_a_range() {
        let r = WildRange::parse("1..5");
        assert_eq!(r, WildRange::new(1, 5));
    }

    #[test]
    fn wild_range_parse_hex_and_negative() {
        assert_eq!(WildRange::parse("-0x10..0x10"), WildRange::new(-16, 16));
    }

    #[test]
    #[should_panic(expected = "max > max")]
    fn wild_range_new_panics_with_the_literal_javas_typo_message_when_min_exceeds_max() {
        // Preserved Java quirk: the assertion message itself reads "max > max" rather than the
        // presumably-intended "min > max".
        WildRange::new(5, 1);
    }

    #[test]
    fn wild_range_ordering_is_by_min_only() {
        let a = WildRange::new(1, 100);
        let b = WildRange::new(1, 2);
        let c = WildRange::new(5, 5);
        // Same `min`, different `max`: compare equal under `Ord`, even though `!=` under `Eq`.
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
        assert_ne!(a, b);
        assert!(a < c);
    }

    #[test]
    fn wild_range_iter_covers_every_integer_inclusive() {
        let r = WildRange::new(3, 6);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![3, 4, 5, 6]);
    }

    // ---- RangesWildcard ----

    #[test]
    fn ranges_wildcard_parse_ranges_sorts_by_min() {
        let ranges = RangesWildcard::parse_ranges("10,1..2,5");
        assert_eq!(ranges, vec![WildRange::new(1, 2), WildRange::new(5, 5), WildRange::new(10, 10)]);
    }

    #[test]
    fn ranges_wildcard_test_matches_within_any_range() {
        let w = RangesWildcard { name: "n".to_string(), ranges: RangesWildcard::parse_ranges("0..3,10,20..25") };
        assert!(w.test(&0i64));
        assert!(w.test(&3i64));
        assert!(w.test(&10i64));
        assert!(w.test(&22i64));
        assert!(!w.test(&4i64));
        assert!(!w.test(&9i64));
        assert!(!w.test(&11i64));
        assert!(!w.test(&26i64));
    }

    #[test]
    fn ranges_wildcard_test_rejects_non_integers() {
        let w = RangesWildcard { name: "n".to_string(), ranges: RangesWildcard::parse_ranges("0..3") };
        assert!(!w.test(&"1".to_string()));
    }

    #[test]
    fn ranges_wildcard_iter_flattens_all_ranges() {
        let w = RangesWildcard { name: "n".to_string(), ranges: RangesWildcard::parse_ranges("1,3..4") };
        assert_eq!(w.iter().collect::<Vec<_>>(), vec![1, 3, 4]);
    }

    // ---- WildAssemblyParseToken itself ----

    #[test]
    fn new_parses_the_wildcard_spec_and_exposes_it() {
        let token = WildAssemblyParseToken::new(terminal(), "$reg", "reg/R[0-9]+");
        assert_eq!(token.wildcard_name(), "reg");
        assert!(token.wild.test(&"R3".to_string()));
    }

    #[test]
    fn assembly_parse_token_accessors_return_the_constructed_values() {
        let token = WildAssemblyParseToken::new(terminal(), "$reg", "reg");
        assert_eq!(AssemblyParseToken::get_string(&token), "$reg");
        assert_eq!(token.get_sym().terminal_tag(), "reg");
    }
}
