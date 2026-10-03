use std::io;

use crate::util::bytesearch::byte_pattern::BytePattern;
use crate::util::bytesearch::ditted_bit_sequence::DittedBitSequence;
use crate::util::bytesearch::match_action::MatchAction;
use crate::util::bytesearch::post_rule::PostRule;

/// An association of a [`DittedBitSequence`] to match, a set of post rules checked after a
/// match is found, and a set of actions to take if the pattern matches.
///
/// Port of `ghidra.util.bytesearch.Pattern`. Java's `Pattern extends DittedBitSequence`; per
/// this crate's composition-over-inheritance convention the base sequence is a field rather
/// than faked via a trait default or blanket impl. The Java class has no subclasses that
/// override any of its behavior (`GenericByteSequencePattern` only adds specialized
/// constructors; a test-only `TestPattern` overrides `toString()`, not part of this trait
/// surface), so per this crate's shape rule for a concrete class with no genuinely abstract
/// methods, this ports as a `struct` rather than a `struct` + `trait` split -- the fields and
/// all (non-abstract) methods live directly on `Pattern`.
///
/// This was a `seam_stubs.rs` placeholder (`pub trait Pattern: Send + Sync { ... }`) that
/// [`MatchAction`], [`PostRule`], [`DummyMatchAction`](super::DummyMatchAction), and
/// [`GenericMatchAction`](super::GenericMatchAction) were built against before this class had
/// its own port; those were all edited in this same change to use `&Pattern`/`Match<Pattern>`
/// (a concrete reference/value) instead of `&dyn Pattern`/`Match<Box<dyn Pattern>>`, since
/// nothing in this crate actually needs `Pattern` as a trait object.
///
/// # XML restoration is not fully portable yet
///
/// Java's `restoreXml`/`restoreXmlAttributes`/`readPatterns`/`readPostPatterns` all drive an
/// `XmlPullParser` by calling `parser.peek()` to inspect the next sibling tag's name before
/// deciding whether it is a `<postrule>` or a match-action tag. This crate has two incompatible
/// `XmlPullParser`s (mirroring the documented `ByteProvider` split): the real one
/// (`crate::util::xml::xml_pull_parser::XmlPullParser`, generic and `pub(crate)`, used by
/// `DittedBitSequence::restore_xml_data`) has no object-safe form, while the dyn-compatible one
/// this type's callers are built against (`crate::util::seam_stubs::XmlPullParser`) only offers
/// `start`/`end`/`discard_sub_tree` -- no `peek()` or element inspection. Reconciling the two is
/// out of scope here (as with `ByteProvider`), so [`Pattern::restore_xml`] can restore the mark
/// offset from a `mark` attribute value passed in directly, but cannot walk the XML tree to
/// restore `postrule`/`actions`; `read_patterns`/`read_post_patterns` (which also need
/// `PatternPairSet` and a concrete `XmlPullParser` implementation, neither ported) are omitted
/// entirely rather than stubbed with invented behavior.
#[derive(Default)]
pub struct Pattern {
    sequence: DittedBitSequence,
    mark_offset: i32,
    postrule: Vec<Box<dyn PostRule>>,
    actions: Vec<Box<dyn MatchAction>>,
}

impl Pattern {
    /// Constructs an empty pattern. Use [`Pattern::from_parts`] or XML restoration to
    /// initialize it.
    ///
    /// Port of the no-arg `Pattern()` constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs the pattern based on a [`DittedBitSequence`], a match offset, post matching
    /// rules, and a set of actions to take when the match occurs.
    ///
    /// Port of `Pattern(DittedBitSequence, int, PostRule[], MatchAction[])`.
    pub fn from_parts(
        seq: DittedBitSequence,
        offset: i32,
        post_rules: Vec<Box<dyn PostRule>>,
        actions: Vec<Box<dyn MatchAction>>,
    ) -> Self {
        Pattern { sequence: seq, mark_offset: offset, postrule: post_rules, actions }
    }

    /// Returns the underlying ditted bit sequence.
    pub fn sequence(&self) -> &DittedBitSequence {
        &self.sequence
    }

    /// Port of `getPostRules()`.
    pub fn get_post_rules(&self) -> &[Box<dyn PostRule>] {
        &self.postrule
    }

    /// Port of `getMatchActions()`.
    pub fn get_match_actions(&self) -> &[Box<dyn MatchAction>] {
        &self.actions
    }

    /// Port of `setMatchActions(MatchAction[])`.
    pub fn set_match_actions(&mut self, actions: Vec<Box<dyn MatchAction>>) {
        self.actions = actions;
    }

    /// Port of `getMarkOffset()`.
    pub fn get_mark_offset(&self) -> i32 {
        self.mark_offset
    }

    /// Checks that the possible post rules are satisfied.
    ///
    /// Port of `checkPostRules(long)`.
    pub fn check_post_rules(&self, offset: i64) -> bool {
        self.postrule.iter().all(|rule| rule.apply(self, offset))
    }

    /// Restores this pattern's mark offset from a `mark` XML attribute value, mirroring the
    /// `mark` attribute handling in `restoreXml(XmlPullParser, PatternFactory)`. See the
    /// struct's own docs for why the rest of `restoreXml` (the `<data>` tag and post-rule /
    /// match-action child tags) cannot be restored through the dyn-compatible `XmlPullParser`
    /// seam this crate's `Pattern` callers are built against.
    pub fn restore_xml_mark_attribute(&mut self, mark_attribute: Option<&str>) -> io::Result<()> {
        self.mark_offset = 0;
        if let Some(mark) = mark_attribute {
            self.mark_offset = mark.parse::<i32>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, format!("bad mark attribute: {mark}"))
            })?;
        }
        Ok(())
    }
}

impl BytePattern for Pattern {
    /// Port of `getPreSequenceLength()` via `DittedBitSequence::size()` (inherited unchanged).
    fn size(&self) -> usize {
        self.sequence.size()
    }

    /// Inherited unchanged from `DittedBitSequence.isMatch(int, int)`.
    fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool {
        self.sequence.is_match(pattern_offset, byte_value)
    }

    /// Port of `Pattern.getPreSequenceLength()`, which overrides
    /// `DittedBitSequence.getPreSequenceLength()` (always `0`) to return `markOffset` instead:
    /// within the pattern, this is the "marked" byte to report the match position at.
    fn pre_sequence_length(&self) -> usize {
        self.mark_offset.max(0) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::seam_stubs::XmlPullParser;

    struct RecordingPostRule {
        satisfied: bool,
    }

    impl PostRule for RecordingPostRule {
        fn apply(&self, _pat: &Pattern, _matchoffset: i64) -> bool {
            self.satisfied
        }

        fn restore_xml(&self, _parser: &dyn XmlPullParser) {}
    }

    #[test]
    fn new_is_empty_and_matches_default() {
        let pattern = Pattern::new();
        assert_eq!(pattern.get_mark_offset(), 0);
        assert!(pattern.get_post_rules().is_empty());
        assert!(pattern.get_match_actions().is_empty());
        assert_eq!(pattern.size(), 0);
    }

    #[test]
    fn from_parts_carries_sequence_and_mark_offset() {
        let seq = DittedBitSequence::from_bytes(vec![0xDE, 0xAD]);
        let pattern = Pattern::from_parts(seq, 1, Vec::new(), Vec::new());
        assert_eq!(pattern.get_mark_offset(), 1);
        assert_eq!(pattern.size(), 2);
    }

    #[test]
    fn pre_sequence_length_returns_mark_offset_not_zero() {
        // DittedBitSequence::pre_sequence_length() (the base Java class) always returns 0;
        // Pattern overrides it to return markOffset instead.
        let seq = DittedBitSequence::from_bytes(vec![1, 2, 3]);
        let pattern = Pattern::from_parts(seq, 2, Vec::new(), Vec::new());
        assert_eq!(pattern.pre_sequence_length(), 2);

        let base = DittedBitSequence::from_bytes(vec![1, 2, 3]);
        assert_eq!(base.pre_sequence_length(), 0);
    }

    #[test]
    fn is_match_delegates_to_sequence() {
        let seq = DittedBitSequence::from_bytes(vec![0xAB]);
        let pattern = Pattern::from_parts(seq, 0, Vec::new(), Vec::new());
        assert!(pattern.is_match(0, 0xAB));
        assert!(!pattern.is_match(0, 0xAC));
    }

    #[test]
    fn set_match_actions_replaces_actions() {
        let mut pattern = Pattern::new();
        assert!(pattern.get_match_actions().is_empty());
        pattern.set_match_actions(vec![Box::new(crate::util::bytesearch::DummyMatchAction::new())]);
        assert_eq!(pattern.get_match_actions().len(), 1);
    }

    #[test]
    fn check_post_rules_true_when_all_rules_satisfied() {
        let pattern = Pattern::from_parts(
            DittedBitSequence::new(),
            0,
            vec![
                Box::new(RecordingPostRule { satisfied: true }),
                Box::new(RecordingPostRule { satisfied: true }),
            ],
            Vec::new(),
        );
        assert!(pattern.check_post_rules(42));
    }

    #[test]
    fn check_post_rules_false_when_any_rule_fails() {
        let pattern = Pattern::from_parts(
            DittedBitSequence::new(),
            0,
            vec![
                Box::new(RecordingPostRule { satisfied: true }),
                Box::new(RecordingPostRule { satisfied: false }),
            ],
            Vec::new(),
        );
        assert!(!pattern.check_post_rules(7));
    }

    #[test]
    fn check_post_rules_true_with_no_rules() {
        let pattern = Pattern::new();
        assert!(pattern.check_post_rules(0));
    }

    #[test]
    fn restore_xml_mark_attribute_parses_present_value() {
        let mut pattern = Pattern::new();
        pattern.restore_xml_mark_attribute(Some("3")).expect("should parse");
        assert_eq!(pattern.get_mark_offset(), 3);
    }

    #[test]
    fn restore_xml_mark_attribute_defaults_to_zero_when_absent() {
        let mut pattern = Pattern::from_parts(DittedBitSequence::new(), 5, Vec::new(), Vec::new());
        pattern.restore_xml_mark_attribute(None).expect("should not error");
        assert_eq!(pattern.get_mark_offset(), 0);
    }

    #[test]
    fn restore_xml_mark_attribute_errors_on_bad_value() {
        let mut pattern = Pattern::new();
        assert!(pattern.restore_xml_mark_attribute(Some("not-a-number")).is_err());
    }
}
