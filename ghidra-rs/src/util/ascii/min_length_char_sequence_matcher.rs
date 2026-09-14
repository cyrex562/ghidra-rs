//! Finds runs of characters (fed one at a time) that belong to a given character set and are at
//! least a minimum length.
//!
//! Java source: `ghidra.util.ascii.MinLengthCharSequenceMatcher`.
//!
//! # Shape
//!
//! Java's `getSequence()` returns the shared `lastSequence` field itself (an alias, not a copy);
//! [`Sequence`] has no `Clone` (see its own module docs: its `string_data_type` field is a
//! `Box<dyn AbstractStringDataType>`), so [`MinLengthCharSequenceMatcher::get_sequence`] returns a
//! borrow (`Option<&Sequence>`) instead, the direct Rust analogue.
//!
//! `new Sequence(start, end, StringDataType.dataType, nullTerminated)` needs the
//! `StringDataType.dataType` singleton. `StringDataType` itself is ported only as a trait
//! ([`program::model::data::string_data_type::StringDataType`](crate::program::model::data::string_data_type::StringDataType)),
//! with no concrete singleton yet (see that module's docs: it needs `DataTypeManager` wiring not
//! yet part of this port). This reuses the existing concrete stand-in,
//! [`pcode::seam_stubs::StringDataType`](crate::pcode::seam_stubs::StringDataType), which already
//! fully implements the real [`AbstractStringDataType`](crate::program::model::data::abstract_string_data_type::AbstractStringDataType)
//! trait `Sequence` needs (it exists for exactly this same `StringDataType.dataType` gap, reached
//! from a different call site) -- the alternative would be to duplicate its `AbstractStringDataType`
//! impl a second time here for no behavioral difference.
use crate::pcode::seam_stubs::StringDataType;
use crate::util::ascii::sequence::Sequence;
use crate::util::ascii::CharSetRecognizer;

/// Finds sequences of characters that are in a given character set and of a minimum length.
///
/// Characters are fed one at a time via [`Self::add_char`]. Adding a character may trigger the
/// discovery of a sequence if the character is `0` (a null terminator) or not in the character
/// set, and a sequence of included characters at least as long as the minimum length has already
/// been seen.
///
/// Port of `ghidra.util.ascii.MinLengthCharSequenceMatcher`.
pub struct MinLengthCharSequenceMatcher {
    minimum_sequence_length: i32,
    sequence_start_index: i64,
    current_index: i64,
    in_ascii_sequence: bool,
    char_set: Box<dyn CharSetRecognizer>,
    last_sequence: Option<Sequence>,
    alignment: i32,
}

impl MinLengthCharSequenceMatcher {
    /// Port of `MinLengthCharSequenceMatcher(int, CharSetRecognizer, int)`.
    pub fn new(
        minimum_sequence_length: i32,
        char_set: Box<dyn CharSetRecognizer>,
        alignment: i32,
    ) -> Self {
        MinLengthCharSequenceMatcher {
            minimum_sequence_length,
            sequence_start_index: -1,
            current_index: -1,
            in_ascii_sequence: false,
            char_set,
            last_sequence: None,
            alignment,
        }
    }

    /// Adds a character to this sequence matcher.
    ///
    /// Returns `true` if the added character triggered the end of a valid sequence (retrievable
    /// via [`Self::get_sequence`]), otherwise `false`.
    ///
    /// Port of `addChar(int)`.
    pub fn add_char(&mut self, c: i32) -> bool {
        self.last_sequence = None;
        self.current_index += 1;
        if self.char_set.contains(c) {
            if !self.in_ascii_sequence && self.meets_alignment_requirement() {
                self.sequence_start_index = self.current_index;
                self.in_ascii_sequence = true;
            }
        } else if c == 0 {
            return self.check_sequence(self.sequence_start_index, self.current_index, true);
        } else {
            return self.check_sequence(self.sequence_start_index, self.current_index - 1, false);
        }
        false
    }

    /// Port of `meetsAlignmentRequirement()`.
    fn meets_alignment_requirement(&self) -> bool {
        self.current_index % self.alignment as i64 == 0
    }

    /// Indicates there are no more contiguous characters to add to this matcher.
    ///
    /// If a minimum or more number of included characters have been seen before this call, then a
    /// sequence is recorded (retrievable via [`Self::get_sequence`]) and `true` is returned.
    ///
    /// Port of `endSequence()`.
    pub fn end_sequence(&mut self) -> bool {
        self.last_sequence = None;
        self.check_sequence(self.sequence_start_index, self.current_index, false)
    }

    /// Port of `reset()`.
    pub fn reset(&mut self) {
        self.current_index = -1;
        self.in_ascii_sequence = false;
        self.last_sequence = None;
    }

    /// The most recently discovered sequence, if [`Self::add_char`]/[`Self::end_sequence`] just
    /// returned `true`.
    ///
    /// Port of `getSequence()`. Java returns the shared `lastSequence` field directly (an alias);
    /// see this module's docs for why this returns a borrow rather than a copy.
    pub fn get_sequence(&self) -> Option<&Sequence> {
        self.last_sequence.as_ref()
    }

    /// Port of `checkSequence(long, long, boolean)`.
    fn check_sequence(&mut self, start: i64, end: i64, null_terminated: bool) -> bool {
        if !self.in_ascii_sequence {
            return false;
        }
        self.in_ascii_sequence = false;
        let mut length = end - start + 1;
        if null_terminated {
            // Seems we don't count the 0 in the length for purposes of minimum string length.
            length -= 1;
        }
        if length >= self.minimum_sequence_length as i64 {
            self.last_sequence =
                Some(Sequence::new(start, end, Box::new(StringDataType), null_terminated));
        }
        self.last_sequence.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recognizes only lowercase ASCII letters, for small and predictable test fixtures.
    struct LowercaseRecognizer;
    impl CharSetRecognizer for LowercaseRecognizer {
        fn contains(&self, c: i32) -> bool {
            (b'a' as i32..=b'z' as i32).contains(&c)
        }
    }

    fn matcher(min_length: i32, alignment: i32) -> MinLengthCharSequenceMatcher {
        MinLengthCharSequenceMatcher::new(min_length, Box::new(LowercaseRecognizer), alignment)
    }

    #[test]
    fn a_null_terminator_ends_a_sequence_that_meets_the_minimum_length() {
        let mut m = matcher(3, 1);
        assert!(!m.add_char(b'a' as i32));
        assert!(!m.add_char(b'b' as i32));
        assert!(!m.add_char(b'c' as i32));
        assert!(m.add_char(0));

        let seq = m.get_sequence().expect("expected a discovered sequence");
        assert_eq!(seq.get_start(), 0);
        assert_eq!(seq.get_end(), 3);
        assert!(seq.is_null_terminated());
    }

    #[test]
    fn an_excluded_non_null_character_ends_a_sequence_without_including_it() {
        let mut m = matcher(3, 1);
        assert!(!m.add_char(b'a' as i32));
        assert!(!m.add_char(b'b' as i32));
        assert!(!m.add_char(b'c' as i32));
        // '!' (0x21) is not lowercase and not 0: the sequence ends at the *previous* index.
        assert!(m.add_char(b'!' as i32));

        let seq = m.get_sequence().expect("expected a discovered sequence");
        assert_eq!(seq.get_start(), 0);
        assert_eq!(seq.get_end(), 2);
        assert!(!seq.is_null_terminated());
    }

    #[test]
    fn a_sequence_shorter_than_the_minimum_length_is_not_reported() {
        let mut m = matcher(5, 1);
        assert!(!m.add_char(b'a' as i32));
        assert!(!m.add_char(b'b' as i32));
        // Only 2 characters seen; breaking here is one char short of the minimum of 5.
        assert!(!m.add_char(b'!' as i32));
        assert!(m.get_sequence().is_none());
    }

    #[test]
    fn null_terminated_sequences_do_not_count_the_terminator_towards_the_minimum_length() {
        // Faithful to a real (self-acknowledged, "seems") Java quirk in `checkSequence`: for a
        // null-terminated run, the terminator's own position is *not* counted towards the minimum
        // length, even though it is still included in the reported `end`.
        let min_length = 3;

        // 3 real characters + a null terminator: length is computed as 3 (not 4), meeting the
        // minimum exactly.
        let mut passes = matcher(min_length, 1);
        assert!(!passes.add_char(b'a' as i32));
        assert!(!passes.add_char(b'a' as i32));
        assert!(!passes.add_char(b'a' as i32));
        assert!(passes.add_char(0));
        let seq = passes.get_sequence().expect("3 real chars should meet a minimum of 3");
        assert_eq!((seq.get_start(), seq.get_end()), (0, 3));

        // Only 2 real characters + a null terminator: length is computed as 2, one short of the
        // minimum of 3 -- even though 3 total positions (0..=2) were consumed.
        let mut fails = matcher(min_length, 1);
        assert!(!fails.add_char(b'a' as i32));
        assert!(!fails.add_char(b'a' as i32));
        assert!(!fails.add_char(0));
        assert!(fails.get_sequence().is_none());
    }

    #[test]
    fn alignment_requirement_only_starts_sequences_at_aligned_indices() {
        let mut m = matcher(1, 2);
        // Index 0: not in the char set; no sequence starts.
        assert!(!m.add_char(b'!' as i32));
        // Index 1 (odd): in the char set, but 1 % 2 != 0, so no sequence starts here.
        assert!(!m.add_char(b'a' as i32));
        // Index 2 (even): in the char set and aligned, so a sequence starts here.
        assert!(!m.add_char(b'a' as i32));
        // Index 3: breaks the sequence that started at index 2, not index 1.
        assert!(m.add_char(b'!' as i32));

        let seq = m.get_sequence().expect("expected a discovered sequence");
        assert_eq!((seq.get_start(), seq.get_end()), (2, 2));
    }

    #[test]
    fn end_sequence_finalizes_an_in_progress_run() {
        let mut m = matcher(2, 1);
        assert!(!m.add_char(b'a' as i32));
        assert!(!m.add_char(b'a' as i32));
        assert!(!m.add_char(b'a' as i32));
        // No terminator seen yet, but the stream has ended.
        assert!(m.end_sequence());

        let seq = m.get_sequence().expect("expected a discovered sequence");
        assert_eq!((seq.get_start(), seq.get_end()), (0, 2));
        assert!(!seq.is_null_terminated());
    }

    #[test]
    fn end_sequence_with_no_active_run_reports_nothing() {
        let mut m = matcher(1, 1);
        assert!(!m.end_sequence());
        assert!(m.get_sequence().is_none());
    }

    #[test]
    fn get_sequence_is_cleared_at_the_start_of_every_add_char_call() {
        // Java: `lastSequence = null;` is the first statement of `addChar`, so a stale sequence
        // from a prior call never leaks into a call that doesn't itself discover one.
        let mut m = matcher(1, 1);
        assert!(!m.add_char(b'a' as i32));
        assert!(m.add_char(b'!' as i32));
        assert!(m.get_sequence().is_some());

        // This call is inside the char set, so no new sequence completes, and the old one must
        // not still be visible.
        assert!(!m.add_char(b'a' as i32));
        assert!(m.get_sequence().is_none());
    }

    #[test]
    fn reset_clears_all_state_so_indexing_restarts_from_scratch() {
        let mut m = matcher(1, 1);
        assert!(!m.add_char(b'a' as i32));
        assert!(m.add_char(b'!' as i32));
        assert!(m.get_sequence().is_some());

        m.reset();
        assert!(m.get_sequence().is_none());

        // After reset, indexing restarts at 0, exactly as with a freshly constructed matcher.
        assert!(!m.add_char(b'a' as i32));
        assert!(m.add_char(b'!' as i32));
        let seq = m.get_sequence().expect("expected a discovered sequence after reset");
        assert_eq!((seq.get_start(), seq.get_end()), (0, 0));
    }
}
