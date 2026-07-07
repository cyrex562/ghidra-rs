/// Interface for fixed-length patterns that can be combined into a single state machine
/// and simultaneously searched for in a byte sequence.
pub trait BytePattern {
    /// Returns the size of this pattern.
    fn size(&self) -> usize;

    /// Checks if this pattern matches `byte_value` at `pattern_offset` into the pattern.
    ///
    /// `byte_value` is treated as an unsigned byte (0–255).
    fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool;

    /// Returns the number of bytes in this pattern that represent a required pre-sequence
    /// before the actual pattern position of interest (analogous to regex "look-behind").
    ///
    /// For example, if searching for "abcd" only when preceded by "xyz", the full pattern
    /// is "xyzabcd" with a pre-sequence length of 3.  When this pattern matches, the
    /// reported match position points at "a", not at "x".
    fn pre_sequence_length(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::BytePattern;

    /// Minimal concrete implementation used only for testing the trait contract.
    struct ExactPattern {
        bytes: Vec<u8>,
        pre_len: usize,
    }

    impl ExactPattern {
        fn new(bytes: Vec<u8>, pre_len: usize) -> Self {
            Self { bytes, pre_len }
        }
    }

    impl BytePattern for ExactPattern {
        fn size(&self) -> usize {
            self.bytes.len()
        }

        fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool {
            self.bytes.get(pattern_offset).map_or(false, |&b| b == byte_value)
        }

        fn pre_sequence_length(&self) -> usize {
            self.pre_len
        }
    }

    #[test]
    fn size_reflects_pattern_length() {
        let p = ExactPattern::new(vec![0xDE, 0xAD, 0xBE, 0xEF], 0);
        assert_eq!(p.size(), 4);
    }

    #[test]
    fn is_match_returns_true_for_correct_byte() {
        let p = ExactPattern::new(vec![0xAB, 0xCD], 0);
        assert!(p.is_match(0, 0xAB));
        assert!(p.is_match(1, 0xCD));
    }

    #[test]
    fn is_match_returns_false_for_wrong_byte() {
        let p = ExactPattern::new(vec![0xAB, 0xCD], 0);
        assert!(!p.is_match(0, 0x00));
        assert!(!p.is_match(1, 0xAB));
    }

    #[test]
    fn is_match_returns_false_for_out_of_bounds_offset() {
        let p = ExactPattern::new(vec![0xFF], 0);
        assert!(!p.is_match(1, 0xFF));
    }

    #[test]
    fn pre_sequence_length_zero_when_no_pre_sequence() {
        let p = ExactPattern::new(vec![0x41, 0x42], 0);
        assert_eq!(p.pre_sequence_length(), 0);
    }

    #[test]
    fn pre_sequence_length_nonzero() {
        // "xyz" prefix (3 bytes) followed by "abcd" pattern (4 bytes) = 7 total
        let p = ExactPattern::new(
            vec![b'x', b'y', b'z', b'a', b'b', b'c', b'd'],
            3,
        );
        assert_eq!(p.size(), 7);
        assert_eq!(p.pre_sequence_length(), 3);
        // The "real" match starts at offset 3
        assert!(p.is_match(3, b'a'));
    }

    #[test]
    fn empty_pattern_has_size_zero() {
        let p = ExactPattern::new(vec![], 0);
        assert_eq!(p.size(), 0);
    }

    #[test]
    fn byte_value_treated_as_unsigned() {
        // 0xFF == 255 — would be -1 if treated as signed i8
        let p = ExactPattern::new(vec![0xFF], 0);
        assert!(p.is_match(0, 0xFF));
        assert!(!p.is_match(0, 0x7F));
    }
}
