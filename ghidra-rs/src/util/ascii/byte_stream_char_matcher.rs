use crate::util::seam_stubs::Sequence;

/// Trait mirroring `ghidra.util.ascii.ByteStreamCharMatcher`.
///
/// State machines used to look for character sequences within a stream of bytes.
/// Bytes from the stream are added one at a time and converted to a character stream,
/// which is then fed into a character stream recognizer. As each byte is added,
/// an indication is returned if that byte caused a terminated sequence to be found.
/// A sequence is a pair of indices indicating the start and end positions in the
/// byte stream where the character sequence started and ended, along with an indication
/// of whether the sequence was null-terminated.
pub trait ByteStreamCharMatcher: Send + Sync {
    /// Adds the next contiguous byte to this matcher.
    ///
    /// # Arguments
    /// * `b` - The next contiguous byte in the search stream.
    ///
    /// # Returns
    /// `true` if the given byte triggered a sequence match. Note that this byte may not be
    /// part of the recognized sequence.
    fn add(&mut self, b: u8) -> bool;

    /// Signals that there are no more contiguous bytes.
    ///
    /// If the current state of the matcher is such that there is a valid sequence that
    /// can be at the end of the stream, then a sequence will be created and `true` will be returned.
    ///
    /// # Returns
    /// `true` if there is a valid sequence at the end of the stream.
    fn end_sequence(&mut self) -> bool;

    /// Returns the currently recognized sequence.
    ///
    /// This only exists immediately after an `add` or `end_sequence` call that returned `true`.
    fn get_sequence(&self) -> &dyn Sequence;

    /// Resets the internal state of this matcher so it can be reused against another byte stream.
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple test matcher that matches ASCII printable characters.
    struct SimpleMatcher {
        sequence: Option<TestSequence>,
    }

    #[derive(Clone, Debug)]
    struct TestSequence {
        start: i64,
        end: i64,
        null_terminated: bool,
    }

    impl SimpleMatcher {
        fn new() -> Self {
            SimpleMatcher {
                sequence: None,
            }
        }
    }

    impl ByteStreamCharMatcher for SimpleMatcher {
        fn add(&mut self, b: u8) -> bool {
            // Simple logic: match printable ASCII
            if b >= 0x20 && b <= 0x7E {
                if self.sequence.is_none() {
                    self.sequence = Some(TestSequence {
                        start: 0,
                        end: 0,
                        null_terminated: false,
                    });
                }
                if let Some(ref mut seq) = self.sequence {
                    seq.end += 1;
                }
                false
            } else if b == 0 {
                // Null terminator
                if let Some(ref mut seq) = self.sequence {
                    seq.null_terminated = true;
                    true
                } else {
                    false
                }
            } else {
                // Non-printable, non-null: end sequence if one exists
                self.sequence.is_some()
            }
        }

        fn end_sequence(&mut self) -> bool {
            self.sequence.is_some()
        }

        fn get_sequence(&self) -> &dyn Sequence {
            self.sequence.as_ref().expect("no active sequence")
        }

        fn reset(&mut self) {
            self.sequence = None;
        }
    }

    impl Sequence for TestSequence {
        fn get_start(&self) -> i64 {
            self.start
        }

        fn get_end(&self) -> i64 {
            self.end
        }

        fn is_null_terminated(&self) -> bool {
            self.null_terminated
        }

        fn get_string_data_type(&self) -> Box<dyn crate::util::seam_stubs::AbstractStringDataType> {
            Box::new(TestStringDataType)
        }

        fn get_length(&self) -> i32 {
            (self.end - self.start) as i32
        }

        fn equals(&self, _obj: &dyn std::any::Any) -> bool {
            false
        }

        fn hash_code(&self) -> i32 {
            (self.start ^ self.end) as i32
        }

        fn to_string(&self) -> String {
            format!("Sequence(start={}, end={}, null_terminated={})",
                self.start, self.end, self.null_terminated)
        }
    }

    struct TestStringDataType;

    impl crate::util::seam_stubs::AbstractStringDataType for TestStringDataType {}

    #[test]
    fn test_matcher_trait_object() {
        let mut matcher: Box<dyn ByteStreamCharMatcher> = Box::new(SimpleMatcher::new());

        // Add a printable character
        let result = matcher.add(b'H');
        assert!(!result, "first printable should not trigger match");

        // Get the sequence
        let seq = matcher.get_sequence();
        assert_eq!(seq.get_start(), 0);
        assert!(seq.get_length() > 0);

        // Reset
        matcher.reset();
    }

    #[test]
    fn test_sequence_properties() {
        let seq = TestSequence {
            start: 10,
            end: 20,
            null_terminated: true,
        };

        assert_eq!(seq.get_start(), 10);
        assert_eq!(seq.get_end(), 20);
        assert_eq!(seq.get_length(), 10);
        assert!(seq.is_null_terminated());
        assert!(!seq.to_string().is_empty());
    }
}
