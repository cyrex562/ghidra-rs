/// Intermediate parsing result used by `NumberSearchFormat` and `FloatSearchFormat`.
#[derive(Debug, Clone, PartialEq)]
pub struct NumberParseResult {
    /// The bytes that match the parsed number sequence.
    pub bytes: Vec<u8>,
    /// An optional parsing error message; `None` when parsing succeeded.
    pub error_message: Option<String>,
    /// Whether the input was valid.
    pub valid_input: bool,
}

impl NumberParseResult {
    pub fn new(bytes: Vec<u8>, error_message: Option<String>, valid_input: bool) -> Self {
        Self { bytes, error_message, valid_input }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_result_has_no_error() {
        let r = NumberParseResult::new(vec![0x01, 0x02], None, true);
        assert!(r.valid_input);
        assert!(r.error_message.is_none());
        assert_eq!(r.bytes, vec![0x01, 0x02]);
    }

    #[test]
    fn invalid_result_carries_error_message() {
        let r = NumberParseResult::new(vec![], Some("overflow".to_string()), false);
        assert!(!r.valid_input);
        assert_eq!(r.error_message.as_deref(), Some("overflow"));
        assert!(r.bytes.is_empty());
    }

    #[test]
    fn equality_holds_for_identical_results() {
        let a = NumberParseResult::new(vec![0xFF], None, true);
        let b = NumberParseResult::new(vec![0xFF], None, true);
        assert_eq!(a, b);
    }

    #[test]
    fn equality_differs_on_bytes() {
        let a = NumberParseResult::new(vec![0x01], None, true);
        let b = NumberParseResult::new(vec![0x02], None, true);
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_value() {
        let r = NumberParseResult::new(vec![0xAB, 0xCD], Some("err".to_string()), false);
        assert_eq!(r.clone(), r);
    }
}
