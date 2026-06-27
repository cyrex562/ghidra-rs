use std::fmt;

/// Filters a hex-digit byte-sequence string by returning a fixed-width prefix or suffix,
/// rejecting strings that are shorter than a configured minimum.
///
/// Mirrors `ghidra.bitpatterns.info.ByteSequenceLengthFilter`.
///
/// Because the strings are hex-digit encoded (2 chars per byte), the `internal_index`
/// and `min_length` constructor arguments are in *bytes* and are doubled internally.
#[derive(Debug, Clone)]
pub struct ByteSequenceLengthFilter {
    /// Doubled internally. Positive → take first N chars; negative → take last N chars.
    internal_index: i32,
    /// Doubled internally. Minimum hex-string character length.
    min_length: usize,
}

impl ByteSequenceLengthFilter {
    /// Creates a new filter.
    ///
    /// `internal_index`: if positive, [`filter`](Self::filter) returns the first
    /// `internal_index` bytes (2 hex chars per byte); if negative, returns the last
    /// `|internal_index|` bytes.
    ///
    /// `min_length`: minimum number of bytes the input must represent.
    ///
    /// # Errors
    ///
    /// Returns an error string when `min_length` is negative or when
    /// `|internal_index| > min_length`.
    pub fn new(internal_index: i32, min_length: i32) -> Result<Self, String> {
        if min_length < 0 {
            return Err("minLength must be non-negative!".to_string());
        }
        if min_length < internal_index.abs() {
            return Err("minLength too small for this internalIndex!".to_string());
        }
        Ok(Self {
            internal_index: 2 * internal_index,
            min_length: (2 * min_length) as usize,
        })
    }

    /// Applies the filter to `base`.
    ///
    /// Returns `None` if `base` is `None` or if the string is shorter than the minimum
    /// length. Otherwise returns the configured prefix (positive index) or suffix
    /// (negative index).
    pub fn filter(&self, base: Option<&str>) -> Option<String> {
        let s = base?;
        if s.len() < self.min_length {
            return None;
        }
        if self.internal_index >= 0 {
            Some(s[..self.internal_index as usize].to_string())
        } else {
            let len = s.len();
            let start = (len as i32 + self.internal_index) as usize;
            Some(s[start..len].to_string())
        }
    }
}

impl fmt::Display for ByteSequenceLengthFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "internalIndex: {}\nminLength: {}\n", self.internal_index, self.min_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_input_returns_none() {
        let filter = ByteSequenceLengthFilter::new(1, 1).unwrap();
        assert_eq!(filter.filter(None), None);
    }

    #[test]
    fn test_min_length_too_small_for_index_errors() {
        assert!(ByteSequenceLengthFilter::new(3, 2).is_err());
    }

    #[test]
    fn test_negative_min_length_errors() {
        assert!(ByteSequenceLengthFilter::new(1, -1).is_err());
    }

    #[test]
    fn test_positive_index_too_short_returns_none() {
        let filter = ByteSequenceLengthFilter::new(1, 2).unwrap();
        // "a" has 1 char; min_length doubles to 4 hex chars — too short
        assert_eq!(filter.filter(Some("a")), None);
    }

    #[test]
    fn test_positive_index_returns_prefix() {
        let filter = ByteSequenceLengthFilter::new(1, 2).unwrap();
        // internal_index = 2; "abcd"[0..2] = "ab"
        assert_eq!(filter.filter(Some("abcd")), Some("ab".to_string()));
    }

    #[test]
    fn test_negative_index_returns_suffix() {
        let filter = ByteSequenceLengthFilter::new(-1, 2).unwrap();
        // internal_index = -2; "abcd"[2..4] = "cd"
        assert_eq!(filter.filter(Some("abcd")), Some("cd".to_string()));
    }

    #[test]
    fn test_zero_index_and_zero_min_length() {
        let filter = ByteSequenceLengthFilter::new(0, 0).unwrap();
        // internal_index = 0; "aa"[0..0] = ""
        assert_eq!(filter.filter(Some("aa")), Some(String::new()));
    }

    #[test]
    fn test_display_format() {
        let filter = ByteSequenceLengthFilter::new(1, 2).unwrap();
        let s = format!("{}", filter);
        assert!(s.contains("internalIndex: 2"));
        assert!(s.contains("minLength: 4"));
    }

    #[test]
    fn test_string_exactly_at_min_length_passes() {
        let filter = ByteSequenceLengthFilter::new(1, 2).unwrap();
        // min_length = 4 hex chars; "abcd" is exactly 4 chars
        assert_eq!(filter.filter(Some("abcd")), Some("ab".to_string()));
    }

    #[test]
    fn test_string_one_short_of_min_length_returns_none() {
        let filter = ByteSequenceLengthFilter::new(1, 2).unwrap();
        // min_length = 4 hex chars; "abc" is 3 chars
        assert_eq!(filter.filter(Some("abc")), None);
    }
}
