use std::fmt;

/// Controls string termination and layout.
///
/// Mirrors `StringLayoutEnum` from the Java source.
///
/// - [`StringLayoutEnum::FixedLen`] — fixed length, trailing nulls trimmed
/// - [`StringLayoutEnum::CharSeq`] — fixed length character sequence, all nulls retained
/// - [`StringLayoutEnum::NullTerminatedUnbounded`] — null-terminated, ignores container length
/// - [`StringLayoutEnum::NullTerminatedBounded`] — null-terminated, bounded by container length
/// - [`StringLayoutEnum::Pascal255`] — pascal string with 1-byte length field (max 255 elements)
/// - [`StringLayoutEnum::Pascal64k`] — pascal string with 2-byte length field (max 64k elements)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringLayoutEnum {
    /// Fixed length string, trailing nulls trimmed, interior nulls retained.
    FixedLen,
    /// Fixed length sequence of characters, all nulls retained.
    CharSeq,
    /// Null terminated string that ignores its container's length when searching for the
    /// terminating null character.
    NullTerminatedUnbounded,
    /// Null-terminated string that is limited to its container's length.
    NullTerminatedBounded,
    /// Pascal string, using 1 byte for length field, max 255 char elements.
    Pascal255,
    /// Pascal string, using 2 bytes for length field, max 64k char elements.
    Pascal64k,
}

impl fmt::Display for StringLayoutEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            StringLayoutEnum::FixedLen => "fixed length",
            StringLayoutEnum::CharSeq => "char sequence",
            StringLayoutEnum::NullTerminatedUnbounded => "null-terminated & unbounded",
            StringLayoutEnum::NullTerminatedBounded => "null-terminated & bounded",
            StringLayoutEnum::Pascal255 => "pascal255",
            StringLayoutEnum::Pascal64k => "pascal64k",
        };
        f.write_str(s)
    }
}

impl StringLayoutEnum {
    /// Returns `true` if this layout is one of the pascal types.
    pub fn is_pascal(self) -> bool {
        matches!(self, Self::Pascal255 | Self::Pascal64k)
    }

    /// Returns `true` if this layout is one of the null terminated types.
    pub fn is_null_terminated(self) -> bool {
        matches!(self, Self::NullTerminatedUnbounded | Self::NullTerminatedBounded)
    }

    /// Returns `true` if trailing null characters should be trimmed for this layout.
    pub fn should_trim_trailing_nulls(self) -> bool {
        matches!(
            self,
            Self::NullTerminatedUnbounded | Self::NullTerminatedBounded | Self::FixedLen
        )
    }

    /// Returns `true` if this layout is one of the fixed-size types.
    pub fn is_fixed_len(self) -> bool {
        matches!(self, Self::FixedLen | Self::CharSeq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_strings_match_java() {
        assert_eq!(StringLayoutEnum::FixedLen.to_string(), "fixed length");
        assert_eq!(StringLayoutEnum::CharSeq.to_string(), "char sequence");
        assert_eq!(
            StringLayoutEnum::NullTerminatedUnbounded.to_string(),
            "null-terminated & unbounded"
        );
        assert_eq!(
            StringLayoutEnum::NullTerminatedBounded.to_string(),
            "null-terminated & bounded"
        );
        assert_eq!(StringLayoutEnum::Pascal255.to_string(), "pascal255");
        assert_eq!(StringLayoutEnum::Pascal64k.to_string(), "pascal64k");
    }

    #[test]
    fn is_pascal_only_for_pascal_variants() {
        assert!(StringLayoutEnum::Pascal255.is_pascal());
        assert!(StringLayoutEnum::Pascal64k.is_pascal());
        assert!(!StringLayoutEnum::FixedLen.is_pascal());
        assert!(!StringLayoutEnum::CharSeq.is_pascal());
        assert!(!StringLayoutEnum::NullTerminatedUnbounded.is_pascal());
        assert!(!StringLayoutEnum::NullTerminatedBounded.is_pascal());
    }

    #[test]
    fn is_null_terminated_only_for_null_terminated_variants() {
        assert!(StringLayoutEnum::NullTerminatedUnbounded.is_null_terminated());
        assert!(StringLayoutEnum::NullTerminatedBounded.is_null_terminated());
        assert!(!StringLayoutEnum::FixedLen.is_null_terminated());
        assert!(!StringLayoutEnum::CharSeq.is_null_terminated());
        assert!(!StringLayoutEnum::Pascal255.is_null_terminated());
        assert!(!StringLayoutEnum::Pascal64k.is_null_terminated());
    }

    #[test]
    fn should_trim_trailing_nulls_for_correct_variants() {
        assert!(StringLayoutEnum::NullTerminatedUnbounded.should_trim_trailing_nulls());
        assert!(StringLayoutEnum::NullTerminatedBounded.should_trim_trailing_nulls());
        assert!(StringLayoutEnum::FixedLen.should_trim_trailing_nulls());
        assert!(!StringLayoutEnum::CharSeq.should_trim_trailing_nulls());
        assert!(!StringLayoutEnum::Pascal255.should_trim_trailing_nulls());
        assert!(!StringLayoutEnum::Pascal64k.should_trim_trailing_nulls());
    }

    #[test]
    fn is_fixed_len_for_fixed_size_variants() {
        assert!(StringLayoutEnum::FixedLen.is_fixed_len());
        assert!(StringLayoutEnum::CharSeq.is_fixed_len());
        assert!(!StringLayoutEnum::NullTerminatedUnbounded.is_fixed_len());
        assert!(!StringLayoutEnum::NullTerminatedBounded.is_fixed_len());
        assert!(!StringLayoutEnum::Pascal255.is_fixed_len());
        assert!(!StringLayoutEnum::Pascal64k.is_fixed_len());
    }

    #[test]
    fn variants_are_distinct() {
        let all = [
            StringLayoutEnum::FixedLen,
            StringLayoutEnum::CharSeq,
            StringLayoutEnum::NullTerminatedUnbounded,
            StringLayoutEnum::NullTerminatedBounded,
            StringLayoutEnum::Pascal255,
            StringLayoutEnum::Pascal64k,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy_preserve_variant() {
        let v = StringLayoutEnum::Pascal255;
        let c = v;
        assert_eq!(v, c);
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(StringLayoutEnum::Pascal255);
        assert!(set.contains(&StringLayoutEnum::Pascal255));
        assert!(!set.contains(&StringLayoutEnum::Pascal64k));
    }
}
