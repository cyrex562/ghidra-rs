/// Represents the type of identifier used to identify a source file, such as MD5 or SHA-1.
///
/// Each variant carries a fixed byte length for the corresponding identifier payload.
/// A byte length of `0` means there is no length restriction.
///
/// Declaration order matches the Java enum's ordinal order, so the derived [`Ord`] reproduces
/// `SourceFileIdType`'s Java `compareTo` (ordinal comparison).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceFileIdType {
    /// No identifier; identifier length is unconstrained.
    None,
    /// Unknown identifier type; identifier length is unconstrained.
    Unknown,
    /// 64-bit timestamp identifier (8 bytes).
    Timestamp64,
    /// MD5 digest (16 bytes).
    Md5,
    /// SHA-1 digest (20 bytes).
    Sha1,
    /// SHA-256 digest (32 bytes).
    Sha256,
    /// SHA-512 digest (64 bytes).
    Sha512,
}

impl SourceFileIdType {
    /// Maximum byte length of any identifier supported by this enum.
    pub const MAX_LENGTH: usize = 64;

    /// Returns the fixed byte length of the corresponding identifier.
    ///
    /// A value of `0` indicates no length restriction.
    pub fn byte_length(self) -> usize {
        match self {
            Self::None => 0,
            Self::Unknown => 0,
            Self::Timestamp64 => 8,
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Returns the serialization index for this identifier type.
    pub(crate) fn index(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Unknown => 1,
            Self::Timestamp64 => 2,
            Self::Md5 => 3,
            Self::Sha1 => 4,
            Self::Sha256 => 5,
            Self::Sha512 => 6,
        }
    }

    /// Returns the identifier type for the given serialization index, or `None` if unrecognized.
    pub(crate) fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::None),
            1 => Some(Self::Unknown),
            2 => Some(Self::Timestamp64),
            3 => Some(Self::Md5),
            4 => Some(Self::Sha1),
            5 => Some(Self::Sha256),
            6 => Some(Self::Sha512),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_length_matches_sha512() {
        assert_eq!(SourceFileIdType::MAX_LENGTH, 64);
        assert_eq!(SourceFileIdType::Sha512.byte_length(), SourceFileIdType::MAX_LENGTH);
    }

    #[test]
    fn byte_lengths_match_java_source() {
        assert_eq!(SourceFileIdType::None.byte_length(), 0);
        assert_eq!(SourceFileIdType::Unknown.byte_length(), 0);
        assert_eq!(SourceFileIdType::Timestamp64.byte_length(), 8);
        assert_eq!(SourceFileIdType::Md5.byte_length(), 16);
        assert_eq!(SourceFileIdType::Sha1.byte_length(), 20);
        assert_eq!(SourceFileIdType::Sha256.byte_length(), 32);
        assert_eq!(SourceFileIdType::Sha512.byte_length(), 64);
    }

    #[test]
    fn indices_match_java_source() {
        assert_eq!(SourceFileIdType::None.index(), 0);
        assert_eq!(SourceFileIdType::Unknown.index(), 1);
        assert_eq!(SourceFileIdType::Timestamp64.index(), 2);
        assert_eq!(SourceFileIdType::Md5.index(), 3);
        assert_eq!(SourceFileIdType::Sha1.index(), 4);
        assert_eq!(SourceFileIdType::Sha256.index(), 5);
        assert_eq!(SourceFileIdType::Sha512.index(), 6);
    }

    #[test]
    fn from_index_round_trips_all_variants() {
        let all = [
            SourceFileIdType::None,
            SourceFileIdType::Unknown,
            SourceFileIdType::Timestamp64,
            SourceFileIdType::Md5,
            SourceFileIdType::Sha1,
            SourceFileIdType::Sha256,
            SourceFileIdType::Sha512,
        ];
        for variant in all {
            assert_eq!(SourceFileIdType::from_index(variant.index()), Some(variant));
        }
    }

    #[test]
    fn from_index_returns_none_for_unknown_index() {
        assert_eq!(SourceFileIdType::from_index(7), None);
        assert_eq!(SourceFileIdType::from_index(255), None);
    }

    #[test]
    fn variants_are_distinct() {
        let all = [
            SourceFileIdType::None,
            SourceFileIdType::Unknown,
            SourceFileIdType::Timestamp64,
            SourceFileIdType::Md5,
            SourceFileIdType::Sha1,
            SourceFileIdType::Sha256,
            SourceFileIdType::Sha512,
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
    fn clone_preserves_variant() {
        for variant in [
            SourceFileIdType::None,
            SourceFileIdType::Unknown,
            SourceFileIdType::Timestamp64,
            SourceFileIdType::Md5,
            SourceFileIdType::Sha1,
            SourceFileIdType::Sha256,
            SourceFileIdType::Sha512,
        ] {
            assert_eq!(variant.clone(), variant);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", SourceFileIdType::None).contains("None"));
        assert!(format!("{:?}", SourceFileIdType::Unknown).contains("Unknown"));
        assert!(format!("{:?}", SourceFileIdType::Timestamp64).contains("Timestamp64"));
        assert!(format!("{:?}", SourceFileIdType::Md5).contains("Md5"));
        assert!(format!("{:?}", SourceFileIdType::Sha1).contains("Sha1"));
        assert!(format!("{:?}", SourceFileIdType::Sha256).contains("Sha256"));
        assert!(format!("{:?}", SourceFileIdType::Sha512).contains("Sha512"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SourceFileIdType::Md5);
        assert!(set.contains(&SourceFileIdType::Md5));
        assert!(!set.contains(&SourceFileIdType::Sha1));
    }
}
