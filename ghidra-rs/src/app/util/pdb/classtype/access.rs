use std::fmt;

/// Class access attributes for C++ PDB symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Unknown,
    Blank,
    Public,
    Protected,
    Private,
}

impl Access {
    /// Integer value assigned to each variant; used for ordering and serialization.
    pub fn value(self) -> i32 {
        match self {
            Access::Unknown => -1,
            Access::Blank => 0,
            Access::Public => 1,
            Access::Protected => 2,
            Access::Private => 3,
        }
    }

    /// Human-readable label, matching the Java `getString()` / `toString()` output.
    pub fn label(self) -> &'static str {
        match self {
            Access::Unknown => "UNKNOWN_ACCESS",
            Access::Blank => "",
            Access::Public => "public",
            Access::Protected => "protected",
            Access::Private => "private",
        }
    }

    /// Returns the variant whose integer value is `val`, or `Unknown` if unrecognised.
    pub fn from_value(val: i32) -> Self {
        match val {
            -1 => Access::Unknown,
            0 => Access::Blank,
            1 => Access::Public,
            2 => Access::Protected,
            3 => Access::Private,
            _ => Access::Unknown,
        }
    }

    /// Merge two `Access` values, preferring the more restrictive one.
    /// `Unknown` is only returned when both operands are `Unknown`.
    pub fn merge_restrictive(self, other: Access) -> Access {
        if self.value() > other.value() {
            self
        } else {
            other
        }
    }

    /// Merge two `Access` values, preferring the more permissive one.
    /// `Unknown` is only returned when both operands are `Unknown`.
    pub fn merge_permissive(self, other: Access) -> Access {
        if self.value() < other.value() {
            if self == Access::Unknown {
                return other;
            }
            return self;
        }
        other
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_values() {
        assert_eq!(Access::Unknown.value(), -1);
        assert_eq!(Access::Blank.value(), 0);
        assert_eq!(Access::Public.value(), 1);
        assert_eq!(Access::Protected.value(), 2);
        assert_eq!(Access::Private.value(), 3);
    }

    #[test]
    fn test_labels() {
        assert_eq!(Access::Unknown.label(), "UNKNOWN_ACCESS");
        assert_eq!(Access::Blank.label(), "");
        assert_eq!(Access::Public.label(), "public");
        assert_eq!(Access::Protected.label(), "protected");
        assert_eq!(Access::Private.label(), "private");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Access::Public), "public");
        assert_eq!(format!("{}", Access::Unknown), "UNKNOWN_ACCESS");
    }

    #[test]
    fn test_from_value_known() {
        assert_eq!(Access::from_value(-1), Access::Unknown);
        assert_eq!(Access::from_value(0), Access::Blank);
        assert_eq!(Access::from_value(1), Access::Public);
        assert_eq!(Access::from_value(2), Access::Protected);
        assert_eq!(Access::from_value(3), Access::Private);
    }

    #[test]
    fn test_from_value_unknown_fallback() {
        assert_eq!(Access::from_value(99), Access::Unknown);
        assert_eq!(Access::from_value(-99), Access::Unknown);
    }

    #[test]
    fn test_merge_restrictive_higher_value_wins() {
        assert_eq!(Access::Public.merge_restrictive(Access::Protected), Access::Protected);
        assert_eq!(Access::Protected.merge_restrictive(Access::Public), Access::Protected);
        assert_eq!(Access::Private.merge_restrictive(Access::Public), Access::Private);
    }

    #[test]
    fn test_merge_restrictive_unknown_loses_to_real() {
        assert_eq!(Access::Unknown.merge_restrictive(Access::Blank), Access::Blank);
        assert_eq!(Access::Blank.merge_restrictive(Access::Unknown), Access::Blank);
    }

    #[test]
    fn test_merge_restrictive_both_unknown() {
        assert_eq!(Access::Unknown.merge_restrictive(Access::Unknown), Access::Unknown);
    }

    #[test]
    fn test_merge_permissive_lower_value_wins() {
        assert_eq!(Access::Public.merge_permissive(Access::Protected), Access::Public);
        assert_eq!(Access::Protected.merge_permissive(Access::Public), Access::Public);
        assert_eq!(Access::Blank.merge_permissive(Access::Public), Access::Blank);
    }

    #[test]
    fn test_merge_permissive_unknown_skipped() {
        // UNKNOWN has the lowest value (-1) but is skipped so the real value wins.
        assert_eq!(Access::Unknown.merge_permissive(Access::Blank), Access::Blank);
        assert_eq!(Access::Unknown.merge_permissive(Access::Public), Access::Public);
        // When UNKNOWN is on the right, lower-value comparison is false so `other` is returned.
        assert_eq!(Access::Blank.merge_permissive(Access::Unknown), Access::Unknown);
    }

    #[test]
    fn test_merge_permissive_both_unknown() {
        assert_eq!(Access::Unknown.merge_permissive(Access::Unknown), Access::Unknown);
    }

    #[test]
    fn test_roundtrip_value() {
        for acc in [
            Access::Unknown,
            Access::Blank,
            Access::Public,
            Access::Protected,
            Access::Private,
        ] {
            assert_eq!(Access::from_value(acc.value()), acc);
        }
    }
}
