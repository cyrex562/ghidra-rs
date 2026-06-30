use std::fmt;

/// Byte order of a processor or data element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    /// Parse an endianness string (case-insensitive).
    ///
    /// Accepts `"big"` / `"BE"` for [`Endian::Big`] and `"little"` / `"LE"` for
    /// [`Endian::Little`].  Returns `None` for any other input, including `None`-like
    /// callers that pass an empty string.
    pub fn to_endian(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "big" | "be" => Some(Self::Big),
            "little" | "le" => Some(Self::Little),
            _ => None,
        }
    }

    /// Returns `true` when this is big-endian.
    pub fn is_big_endian(self) -> bool {
        matches!(self, Self::Big)
    }

    /// Returns the abbreviated endianness tag (`"BE"` or `"LE"`).
    pub fn to_short_string(self) -> &'static str {
        match self {
            Self::Big => "BE",
            Self::Little => "LE",
        }
    }

    /// Returns the display name with the first letter capitalised (`"Big"` or `"Little"`).
    pub fn get_display_name(self) -> &'static str {
        match self {
            Self::Big => "Big",
            Self::Little => "Little",
        }
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Big => "big",
            Self::Little => "little",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_big() {
        assert_eq!(Endian::Big.to_string(), "big");
    }

    #[test]
    fn display_little() {
        assert_eq!(Endian::Little.to_string(), "little");
    }

    #[test]
    fn to_short_string_variants() {
        assert_eq!(Endian::Big.to_short_string(), "BE");
        assert_eq!(Endian::Little.to_short_string(), "LE");
    }

    #[test]
    fn get_display_name_variants() {
        assert_eq!(Endian::Big.get_display_name(), "Big");
        assert_eq!(Endian::Little.get_display_name(), "Little");
    }

    #[test]
    fn is_big_endian() {
        assert!(Endian::Big.is_big_endian());
        assert!(!Endian::Little.is_big_endian());
    }

    #[test]
    fn to_endian_long_names() {
        assert_eq!(Endian::to_endian("big"), Some(Endian::Big));
        assert_eq!(Endian::to_endian("little"), Some(Endian::Little));
    }

    #[test]
    fn to_endian_short_names() {
        assert_eq!(Endian::to_endian("BE"), Some(Endian::Big));
        assert_eq!(Endian::to_endian("LE"), Some(Endian::Little));
    }

    #[test]
    fn to_endian_case_insensitive() {
        assert_eq!(Endian::to_endian("BIG"), Some(Endian::Big));
        assert_eq!(Endian::to_endian("Big"), Some(Endian::Big));
        assert_eq!(Endian::to_endian("be"), Some(Endian::Big));
        assert_eq!(Endian::to_endian("LITTLE"), Some(Endian::Little));
        assert_eq!(Endian::to_endian("Le"), Some(Endian::Little));
    }

    #[test]
    fn to_endian_unknown_returns_none() {
        assert_eq!(Endian::to_endian("unknown"), None);
        assert_eq!(Endian::to_endian(""), None);
        assert_eq!(Endian::to_endian("b"), None);
    }

    #[test]
    fn clone_and_copy() {
        let e = Endian::Big;
        assert_eq!(e, e);
        let c = e;
        assert_eq!(c, Endian::Big);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Endian::Big);
        assert!(set.contains(&Endian::Big));
        assert!(!set.contains(&Endian::Little));
    }
}
