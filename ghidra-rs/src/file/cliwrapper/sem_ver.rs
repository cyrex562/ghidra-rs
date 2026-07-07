use std::cmp::Ordering;
use std::fmt;

/// A semantic version number of the form `X.Y.Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemVer {
    pub major: i32,
    pub minor: i32,
    pub patch: i32,
}

impl SemVer {
    /// The sentinel "invalid" version (0.0.0).
    pub const INVALID: SemVer = SemVer { major: 0, minor: 0, patch: 0 };

    /// The sentinel "any / wildcard" version (-1.-1.-1).
    pub const ANY: SemVer = SemVer { major: -1, minor: -1, patch: -1 };

    pub fn new(major: i32, minor: i32, patch: i32) -> Self {
        Self { major, minor, patch }
    }

    /// Parses `"X.Y"` or `"X.Y.Z"` (ignoring trailing non-numeric text).
    /// Missing patch defaults to `0`. Returns [`SemVer::INVALID`] on bad input.
    pub fn parse(s: &str) -> Self {
        Self::parse_internal(s, 0)
    }

    /// Like [`parse`] but a missing patch component is replaced with `-1` (wildcard).
    pub fn parse_wildcard_patch(s: &str) -> Self {
        Self::parse_internal(s, -1)
    }

    fn parse_internal(s: &str, missing_patch: i32) -> Self {
        // Strip everything after the first non-`.`/non-digit character.
        let trimmed: String = s
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();

        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() < 2 {
            return Self::INVALID;
        }

        let parse_part = |p: &str| -> Option<i32> { p.parse::<i32>().ok() };

        match (parse_part(parts[0]), parse_part(parts[1])) {
            (Some(major), Some(minor)) => {
                let patch = if parts.len() > 2 {
                    match parse_part(parts[2]) {
                        Some(p) => p,
                        None => return Self::INVALID,
                    }
                } else {
                    missing_patch
                };
                Self { major, minor, patch }
            }
            _ => Self::INVALID,
        }
    }

    pub fn is_invalid(self) -> bool {
        self.major == 0 && self.minor == 0
    }

    pub fn is_wildcard(self) -> bool {
        self.major == -1 && self.minor == -1
    }

    /// Returns a new `SemVer` with patch decremented by 1 (minimum 0).
    pub fn prev_patch(self) -> Self {
        Self::new(self.major, self.minor, if self.patch > 0 { self.patch - 1 } else { 0 })
    }

    /// Returns a new `SemVer` with the patch component replaced.
    pub fn with_patch(self, new_patch: i32) -> Self {
        Self::new(self.major, self.minor, new_patch)
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        let r = self.major.cmp(&other.major);
        if r != Ordering::Equal {
            return r;
        }
        let r = self.minor.cmp(&other.minor);
        if r != Ordering::Equal {
            return r;
        }
        // Either wildcard patch → treat as equal
        if self.patch == -1 || other.patch == -1 {
            Ordering::Equal
        } else {
            self.patch.cmp(&other.patch)
        }
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.patch != -1 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_three_part() {
        let v = SemVer::parse("1.2.3");
        assert_eq!(v, SemVer::new(1, 2, 3));
    }

    #[test]
    fn parse_two_part_defaults_patch_zero() {
        let v = SemVer::parse("1.22");
        assert_eq!(v, SemVer::new(1, 22, 0));
    }

    #[test]
    fn parse_wildcard_patch_missing() {
        let v = SemVer::parse_wildcard_patch("1.22");
        assert_eq!(v, SemVer::new(1, 22, -1));
    }

    #[test]
    fn parse_strips_trailing_text() {
        let v = SemVer::parse("1.22.8 blah extra");
        assert_eq!(v, SemVer::new(1, 22, 8));
    }

    #[test]
    fn parse_empty_returns_invalid() {
        assert_eq!(SemVer::parse(""), SemVer::INVALID);
    }

    #[test]
    fn parse_non_numeric_returns_invalid() {
        assert_eq!(SemVer::parse("abc"), SemVer::INVALID);
    }

    #[test]
    fn parse_single_number_returns_invalid() {
        assert_eq!(SemVer::parse("1"), SemVer::INVALID);
    }

    #[test]
    fn is_invalid() {
        assert!(SemVer::INVALID.is_invalid());
        assert!(!SemVer::new(1, 0, 0).is_invalid());
    }

    #[test]
    fn is_wildcard() {
        assert!(SemVer::ANY.is_wildcard());
        assert!(!SemVer::new(0, 0, 0).is_wildcard());
    }

    #[test]
    fn prev_patch_decrements() {
        assert_eq!(SemVer::new(1, 2, 5).prev_patch(), SemVer::new(1, 2, 4));
    }

    #[test]
    fn prev_patch_clamps_at_zero() {
        assert_eq!(SemVer::new(1, 2, 0).prev_patch(), SemVer::new(1, 2, 0));
    }

    #[test]
    fn with_patch_replaces() {
        assert_eq!(SemVer::new(1, 2, 3).with_patch(9), SemVer::new(1, 2, 9));
    }

    #[test]
    fn ordering_major_wins() {
        assert!(SemVer::new(2, 0, 0) > SemVer::new(1, 9, 9));
    }

    #[test]
    fn ordering_minor_second() {
        assert!(SemVer::new(1, 3, 0) > SemVer::new(1, 2, 9));
    }

    #[test]
    fn ordering_patch_third() {
        assert!(SemVer::new(1, 2, 3) < SemVer::new(1, 2, 4));
    }

    #[test]
    fn wildcard_patch_compares_equal() {
        let a = SemVer::new(1, 2, -1);
        let b = SemVer::new(1, 2, 5);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn display_three_part() {
        assert_eq!(SemVer::new(1, 2, 3).to_string(), "1.2.3");
    }

    #[test]
    fn display_wildcard_patch_omits_patch() {
        assert_eq!(SemVer::new(1, 2, -1).to_string(), "1.2");
    }
}
