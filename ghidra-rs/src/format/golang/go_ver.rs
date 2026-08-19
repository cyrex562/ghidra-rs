use std::cmp::Ordering;
use std::fmt;

use crate::framework::options::Options;
use crate::program::model::listing::{Program, PROGRAM_INFO};

/// Name of the program property that holds the original Go version string.
///
/// Stands in for `GoVer.GOLANG_VERSION_PROPERTY_NAME`.
pub const GOLANG_VERSION_PROPERTY_NAME: &str = "Golang go version";

/// Represents a Go version number (major.minor.patch), with some special sentinel values
/// for wildcarding.
///
/// Port of Ghidra's `GoVer` Java record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoVer {
    /// Currently just 1.
    pub major: i32,
    /// Second part of version number, ranges from 0..unknown upper limit.
    pub minor: i32,
    /// Third part of version number, ranges from 0..unknown upper limit per minor version.
    pub patch: i32,
}

impl GoVer {
    /// Sentinel value representing an invalid/unparsed version.
    pub const INVALID: GoVer = GoVer {
        major: 0,
        minor: 0,
        patch: 0,
    };

    /// Sentinel value representing a wildcard version that matches any version.
    pub const ANY: GoVer = GoVer {
        major: -1,
        minor: -1,
        patch: -1,
    };

    /// Creates a new [`GoVer`].
    pub fn new(major: i32, minor: i32, patch: i32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses a version string ("1.2.0") and returns a [`GoVer`] instance, or [`GoVer::INVALID`]
    /// if bad data.
    ///
    /// Missing patch numbers will be defaulted to 0.
    pub fn parse(s: &str) -> GoVer {
        Self::parse_with_missing_patch(s, 0)
    }

    /// Parses a version string ("1.2.0") and returns a [`GoVer`] instance, or [`GoVer::INVALID`]
    /// if bad data.
    ///
    /// Missing patch numbers will be replaced with the wildcard value.
    pub fn parse_wildcard_patch(s: &str) -> GoVer {
        Self::parse_with_missing_patch(s, -1)
    }

    fn parse_with_missing_patch(s: &str, missing_patch_value: i32) -> GoVer {
        // handle extra info at end of ver string: "1.22.8 X:rangefunc"
        let cut = s
            .find(|c: char| c != '.' && !c.is_ascii_digit())
            .unwrap_or(s.len());
        let trimmed = &s[..cut];
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() < 2 {
            return GoVer::INVALID;
        }
        let major = match parts[0].parse::<i32>() {
            Ok(v) => v,
            Err(_) => return GoVer::INVALID,
        };
        let minor = match parts[1].parse::<i32>() {
            Ok(v) => v,
            Err(_) => return GoVer::INVALID,
        };
        let patch = if parts.len() > 2 {
            match parts[2].parse::<i32>() {
                Ok(v) => v,
                Err(_) => return GoVer::INVALID,
            }
        }
        else {
            missing_patch_value
        };
        GoVer::new(major, minor, patch)
    }

    /// Parses a version string found in a Ghidra program info properties list.
    pub fn from_program_properties(program: &dyn Program) -> GoVer {
        let props = program.get_options(PROGRAM_INFO);
        let ver_str = props.get_string(GOLANG_VERSION_PROPERTY_NAME, "");
        Self::parse_with_missing_patch(&ver_str, 0)
    }

    /// Writes a version string to a Ghidra program info properties list.
    pub fn set_program_properties_with_original_version_string(props: &mut dyn Options, s: &str) {
        props.set_string(GOLANG_VERSION_PROPERTY_NAME, s);
    }

    /// Returns true if this is the [`GoVer::INVALID`] sentinel value.
    pub fn is_invalid(&self) -> bool {
        self.major == 0 && self.minor == 0
    }

    /// Returns true if this is the [`GoVer::ANY`] wildcard sentinel value.
    pub fn is_wildcard(&self) -> bool {
        self.major == -1 && self.minor == -1
    }

    /// Returns a copy of this version with the patch number decremented by one, floored at 0.
    pub fn prev_patch(&self) -> GoVer {
        GoVer::new(self.major, self.minor, if self.patch > 0 { self.patch - 1 } else { 0 })
    }

    /// Returns a copy of this version with the patch number replaced.
    pub fn with_patch(&self, new_patch_num: i32) -> GoVer {
        GoVer::new(self.major, self.minor, new_patch_num)
    }
}

impl PartialOrd for GoVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GoVer {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut result = self.major.cmp(&other.major);
        if result == Ordering::Equal {
            result = self.minor.cmp(&other.minor);
        }
        if result == Ordering::Equal {
            result = if self.patch == -1 || other.patch == -1 {
                Ordering::Equal
            }
            else {
                self.patch.cmp(&other.patch)
            };
        }
        result
    }
}

impl fmt::Display for GoVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.patch != -1 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
        else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_version() {
        assert_eq!(GoVer::parse("1.22.8"), GoVer::new(1, 22, 8));
    }

    #[test]
    fn parse_missing_patch_defaults_to_zero() {
        assert_eq!(GoVer::parse("1.22"), GoVer::new(1, 22, 0));
    }

    #[test]
    fn parse_wildcard_patch_missing_patch_is_wildcard() {
        assert_eq!(GoVer::parse_wildcard_patch("1.22"), GoVer::new(1, 22, -1));
    }

    #[test]
    fn parse_strips_trailing_junk() {
        assert_eq!(GoVer::parse("1.22.8 X:rangefunc"), GoVer::new(1, 22, 8));
    }

    #[test]
    fn parse_bad_data_is_invalid() {
        assert_eq!(GoVer::parse("nope"), GoVer::INVALID);
        assert_eq!(GoVer::parse("1"), GoVer::INVALID);
        assert_eq!(GoVer::parse(""), GoVer::INVALID);
    }

    #[test]
    fn is_invalid_checks_major_and_minor() {
        assert!(GoVer::INVALID.is_invalid());
        assert!(!GoVer::new(1, 0, 0).is_invalid());
    }

    #[test]
    fn is_wildcard_checks_major_and_minor() {
        assert!(GoVer::ANY.is_wildcard());
        assert!(!GoVer::new(1, 22, -1).is_wildcard());
    }

    #[test]
    fn prev_patch_decrements() {
        assert_eq!(GoVer::new(1, 22, 8).prev_patch(), GoVer::new(1, 22, 7));
    }

    #[test]
    fn prev_patch_floors_at_zero() {
        assert_eq!(GoVer::new(1, 22, 0).prev_patch(), GoVer::new(1, 22, 0));
    }

    #[test]
    fn with_patch_replaces_patch() {
        assert_eq!(GoVer::new(1, 22, 8).with_patch(3), GoVer::new(1, 22, 3));
    }

    #[test]
    fn compare_orders_by_major_then_minor_then_patch() {
        assert!(GoVer::new(1, 22, 0) < GoVer::new(1, 23, 0));
        assert!(GoVer::new(1, 22, 1) < GoVer::new(1, 22, 2));
        assert!(GoVer::new(2, 0, 0) > GoVer::new(1, 99, 99));
    }

    #[test]
    fn compare_treats_wildcard_patch_as_equal() {
        assert_eq!(
            GoVer::new(1, 22, -1).cmp(&GoVer::new(1, 22, 5)),
            Ordering::Equal
        );
    }

    #[test]
    fn display_includes_patch() {
        assert_eq!(GoVer::new(1, 22, 8).to_string(), "1.22.8");
    }

    #[test]
    fn display_omits_wildcard_patch() {
        assert_eq!(GoVer::new(1, 22, -1).to_string(), "1.22");
    }

    #[test]
    fn parse_ver_major_minor_patch() {
        assert_eq!(GoVer::parse("1.2").major, 1);
        assert_eq!(GoVer::parse("1.2").minor, 2);
        assert_eq!(GoVer::parse("1.2.0").patch, 0);
        assert_eq!(GoVer::parse("1.2.3").patch, 3);
    }
}
