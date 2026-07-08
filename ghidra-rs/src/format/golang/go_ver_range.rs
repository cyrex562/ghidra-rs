use std::io;

use super::go_ver::GoVer;

/// Represents a range of versions.
///
/// Port of Ghidra's `GoVerRange` Java record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoVerRange {
    /// First version contained in the range.
    pub start: GoVer,
    /// Last version contained in the range.
    pub end: GoVer,
}

impl GoVerRange {
    /// Sentinel value representing a range that matches any version.
    pub const ALL: GoVerRange = GoVerRange {
        start: GoVer::ANY,
        end: GoVer::ANY,
    };

    /// Sentinel value representing an empty range.
    pub const EMPTY: GoVerRange = GoVerRange {
        start: GoVer::INVALID,
        end: GoVer::INVALID,
    };

    /// Creates a new [`GoVerRange`].
    pub fn new(start: GoVer, end: GoVer) -> Self {
        Self { start, end }
    }

    /// Parses a version range string (eg. "1.2-1.5", or "-1.5", or "1.2+").
    ///
    /// Version ranges can be specified with leading or trailing wildcards
    /// (eg. "-end_ver", or "start_ver-", or "start_ver+").
    ///
    /// Returns a [`GoVerRange`] instance, or [`GoVerRange::EMPTY`] if the string is bad.
    pub fn parse(s: &str) -> GoVerRange {
        // "1.2-1.5" or "1.2+" or "-1.2"
        let ver_nums: Vec<&str> = s.split(['+', '-']).collect();
        let start_str = ver_nums[0];

        let start = if start_str.trim().is_empty() {
            GoVer::ANY
        }
        else {
            GoVer::parse_wildcard_patch(start_str)
        };
        let end = if ver_nums.len() <= 1 {
            // no separator found: single version string, end equals start
            start
        }
        else if ver_nums[1].trim().is_empty() {
            GoVer::ANY
        }
        else {
            GoVer::parse_wildcard_patch(ver_nums[1])
        };

        if (start.is_wildcard() && end.is_wildcard()) || start.is_invalid() || end.is_invalid() {
            GoVerRange::EMPTY
        }
        else {
            GoVerRange::new(start, end)
        }
    }

    /// Returns true if this range is empty.
    pub fn is_empty(&self) -> bool {
        self.start.is_invalid() || self.end.is_invalid()
    }

    /// Returns true if this range has wildcard start or end.
    pub fn has_wildcard(&self) -> bool {
        self.start.is_wildcard() || self.end.is_wildcard()
    }

    /// Returns true if this range contains the specified version.
    pub fn contains(&self, ver: GoVer) -> bool {
        !self.start.is_invalid()
            && !self.end.is_invalid()
            && (self.start.is_wildcard() || self.start.cmp(&ver) != std::cmp::Ordering::Greater)
            && (self.end.is_wildcard() || self.end.cmp(&ver) != std::cmp::Ordering::Less)
    }

    /// Returns a list of minor [`GoVer`]s between the start and end of this range (inclusive).
    ///
    /// NOTE: does not work if the major version is different between start and end.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if start and end are not the same major version, or if the
    /// range is empty or has a wildcard boundary.
    pub fn as_list(&self) -> io::Result<Vec<GoVer>> {
        if self.start.major != self.end.major || self.is_empty() || self.has_wildcard() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unable to make version list, invalid or wildcard or spans versions",
            ));
        }
        let mut result = Vec::new();
        for minor in self.start.minor..=self.end.minor {
            result.push(GoVer::new(1, minor, 0));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_range() {
        let range = GoVerRange::parse("1.2-1.5");
        assert_eq!(range.start, GoVer::new(1, 2, -1));
        assert_eq!(range.end, GoVer::new(1, 5, -1));
    }

    #[test]
    fn parse_leading_wildcard() {
        let range = GoVerRange::parse("-1.5");
        assert_eq!(range.start, GoVer::ANY);
        assert_eq!(range.end, GoVer::new(1, 5, -1));
    }

    #[test]
    fn parse_trailing_wildcard() {
        let range = GoVerRange::parse("1.2+");
        assert_eq!(range.start, GoVer::new(1, 2, -1));
        assert_eq!(range.end, GoVer::ANY);
    }

    #[test]
    fn parse_single_version() {
        let range = GoVerRange::parse("1.2");
        assert_eq!(range.start, GoVer::new(1, 2, -1));
        assert_eq!(range.end, GoVer::new(1, 2, -1));
    }

    #[test]
    fn parse_all_wildcard_is_empty() {
        assert_eq!(GoVerRange::parse("-"), GoVerRange::EMPTY);
        assert_eq!(GoVerRange::parse("+"), GoVerRange::EMPTY);
    }

    #[test]
    fn parse_bad_data_is_empty() {
        assert_eq!(GoVerRange::parse("nope-1.5"), GoVerRange::EMPTY);
        assert_eq!(GoVerRange::parse("1.2-nope"), GoVerRange::EMPTY);
    }

    #[test]
    fn is_empty_checks_start_and_end() {
        assert!(GoVerRange::EMPTY.is_empty());
        assert!(!GoVerRange::ALL.is_empty());
    }

    #[test]
    fn has_wildcard_checks_start_and_end() {
        assert!(GoVerRange::ALL.has_wildcard());
        assert!(!GoVerRange::new(GoVer::new(1, 2, 0), GoVer::new(1, 5, 0)).has_wildcard());
    }

    #[test]
    fn contains_checks_bounds_inclusive() {
        let range = GoVerRange::new(GoVer::new(1, 2, 0), GoVer::new(1, 5, 0));
        assert!(range.contains(GoVer::new(1, 2, 0)));
        assert!(range.contains(GoVer::new(1, 3, 5)));
        assert!(range.contains(GoVer::new(1, 5, 0)));
        assert!(!range.contains(GoVer::new(1, 1, 9)));
        assert!(!range.contains(GoVer::new(1, 6, 0)));
    }

    #[test]
    fn contains_all_matches_anything_valid() {
        assert!(GoVerRange::ALL.contains(GoVer::new(1, 2, 3)));
    }

    #[test]
    fn contains_empty_matches_nothing() {
        assert!(!GoVerRange::EMPTY.contains(GoVer::new(1, 2, 3)));
    }

    #[test]
    fn as_list_returns_inclusive_minor_range() {
        let range = GoVerRange::new(GoVer::new(1, 2, 0), GoVer::new(1, 5, 0));
        let list = range.as_list().unwrap();
        assert_eq!(
            list,
            vec![
                GoVer::new(1, 2, 0),
                GoVer::new(1, 3, 0),
                GoVer::new(1, 4, 0),
                GoVer::new(1, 5, 0),
            ]
        );
    }

    #[test]
    fn as_list_errors_on_different_major() {
        let range = GoVerRange::new(GoVer::new(1, 2, 0), GoVer::new(2, 5, 0));
        assert!(range.as_list().is_err());
    }

    #[test]
    fn as_list_errors_on_empty() {
        assert!(GoVerRange::EMPTY.as_list().is_err());
    }

    #[test]
    fn as_list_errors_on_wildcard() {
        assert!(GoVerRange::ALL.as_list().is_err());
    }
}
