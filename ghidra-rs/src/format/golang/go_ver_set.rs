use std::io;

use super::go_ver::GoVer;
use super::go_ver_range::GoVerRange;

/// Represents a set of version numbers.
///
/// Port of Ghidra's `GoVerSet` Java record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoVerSet {
    /// List of ranges that define the set.
    pub ranges: Vec<GoVerRange>,
}

impl GoVerSet {
    /// Sentinel value representing a set that matches any version.
    pub fn all() -> GoVerSet {
        GoVerSet {
            ranges: vec![GoVerRange::ALL],
        }
    }

    /// Creates a new [`GoVerSet`].
    pub fn new(ranges: Vec<GoVerRange>) -> Self {
        Self { ranges }
    }

    /// Parses a version list string (eg. "all", or "1.0-1.5,1.8-1.9,1.11-") and returns
    /// a [`GoVerSet`] containing the found versions.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the string had invalid start or end wildcard ranges.
    pub fn parse(s: &str) -> io::Result<GoVerSet> {
        if s.trim().eq_ignore_ascii_case("all") {
            return Ok(GoVerSet::all());
        }

        let mut result: Vec<GoVerRange> = Vec::new();
        for ver_str in s.split(',') {
            let ver_str = ver_str.trim();
            if ver_str.is_empty() {
                continue;
            }
            let range = GoVerRange::parse(ver_str);
            if range.is_empty() {
                continue;
            }
            if range.start.is_wildcard() && !result.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid start wildcard position: [{}]", s),
                ));
            }
            let prev = result.last();
            if let Some(prev) = prev {
                if prev.end.is_wildcard() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid end wildcard position: [{}]", s),
                    ));
                }
            }
            result.push(range);
        }
        Ok(GoVerSet::new(result))
    }

    /// Returns true if the set contains no versions.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns true if the specified version is present in the set.
    pub fn contains(&self, ver: GoVer) -> bool {
        self.ranges.iter().any(|range| range.contains(ver))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_is_all_sentinel() {
        assert_eq!(GoVerSet::parse("all").unwrap(), GoVerSet::all());
        assert_eq!(GoVerSet::parse("ALL").unwrap(), GoVerSet::all());
    }

    #[test]
    fn parse_single_range() {
        let set = GoVerSet::parse("1.2-1.5").unwrap();
        assert_eq!(
            set,
            GoVerSet::new(vec![GoVerRange::new(
                GoVer::new(1, 2, -1),
                GoVer::new(1, 5, -1)
            )])
        );
    }

    #[test]
    fn parse_multiple_ranges() {
        let set = GoVerSet::parse("1.0-1.5,1.8-1.9,1.11-").unwrap();
        assert_eq!(
            set,
            GoVerSet::new(vec![
                GoVerRange::new(GoVer::new(1, 0, -1), GoVer::new(1, 5, -1)),
                GoVerRange::new(GoVer::new(1, 8, -1), GoVer::new(1, 9, -1)),
                GoVerRange::new(GoVer::new(1, 11, -1), GoVer::ANY),
            ])
        );
    }

    #[test]
    fn parse_skips_empty_entries() {
        let set = GoVerSet::parse("1.2-1.5,,").unwrap();
        assert_eq!(set.ranges.len(), 1);
    }

    #[test]
    fn parse_invalid_start_wildcard_position_errors() {
        assert!(GoVerSet::parse("1.2-1.5,-1.8").is_err());
    }

    #[test]
    fn parse_invalid_end_wildcard_position_errors() {
        assert!(GoVerSet::parse("1.2-,1.8-1.9").is_err());
    }

    #[test]
    fn is_empty_checks_ranges() {
        assert!(GoVerSet::new(Vec::new()).is_empty());
        assert!(!GoVerSet::all().is_empty());
    }

    #[test]
    fn contains_checks_all_ranges() {
        let set = GoVerSet::parse("1.0-1.5,1.8-1.9").unwrap();
        assert!(set.contains(GoVer::new(1, 2, 0)));
        assert!(set.contains(GoVer::new(1, 8, 3)));
        assert!(!set.contains(GoVer::new(1, 6, 0)));
    }

    #[test]
    fn contains_all_matches_anything_valid() {
        assert!(GoVerSet::all().contains(GoVer::new(1, 22, 8)));
    }

    #[test]
    fn parse_all_contains_arbitrary_versions() {
        let all = GoVerSet::parse("all").unwrap();
        assert!(all.contains(GoVer::parse("1.1")));
        assert!(all.contains(GoVer::parse("99.44")));
    }

    #[test]
    fn parse_empty_string_is_empty() {
        assert!(GoVerSet::parse("").unwrap().is_empty());
    }

    #[test]
    fn parse_dash_only_is_empty() {
        assert!(GoVerSet::parse("-").unwrap().is_empty());
    }

    #[test]
    fn parse_multirange_respects_patch_boundaries() {
        let vers = GoVerSet::parse("1.2-1.22.3,1.55,1.77.0").unwrap();

        assert!(!vers.contains(GoVer::parse("1.1")));

        assert!(vers.contains(GoVer::parse("1.2")));
        assert!(vers.contains(GoVer::parse("1.22.3")));
        assert!(!vers.contains(GoVer::parse("1.22.4")));

        assert!(vers.contains(GoVer::parse("1.55.0")));
        assert!(vers.contains(GoVer::parse("1.55.1")));

        assert!(vers.contains(GoVer::parse("1.77.0")));
        assert!(!vers.contains(GoVer::parse("1.77.1")));
    }

    #[test]
    fn parse_wildcard_ranges_variants() {
        let mut vers = GoVerSet::parse("1.2-").unwrap();
        assert!(!vers.contains(GoVer::parse("1.1")));
        assert!(vers.contains(GoVer::parse("1.2")));
        assert!(vers.contains(GoVer::parse("1.99")));
        assert!(vers.contains(GoVer::parse("99.99")));

        vers = GoVerSet::parse("-1.2,1.5,1.9-").unwrap();
        assert!(vers.contains(GoVer::parse("1.1")));
        assert!(vers.contains(GoVer::parse("1.2")));
        assert!(!vers.contains(GoVer::parse("1.3")));
        assert!(vers.contains(GoVer::parse("1.5.1")));
        assert!(!vers.contains(GoVer::parse("1.8")));
        assert!(vers.contains(GoVer::parse("1.9")));
        assert!(vers.contains(GoVer::parse("99.99")));

        vers = GoVerSet::parse("-1.2.1").unwrap();
        assert!(vers.contains(GoVer::parse("1.1")));
        assert!(vers.contains(GoVer::parse("1.2.0")));
        assert!(vers.contains(GoVer::parse("1.2.1")));
        assert!(!vers.contains(GoVer::parse("1.2.3")));
        assert!(vers.contains(GoVer::parse("1.2")));
    }

    #[test]
    fn parse_wildcard_ranges_bad_leading_errors() {
        assert!(GoVerSet::parse("1.2-1.3,-1.5").is_err());
    }

    #[test]
    fn parse_wildcard_ranges_bad_trailing_errors() {
        assert!(GoVerSet::parse("1.2-1.3,1.5-,1.8").is_err());
    }
}
