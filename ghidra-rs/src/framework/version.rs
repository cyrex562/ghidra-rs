use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApplicationVersion {
    major: i32,
    minor: i32,
    patch: i32,
    tag: String,
}

#[derive(Error, Debug, PartialEq)]
pub enum VersionError {
    #[error("Version is empty")]
    Empty,
    #[error("Version '{0}' has {1} parts but 2 or 3 are required")]
    InvalidPartCount(String, usize),
    #[error("Failed to convert version to integer: '{0}' value '{1}'")]
    ParseIntError(String, String),
    #[error("{0} cannot be negative")]
    NegativeValue(String),
}

impl ApplicationVersion {
    pub fn new(major: i32, minor: i32, patch: i32, tag: String) -> Self {
        Self {
            major,
            minor,
            patch,
            tag,
        }
    }

    pub fn major(&self) -> i32 {
        self.major
    }
    pub fn minor(&self) -> i32 {
        self.minor
    }
    pub fn patch(&self) -> i32 {
        self.patch
    }
    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl FromStr for ApplicationVersion {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(VersionError::Empty);
        }

        let mut version_str = s;
        let mut tag = String::new();

        if let Some(dash_idx) = s.find('-') {
            tag = s[dash_idx + 1..].to_string();
            version_str = &s[..dash_idx];
        }

        let parts: Vec<&str> = version_str.split('.').collect();
        match parts.len() {
            2 => {
                let major = parse_part(parts[0], "major")?;
                let minor = parse_part(parts[1], "minor")?;
                Ok(Self::new(major, minor, 0, tag))
            }
            3 => {
                let major = parse_part(parts[0], "major")?;
                let minor = parse_part(parts[1], "minor")?;
                let patch = parse_part(parts[2], "patch")?;
                Ok(Self::new(major, minor, patch, tag))
            }
            _ => Err(VersionError::InvalidPartCount(
                version_str.to_string(),
                parts.len(),
            )),
        }
    }
}

fn parse_part(s: &str, name: &str) -> Result<i32, VersionError> {
    let val = s
        .parse::<i32>()
        .map_err(|_| VersionError::ParseIntError(name.to_string(), s.to_string()))?;
    if val < 0 {
        return Err(VersionError::NegativeValue(name.to_string()));
    }
    Ok(val)
}

impl fmt::Display for ApplicationVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if self.patch > 0 {
            write!(f, ".{}", self.patch)?;
        }
        if !self.tag.is_empty() {
            write!(f, "-{}", self.tag)?;
        }
        Ok(())
    }
}

impl PartialOrd for ApplicationVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApplicationVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(
            "7.4".parse::<ApplicationVersion>().unwrap(),
            ApplicationVersion::new(7, 4, 0, "".to_string())
        );
        assert_eq!(
            "7.4.1".parse::<ApplicationVersion>().unwrap(),
            ApplicationVersion::new(7, 4, 1, "".to_string())
        );
        assert_eq!(
            "7.4.1-BETA".parse::<ApplicationVersion>().unwrap(),
            ApplicationVersion::new(7, 4, 1, "BETA".to_string())
        );
    }

    #[test]
    fn test_comparison() {
        let v1 = "7.4".parse::<ApplicationVersion>().unwrap();
        let v2 = "7.4.1".parse::<ApplicationVersion>().unwrap();
        let v3 = "7.5".parse::<ApplicationVersion>().unwrap();
        let v4 = "7.4.1-BETA".parse::<ApplicationVersion>().unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
        // Tag is ignored in comparison as per original Java code
        assert_eq!(v2.cmp(&v4), Ordering::Equal);
    }
}
