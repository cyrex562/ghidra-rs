use std::io;
use std::str::FromStr;

/// Key=value element of Go build settings.
///
/// Mirrors Ghidra's `GoBuildSettings` Java record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBuildSettings {
    /// String name of the property.
    pub key: String,
    /// String value of the property.
    pub value: String,
}

impl GoBuildSettings {
    /// Creates a new [`GoBuildSettings`] with the given key and value.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Parses a `"key=value"` string, splitting at the first `'='`.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the string contains no `'='` separator.
    pub fn from_string(s: &str) -> io::Result<Self> {
        s.split_once('=')
            .map(|(k, v)| Self::new(k, v))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected key=value"))
    }
}

impl FromStr for GoBuildSettings {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        let gs = GoBuildSettings::from_string("GOARCH=amd64").unwrap();
        assert_eq!(gs.key, "GOARCH");
        assert_eq!(gs.value, "amd64");
    }

    #[test]
    fn value_may_contain_equals() {
        let gs = GoBuildSettings::from_string("key=a=b=c").unwrap();
        assert_eq!(gs.key, "key");
        assert_eq!(gs.value, "a=b=c");
    }

    #[test]
    fn empty_key() {
        let gs = GoBuildSettings::from_string("=value").unwrap();
        assert_eq!(gs.key, "");
        assert_eq!(gs.value, "value");
    }

    #[test]
    fn empty_value() {
        let gs = GoBuildSettings::from_string("key=").unwrap();
        assert_eq!(gs.key, "key");
        assert_eq!(gs.value, "");
    }

    #[test]
    fn no_separator_is_error() {
        assert!(GoBuildSettings::from_string("noseparator").is_err());
    }

    #[test]
    fn empty_string_is_error() {
        assert!(GoBuildSettings::from_string("").is_err());
    }

    #[test]
    fn from_str_trait() {
        let gs: GoBuildSettings = "GOOS=linux".parse().unwrap();
        assert_eq!(gs.key, "GOOS");
        assert_eq!(gs.value, "linux");
    }

    #[test]
    fn new_constructor() {
        let gs = GoBuildSettings::new("k", "v");
        assert_eq!(gs.key, "k");
        assert_eq!(gs.value, "v");
    }
}
