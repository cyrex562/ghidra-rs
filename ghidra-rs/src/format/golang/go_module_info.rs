use std::collections::HashMap;
use std::io;

/// Information about a single Go module dependency.
///
/// Mirrors Ghidra's `GoModuleInfo` Java record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoModuleInfo {
    /// Module path.
    pub path: String,
    /// Module version.
    pub version: String,
    /// Checksum, if present.
    pub sum: Option<String>,
    /// Replacement module info, if any.
    pub replace: Option<Box<GoModuleInfo>>,
}

impl GoModuleInfo {
    /// Creates a new [`GoModuleInfo`].
    pub fn new(
        path: impl Into<String>,
        version: impl Into<String>,
        sum: Option<String>,
        replace: Option<GoModuleInfo>,
    ) -> Self {
        Self {
            path: path.into(),
            version: version.into(),
            sum,
            replace: replace.map(Box::new),
        }
    }

    /// Parses a [`GoModuleInfo`] from a tab-separated string `"path\tversion"` or
    /// `"path\tversion\tchecksum"`.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the string does not have exactly 2 or 3 tab-separated
    /// fields.
    pub fn from_string(s: &str, replace: Option<GoModuleInfo>) -> io::Result<Self> {
        let parts: Vec<&str> = s.split('\t').collect();
        if parts.len() != 2 && parts.len() != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected 2 or 3 tab-separated fields",
            ));
        }
        let sum = if parts.len() == 3 {
            Some(parts[2].to_string())
        } else {
            None
        };
        Ok(Self::new(parts[0], parts[1], sum, replace))
    }

    /// Returns a human-readable representation of this module info.
    ///
    /// If a replacement is present, formats as `"path version => <replace>"`;
    /// otherwise as `"path version checksum"` (empty string if no checksum).
    pub fn get_formatted_string(&self) -> String {
        match &self.replace {
            None => format!(
                "{} {} {}",
                self.path,
                self.version,
                self.sum.as_deref().unwrap_or("")
            ),
            Some(rep) => format!(
                "{} {} => {}",
                self.path,
                self.version,
                rep.get_formatted_string()
            ),
        }
    }

    /// Returns the fields of this instance as a [`HashMap`] with keys prefixed by `prefix`.
    ///
    /// Keys produced: `{prefix}path`, `{prefix}version`, and optionally `{prefix}sum` and
    /// `{prefix}replace`.
    pub fn as_key_value_pairs(&self, prefix: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();
        result.insert(
            format!("{}path", prefix),
            if self.path.is_empty() {
                "-missing-".to_string()
            } else {
                self.path.clone()
            },
        );
        result.insert(
            format!("{}version", prefix),
            if self.version.is_empty() {
                "-missing-".to_string()
            } else {
                self.version.clone()
            },
        );
        if let Some(sum) = &self.sum {
            result.insert(format!("{}sum", prefix), sum.clone());
        }
        if let Some(rep) = &self.replace {
            result.insert(format!("{}replace", prefix), rep.get_formatted_string());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_two_fields() {
        let m = GoModuleInfo::from_string("github.com/foo/bar\tv1.2.3", None).unwrap();
        assert_eq!(m.path, "github.com/foo/bar");
        assert_eq!(m.version, "v1.2.3");
        assert_eq!(m.sum, None);
        assert!(m.replace.is_none());
    }

    #[test]
    fn from_string_three_fields() {
        let m =
            GoModuleInfo::from_string("github.com/foo/bar\tv1.2.3\th1:abc123", None).unwrap();
        assert_eq!(m.path, "github.com/foo/bar");
        assert_eq!(m.version, "v1.2.3");
        assert_eq!(m.sum.as_deref(), Some("h1:abc123"));
    }

    #[test]
    fn from_string_one_field_is_error() {
        assert!(GoModuleInfo::from_string("onlyone", None).is_err());
    }

    #[test]
    fn from_string_four_fields_is_error() {
        assert!(GoModuleInfo::from_string("a\tb\tc\td", None).is_err());
    }

    #[test]
    fn from_string_empty_is_error() {
        assert!(GoModuleInfo::from_string("", None).is_err());
    }

    #[test]
    fn get_formatted_string_no_replace_with_sum() {
        let m = GoModuleInfo::new(
            "example.com/mod",
            "v0.1.0",
            Some("h1:deadbeef".to_string()),
            None,
        );
        assert_eq!(m.get_formatted_string(), "example.com/mod v0.1.0 h1:deadbeef");
    }

    #[test]
    fn get_formatted_string_no_replace_no_sum() {
        let m = GoModuleInfo::new("example.com/mod", "v0.1.0", None, None);
        assert_eq!(m.get_formatted_string(), "example.com/mod v0.1.0 ");
    }

    #[test]
    fn get_formatted_string_with_replace() {
        let rep = GoModuleInfo::new(
            "example.com/fork",
            "v1.0.0",
            Some("h1:cafebabe".to_string()),
            None,
        );
        let m = GoModuleInfo::new("example.com/mod", "v0.1.0", None, Some(rep));
        assert_eq!(
            m.get_formatted_string(),
            "example.com/mod v0.1.0 => example.com/fork v1.0.0 h1:cafebabe"
        );
    }

    #[test]
    fn as_key_value_pairs_basic() {
        let m = GoModuleInfo::new(
            "example.com/mod",
            "v0.1.0",
            Some("h1:abc".to_string()),
            None,
        );
        let kv = m.as_key_value_pairs("dep.");
        assert_eq!(kv["dep.path"], "example.com/mod");
        assert_eq!(kv["dep.version"], "v0.1.0");
        assert_eq!(kv["dep.sum"], "h1:abc");
        assert!(!kv.contains_key("dep.replace"));
    }

    #[test]
    fn as_key_value_pairs_with_replace() {
        let rep = GoModuleInfo::new("example.com/fork", "v1.0.0", None, None);
        let m = GoModuleInfo::new("example.com/mod", "v0.1.0", None, Some(rep));
        let kv = m.as_key_value_pairs("");
        assert_eq!(kv["path"], "example.com/mod");
        assert!(kv.contains_key("replace"));
        assert_eq!(kv["replace"], "example.com/fork v1.0.0 ");
    }

    #[test]
    fn as_key_value_pairs_missing_path_and_version() {
        let m = GoModuleInfo::new("", "", None, None);
        let kv = m.as_key_value_pairs("x.");
        assert_eq!(kv["x.path"], "-missing-");
        assert_eq!(kv["x.version"], "-missing-");
    }

    #[test]
    fn from_string_with_replace() {
        let rep = GoModuleInfo::from_string("example.com/fork\tv2.0.0", None).unwrap();
        let m =
            GoModuleInfo::from_string("example.com/orig\tv1.0.0\th1:xyz", Some(rep)).unwrap();
        assert_eq!(m.replace.as_ref().unwrap().path, "example.com/fork");
    }
}
