use std::collections::HashSet;

use super::{KeyPath, PathFilter};

/// Returns true if `key` matches the pattern `pat`.
///
/// `"[]"` matches any element index; `""` matches any attribute name; otherwise exact equality.
pub fn key_matches(pat: &str, key: &str) -> bool {
    if key == pat {
        return true;
    }
    if pat == "[]" {
        return KeyPath::is_index(key);
    }
    if pat.is_empty() {
        return KeyPath::is_name(key);
    }
    false
}

/// A single path pattern that matches paths against a key-by-key template.
///
/// Wildcards: `""` matches any attribute name; `"[]"` matches any element index.
pub struct PathPattern {
    pattern: KeyPath,
}

impl PathPattern {
    pub fn new(pattern: KeyPath) -> Self {
        Self { pattern }
    }

    /// Parses a dot-separated pattern string (e.g. `"Processes[0].Threads[].Stack"`).
    pub fn parse(s: &str) -> Result<Self, String> {
        Ok(Self { pattern: KeyPath::parse(s)? })
    }

    /// Returns the underlying key-path pattern.
    pub fn as_path(&self) -> &KeyPath {
        &self.pattern
    }

    fn matches_up_to(&self, path: &KeyPath, length: usize) -> bool {
        for i in 0..length {
            if !key_matches(self.pattern.key(i), path.key(i)) {
                return false;
            }
        }
        true
    }

    fn matches_back_to(&self, path: &KeyPath, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        let pattern_max = self.pattern.size() - 1;
        let path_max = path.size() - 1;
        for i in 0..length {
            if !key_matches(self.pattern.key(pattern_max - i), path.key(path_max - i)) {
                return false;
            }
        }
        true
    }
}

impl PathFilter for PathPattern {
    fn matches(&self, path: &KeyPath) -> bool {
        if path.size() != self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, path.size())
    }

    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() < self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, self.pattern.size())
    }

    fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_back_to(path, path.size()) {
            return HashSet::new();
        }
        let key = self.pattern.key(self.pattern.size() - 1 - path.size());
        [key.to_string()].into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_prev_keys() {
        let pred = PathPattern::parse("Processes[0].Threads[].Stack").unwrap();

        assert_eq!(
            pred.get_prev_keys(&KeyPath::root()),
            HashSet::from(["Stack".to_string()])
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("Stack").unwrap()),
            HashSet::from(["[]".to_string()])
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("[].Stack").unwrap()),
            HashSet::from(["Threads".to_string()])
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("Threads[].Stack").unwrap()),
            HashSet::from(["[0]".to_string()])
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("[0].Threads[].Stack").unwrap()),
            HashSet::from(["Processes".to_string()])
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("Processes[0].Threads[].Stack").unwrap()),
            HashSet::new()
        );

        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("Foo.Processes[0].Threads[].Stack").unwrap()),
            HashSet::new()
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("Foo").unwrap()),
            HashSet::new()
        );
        assert_eq!(
            pred.get_prev_keys(&KeyPath::parse("[]").unwrap()),
            HashSet::new()
        );
    }
}
