use std::collections::HashSet;

use super::{is_wildcard, KeyPath, PathFilter};

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

/// Alignment for [`PathPattern::apply_keys`]/[`crate::trace::model::target::path::path_matcher::PathMatcher::apply_keys`]
/// wildcard substitution.
///
/// Port of the nested `PathFilter.Align` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Substitute the left-most wildcards for the left-most keys.
    Left,
    /// Substitute the right-most wildcards for the right-most keys.
    Right,
}

/// A single path pattern that matches paths against a key-by-key template.
///
/// Wildcards: `""` matches any attribute name; `"[]"` matches any element index.
///
/// # Differences from Java
///
/// Java never overrides `equals`/`hashCode` on... actually it does: both delegate to the wrapped
/// `pattern` field (`Objects.equals(this.pattern, that.pattern)` / `pattern.hashCode()`). Deriving
/// `PartialEq`/`Eq`/`Hash` on this single-field struct is exactly that behavior, not a
/// simplification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// Port of `PathPattern.isWildcard(String)`.
    pub fn is_wildcard(pat: &str) -> bool {
        is_wildcard(pat)
    }

    /// Port of `PathPattern.sanitizeKey(String)`: replaces `[`/`]` with `{`/`}` since brackets
    /// are reserved for index syntax in a path.
    pub fn sanitize_key(key: &str) -> String {
        key.replace('[', "{").replace(']', "}")
    }

    /// Port of `PathPattern.countWildcards()`.
    pub fn count_wildcards(&self) -> usize {
        self.pattern.count_wildcards()
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

    /// Port of `PathPattern.successorCouldMatch(KeyPath, boolean)`.
    pub fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() > self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_up_to(path, path.size())
    }

    /// Port of `PathPattern.ancestorCouldMatchRight(KeyPath, boolean)`.
    pub fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        if path.size() > self.pattern.size() {
            return false;
        }
        if strict && path.size() == self.pattern.size() {
            return false;
        }
        self.matches_back_to(path, path.size())
    }

    /// Port of `PathPattern.getSingletonPath()`.
    pub fn get_singleton_path(&self) -> Option<KeyPath> {
        if self.pattern.contains_wildcard() {
            None
        } else {
            Some(self.pattern.clone())
        }
    }

    /// Port of `PathPattern.getNextKeys(KeyPath)`.
    pub fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_up_to(path, path.size()) {
            return HashSet::new();
        }
        [self.pattern.key(path.size()).to_string()].into_iter().collect()
    }

    /// Port of `PathPattern.getNextNames(KeyPath)`.
    pub fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_up_to(path, path.size()) {
            return HashSet::new();
        }
        let pat = self.pattern.key(path.size());
        if KeyPath::is_name(pat) {
            [pat.to_string()].into_iter().collect()
        } else {
            HashSet::new()
        }
    }

    /// Port of `PathPattern.getNextIndices(KeyPath)`.
    pub fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        if path.size() >= self.pattern.size() {
            return HashSet::new();
        }
        if !self.matches_up_to(path, path.size()) {
            return HashSet::new();
        }
        let pat = self.pattern.key(path.size());
        if KeyPath::is_index(pat) {
            let idx = KeyPath::parse_index(pat)
                .expect("KeyPath::is_index(pat) was true, so parse_index cannot fail");
            [idx.to_string()].into_iter().collect()
        } else {
            HashSet::new()
        }
    }

    /// Port of `PathPattern.applyKeys(Align, List<String>)`.
    ///
    /// Substitutes each wildcard key (`""` or `"[]"`) in this pattern, from the aligned end, with
    /// the next available entry from `keys` (sanitized so brackets in the substituted value can't
    /// be mistaken for index syntax). Once `keys` is exhausted, remaining wildcards are left as-is.
    pub fn apply_keys(&self, align: Align, keys: &[String]) -> PathPattern {
        let pat_keys = self.pattern.to_list();
        let n = pat_keys.len();
        let mut result = vec![String::new(); n];
        match align {
            Align::Left => {
                let mut kit = keys.iter();
                for (i, pat) in pat_keys.iter().enumerate() {
                    result[i] = Self::apply_one_key(pat, &mut kit);
                }
            }
            Align::Right => {
                let mut kit = keys.iter().rev();
                for i in (0..n).rev() {
                    result[i] = Self::apply_one_key(&pat_keys[i], &mut kit);
                }
            }
        }
        PathPattern::new(KeyPath::of_list(result))
    }

    fn apply_one_key<'a>(pat: &str, kit: &mut impl Iterator<Item = &'a String>) -> String {
        if Self::is_wildcard(pat) {
            if let Some(k) = kit.next() {
                let index = Self::sanitize_key(k);
                return if KeyPath::is_index(pat) { KeyPath::make_key(&index) } else { index };
            }
        }
        pat.to_string()
    }

    /// Port of the package-private `PathPattern.doRemoveRight(int, Set<PathPattern>)`.
    pub(crate) fn do_remove_right(&self, count: usize, result: &mut HashSet<PathPattern>) {
        if let Some(parent) = self.pattern.parent_n(count) {
            result.insert(PathPattern::new(parent));
        }
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

impl std::fmt::Display for PathPattern {
    /// Port of `PathPattern.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<PathPattern {}>", self.pattern)
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

    #[test]
    fn test_successor_could_match() {
        let pat = PathPattern::parse("Processes[].Threads").unwrap();
        // A viable prefix.
        assert!(pat.successor_could_match(&KeyPath::parse("Processes[0]").unwrap(), false));
        // An exact match is allowed unless strict.
        assert!(pat.successor_could_match(&KeyPath::parse("Processes[0].Threads").unwrap(), false));
        assert!(!pat.successor_could_match(&KeyPath::parse("Processes[0].Threads").unwrap(), true));
        // Not a viable prefix: wrong second key.
        assert!(!pat.successor_could_match(&KeyPath::parse("Processes[0].Other").unwrap(), false));
        // Longer than the pattern: cannot match.
        assert!(!pat.successor_could_match(
            &KeyPath::parse("Processes[0].Threads[0]").unwrap(),
            false
        ));
    }

    #[test]
    fn test_ancestor_could_match_right() {
        let pat = PathPattern::parse("Processes[].Threads").unwrap();
        // A viable suffix (right-aligned).
        assert!(pat.ancestor_could_match_right(&KeyPath::parse("Threads").unwrap(), false));
        assert!(pat.ancestor_could_match_right(
            &KeyPath::parse("Processes[0].Threads").unwrap(),
            false
        ));
        assert!(!pat.ancestor_could_match_right(
            &KeyPath::parse("Processes[0].Threads").unwrap(),
            true
        ));
        // Not a viable suffix: wrong last key.
        assert!(!pat.ancestor_could_match_right(&KeyPath::parse("Other").unwrap(), false));
    }

    #[test]
    fn test_get_singleton_path_no_wildcards() {
        let pat = PathPattern::parse("Processes[0].Threads").unwrap();
        assert_eq!(pat.get_singleton_path(), Some(KeyPath::parse("Processes[0].Threads").unwrap()));
    }

    #[test]
    fn test_get_singleton_path_with_wildcard_is_none() {
        let pat = PathPattern::parse("Processes[].Threads").unwrap();
        assert_eq!(pat.get_singleton_path(), None);
    }

    #[test]
    fn test_get_next_keys() {
        let pat = PathPattern::parse("Processes[].Threads").unwrap();
        assert_eq!(
            pat.get_next_keys(&KeyPath::root()),
            HashSet::from(["Processes".to_string()])
        );
        assert_eq!(
            pat.get_next_keys(&KeyPath::parse("Processes").unwrap()),
            HashSet::from(["[]".to_string()])
        );
        // Path already as long as the pattern: no next key.
        assert_eq!(
            pat.get_next_keys(&KeyPath::parse("Processes[0].Threads").unwrap()),
            HashSet::new()
        );
        // Path that doesn't match the pattern prefix: no next key.
        assert_eq!(pat.get_next_keys(&KeyPath::parse("Other").unwrap()), HashSet::new());
    }

    #[test]
    fn test_get_next_names_and_indices() {
        let pat = PathPattern::parse("Processes[].Threads").unwrap();
        // Next key at the root is a name ("Processes"): getNextNames returns it, getNextIndices
        // doesn't.
        assert_eq!(
            pat.get_next_names(&KeyPath::root()),
            HashSet::from(["Processes".to_string()])
        );
        assert_eq!(pat.get_next_indices(&KeyPath::root()), HashSet::new());

        // Next key after "Processes" is an index wildcard ("[]"): getNextIndices returns the
        // bracket-stripped form, getNextNames doesn't.
        let after_processes = KeyPath::parse("Processes").unwrap();
        assert_eq!(pat.get_next_names(&after_processes), HashSet::new());
        assert_eq!(
            pat.get_next_indices(&after_processes),
            HashSet::from(["".to_string()])
        );
    }

    #[test]
    fn test_apply_keys_left_aligned() {
        let pat = PathPattern::parse("Processes[].Threads[]").unwrap();
        let keys = vec!["7".to_string(), "3".to_string()];
        let applied = pat.apply_keys(Align::Left, &keys);
        assert_eq!(applied.as_path(), &KeyPath::parse("Processes[7].Threads[3]").unwrap());
    }

    #[test]
    fn test_apply_keys_right_aligned() {
        let pat = PathPattern::parse("Processes[].Threads[]").unwrap();
        // Only one key: right-alignment substitutes the right-most wildcard first.
        let keys = vec!["3".to_string()];
        let applied = pat.apply_keys(Align::Right, &keys);
        assert_eq!(applied.as_path(), &KeyPath::parse("Processes[].Threads[3]").unwrap());
    }

    #[test]
    fn test_apply_keys_left_aligned_runs_out_of_keys() {
        let pat = PathPattern::parse("Processes[].Threads[]").unwrap();
        // Only one key: left-alignment substitutes the left-most wildcard first, leaving the
        // second wildcard untouched.
        let keys = vec!["3".to_string()];
        let applied = pat.apply_keys(Align::Left, &keys);
        assert_eq!(applied.as_path(), &KeyPath::parse("Processes[3].Threads[]").unwrap());
    }

    #[test]
    fn test_apply_keys_sanitizes_brackets() {
        let pat = PathPattern::parse("Memory[]").unwrap();
        let keys = vec!["has[bracket]".to_string()];
        let applied = pat.apply_keys(Align::Left, &keys);
        // Java: sanitizeKey replaces '[' -> '{' and ']' -> '}' so the substituted value can't be
        // mistaken for index syntax.
        assert_eq!(applied.as_path(), &KeyPath::parse("Memory[has{bracket}]").unwrap());
    }

    #[test]
    fn test_do_remove_right() {
        let pat = PathPattern::parse("Processes[0].Threads").unwrap();
        let mut result = HashSet::new();
        pat.do_remove_right(1, &mut result);
        assert_eq!(
            result,
            HashSet::from([PathPattern::parse("Processes[0]").unwrap()])
        );
    }

    #[test]
    fn test_do_remove_right_beyond_length_adds_nothing() {
        let pat = PathPattern::parse("Processes[0]").unwrap();
        let mut result = HashSet::new();
        pat.do_remove_right(5, &mut result);
        assert!(result.is_empty());
    }

    #[test]
    fn test_is_wildcard() {
        assert!(PathPattern::is_wildcard(""));
        assert!(PathPattern::is_wildcard("[]"));
        assert!(!PathPattern::is_wildcard("Processes"));
    }

    #[test]
    fn test_sanitize_key() {
        assert_eq!(PathPattern::sanitize_key("a[b]c"), "a{b}c");
    }

    #[test]
    fn test_display() {
        let pat = PathPattern::parse("Processes[0].Threads").unwrap();
        assert_eq!(pat.to_string(), "<PathPattern Processes[0].Threads>");
    }

    #[test]
    fn test_count_wildcards() {
        let pat = PathPattern::parse("Processes[].Threads[]").unwrap();
        assert_eq!(pat.count_wildcards(), 2);
    }
}
