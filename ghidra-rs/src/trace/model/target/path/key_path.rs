use std::fmt;

use once_cell::sync::Lazy;

/// Minimum interface for path filtering used by [`KeyPath::stream_matching_ancestry`].
pub trait PathFilter {
    fn matches(&self, path: &KeyPath) -> bool;
    fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool;
    /// Get the pattern for the previous key (right-to-left matching).
    ///
    /// Returns empty set if no ancestor of `path` can match this filter at the preceding position.
    fn get_prev_keys(&self, _path: &KeyPath) -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }
}

/// Returns `true` if `key` is a wildcard pattern (`""` or `"[]"`).
///
/// Corresponds to `PathPattern.isWildcard` in the Java source; lives here because
/// [`KeyPath`] needs it before `PathPattern` is ported.
pub fn is_wildcard(key: &str) -> bool {
    key == "[]" || key.is_empty()
}

/// Sort order for individual keys within a path.
pub enum KeyComparator {
    /// Lexicographic sort on attribute names.
    Attribute,
    /// Multi-dimensional element-index sort (comma-separated, numeric-first per dimension).
    Element,
    /// Single-dimension element-index sort (numeric-first, then lexicographic).
    ElementDim,
    /// Element indices first, then attribute names.
    Child,
}

impl KeyComparator {
    pub fn compare(&self, o1: &str, o2: &str) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self {
            Self::Attribute => o1.cmp(o2),
            Self::Element => {
                let p1: Vec<&str> = o1.split(',').collect();
                let p2: Vec<&str> = o2.split(',').collect();
                let min = p1.len().min(p2.len());
                for i in 0..min {
                    let c = Self::ElementDim.compare(p1[i], p2[i]);
                    if c != Ordering::Equal {
                        return c;
                    }
                }
                p1.len().cmp(&p2.len())
            }
            Self::ElementDim => {
                let l1 = u64::from_str_radix(o1, 16).ok();
                let l2 = u64::from_str_radix(o2, 16).ok();
                match (l1, l2) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => o1.cmp(o2),
                }
            }
            Self::Child => {
                let ii1 = o1.starts_with('[') && o1.ends_with(']');
                let ii2 = o2.starts_with('[') && o2.ends_with(']');
                match (ii1, ii2) {
                    (true, true) => {
                        Self::Element.compare(&o1[1..o1.len() - 1], &o2[1..o2.len() - 1])
                    }
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => Self::Attribute.compare(o1, o2),
                }
            }
        }
    }
}

/// Sort order for complete key paths.
pub enum PathComparator {
    /// Sort by key, left-most first; a prefix path is less than the longer path.
    Keyed,
    /// Longest paths first, then by [`PathComparator::Keyed`].
    LongestFirst,
}

impl PathComparator {
    pub fn compare(&self, o1: &KeyPath, o2: &KeyPath) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self {
            Self::Keyed => {
                let min = o1.size().min(o2.size());
                for i in 0..min {
                    let c = o1.key(i).cmp(o2.key(i));
                    if c != Ordering::Equal {
                        return c;
                    }
                }
                o1.size().cmp(&o2.size())
            }
            Self::LongestFirst => {
                let c = o2.size().cmp(&o1.size());
                if c != std::cmp::Ordering::Equal {
                    return c;
                }
                Self::Keyed.compare(o1, o2)
            }
        }
    }
}

/// Parser for dot-separated path strings with bracket-enclosed indices.
///
/// The separator character is `.` when used via [`KeyPath::parse`].
pub struct PathParser {
    input: Vec<char>,
    pos: usize,
    sep: char,
    result: Vec<String>,
}

impl PathParser {
    pub fn new(path: &str, sep: char) -> Self {
        Self { input: path.chars().collect(), pos: 0, sep, result: vec![] }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn current(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance_parenthesized(&mut self) {
        while !self.at_end() {
            let ch = self.current().unwrap();
            self.pos += 1;
            if ch == ')' {
                break;
            } else if ch == '(' {
                self.advance_parenthesized();
            }
        }
    }

    fn parse_name(&mut self) -> String {
        let start = self.pos;
        while !self.at_end() {
            let ch = self.current().unwrap();
            if ch == self.sep || ch == '[' {
                break;
            } else if ch == '(' {
                self.pos += 1;
                self.advance_parenthesized();
            } else {
                self.pos += 1;
            }
        }
        self.input[start..self.pos].iter().collect()
    }

    fn match_bracketed(&mut self) -> Result<String, String> {
        let start = self.pos;
        self.pos += 1; // consume '['
        while !self.at_end() && self.current() != Some(']') {
            self.pos += 1;
        }
        if self.at_end() {
            return Err("Unterminated bracket in path".to_string());
        }
        self.pos += 1; // consume ']'
        Ok(self.input[start..self.pos].iter().collect())
    }

    fn parse_next(&mut self) -> Result<String, String> {
        match self.current() {
            Some(c) if c == self.sep => {
                self.pos += 1;
                Ok(self.parse_name())
            }
            Some('[') => self.match_bracketed(),
            other => Err(format!(
                "Expected {:?} or '[', but had {:?}",
                self.sep, other
            )),
        }
    }

    pub fn parse(mut self) -> Result<KeyPath, String> {
        let first = self.parse_name();
        if !first.is_empty() {
            self.result.push(first);
        }
        while !self.at_end() {
            let next = self.parse_next()?;
            self.result.push(next);
        }
        Ok(KeyPath { keys: self.result })
    }
}

/// An immutable path of keys from one object (usually root) to another.
///
/// Keys are either attribute names (plain strings) or element indices (bracketed: `[idx]`).
/// The string representation joins keys with `.` between consecutive attribute names.
#[derive(Clone, Debug)]
pub struct KeyPath {
    keys: Vec<String>,
}

/// The empty (root) path.
pub static ROOT: Lazy<KeyPath> = Lazy::new(|| KeyPath { keys: vec![] });

impl KeyPath {
    /// Creates an empty (root) path.
    pub fn root() -> Self {
        KeyPath { keys: vec![] }
    }

    /// Creates a path from a slice of key strings.
    pub fn of(keys: &[&str]) -> Self {
        KeyPath { keys: keys.iter().map(|s| s.to_string()).collect() }
    }

    /// Creates a path from a `Vec<String>`.
    pub fn of_list(keys: Vec<String>) -> Self {
        KeyPath { keys }
    }

    /// Creates a path from an iterator of owned strings.
    pub fn of_iter(iter: impl IntoIterator<Item = String>) -> Self {
        KeyPath { keys: iter.into_iter().collect() }
    }

    /// Parses a dot-separated path string (e.g. `"Processes[2].Threads"`).
    pub fn parse(path: &str) -> Result<Self, String> {
        PathParser::new(path, '.').parse()
    }

    /// Encodes `i` as a decimal string (no brackets).
    pub fn make_index(i: i64) -> String {
        i.to_string()
    }

    /// Returns `true` if `key` is a bracketed index (`[…]`).
    pub fn is_index(key: &str) -> bool {
        key.starts_with('[') && key.ends_with(']')
    }

    /// Returns `true` if `key` is an attribute name (not a bracketed index).
    pub fn is_name(key: &str) -> bool {
        !Self::is_index(key)
    }

    /// Strips brackets from a key of the form `[index]`, returning `index`.
    ///
    /// Returns `Err` if the key is not in bracketed form.
    pub fn parse_index(key: &str) -> Result<&str, String> {
        if Self::is_index(key) {
            Ok(&key[1..key.len() - 1])
        } else {
            Err(format!(
                "Index keys must be of the form '[index]'. Got {}",
                key
            ))
        }
    }

    /// Strips brackets from `key` if it is an index, otherwise returns `key` as-is.
    pub fn parse_if_index(key: &str) -> &str {
        if Self::is_index(key) {
            &key[1..key.len() - 1]
        } else {
            key
        }
    }

    /// Wraps `index` in brackets to form an element key: `index` → `[index]`.
    pub fn make_key(index: &str) -> String {
        format!("[{}]", index)
    }

    /// Returns the number of keys in this path.
    pub fn size(&self) -> usize {
        self.keys.len()
    }

    /// Returns the key at position `i`.
    pub fn key(&self, i: usize) -> &str {
        &self.keys[i]
    }

    /// Returns the final key, or `None` if the path is empty.
    pub fn last_key(&self) -> Option<&str> {
        self.keys.last().map(String::as_str)
    }

    /// Creates a new path by appending the named attribute key `name`.
    pub fn with_key(&self, name: &str) -> KeyPath {
        let mut keys = self.keys.clone();
        keys.push(name.to_string());
        KeyPath { keys }
    }

    /// Creates a new path by appending element key `[index]`.
    pub fn with_index(&self, index: &str) -> KeyPath {
        self.with_key(&Self::make_key(index))
    }

    /// Creates a new path by appending the numeric element index.
    pub fn with_index_num(&self, index: i64) -> KeyPath {
        self.with_index(&Self::make_index(index))
    }

    /// Returns the final key parsed as an index (brackets stripped).
    ///
    /// Returns `Ok(None)` if the path is empty, `Err` if the final key is not an index.
    pub fn last_index(&self) -> Result<Option<&str>, String> {
        match self.last_key() {
            None => Ok(None),
            Some(key) => Self::parse_index(key).map(Some),
        }
    }

    /// Returns an owned copy of the key list.
    pub fn to_list(&self) -> Vec<String> {
        self.keys.clone()
    }

    /// Returns `true` if any key is a wildcard (`""` or `"[]"`).
    pub fn contains_wildcard(&self) -> bool {
        self.keys.iter().any(|k| is_wildcard(k))
    }

    /// Counts the number of wildcard keys.
    pub fn count_wildcards(&self) -> usize {
        self.keys.iter().filter(|k| is_wildcard(k.as_str())).count()
    }

    /// Returns `true` if this is the root (empty) path.
    pub fn is_root(&self) -> bool {
        self.keys.is_empty()
    }

    /// Creates a new path by removing the final key.
    ///
    /// Returns `None` if the path is already empty.
    pub fn parent(&self) -> Option<KeyPath> {
        self.parent_n(1)
    }

    /// Creates a new path by removing the final `n` keys.
    ///
    /// Returns `None` if the path has fewer than `n` keys.
    pub fn parent_n(&self, n: usize) -> Option<KeyPath> {
        if self.keys.len() < n {
            return None;
        }
        Some(KeyPath { keys: self.keys[..self.keys.len() - n].to_vec() })
    }

    /// Creates a new path by appending all keys from `sub`.
    pub fn extend(&self, sub: &KeyPath) -> KeyPath {
        let mut keys = self.keys.clone();
        keys.extend(sub.keys.iter().cloned());
        KeyPath { keys }
    }

    /// Creates a new path by appending the given key strings.
    pub fn extend_keys(&self, sub_keys: &[&str]) -> KeyPath {
        let mut keys = self.keys.clone();
        keys.extend(sub_keys.iter().map(|s| s.to_string()));
        KeyPath { keys }
    }

    /// Returns matching ancestor paths (including self), longest first.
    pub fn stream_matching_ancestry(&self, filter: &dyn PathFilter) -> Vec<KeyPath> {
        if !filter.ancestor_matches(self, false) {
            return vec![];
        }
        let ancestry = match self.parent() {
            None => vec![],
            Some(p) => p.stream_matching_ancestry(filter),
        };
        if filter.matches(self) {
            let mut result = vec![self.clone()];
            result.extend(ancestry);
            result
        } else {
            ancestry
        }
    }

    /// Returns `true` if this path is a prefix of (or equal to) `successor`.
    pub fn is_ancestor(&self, successor: &KeyPath) -> bool {
        if self.keys.len() > successor.keys.len() {
            return false;
        }
        let len = self.keys.len();
        self.keys[..len] == successor.keys[..len]
    }

    /// Returns the relative path from this ancestor to `successor`.
    ///
    /// Returns `Err` if this path is not an ancestor of `successor`.
    pub fn relativize(&self, successor: &KeyPath) -> Result<KeyPath, String> {
        if !self.is_ancestor(successor) {
            return Err("this is not an ancestor to successor".to_string());
        }
        Ok(KeyPath { keys: successor.keys[self.keys.len()..].to_vec() })
    }
}

impl PartialEq for KeyPath {
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys
    }
}

impl Eq for KeyPath {}

impl std::hash::Hash for KeyPath {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.keys.hash(state);
    }
}

impl PartialOrd for KeyPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        PathComparator::Keyed.compare(self, other)
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for k in &self.keys {
            if !Self::is_index(k) && !first {
                write!(f, ".")?;
            }
            first = false;
            write!(f, "{}", k)?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a KeyPath {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse ---

    #[test]
    fn test_parse_empty() {
        assert_eq!(KeyPath::root(), KeyPath::parse("").unwrap());
    }

    #[test]
    fn test_parse_name() {
        assert_eq!(KeyPath::of(&["name"]), KeyPath::parse("name").unwrap());
    }

    #[test]
    fn test_parse_dotted_name() {
        assert_eq!(KeyPath::of(&["name"]), KeyPath::parse(".name").unwrap());
    }

    #[test]
    fn test_parse_index() {
        assert_eq!(KeyPath::of(&["[index]"]), KeyPath::parse("[index]").unwrap());
    }

    #[test]
    fn test_parse_name_then_index() {
        assert_eq!(
            KeyPath::of(&["name", "[index]"]),
            KeyPath::parse("name[index]").unwrap()
        );
    }

    #[test]
    fn test_parse_index_then_name() {
        assert_eq!(
            KeyPath::of(&["[index]", "name"]),
            KeyPath::parse("[index].name").unwrap()
        );
    }

    #[test]
    fn test_parse_err_index_no_dot_name() {
        assert!(KeyPath::parse("[index]name").is_err());
    }

    #[test]
    fn test_parse_name_then_name() {
        assert_eq!(KeyPath::of(&["n1", "n2"]), KeyPath::parse("n1.n2").unwrap());
    }

    #[test]
    fn test_parse_index_then_index() {
        assert_eq!(
            KeyPath::of(&["[i1]", "[i2]"]),
            KeyPath::parse("[i1][i2]").unwrap()
        );
    }

    #[test]
    fn test_parse_index_with_dot() {
        assert_eq!(
            KeyPath::of(&["[index.more]"]),
            KeyPath::parse("[index.more]").unwrap()
        );
    }

    #[test]
    fn test_parse_parenthesized_name_with_dot() {
        assert_eq!(
            KeyPath::of(&["query(e.x==6)"]),
            KeyPath::parse(".query(e.x==6)").unwrap()
        );
    }

    // --- key helpers ---

    #[test]
    fn test_is_index() {
        assert!(KeyPath::is_index("[foo]"));
        assert!(KeyPath::is_index("[]"));
        assert!(!KeyPath::is_index("foo"));
        assert!(!KeyPath::is_index("[foo"));
        assert!(!KeyPath::is_index("foo]"));
    }

    #[test]
    fn test_is_name() {
        assert!(KeyPath::is_name("foo"));
        assert!(!KeyPath::is_name("[foo]"));
    }

    #[test]
    fn test_parse_index_fn() {
        assert_eq!(KeyPath::parse_index("[hello]").unwrap(), "hello");
        assert_eq!(KeyPath::parse_index("[]").unwrap(), "");
        assert!(KeyPath::parse_index("hello").is_err());
    }

    #[test]
    fn test_parse_if_index() {
        assert_eq!(KeyPath::parse_if_index("[foo]"), "foo");
        assert_eq!(KeyPath::parse_if_index("bar"), "bar");
    }

    #[test]
    fn test_make_key() {
        assert_eq!(KeyPath::make_key("foo"), "[foo]");
    }

    #[test]
    fn test_make_index() {
        assert_eq!(KeyPath::make_index(42), "42");
        assert_eq!(KeyPath::make_index(-1), "-1");
    }

    // --- path construction ---

    #[test]
    fn test_with_key() {
        let base = KeyPath::of(&["Processes", "[2]"]);
        let result = base.with_key("Threads");
        assert_eq!(result, KeyPath::of(&["Processes", "[2]", "Threads"]));
    }

    #[test]
    fn test_with_index() {
        let base = KeyPath::of(&["Processes"]);
        let result = base.with_index("2");
        assert_eq!(result, KeyPath::of(&["Processes", "[2]"]));
    }

    #[test]
    fn test_with_index_num() {
        let base = KeyPath::of(&["Processes"]);
        let result = base.with_index_num(2);
        assert_eq!(result, KeyPath::of(&["Processes", "[2]"]));
    }

    #[test]
    fn test_extend() {
        let a = KeyPath::of(&["Processes", "[2]"]);
        let b = KeyPath::of(&["Threads", "[0]"]);
        assert_eq!(
            a.extend(&b),
            KeyPath::of(&["Processes", "[2]", "Threads", "[0]"])
        );
    }

    #[test]
    fn test_extend_keys() {
        let base = KeyPath::of(&["a"]);
        assert_eq!(base.extend_keys(&["b", "c"]), KeyPath::of(&["a", "b", "c"]));
    }

    // --- parent / ancestor ---

    #[test]
    fn test_parent() {
        let p = KeyPath::of(&["a", "b", "c"]);
        assert_eq!(p.parent().unwrap(), KeyPath::of(&["a", "b"]));
    }

    #[test]
    fn test_parent_of_root_is_none() {
        assert!(KeyPath::root().parent().is_none());
    }

    #[test]
    fn test_parent_n() {
        let p = KeyPath::of(&["a", "b", "c"]);
        assert_eq!(p.parent_n(2).unwrap(), KeyPath::of(&["a"]));
        assert_eq!(p.parent_n(3).unwrap(), KeyPath::root());
        assert!(p.parent_n(4).is_none());
    }

    #[test]
    fn test_is_ancestor() {
        let ancestor = KeyPath::of(&["a", "b"]);
        let successor = KeyPath::of(&["a", "b", "c"]);
        assert!(ancestor.is_ancestor(&successor));
        assert!(ancestor.is_ancestor(&ancestor));
        assert!(!successor.is_ancestor(&ancestor));
    }

    #[test]
    fn test_relativize() {
        let ancestor = KeyPath::of(&["a", "b"]);
        let successor = KeyPath::of(&["a", "b", "c", "d"]);
        assert_eq!(
            ancestor.relativize(&successor).unwrap(),
            KeyPath::of(&["c", "d"])
        );
    }

    #[test]
    fn test_relativize_err() {
        let a = KeyPath::of(&["x"]);
        let b = KeyPath::of(&["y"]);
        assert!(a.relativize(&b).is_err());
    }

    // --- display ---

    #[test]
    fn test_display_root() {
        assert_eq!(KeyPath::root().to_string(), "");
    }

    #[test]
    fn test_display_names() {
        assert_eq!(KeyPath::of(&["a", "b", "c"]).to_string(), "a.b.c");
    }

    #[test]
    fn test_display_mixed() {
        assert_eq!(
            KeyPath::of(&["Processes", "[2]", "Threads"]).to_string(),
            "Processes[2].Threads"
        );
    }

    #[test]
    fn test_display_indices_only() {
        assert_eq!(KeyPath::of(&["[0]", "[1]"]).to_string(), "[0][1]");
    }

    // --- comparators ---

    #[test]
    fn test_key_comparator_attribute() {
        use std::cmp::Ordering;
        assert_eq!(KeyComparator::Attribute.compare("a", "b"), Ordering::Less);
        assert_eq!(KeyComparator::Attribute.compare("b", "a"), Ordering::Greater);
        assert_eq!(KeyComparator::Attribute.compare("a", "a"), Ordering::Equal);
    }

    #[test]
    fn test_key_comparator_element_dim_numeric() {
        use std::cmp::Ordering;
        // Both numeric (hex): 0xf < 0x10
        assert_eq!(KeyComparator::ElementDim.compare("f", "10"), Ordering::Less);
        // Numeric < non-numeric
        assert_eq!(KeyComparator::ElementDim.compare("1", "z"), Ordering::Less);
        // Non-numeric > numeric
        assert_eq!(KeyComparator::ElementDim.compare("z", "1"), Ordering::Greater);
    }

    #[test]
    fn test_key_comparator_element_multidim() {
        use std::cmp::Ordering;
        // "1,2" < "1,3" (same first dim, second differs)
        assert_eq!(
            KeyComparator::Element.compare("1,2", "1,3"),
            Ordering::Less
        );
        // "1,2" < "1,2,0" (prefix is less)
        assert_eq!(
            KeyComparator::Element.compare("1,2", "1,2,0"),
            Ordering::Less
        );
    }

    #[test]
    fn test_key_comparator_child() {
        use std::cmp::Ordering;
        // Index before attribute
        assert_eq!(KeyComparator::Child.compare("[0]", "a"), Ordering::Less);
        // Attribute after index
        assert_eq!(KeyComparator::Child.compare("a", "[0]"), Ordering::Greater);
        // Both attributes: lex
        assert_eq!(KeyComparator::Child.compare("a", "b"), Ordering::Less);
    }

    #[test]
    fn test_path_comparator_keyed() {
        let a = KeyPath::of(&["a", "b"]);
        let b = KeyPath::of(&["a", "c"]);
        assert!(PathComparator::Keyed.compare(&a, &b) == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_path_comparator_longest_first() {
        let short = KeyPath::of(&["a"]);
        let long = KeyPath::of(&["a", "b"]);
        assert!(PathComparator::LongestFirst.compare(&long, &short) == std::cmp::Ordering::Less);
    }

    // --- wildcards ---

    #[test]
    fn test_contains_wildcard() {
        assert!(KeyPath::of(&["a", "[]", "b"]).contains_wildcard());
        assert!(KeyPath::of(&["", "b"]).contains_wildcard());
        assert!(!KeyPath::of(&["a", "[x]", "b"]).contains_wildcard());
    }

    #[test]
    fn test_count_wildcards() {
        assert_eq!(KeyPath::of(&["a", "[]", "", "b"]).count_wildcards(), 2);
        assert_eq!(KeyPath::of(&["a", "b"]).count_wildcards(), 0);
    }

    // --- ord / hash ---

    #[test]
    fn test_ord() {
        let a = KeyPath::of(&["a"]);
        let b = KeyPath::of(&["b"]);
        assert!(a < b);
    }

    #[test]
    fn test_hash_eq_paths_same_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let a = KeyPath::of(&["x", "y"]);
        let b = KeyPath::of(&["x", "y"]);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    // --- stream_matching_ancestry ---

    struct AlwaysMatch;
    impl PathFilter for AlwaysMatch {
        fn matches(&self, _: &KeyPath) -> bool {
            true
        }
        fn ancestor_matches(&self, _: &KeyPath, _: bool) -> bool {
            true
        }
    }

    struct NeverMatch;
    impl PathFilter for NeverMatch {
        fn matches(&self, _: &KeyPath) -> bool {
            false
        }
        fn ancestor_matches(&self, _: &KeyPath, _: bool) -> bool {
            false
        }
    }

    #[test]
    fn test_stream_matching_ancestry_all_match() {
        let path = KeyPath::of(&["a", "b", "c"]);
        let result = path.stream_matching_ancestry(&AlwaysMatch);
        assert_eq!(result, vec![
            KeyPath::of(&["a", "b", "c"]),
            KeyPath::of(&["a", "b"]),
            KeyPath::of(&["a"]),
            KeyPath::root(),
        ]);
    }

    #[test]
    fn test_stream_matching_ancestry_none_match() {
        let path = KeyPath::of(&["a", "b"]);
        let result = path.stream_matching_ancestry(&NeverMatch);
        assert!(result.is_empty());
    }
}
