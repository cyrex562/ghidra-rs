use std::fmt;

use once_cell::sync::Lazy;

/// The delimiter character used to separate the elements of a category path.
pub const DELIMITER_CHAR: char = '/';

/// The delimiter character as a string.
pub const DELIMITER_STRING: &str = "/";

/// The escaped form of [`DELIMITER_STRING`], used when a path element contains a literal
/// delimiter character.
pub const ESCAPED_DELIMITER_STRING: &str = "\\/";

/// Two consecutive (non-escaped) delimiters, which are never legal in a category path string.
const ILLEGAL_STRING: &str = "//";

/// Difference in length between [`ESCAPED_DELIMITER_STRING`] and [`DELIMITER_STRING`].
const DIFF: isize = (ESCAPED_DELIMITER_STRING.len() - DELIMITER_STRING.len()) as isize;

/// The root category path (`"/"`).
pub static ROOT: Lazy<CategoryPath> = Lazy::new(|| CategoryPath { parent: None, name: String::new() });

/// A category path is the full path to a particular data type.
///
/// Port of `ghidra.program.model.data.CategoryPath`. The Java class implements
/// `Comparable<CategoryPath>` and overrides `equals`/`hashCode`; those are represented here by
/// deriving [`Ord`]/[`Eq`]/[`Hash`] on the same `(parent, name)` fields the Java methods compare,
/// which reproduces the Java `compareTo` recursion (parent chain first, then name) exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CategoryPath {
    // parent can only be `None` for ROOT
    parent: Option<Box<CategoryPath>>,
    name: String,
}

impl CategoryPath {
    /// Converts a non-escaped string into an escaped string suitable for being passed in as a
    /// component of a single category path string to [`CategoryPath::parse`]. The caller is
    /// responsible for constructing the single category path string from the escaped components.
    pub fn escape_string(non_escaped_string: &str) -> String {
        non_escaped_string.replace(DELIMITER_STRING, ESCAPED_DELIMITER_STRING)
    }

    /// Converts an escaped string suitable for being passed in as a component of a single
    /// category path string into a non-escaped string.
    pub fn unescape_string(escaped_string: &str) -> String {
        escaped_string.replace(ESCAPED_DELIMITER_STRING, DELIMITER_STRING)
    }

    /// Construct a `CategoryPath` from a parent and a hierarchical list of names, where each
    /// name is a category in the category path.
    ///
    /// # Errors
    /// Returns `Err` if `sub_path_elements` is empty, mirroring the `IllegalArgumentException`
    /// thrown by the Java constructors.
    pub fn new(parent: CategoryPath, sub_path_elements: &[&str]) -> Result<Self, String> {
        if sub_path_elements.is_empty() {
            return Err("Category list must contain at least one string name!".to_string());
        }
        let last = sub_path_elements.len() - 1;
        let name = sub_path_elements[last].to_string();
        let effective_parent = if sub_path_elements.len() == 1 {
            parent
        }
        else {
            CategoryPath::new(parent, &sub_path_elements[..last])?
        };
        Ok(CategoryPath { parent: Some(Box::new(effective_parent)), name })
    }

    /// Returns a `CategoryPath` that extends this path using a hierarchical list of names.
    ///
    /// Returns a clone of `self` if `sub_path_elements` is empty.
    pub fn extend(&self, sub_path_elements: &[&str]) -> Self {
        if sub_path_elements.is_empty() {
            return self.clone();
        }
        CategoryPath::new(self.clone(), sub_path_elements)
            .expect("sub_path_elements was just checked to be non-empty")
    }

    /// Creates a category path given a forward-slash-delimited string (e.g. `"/aa/bb"`). If an
    /// individual path component has one or more `/` characters in it, it can be escaped using
    /// [`CategoryPath::escape_string`].
    ///
    /// # Errors
    /// Returns `Err` if `path` does not start with `/`, ends with a non-escaped `/`, or contains
    /// an empty (non-escaped) element, mirroring the `IllegalArgumentException` thrown by the
    /// Java constructor.
    pub fn parse(path: &str) -> Result<Self, String> {
        if path.is_empty() || path == DELIMITER_STRING {
            return Ok(CategoryPath { parent: None, name: String::new() });
        }
        if !path.starts_with(DELIMITER_CHAR) {
            return Err(format!("Paths must start with {DELIMITER_STRING}"));
        }
        if Self::ends_with_non_escaped_delimiter(path) {
            return Err(format!("Paths must not end with {DELIMITER_STRING}"));
        }
        if path.contains(ILLEGAL_STRING) {
            return Err("Paths must have non-empty elements".to_string());
        }

        let delimiter_index = Self::find_index_of_last_non_escaped_delimiter(path) as usize;
        let parent = CategoryPath::parse(&path[..delimiter_index])?;
        let name = Self::unescape_string(&path[delimiter_index + 1..]);
        Ok(CategoryPath { parent: Some(Box::new(parent)), name })
    }

    fn ends_with_non_escaped_delimiter(string: &str) -> bool {
        let bytes = string.as_bytes();
        if bytes[bytes.len() - 1] != DELIMITER_CHAR as u8 {
            return false;
        }
        let last_escaped = Self::last_index_of_str(string, ESCAPED_DELIMITER_STRING, string.len() as isize - 1);
        last_escaped != string.len() as isize - ESCAPED_DELIMITER_STRING.len() as isize
    }

    fn find_index_of_last_non_escaped_delimiter(string: &str) -> isize {
        let mut escaped_index = string.len() as isize;
        let mut delimiter_index = escaped_index;
        while delimiter_index > 0 {
            escaped_index = Self::last_index_of_str(string, ESCAPED_DELIMITER_STRING, escaped_index - 1);
            delimiter_index = Self::last_index_of_char(string, DELIMITER_CHAR, delimiter_index - 1);
            if delimiter_index != escaped_index + DIFF {
                break;
            }
        }
        delimiter_index
    }

    /// Rust equivalent of `String.lastIndexOf(String, int)`: the largest `k <= from_index` such
    /// that `string[k..]` starts with `pat`, or `-1` if there is none.
    fn last_index_of_str(string: &str, pat: &str, from_index: isize) -> isize {
        if from_index < 0 {
            return -1;
        }
        let bytes = string.as_bytes();
        let pat_bytes = pat.as_bytes();
        if bytes.len() < pat_bytes.len() {
            return -1;
        }
        let max_start = (from_index as usize).min(bytes.len() - pat_bytes.len());
        (0..=max_start).rev().find(|&k| &bytes[k..k + pat_bytes.len()] == pat_bytes).map_or(-1, |k| k as isize)
    }

    /// Rust equivalent of `String.lastIndexOf(char, int)`: the largest `k <= from_index` such
    /// that `string[k]` is `ch`, or `-1` if there is none.
    fn last_index_of_char(string: &str, ch: char, from_index: isize) -> isize {
        if from_index < 0 {
            return -1;
        }
        let bytes = string.as_bytes();
        if bytes.is_empty() {
            return -1;
        }
        let start = (from_index as usize).min(bytes.len() - 1);
        let ch_byte = ch as u8;
        (0..=start).rev().find(|&k| bytes[k] == ch_byte).map_or(-1, |k| k as isize)
    }

    /// Determine if this category path corresponds to the root category.
    pub fn is_root(&self) -> bool {
        // parent can only be `None` for ROOT
        self.parent.is_none()
    }

    /// Return the parent category path, or `None` if this is the root category.
    pub fn get_parent(&self) -> Option<CategoryPath> {
        self.parent.as_deref().cloned()
    }

    /// Return the terminating name of this category path.
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    /// Return the string representation of this category path including the category name,
    /// where components are delimited with a forward slash. Any occurrence of a forward slash
    /// within an individual path component will be escaped (e.g. `"\/"`).
    ///
    /// # Panics
    /// Panics if this path (or an ancestor) was constructed with a blank name component, which
    /// would also have thrown `IllegalArgumentException` from the Java `getPath()`.
    pub fn get_path(&self) -> String {
        if self.is_root() {
            return DELIMITER_STRING.to_string();
        }
        self.parent
            .as_ref()
            .expect("non-root CategoryPath always has a parent")
            .get_path_for_child(&self.name)
            .expect("CategoryPath name must not be blank")
    }

    /// Return the string representation of the specified `child_name` within this category path,
    /// where all path components are delimited with a forward slash. Any occurrence of a forward
    /// slash within individual path components, including `child_name`, will be escaped.
    ///
    /// # Errors
    /// Returns `Err` if `child_name` is blank, mirroring the `IllegalArgumentException` thrown by
    /// the Java `getPath(String)`.
    pub fn get_path_for_child(&self, child_name: &str) -> Result<String, String> {
        if child_name.trim().is_empty() {
            return Err("blank child name".to_string());
        }
        let mut path = self.get_path();
        if !self.is_root() {
            path.push(DELIMITER_CHAR);
        }
        path.push_str(&Self::escape_string(child_name));
        Ok(path)
    }

    /// Tests if `candidate_ancestor_path` is the same as, or an ancestor of, this category path.
    pub fn is_ancestor_or_self(&self, candidate_ancestor_path: &CategoryPath) -> bool {
        if candidate_ancestor_path.is_root() {
            return true;
        }

        let mut path = self.clone();
        while !path.is_root() {
            if *candidate_ancestor_path == path {
                return true;
            }
            path = path.get_parent().expect("non-root CategoryPath always has a parent");
        }
        false
    }

    /// Returns a hierarchical list of names of the categories in the category path, starting
    /// with the name just below the root category.
    pub fn as_list(&self) -> Vec<String> {
        if self.is_root() {
            return Vec::new();
        }
        let mut list = self.parent.as_ref().expect("non-root CategoryPath always has a parent").as_list();
        list.push(self.name.clone());
        list
    }

    /// Returns a hierarchical array of names of the categories in the category path, starting
    /// with the name just below the root category.
    pub fn as_array(&self) -> Vec<String> {
        self.as_list()
    }

    /// Returns the array of names in this category path. Equivalent to [`CategoryPath::as_array`].
    pub fn get_path_elements(&self) -> Vec<String> {
        self.as_array()
    }
}

impl fmt::Display for CategoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_string_empty() {
        let orig = "";
        let escaped = CategoryPath::escape_string(orig);
        let unescaped = CategoryPath::unescape_string(&escaped);
        assert_eq!(orig, unescaped);
        assert_eq!("", escaped);
    }

    #[test]
    fn escape_string_1() {
        let orig = "/";
        let escaped = CategoryPath::escape_string(orig);
        let unescaped = CategoryPath::unescape_string(&escaped);
        assert_eq!(orig, unescaped);
        assert_eq!("\\/", escaped);
    }

    #[test]
    fn escape_string_2() {
        let orig = "//";
        let escaped = CategoryPath::escape_string(orig);
        let unescaped = CategoryPath::unescape_string(&escaped);
        assert_eq!(orig, unescaped);
        assert_eq!("\\/\\/", escaped);
    }

    #[test]
    fn constructor_root_static() {
        let c = &*ROOT;
        assert_eq!("/", c.get_path());
        assert_eq!("", c.get_name());
        assert!(c.is_root());
    }

    #[test]
    fn constructor_root_empty_string() {
        let c = CategoryPath::parse("").unwrap();
        assert_eq!("/", c.get_path());
        assert_eq!("", c.get_name());
        assert!(c.is_root());
    }

    #[test]
    fn constructor_root_slash() {
        let c = CategoryPath::parse("/").unwrap();
        assert_eq!("/", c.get_path());
        assert_eq!("", c.get_name());
        assert!(c.is_root());
    }

    #[test]
    fn constructor_basic_string_1() {
        let c = CategoryPath::parse("/apple").unwrap();
        assert_eq!("/apple", c.get_path());
        assert_eq!("apple", c.get_name());
    }

    #[test]
    fn constructor_basic_string_2() {
        let c = CategoryPath::parse("/apple/pear").unwrap();
        assert_eq!("/apple/pear", c.get_path());
        assert_eq!("pear", c.get_name());
    }

    #[test]
    fn constructor_parent_single_element() {
        let c = CategoryPath::parse("/apple/pear").unwrap();
        let c = CategoryPath::new(c, &["mango"]).unwrap();
        assert_eq!("/apple/pear/mango", c.get_path());
        assert_eq!("mango", c.get_name());
    }

    #[test]
    fn constructor_empty_elements_is_error() {
        let err = CategoryPath::new(ROOT.clone(), &[]).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn constructor_parent_and_multiple_elements() {
        let parent = CategoryPath::parse("/universe/earth").unwrap();
        let c = CategoryPath::new(parent, &["boy", "bad"]).unwrap();
        assert_eq!("/universe/earth/boy/bad", c.get_path());
        assert_eq!("bad", c.get_name());
    }

    #[test]
    fn constructor_parent_and_multiple_elements_chain() {
        let parent = CategoryPath::parse("/apple/peaches").unwrap();
        let mut c = CategoryPath::new(parent, &["pumpkin", "pie"]).unwrap();
        assert_eq!("pie", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("pumpkin", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("peaches", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("apple", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("", c.get_name());
        assert!(c.is_root());
    }

    #[test]
    fn extend_multiple() {
        let parent = CategoryPath::parse("/universe/earth").unwrap();
        let c = parent.extend(&["boy", "bad"]);
        assert_eq!("/universe/earth/boy/bad", c.get_path());
        assert_eq!("bad", c.get_name());
    }

    #[test]
    fn extend_empty_returns_clone() {
        let parent = CategoryPath::parse("/universe/earth").unwrap();
        let c = parent.extend(&[]);
        assert_eq!(parent, c);
    }

    #[test]
    fn extend_chain() {
        let parent = CategoryPath::parse("/apple/peaches").unwrap();
        let mut c = parent.extend(&["pumpkin", "pie"]);
        assert_eq!("pie", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("pumpkin", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("peaches", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("apple", c.get_name());
        c = c.get_parent().unwrap();
        assert_eq!("", c.get_name());
        assert!(c.is_root());
    }

    #[test]
    fn bad_ctor_param_empty_path_element() {
        assert!(CategoryPath::parse("//").is_err());
    }

    #[test]
    fn bad_ctor_param_empty_path_element_2() {
        assert!(CategoryPath::parse("/apple//bob").is_err());
    }

    #[test]
    fn bad_ctor_param_missing_leading_slash() {
        assert!(CategoryPath::parse("apple").is_err());
    }

    #[test]
    fn bad_ctor_param_bad_trailing_slash() {
        assert!(CategoryPath::parse("/apple/").is_err());
    }

    #[test]
    fn get_parent() {
        assert!(ROOT.get_parent().is_none());
        let c = CategoryPath::parse("/aaa/bbb/ccc").unwrap();
        let c = c.get_parent().unwrap();
        assert_eq!("/aaa/bbb", c.get_path());
    }

    #[test]
    fn is_ancestor_root_root() {
        assert!(ROOT.is_ancestor_or_self(&ROOT));
    }

    #[test]
    fn is_ancestor_root_apple() {
        let apple = CategoryPath::parse("/apple").unwrap();
        assert!(apple.is_ancestor_or_self(&ROOT));
        assert!(!ROOT.is_ancestor_or_self(&apple));
    }

    #[test]
    fn is_ancestor_apple_sub_apple() {
        let apple = CategoryPath::parse("/apple").unwrap();
        let apple_sub = CategoryPath::parse("/apple/sub").unwrap();
        assert!(apple_sub.is_ancestor_or_self(&apple));
        assert!(apple_sub.is_ancestor_or_self(&apple_sub));
    }

    #[test]
    fn is_ancestor_apple_sub_not_apple() {
        let apple_sub = CategoryPath::parse("/apple/sub").unwrap();
        let not_apple = CategoryPath::parse("/notapple").unwrap();
        assert!(!apple_sub.is_ancestor_or_self(&not_apple));
    }

    #[test]
    fn is_ancestor_apple_sub_app() {
        let apple_sub = CategoryPath::parse("/apple/sub").unwrap();
        let app = CategoryPath::parse("/app").unwrap();
        assert!(!apple_sub.is_ancestor_or_self(&app));
    }

    #[test]
    fn to_array() {
        let path = CategoryPath::parse("/aaa/bbb/bob").unwrap();
        let names = path.as_array();
        assert_eq!(vec!["aaa", "bbb", "bob"], names);
    }

    #[test]
    fn to_list() {
        let path = CategoryPath::parse("/aaa/bbb/bob").unwrap();
        let names = path.as_list();
        assert_eq!(vec!["aaa", "bbb", "bob"], names);
    }

    #[test]
    fn constructor_delimiter_escape_1() {
        let path = CategoryPath::parse("/aaa/bbb/\\/bob").unwrap();
        let names = path.as_list();
        assert_eq!(vec!["aaa", "bbb", "/bob"], names);
        assert_eq!("/aaa/bbb/\\/bob", path.get_path());
    }

    #[test]
    fn constructor_delimiter_escape_2() {
        // Should not complain about terminating slash.
        let path = CategoryPath::parse("/aaa/bbb/bob\\/").unwrap();
        let names = path.as_list();
        assert_eq!(vec!["aaa", "bbb", "bob/"], names);
        assert_eq!("/aaa/bbb/bob\\/", path.get_path());
    }

    #[test]
    fn constructor_delimiter_escape_3() {
        let path = CategoryPath::parse("/\\/aaa/bbb/bob").unwrap();
        let names = path.as_list();
        assert_eq!(vec!["/aaa", "bbb", "bob"], names);
        assert_eq!("/\\/aaa/bbb/bob", path.get_path());
    }

    #[test]
    fn constructor_delimiter_escape_4() {
        let path = CategoryPath::parse("/\\/\\/aaa/bbb/bob").unwrap();
        let names = path.as_list();
        assert_eq!(vec!["//aaa", "bbb", "bob"], names);
        assert_eq!("/\\/\\/aaa/bbb/bob", path.get_path());
    }

    #[test]
    fn delimiter_escape_at_root_is_error() {
        assert!(CategoryPath::parse("\\//aaa/bbb/bob").is_err());
    }

    #[test]
    fn constructor_parent_nested_delimiter() {
        let c = CategoryPath::parse("/apple/pear").unwrap();
        // A nested delimiter sequence should be ignored on construction and get_name(), but
        // output on get_path().
        let c = CategoryPath::new(c, &["man/go"]).unwrap();
        assert_eq!("/apple/pear/man\\/go", c.get_path());
        assert_eq!("man/go", c.get_name());
    }

    #[test]
    fn constructor_parent_nested_escape() {
        let c = CategoryPath::parse("/apple/pear").unwrap();
        // A nested escape sequence should be ignored on construction and get_name(), but output
        // on get_path().
        let c = CategoryPath::new(c, &["man\\/go"]).unwrap();
        assert_eq!("/apple/pear/man\\\\/go", c.get_path());
        assert_eq!("man\\/go", c.get_name());
    }

    #[test]
    fn ordering_root_is_less_than_any_child() {
        let apple = CategoryPath::parse("/apple").unwrap();
        assert!(*ROOT < apple);
        assert!(apple > *ROOT);
        assert_eq!(std::cmp::Ordering::Equal, ROOT.cmp(&ROOT));
    }

    #[test]
    fn ordering_by_name_within_same_parent() {
        let apple = CategoryPath::parse("/apple").unwrap();
        let pear = CategoryPath::parse("/pear").unwrap();
        assert!(apple < pear);
        assert!(pear > apple);
    }

    #[test]
    fn equality_and_hash_are_structural() {
        use std::collections::HashSet;

        let a1 = CategoryPath::parse("/aaa/bbb").unwrap();
        let a2 = CategoryPath::parse("/aaa/bbb").unwrap();
        let b = CategoryPath::parse("/aaa/ccc").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);

        let mut set = HashSet::new();
        set.insert(a1.clone());
        assert!(set.contains(&a2));
        assert!(!set.contains(&b));
    }

    #[test]
    fn display_matches_get_path() {
        let c = CategoryPath::parse("/aaa/bbb").unwrap();
        assert_eq!(c.get_path(), c.to_string());
    }
}
