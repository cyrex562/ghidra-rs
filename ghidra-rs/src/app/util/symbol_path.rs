//! A convenience trait for parsing a namespace path to a symbol.
//!
//! For example, if a `SymbolPath` is constructed with "foo::bar::baz", then "baz" is the
//! name of a symbol in the "bar" namespace, which is in the "foo" namespace.
//! - [`SymbolPath::name`] returns "baz".
//! - [`SymbolPath::parent_path`] returns "foo::bar".
//! - [`SymbolPath::path`] returns "foo::bar::baz".
//!
//! Port of `ghidra.app.util.SymbolPath`. The concrete Java class is mapped to an object-safe
//! trait (this was selected as a dependency-cycle cut point), with [`SymbolPathNode`] as the
//! reference implementation used by the trait's default methods and free constructors.
//!
//! `ghidra.app.util.SymbolPathParser`, which the Java constructor delegates to for parsing a
//! delimited path string, is not yet ported as its own class (still `TODO` in
//! `PORT_MANIFEST.tsv`). It is a stateless static algorithm rather than a polymorphic core type,
//! so rather than fabricate a placeholder trait for it, its `parse`/`naiveParse` logic is
//! reproduced directly as private free functions below.

use std::cmp::Ordering;
use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::GLOBAL_NAMESPACE_NAME;
use crate::program::model::symbol::{Namespace, Symbol, SymbolUtilities, DELIMITER};

/// Errors produced constructing a [`SymbolPath`] from a string or list of names.
///
/// Combines the `IllegalArgumentException` cases thrown by the Java constructors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SymbolPathError {
    #[error("Symbol list must contain at least one symbol name!")]
    EmptyList,
    #[error("Pathname cannot be empty!")]
    BlankPathname,
}

/// A convenience object for parsing a namespace path to a symbol.
///
/// Port of `ghidra.app.util.SymbolPath`.
pub trait SymbolPath: Send + Sync {
    /// Returns the name of the symbol, without any path information.
    fn name(&self) -> &str;

    /// Returns the `SymbolPath` for the parent namespace, or `None` if the parent is the global
    /// space.
    fn parent(&self) -> Option<Arc<dyn SymbolPath>>;

    /// Returns `None` if the parent is `None`; otherwise returns the path of the parent
    /// namespace as a string.
    fn parent_path(&self) -> Option<String> {
        self.parent().map(|p| p.path())
    }

    /// Returns the full symbol path as a string.
    fn path(&self) -> String {
        match self.parent() {
            Some(parent) => format!("{}{}{}", parent.path(), DELIMITER, self.name()),
            None => self.name().to_string(),
        }
    }

    /// Returns a list of names of the symbols in the symbol path, starting with the name just
    /// below the global namespace.
    fn as_list(&self) -> Vec<String> {
        let mut list = match self.parent() {
            Some(parent) => parent.as_list(),
            None => Vec::new(),
        };
        list.push(self.name().to_string());
        list
    }

    /// Returns the names of the symbols in the symbol path, starting with the name just below
    /// the global namespace. Stands in for Java's `String[] asArray()`.
    fn as_array(&self) -> Vec<String> {
        self.as_list()
    }

    /// Returns a new `SymbolPath` in which invalid characters are replaced with underscores.
    fn replace_invalid_chars(&self) -> Box<dyn SymbolPath> {
        let names: Vec<String> = self
            .as_list()
            .into_iter()
            .map(|name| {
                crate::program::model::symbol::DefaultSymbolUtilities
                    .replace_invalid_chars(Some(&name), true)
                    .unwrap_or_default()
            })
            .collect();
        Box::new(build_chain(&names))
    }

    /// Creates a new `SymbolPath` composed of the list of names in this path followed by the
    /// list of names in the given path.
    fn append(&self, path: &dyn SymbolPath) -> Box<dyn SymbolPath> {
        let mut names = self.as_list();
        names.extend(path.as_list());
        Box::new(build_chain(&names))
    }

    /// Returns true if this path contains any path entry matching the given text.
    fn contains_path_entry(&self, text: &str) -> bool {
        self.as_list().iter().any(|entry| entry == text)
    }

    /// A convenience method to check if the given symbol's symbol path matches this path.
    fn matches_path_of(&self, symbol: &dyn Symbol) -> bool {
        self.equals_path(&symbol_path_from_symbol(symbol, false))
    }

    /// Structural equality, matching Java's `equals(Object)`: compares `name()` and `parent()`
    /// recursively. Named `equals_path` (rather than `eq`) since trait objects cannot implement
    /// `PartialEq` directly.
    fn equals_path(&self, other: &dyn SymbolPath) -> bool {
        if self.name() != other.name() {
            return false;
        }
        match (self.parent(), other.parent()) {
            (None, None) => true,
            (Some(a), Some(b)) => a.equals_path(b.as_ref()),
            _ => false,
        }
    }

    /// Port of `Comparable<SymbolPath>.compareTo`. Note this is *not* simple lexicographic
    /// comparison of [`SymbolPath::as_list`]: a path with no parent always sorts before one
    /// with a parent, regardless of name, matching the recursive Java algorithm.
    fn compare_to(&self, other: &dyn SymbolPath) -> Ordering {
        let self_parent = self.parent();
        let other_parent = other.parent();
        let parent_order = match (&self_parent, &other_parent) {
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => a.compare_to(b.as_ref()),
            (None, None) => Ordering::Equal,
        };
        if parent_order != Ordering::Equal {
            return parent_order;
        }
        self.name().cmp(other.name())
    }
}

impl std::fmt::Display for dyn SymbolPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.path())
    }
}

/// Reference implementation of [`SymbolPath`]: a single name plus an optional parent path.
///
/// Port of the private `SymbolPath.parentPath`/`SymbolPath.symbolName` fields.
#[derive(Clone)]
pub struct SymbolPathNode {
    parent: Option<Arc<dyn SymbolPath>>,
    name: String,
}

impl std::fmt::Debug for SymbolPathNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymbolPathNode").field(&self.path()).finish()
    }
}

impl PartialEq for SymbolPathNode {
    fn eq(&self, other: &Self) -> bool {
        self.equals_path(other)
    }
}

impl Eq for SymbolPathNode {}

impl SymbolPathNode {
    /// Construct a `SymbolPathNode` from a string containing `"::"` sequences to separate the
    /// namespace names. This is the only constructor that employs special string-based
    /// namespace parsing.
    ///
    /// Port of `SymbolPath(String)`.
    pub fn parse(symbol_path_string: &str) -> Result<Self, SymbolPathError> {
        let names = parse_symbol_path(symbol_path_string)?;
        Self::from_names(names)
    }

    /// Construct a `SymbolPathNode` from a list of names where each string is the name of a
    /// namespace in the symbol path.
    ///
    /// Port of `SymbolPath(List<String>)` / `SymbolPath(String[])`.
    ///
    /// # Errors
    /// Returns `Err` if `names` is empty.
    pub fn from_names(names: Vec<String>) -> Result<Self, SymbolPathError> {
        if names.is_empty() {
            return Err(SymbolPathError::EmptyList);
        }
        Ok(build_chain(&names))
    }

    /// Constructs a new `SymbolPathNode` for the given symbol.
    ///
    /// Port of `SymbolPath(Symbol)` / `SymbolPath(Symbol, boolean)`.
    ///
    /// `exclude_library` mirrors the Java parameter: if true, a library name at the front of the
    /// path is removed. Note that (matching the Java source exactly) this only applies to the
    /// immediate parent namespace; deeper ancestors are always walked with the library included.
    pub fn from_symbol(symbol: &dyn Symbol, exclude_library: bool) -> Self {
        symbol_path_from_symbol(symbol, exclude_library)
    }

    /// Creates a `SymbolPathNode` from a parent path and a symbol name.
    ///
    /// Port of `SymbolPath(SymbolPath parent, String name)`.
    pub fn with_parent(parent: Option<Arc<dyn SymbolPath>>, name: impl Into<String>) -> Self {
        SymbolPathNode { parent: check_global(parent), name: name.into() }
    }
}

impl SymbolPath for SymbolPathNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn parent(&self) -> Option<Arc<dyn SymbolPath>> {
        self.parent.clone()
    }
}

/// Builds a `SymbolPathNode` chain from a non-empty slice of names, applying [`check_global`] to
/// every intermediate parent (matching the recursive Java `SymbolPath(List<String>)`
/// constructor). Panics if `names` is empty; callers must validate first.
fn build_chain(names: &[String]) -> SymbolPathNode {
    let (name, rest) = names.split_last().expect("names must be non-empty");
    let parent = if rest.is_empty() {
        None
    } else {
        let parent_node: Arc<dyn SymbolPath> = Arc::new(build_chain(rest));
        check_global(Some(parent_node))
    };
    SymbolPathNode { parent, name: name.clone() }
}

/// Some existing code might include "Global" at the beginning of their path. This eliminates any
/// "Global" at the beginning of the path.
///
/// Port of the private `SymbolPath.checkGlobal`.
fn check_global(path: Option<Arc<dyn SymbolPath>>) -> Option<Arc<dyn SymbolPath>> {
    let path = path?;
    if path.parent().is_none() && path.name().eq_ignore_ascii_case(GLOBAL_NAMESPACE_NAME) {
        return None;
    }
    Some(path)
}

/// Port of `SymbolPath(Symbol, boolean)`. Note the recursive call in Java always passes
/// `excludeLibrary = false` for ancestors beyond the immediate parent; this is preserved here.
fn symbol_path_from_symbol(symbol: &dyn Symbol, exclude_library: bool) -> SymbolPathNode {
    let name = symbol.get_name().to_string();
    let parent_namespace = symbol.get_parent_namespace();
    let parent = parent_namespace.and_then(|ns| {
        if ns.is_global() {
            return None;
        }
        if exclude_library && ns.as_library().is_some() {
            return None;
        }
        let parent_symbol = ns.get_symbol();
        Some(Arc::new(symbol_path_from_symbol(parent_symbol.as_ref(), false)) as Arc<dyn SymbolPath>)
    });
    SymbolPathNode { parent, name }
}

/// Port of `SymbolPathParser.parse(String, boolean)` with `ignoreLeaderParens = true` (the
/// default used by `SymbolPath(String)`).
fn parse_symbol_path(name: &str) -> Result<Vec<String>, SymbolPathError> {
    if name.trim().is_empty() {
        return Err(SymbolPathError::BlankPathname);
    }
    if skip_parsing(name) {
        return Ok(vec![name.to_string()]);
    }
    Ok(naive_parse(name))
}

/// Port of the private `SymbolPathParser.skipParsing`.
fn skip_parsing(name: &str) -> bool {
    // Working around a type seen in "Rust." - a name starting with '(' is left unparsed.
    if name.starts_with('(') {
        return true;
    }
    !name.contains(DELIMITER)
}

/// Port of the private `SymbolPathParser.naiveParse`: naive parsing that assumes evenly matched
/// angle brackets (templates) and parentheses, breaking only on namespace delimiters found
/// outside of both.
fn naive_parse(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();

    // Only break on namespace delimiters found at templateLevel == 0 && parenthesesLevel == 0.
    let mut list = Vec::new();
    let mut template_level = 0i32;
    let mut paren_level = 0i32;
    let mut start_index = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == ':' && i != chars.len() - 1 && chars[i + 1] == ':' {
            if template_level == 0 && paren_level == 0 {
                let end_index = i;
                if end_index > start_index {
                    list.push(chars[start_index..end_index].iter().collect());
                    start_index = i + 2;
                    i += 1;
                }
            }
        } else if chars[i] == '<' {
            template_level += 1;
        } else if chars[i] == '>' {
            template_level -= 1;
        } else if chars[i] == '(' {
            paren_level += 1;
        } else if chars[i] == ')' {
            paren_level -= 1;
        }
        i += 1;
    }

    if template_level != 0 || paren_level != 0 {
        // Revert to no checking template/parentheses level.
        start_index = 0;
        list = Vec::new();
        i = 0;
        while i < chars.len() {
            if chars[i] == ':' && i != chars.len() - 1 && chars[i + 1] == ':' {
                let end_index = i;
                if end_index > start_index {
                    list.push(chars[start_index..end_index].iter().collect());
                    start_index = i + 2;
                    i += 1;
                }
            }
            i += 1;
        }
    }
    list.push(chars[start_index..].iter().collect());
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolType};

    /// Minimal mock proving [`SymbolPath`] is object-safe and usable via `Arc`/`Box<dyn
    /// SymbolPath>`, independent of [`SymbolPathNode`].
    struct MockPath {
        parent: Option<Arc<dyn SymbolPath>>,
        name: String,
    }

    impl SymbolPath for MockPath {
        fn name(&self) -> &str {
            &self.name
        }

        fn parent(&self) -> Option<Arc<dyn SymbolPath>> {
            self.parent.clone()
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let root: Arc<dyn SymbolPath> =
            Arc::new(MockPath { parent: None, name: "foo".to_string() });
        let child: Box<dyn SymbolPath> =
            Box::new(MockPath { parent: Some(root), name: "bar".to_string() });

        assert_eq!(child.name(), "bar");
        assert_eq!(child.path(), "foo::bar");
        assert_eq!(child.parent_path(), Some("foo".to_string()));
        assert_eq!(child.as_list(), vec!["foo".to_string(), "bar".to_string()]);
        assert!(child.contains_path_entry("foo"));
        assert!(!child.contains_path_entry("baz"));
        assert_eq!(child.to_string(), "foo::bar");
    }

    #[test]
    fn parses_simple_dotted_path_from_string() {
        let path = SymbolPathNode::parse("foo::bar::baz").unwrap();

        assert_eq!(path.name(), "baz");
        assert_eq!(path.path(), "foo::bar::baz");
        assert_eq!(path.parent_path(), Some("foo::bar".to_string()));
        assert_eq!(
            path.as_list(),
            vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
        );
    }

    #[test]
    fn single_name_path_has_no_parent() {
        let path = SymbolPathNode::parse("baz").unwrap();

        assert_eq!(path.name(), "baz");
        assert!(path.parent().is_none());
        assert_eq!(path.parent_path(), None);
        assert_eq!(path.path(), "baz");
    }

    #[test]
    fn empty_string_is_rejected() {
        assert_eq!(SymbolPathNode::parse(""), Err(SymbolPathError::BlankPathname));
        assert_eq!(SymbolPathNode::parse("   "), Err(SymbolPathError::BlankPathname));
    }

    #[test]
    fn empty_name_list_is_rejected() {
        assert_eq!(SymbolPathNode::from_names(vec![]), Err(SymbolPathError::EmptyList));
    }

    #[test]
    fn leading_global_namespace_is_dropped() {
        let path =
            SymbolPathNode::from_names(vec!["Global".to_string(), "foo".to_string()]).unwrap();

        assert_eq!(path.name(), "foo");
        assert!(path.parent().is_none());
        assert_eq!(path.path(), "foo");
    }

    #[test]
    fn global_case_insensitive_match_is_dropped() {
        let path =
            SymbolPathNode::from_names(vec!["GLOBAL".to_string(), "foo".to_string()]).unwrap();
        assert!(path.parent().is_none());
    }

    #[test]
    fn append_combines_two_paths() {
        let a = SymbolPathNode::parse("foo::bar").unwrap();
        let b = SymbolPathNode::parse("baz::qux").unwrap();

        let combined = a.append(&b);

        assert_eq!(combined.path(), "foo::bar::baz::qux");
        assert_eq!(
            combined.as_list(),
            vec!["foo", "bar", "baz", "qux"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn equals_path_is_structural_not_pointer_identity() {
        let a = SymbolPathNode::parse("foo::bar").unwrap();
        let b = SymbolPathNode::parse("foo::bar").unwrap();
        let c = SymbolPathNode::parse("foo::baz").unwrap();

        assert!(a.equals_path(&b));
        assert!(!a.equals_path(&c));
    }

    #[test]
    fn compare_to_orders_shorter_paths_before_longer_regardless_of_name() {
        // Matches Java's compareTo: a path with no parent always sorts before one with a
        // parent, even when plain lexicographic name comparison would disagree ("z" < "a").
        let shallow = SymbolPathNode::parse("z").unwrap();
        let deep = SymbolPathNode::parse("a::z").unwrap();

        assert_eq!(shallow.compare_to(&deep), Ordering::Less);
        assert_eq!(deep.compare_to(&shallow), Ordering::Greater);
    }

    #[test]
    fn compare_to_falls_back_to_name_at_equal_depth() {
        let a = SymbolPathNode::parse("ns::alpha").unwrap();
        let b = SymbolPathNode::parse("ns::beta").unwrap();

        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
    }

    #[test]
    fn naive_parse_ignores_delimiters_inside_templates_and_parens() {
        let path = SymbolPathNode::parse("foo<int, blah::hah>::bar::baz").unwrap();

        assert_eq!(
            path.as_list(),
            vec!["foo<int, blah::hah>".to_string(), "bar".to_string(), "baz".to_string()]
        );
    }

    #[test]
    fn leading_parens_skip_parsing_entirely() {
        let path = SymbolPathNode::parse("(some::weird::type)").unwrap();

        assert_eq!(path.as_list(), vec!["(some::weird::type)".to_string()]);
    }

    #[test]
    fn replace_invalid_chars_swaps_spaces_for_underscores() {
        let path = SymbolPathNode::from_names(vec!["bad name".to_string(), "ok".to_string()])
            .unwrap();

        let cleaned = path.replace_invalid_chars();

        assert_eq!(cleaned.path(), "bad_name::ok");
    }

    struct MockSymbol {
        name: String,
        symbol_type: SymbolType,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    struct MockNamespace {
        id: i64,
        symbol_name: String,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: self.symbol_name.clone(),
                symbol_type: SymbolType::Namespace,
                parent: self.parent.clone(),
            })
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }

        fn get_id(&self) -> i64 {
            self.id
        }
    }

    #[test]
    fn from_symbol_walks_the_namespace_chain() {
        use crate::program::model::symbol::GLOBAL_NAMESPACE_ID;

        let global: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: GLOBAL_NAMESPACE_ID,
            symbol_name: "Global".to_string(),
            parent: None,
        });
        let outer: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 1,
            symbol_name: "outer".to_string(),
            parent: Some(global),
        });
        let leaf = MockSymbol {
            name: "leaf".to_string(),
            symbol_type: SymbolType::Label,
            parent: Some(outer),
        };

        let path = SymbolPathNode::from_symbol(&leaf, false);

        assert_eq!(path.path(), "outer::leaf");
    }

    #[test]
    fn matches_path_of_compares_symbol_derived_path() {
        use crate::program::model::symbol::GLOBAL_NAMESPACE_ID;

        let global: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: GLOBAL_NAMESPACE_ID,
            symbol_name: "Global".to_string(),
            parent: None,
        });
        let outer: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 1,
            symbol_name: "outer".to_string(),
            parent: Some(global),
        });
        let leaf = MockSymbol {
            name: "leaf".to_string(),
            symbol_type: SymbolType::Label,
            parent: Some(outer),
        };

        let matching = SymbolPathNode::parse("outer::leaf").unwrap();
        let mismatched = SymbolPathNode::parse("other::leaf").unwrap();

        assert!(matching.matches_path_of(&leaf));
        assert!(!mismatched.matches_path_of(&leaf));
    }
}
