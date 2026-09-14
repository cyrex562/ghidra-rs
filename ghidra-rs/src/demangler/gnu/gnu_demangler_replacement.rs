//! Port of `ghidra.app.util.demangler.gnu.GnuDemanglerReplacement`.

use std::fmt;

use crate::generic::jar::resource_file::ResourceFile;

/// A simple object that is used to find and replace content within Gnu demangled strings.
///
/// Port of the `GnuDemanglerReplacement` record. Java's `record` gives `find`/`replace`/`source`
/// accessors, `equals`/`hashCode`, and a canonical constructor for free; those are reproduced by
/// hand here since [`ResourceFile`] (the `source` field's type) implements neither
/// [`Clone`] nor [`std::fmt::Debug`] nor [`PartialEq`] itself (it wraps a `Box<dyn Resource>`,
/// and `Resource` carries none of those either) -- so this type's own `Debug`/`PartialEq` impls
/// below only reach into `source` through [`ResourceFile::absolute_path`], the one comparable/
/// displayable thing it exposes.
pub struct GnuDemanglerReplacement {
    /// The string to search for; cannot be null (enforced here by `String`'s non-nullability,
    /// standing in for the record's compact constructor `Objects.requireNonNull(find, ...)`
    /// check).
    find: String,
    /// The replacement string; cannot be null (see [`Self::find`]).
    replace: String,
    /// The file from whence the replacement came; may be `None` (Java: may be null).
    source: Option<ResourceFile>,
}

impl GnuDemanglerReplacement {
    /// Constructs a new replacement rule.
    ///
    /// Port of the record's canonical constructor, `GnuDemanglerReplacement(String find, String
    /// replace, ResourceFile source)`.
    pub fn new(find: impl Into<String>, replace: impl Into<String>, source: Option<ResourceFile>) -> Self {
        GnuDemanglerReplacement { find: find.into(), replace: replace.into(), source }
    }

    /// The string to search for.
    ///
    /// Port of the record accessor `find()`.
    pub fn find(&self) -> &str {
        &self.find
    }

    /// The replacement string.
    ///
    /// Port of the record accessor `replace()`.
    pub fn replace(&self) -> &str {
        &self.replace
    }

    /// The file from whence the replacement came, if any.
    ///
    /// Port of the record accessor `source()`.
    pub fn source(&self) -> Option<&ResourceFile> {
        self.source.as_ref()
    }
}

impl fmt::Display for GnuDemanglerReplacement {
    /// Port of the overridden `toString()`: `replace + "\t\t" + find`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t\t{}", self.replace, self.find)
    }
}

impl fmt::Debug for GnuDemanglerReplacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnuDemanglerReplacement")
            .field("find", &self.find)
            .field("replace", &self.replace)
            .field("source", &self.source.as_ref().map(ResourceFile::absolute_path))
            .finish()
    }
}

impl PartialEq for GnuDemanglerReplacement {
    /// Port of the record's generated `equals()`. `source` is compared by
    /// [`ResourceFile::absolute_path`], since `ResourceFile` has no equality of its own; two
    /// `None` sources are equal, matching Java's null-safe record field comparison.
    fn eq(&self, other: &Self) -> bool {
        self.find == other.find
            && self.replace == other.replace
            && self.source.as_ref().map(ResourceFile::absolute_path)
                == other.source.as_ref().map(ResourceFile::absolute_path)
    }
}

impl Eq for GnuDemanglerReplacement {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn accessors_return_constructor_values() {
        let r = GnuDemanglerReplacement::new("std::basic_string", "string", None);
        assert_eq!(r.find(), "std::basic_string");
        assert_eq!(r.replace(), "string");
        assert!(r.source().is_none());
    }

    #[test]
    fn to_string_is_replace_then_two_tabs_then_find() {
        let r = GnuDemanglerReplacement::new("find_me", "replace_me", None);
        assert_eq!(r.to_string(), "replace_me\t\tfind_me");
    }

    #[test]
    fn source_round_trips_through_the_accessor() {
        let source = ResourceFile::new(PathBuf::from("/tmp/replacements.txt"));
        let r = GnuDemanglerReplacement::new("a", "b", Some(source));
        assert_eq!(r.source().unwrap().absolute_path(), PathBuf::from("/tmp/replacements.txt").to_string_lossy());
    }

    #[test]
    fn equal_when_all_fields_match() {
        let a = GnuDemanglerReplacement::new("f", "r", None);
        let b = GnuDemanglerReplacement::new("f", "r", None);
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_when_find_differs() {
        let a = GnuDemanglerReplacement::new("f1", "r", None);
        let b = GnuDemanglerReplacement::new("f2", "r", None);
        assert_ne!(a, b);
    }

    #[test]
    fn not_equal_when_one_source_is_present_and_the_other_is_not() {
        let with_source =
            GnuDemanglerReplacement::new("f", "r", Some(ResourceFile::new(PathBuf::from("/a"))));
        let without_source = GnuDemanglerReplacement::new("f", "r", None);
        assert_ne!(with_source, without_source);
    }

    #[test]
    fn equal_when_sources_have_the_same_absolute_path() {
        let a = GnuDemanglerReplacement::new("f", "r", Some(ResourceFile::new(PathBuf::from("/a"))));
        let b = GnuDemanglerReplacement::new("f", "r", Some(ResourceFile::new(PathBuf::from("/a"))));
        assert_eq!(a, b);
    }

    #[test]
    fn debug_includes_find_replace_and_source_path() {
        let r = GnuDemanglerReplacement::new("f", "r", Some(ResourceFile::new(PathBuf::from("/a"))));
        let debug = format!("{r:?}");
        assert!(debug.contains('f'));
        assert!(debug.contains('r'));
    }
}
