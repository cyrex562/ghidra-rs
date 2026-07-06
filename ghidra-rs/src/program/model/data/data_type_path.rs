use std::fmt;

use crate::program::model::data::category_path::{CategoryPath, DELIMITER_CHAR};

/// Object to hold a category path and a datatype name. They are held separately so that the
/// datatype name can contain a categoryPath delimiter (`"/"`) character.
///
/// Port of `ghidra.program.model.data.DataTypePath`. The Java class implements
/// `Comparable<DataTypePath>` and overrides `equals`/`hashCode`; those are represented here by
/// deriving [`Ord`]/[`Eq`]/[`Hash`] on the same `(category_path, data_type_name)` fields the Java
/// methods compare, which reproduces the Java `compareTo` (category path first, then name)
/// exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DataTypePath {
    category_path: CategoryPath,
    data_type_name: String,
}

impl DataTypePath {
    /// Create a `DataTypePath` from a category path and a datatype name.
    pub fn new(category_path: CategoryPath, data_type_name: impl Into<String>) -> Self {
        DataTypePath { category_path, data_type_name: data_type_name.into() }
    }

    /// Create a `DataTypePath` from a forward-slash-delimited category path string and a
    /// datatype name.
    ///
    /// # Errors
    /// Returns `Err` if `category_path` is not a valid category path string, mirroring the
    /// `IllegalArgumentException` thrown by the Java constructor's call to `new CategoryPath(String)`.
    pub fn parse(category_path: &str, data_type_name: impl Into<String>) -> Result<Self, String> {
        Ok(DataTypePath::new(CategoryPath::parse(category_path)?, data_type_name))
    }

    /// Returns the categoryPath for the datatype represented by this datatype path (i.e. the
    /// `CategoryPath` that contains the `DataType` that this `DataTypePath` points to).
    pub fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    /// Determine if the specified `other_category_path` is an ancestor of this data type path
    /// (i.e. does this data type's category or any of its parent hierarchy correspond to the
    /// specified category path).
    pub fn is_ancestor(&self, other_category_path: &CategoryPath) -> bool {
        self.category_path.is_ancestor_or_self(other_category_path)
    }

    /// Returns the name of the datatype.
    pub fn get_data_type_name(&self) -> String {
        self.data_type_name.clone()
    }

    /// Returns the full path of this datatype. NOTE: if the datatype name contains any `"/"`
    /// characters, then the resulting path string may be ambiguous as to where the category path
    /// ends and the datatype name begins.
    pub fn get_path(&self) -> String {
        let mut path = self.category_path.get_path();
        if !path.ends_with(DELIMITER_CHAR) {
            path.push(DELIMITER_CHAR);
        }
        path.push_str(&self.data_type_name);
        path
    }
}

impl fmt::Display for DataTypePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_path_root_category() {
        let dtp = DataTypePath::parse("/", "foo").unwrap();
        assert_eq!("/foo", dtp.get_path());
    }

    #[test]
    fn get_path_nested_category() {
        let dtp = DataTypePath::parse("/aaa/bbb", "foo").unwrap();
        assert_eq!("/aaa/bbb/foo", dtp.get_path());
    }

    #[test]
    fn to_string_matches_get_path() {
        let dtp = DataTypePath::parse("/aaa", "foo").unwrap();
        assert_eq!(dtp.get_path(), dtp.to_string());
    }

    #[test]
    fn new_with_category_path_value() {
        let category_path = CategoryPath::parse("/aaa/bbb").unwrap();
        let dtp = DataTypePath::new(category_path.clone(), "foo");
        assert_eq!(category_path, dtp.get_category_path());
        assert_eq!("foo", dtp.get_data_type_name());
    }

    #[test]
    fn parse_invalid_category_path_is_error() {
        assert!(DataTypePath::parse("apple", "foo").is_err());
    }

    #[test]
    fn is_ancestor_true_for_containing_category() {
        let dtp = DataTypePath::parse("/aaa/bbb", "foo").unwrap();
        let ancestor = CategoryPath::parse("/aaa").unwrap();
        assert!(dtp.is_ancestor(&ancestor));
    }

    #[test]
    fn is_ancestor_false_for_unrelated_category() {
        let dtp = DataTypePath::parse("/aaa/bbb", "foo").unwrap();
        let unrelated = CategoryPath::parse("/ccc").unwrap();
        assert!(!dtp.is_ancestor(&unrelated));
    }

    #[test]
    fn equality_and_hash_are_structural() {
        use std::collections::HashSet;

        let a1 = DataTypePath::parse("/aaa/bbb", "foo").unwrap();
        let a2 = DataTypePath::parse("/aaa/bbb", "foo").unwrap();
        let b = DataTypePath::parse("/aaa/bbb", "bar").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);

        let mut set = HashSet::new();
        set.insert(a1.clone());
        assert!(set.contains(&a2));
        assert!(!set.contains(&b));
    }

    #[test]
    fn ordering_by_category_path_then_name() {
        let a = DataTypePath::parse("/aaa", "zzz").unwrap();
        let b = DataTypePath::parse("/bbb", "aaa").unwrap();
        assert!(a < b);

        let c1 = DataTypePath::parse("/aaa", "one").unwrap();
        let c2 = DataTypePath::parse("/aaa", "two").unwrap();
        assert!(c1 < c2);
    }
}
