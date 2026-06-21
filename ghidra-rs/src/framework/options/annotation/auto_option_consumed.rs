/// Metadata for an option-consumption point, mirroring Java's `@AutoOptionConsumed`
/// runtime annotation.
///
/// In Java this annotation is placed on fields or methods so that the options
/// framework can automatically wire named option values into the annotated member
/// at runtime. In Rust, where there is no reflective annotation system, the same
/// metadata is carried in this struct and associated with members via the framework's
/// registration API.
///
/// The `category` path is optional (defaults to empty, meaning the root category).
/// The `name` path must contain at least one element identifying the option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoOptionConsumed {
    /// Optional category path components (Java: `category = {"A", "B"}`).
    pub category: Vec<String>,
    /// Option name path components; must be non-empty (Java: `name = {"MyOption"}`).
    pub name: Vec<String>,
}

impl AutoOptionConsumed {
    /// Creates an `AutoOptionConsumed` with only a name and no category prefix,
    /// matching `@AutoOptionConsumed(name = {...})`.
    ///
    /// # Panics
    /// Panics when `name` is empty, mirroring the Java requirement that `name()` has
    /// no default and must be supplied.
    pub fn new(name: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let name: Vec<String> = name.into_iter().map(Into::into).collect();
        assert!(!name.is_empty(), "AutoOptionConsumed: name must not be empty");
        Self { category: Vec::new(), name }
    }

    /// Creates an `AutoOptionConsumed` with an explicit category prefix,
    /// matching `@AutoOptionConsumed(category = {...}, name = {...})`.
    ///
    /// # Panics
    /// Panics when `name` is empty.
    pub fn with_category(
        category: impl IntoIterator<Item = impl Into<String>>,
        name: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let name: Vec<String> = name.into_iter().map(Into::into).collect();
        assert!(!name.is_empty(), "AutoOptionConsumed: name must not be empty");
        Self {
            category: category.into_iter().map(Into::into).collect(),
            name,
        }
    }

    /// Returns `true` when no category prefix was specified (the default).
    pub fn has_category(&self) -> bool {
        !self.category.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_name_and_empty_category() {
        let a = AutoOptionConsumed::new(["MyOption"]);
        assert_eq!(a.name, vec!["MyOption"]);
        assert!(a.category.is_empty());
        assert!(!a.has_category());
    }

    #[test]
    fn new_with_multiple_name_segments() {
        let a = AutoOptionConsumed::new(["Foo", "Bar"]);
        assert_eq!(a.name, vec!["Foo", "Bar"]);
    }

    #[test]
    fn with_category_stores_both() {
        let a = AutoOptionConsumed::with_category(["Debug", "Trace"], ["MyOption"]);
        assert_eq!(a.category, vec!["Debug", "Trace"]);
        assert_eq!(a.name, vec!["MyOption"]);
        assert!(a.has_category());
    }

    #[test]
    fn with_empty_category_has_no_category() {
        let a = AutoOptionConsumed::with_category([] as [&str; 0], ["MyOption"]);
        assert!(a.category.is_empty());
        assert!(!a.has_category());
    }

    #[test]
    #[should_panic(expected = "name must not be empty")]
    fn new_empty_name_panics() {
        AutoOptionConsumed::new([] as [&str; 0]);
    }

    #[test]
    #[should_panic(expected = "name must not be empty")]
    fn with_category_empty_name_panics() {
        AutoOptionConsumed::with_category(["Cat"], [] as [&str; 0]);
    }

    #[test]
    fn equality_holds_for_identical_instances() {
        let a = AutoOptionConsumed::with_category(["X"], ["Y"]);
        let b = AutoOptionConsumed::with_category(["X"], ["Y"]);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_when_names_differ() {
        let a = AutoOptionConsumed::new(["Opt1"]);
        let b = AutoOptionConsumed::new(["Opt2"]);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_when_categories_differ() {
        let a = AutoOptionConsumed::with_category(["A"], ["Opt"]);
        let b = AutoOptionConsumed::with_category(["B"], ["Opt"]);
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = AutoOptionConsumed::with_category(["Cat"], ["Name"]);
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn debug_contains_name() {
        let a = AutoOptionConsumed::new(["DebugOption"]);
        let s = format!("{a:?}");
        assert!(s.contains("DebugOption"));
    }
}
