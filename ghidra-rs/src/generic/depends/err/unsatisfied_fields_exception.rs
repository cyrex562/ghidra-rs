use std::any::TypeId;
use std::collections::HashSet;
use std::fmt;

/// Error raised when dependency fields have no suitable constructor.
///
/// Mirrors Java's `generic.depends.err.UnsatisfiedFieldsException`, which is thrown
/// by the dependency resolver when one or more injected fields cannot be satisfied.
/// The `missing` set identifies each unsatisfied type by its [`TypeId`] (the Rust
/// equivalent of Java's `Class<?>`).
#[derive(Debug)]
pub struct UnsatisfiedFieldsException {
    message: String,
    missing: HashSet<TypeId>,
}

impl UnsatisfiedFieldsException {
    /// Creates a new exception for the given set of unsatisfied types.
    ///
    /// The error message mirrors Java's format: "There are fields without suitable
    /// constructors: …". Because [`TypeId`] has no human-readable representation the
    /// message includes the count of missing types rather than their names.
    pub fn new(missing: HashSet<TypeId>) -> Self {
        let message = format!(
            "There are fields without suitable constructors: {} missing type(s)",
            missing.len()
        );
        Self { message, missing }
    }

    /// Returns the set of types that could not be satisfied.
    pub fn missing(&self) -> &HashSet<TypeId> {
        &self.missing
    }
}

impl fmt::Display for UnsatisfiedFieldsException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnsatisfiedFieldsException {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ServiceA;
    struct ServiceB;
    struct ServiceC;

    fn make_set(ids: impl IntoIterator<Item = TypeId>) -> HashSet<TypeId> {
        ids.into_iter().collect()
    }

    #[test]
    fn stores_missing_set() {
        let ids = make_set([TypeId::of::<ServiceA>(), TypeId::of::<ServiceB>()]);
        let ex = UnsatisfiedFieldsException::new(ids.clone());
        assert_eq!(ex.missing(), &ids);
    }

    #[test]
    fn message_includes_count() {
        let ex = UnsatisfiedFieldsException::new(make_set([
            TypeId::of::<ServiceA>(),
            TypeId::of::<ServiceB>(),
        ]));
        assert!(ex.to_string().contains('2'));
    }

    #[test]
    fn display_matches_message() {
        let ex = UnsatisfiedFieldsException::new(make_set([TypeId::of::<ServiceA>()]));
        assert_eq!(ex.to_string(), ex.message);
    }

    #[test]
    fn empty_set_is_valid() {
        let ex = UnsatisfiedFieldsException::new(HashSet::new());
        assert!(ex.missing().is_empty());
        assert!(ex.to_string().contains('0'));
    }

    #[test]
    fn single_missing_type() {
        let ex = UnsatisfiedFieldsException::new(make_set([TypeId::of::<ServiceC>()]));
        assert_eq!(ex.missing().len(), 1);
        assert!(ex.missing().contains(&TypeId::of::<ServiceC>()));
    }

    #[test]
    fn implements_error_trait() {
        let ex = UnsatisfiedFieldsException::new(make_set([TypeId::of::<ServiceA>()]));
        let _: &dyn std::error::Error = &ex;
    }

    #[test]
    fn error_source_is_none() {
        let ex = UnsatisfiedFieldsException::new(make_set([TypeId::of::<ServiceA>()]));
        assert!(std::error::Error::source(&ex).is_none());
    }

    #[test]
    fn missing_set_is_unchanged_after_construction() {
        let ids = make_set([TypeId::of::<ServiceA>(), TypeId::of::<ServiceB>()]);
        let ex = UnsatisfiedFieldsException::new(ids.clone());
        assert_eq!(ex.missing().len(), 2);
        assert!(ex.missing().contains(&TypeId::of::<ServiceA>()));
        assert!(ex.missing().contains(&TypeId::of::<ServiceB>()));
    }
}
