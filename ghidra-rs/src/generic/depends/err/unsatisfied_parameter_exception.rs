use std::any::TypeId;
use std::collections::HashSet;
use std::fmt;

/// Error raised when a required constructor parameter cannot be resolved.
///
/// Mirrors Java's `generic.depends.err.UnsatisfiedParameterException`, which is
/// thrown by the dependency resolver when it cannot find a suitable value for a
/// required parameter of the next service to be constructed — often indicating a
/// circular dependency.  The `left` set identifies each unresolvable type by its
/// [`TypeId`] (the Rust equivalent of Java's `Class<?>`).
#[derive(Debug)]
pub struct UnsatisfiedParameterException {
    message: String,
    left: HashSet<TypeId>,
}

impl UnsatisfiedParameterException {
    /// Creates a new exception for the given set of unresolved parameter types.
    ///
    /// The error message mirrors Java's format:
    /// "Could not resolve required parameter for next in: … Note: it may be a
    /// circular dependency."  Because [`TypeId`] has no human-readable name the
    /// message includes the count of unresolved types rather than their names.
    pub fn new(left: HashSet<TypeId>) -> Self {
        let message = format!(
            "Could not resolve required parameter for next in: {} type(s). \
             Note: it may be a circular dependency.",
            left.len()
        );
        Self { message, left }
    }

    /// Returns the set of parameter types that could not be resolved.
    pub fn left(&self) -> &HashSet<TypeId> {
        &self.left
    }
}

impl fmt::Display for UnsatisfiedParameterException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnsatisfiedParameterException {}

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
    fn stores_left_set() {
        let ids = make_set([TypeId::of::<ServiceA>(), TypeId::of::<ServiceB>()]);
        let ex = UnsatisfiedParameterException::new(ids.clone());
        assert_eq!(ex.left(), &ids);
    }

    #[test]
    fn message_includes_count() {
        let ex = UnsatisfiedParameterException::new(make_set([
            TypeId::of::<ServiceA>(),
            TypeId::of::<ServiceB>(),
        ]));
        assert!(ex.to_string().contains('2'));
    }

    #[test]
    fn message_mentions_circular_dependency() {
        let ex = UnsatisfiedParameterException::new(make_set([TypeId::of::<ServiceA>()]));
        assert!(ex.to_string().contains("circular dependency"));
    }

    #[test]
    fn display_matches_message() {
        let ex = UnsatisfiedParameterException::new(make_set([TypeId::of::<ServiceA>()]));
        assert_eq!(ex.to_string(), ex.message);
    }

    #[test]
    fn empty_set_is_valid() {
        let ex = UnsatisfiedParameterException::new(HashSet::new());
        assert!(ex.left().is_empty());
        assert!(ex.to_string().contains('0'));
    }

    #[test]
    fn single_unresolved_type() {
        let ex = UnsatisfiedParameterException::new(make_set([TypeId::of::<ServiceC>()]));
        assert_eq!(ex.left().len(), 1);
        assert!(ex.left().contains(&TypeId::of::<ServiceC>()));
    }

    #[test]
    fn implements_error_trait() {
        let ex = UnsatisfiedParameterException::new(make_set([TypeId::of::<ServiceA>()]));
        let _: &dyn std::error::Error = &ex;
    }

    #[test]
    fn error_source_is_none() {
        let ex = UnsatisfiedParameterException::new(make_set([TypeId::of::<ServiceA>()]));
        assert!(std::error::Error::source(&ex).is_none());
    }

    #[test]
    fn left_set_is_unchanged_after_construction() {
        let ids = make_set([TypeId::of::<ServiceA>(), TypeId::of::<ServiceB>()]);
        let ex = UnsatisfiedParameterException::new(ids.clone());
        assert_eq!(ex.left().len(), 2);
        assert!(ex.left().contains(&TypeId::of::<ServiceA>()));
        assert!(ex.left().contains(&TypeId::of::<ServiceB>()));
    }
}
