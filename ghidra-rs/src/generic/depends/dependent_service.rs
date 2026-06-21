use std::any::TypeId;

/// Uninhabited sentinel type used as the default "no override" marker for
/// [`DependentService`]. Mirrors Java's `DependentService.Sentinel` enum.
pub enum Sentinel {}

/// Metadata for a dependency-injection point, mirroring Java's `@DependentService`
/// runtime annotation.
///
/// In the Java original this annotation is placed on fields (injection targets) or
/// methods (factory methods) so that `DependentServiceResolver` can wire services
/// together without manual plumbing. In Rust, where there is no reflective annotation
/// system, the same metadata is carried in this struct and associated with members via
/// the resolver's registration API.
///
/// When `override_type` is `None` the injection point uses the declared field/parameter
/// type; when it is `Some(TypeId)` that type overrides the declared one (matching Java's
/// `@DependentService(override = Foo.class)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentService {
    /// Overriding service type, or `None` for the default (Java: `Sentinel.class`).
    pub override_type: Option<TypeId>,
}

impl DependentService {
    /// Creates a `DependentService` with no override (the default, equivalent to Java's
    /// `@DependentService` without arguments).
    pub fn new() -> Self {
        Self { override_type: None }
    }

    /// Creates a `DependentService` that overrides the injection point with type `T`
    /// (equivalent to Java's `@DependentService(override = T.class)`).
    pub fn with_override<T: 'static>() -> Self {
        Self {
            override_type: Some(TypeId::of::<T>()),
        }
    }

    /// Returns `true` when no override was specified (the [`Sentinel`] default applies).
    pub fn is_default(&self) -> bool {
        self.override_type.is_none()
    }
}

impl Default for DependentService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ServiceA;
    struct ServiceB;

    #[test]
    fn new_has_no_override() {
        let ds = DependentService::new();
        assert!(ds.override_type.is_none());
        assert!(ds.is_default());
    }

    #[test]
    fn default_equals_new() {
        assert_eq!(DependentService::default(), DependentService::new());
    }

    #[test]
    fn with_override_stores_type_id() {
        let ds = DependentService::with_override::<ServiceA>();
        assert_eq!(ds.override_type, Some(TypeId::of::<ServiceA>()));
        assert!(!ds.is_default());
    }

    #[test]
    fn different_overrides_are_not_equal() {
        let ds_a = DependentService::with_override::<ServiceA>();
        let ds_b = DependentService::with_override::<ServiceB>();
        assert_ne!(ds_a, ds_b);
    }

    #[test]
    fn same_override_type_is_equal() {
        let ds1 = DependentService::with_override::<ServiceA>();
        let ds2 = DependentService::with_override::<ServiceA>();
        assert_eq!(ds1, ds2);
    }

    #[test]
    fn sentinel_is_uninhabited() {
        // Sentinel has no variants — this is a compile-time check.
        // Verify the type exists and can be used in match arms.
        fn accept_sentinel(s: Sentinel) -> ! {
            match s {}
        }
        let _ = accept_sentinel as fn(Sentinel) -> !;
    }

    #[test]
    fn clone_works() {
        let ds = DependentService::with_override::<ServiceA>();
        assert_eq!(ds.clone(), ds);
    }
}
