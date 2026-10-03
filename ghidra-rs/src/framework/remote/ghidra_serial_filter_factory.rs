use std::sync::{Arc, OnceLock};

use super::ghidra_object_input_filter::{FilterInfo, FilterStatus, GhidraObjectInputFilter};

/// The general-purpose single-method filter interface `GhidraSerialFilterFactory` composes
/// together, standing in for `java.io.ObjectInputFilter` -- the JDK interface `current`/
/// `requested` are typed as in Java's `apply(ObjectInputFilter, ObjectInputFilter)`.
///
/// This is deliberately a separate (smaller) trait from [`GhidraObjectInputFilter`], not a
/// supertrait relationship: in Java, `GhidraObjectInputFilter` is just *one* implementation of the
/// general `ObjectInputFilter` interface (the global filter this factory always folds in), while
/// `current`/`requested` here can be *any* filter an `ObjectInputStream` happens to already carry
/// or request. [`GhidraFilterAdapter`] bridges a [`GhidraObjectInputFilter`] into this trait at the
/// one place ([`GhidraSerialFilterFactory::apply`]) that needs to treat the global filter uniformly
/// with `current`/`requested`.
pub trait ObjectInputFilter: Send + Sync {
    fn check_input(&self, info: &FilterInfo) -> FilterStatus;
}

/// Adapts a [`GhidraObjectInputFilter`] to the smaller [`ObjectInputFilter`] interface.
struct GhidraFilterAdapter(Arc<dyn GhidraObjectInputFilter + Send + Sync>);

impl ObjectInputFilter for GhidraFilterAdapter {
    fn check_input(&self, info: &FilterInfo) -> FilterStatus {
        self.0.check_input(info)
    }
}

/// A filter that ANDs two [`ObjectInputFilter`]s together.
///
/// Port of the composition `java.io.ObjectInputFilter.Config.merge(ObjectInputFilter,
/// ObjectInputFilter)` performs (used, but not itself defined, by `GhidraSerialFilterFactory`):
/// the merged filter rejects if either side rejects, allows if either side allows (and neither
/// rejects), and is otherwise undecided.
struct MergedFilter {
    first: Arc<dyn ObjectInputFilter>,
    second: Arc<dyn ObjectInputFilter>,
}

impl ObjectInputFilter for MergedFilter {
    fn check_input(&self, info: &FilterInfo) -> FilterStatus {
        let first_status = self.first.check_input(info);
        if first_status == FilterStatus::Rejected {
            return FilterStatus::Rejected;
        }
        let second_status = self.second.check_input(info);
        if second_status == FilterStatus::Rejected {
            return FilterStatus::Rejected;
        }
        if first_status == FilterStatus::Allowed || second_status == FilterStatus::Allowed {
            return FilterStatus::Allowed;
        }
        FilterStatus::Undecided
    }
}

fn merge(a: Arc<dyn ObjectInputFilter>, b: Arc<dyn ObjectInputFilter>) -> Arc<dyn ObjectInputFilter> {
    Arc::new(MergedFilter { first: a, second: b })
}

/// Process-wide installed factory instance, mirroring
/// `GhidraSerialFilterFactory.filterFactoryRef` (a Java `AtomicReference`). `OnceLock` gives the
/// same "settable exactly once, safely racy" semantics `AtomicReference.compareAndSet` provided.
static FILTER_FACTORY_REF: OnceLock<Arc<GhidraSerialFilterFactory>> = OnceLock::new();

/// Provides the serial filter factory which imposes a [`GhidraObjectInputFilter`] as a global
/// serial input filter.
///
/// Port of `ghidra.framework.remote.GhidraSerialFilterFactory`.
///
/// Java implements `BinaryOperator<ObjectInputFilter>`: the JDK invokes `apply(current,
/// requested)` on the installed factory every time an `ObjectInputStream` is created or has its
/// filter changed, letting the factory fold its own (always-applied) global filter into whatever
/// filter that stream already has or is requesting. That mechanism -- native Java object
/// deserialization, and the JVM-level `ObjectInputFilter.Config.setSerialFilterFactory` hook that
/// installs a factory into it -- has no Rust equivalent (Rust has no reflective object
/// deserialization to filter in the first place). What *is* ported is the portable half: the
/// singleton-installation bookkeeping and the `current`/`requested`/global merge algorithm
/// ([`Self::apply`]), which callers of a Rust analogue to Java's (de)serialization path can still
/// use to combine filters the same way.
pub struct GhidraSerialFilterFactory {
    global_filter: Arc<dyn GhidraObjectInputFilter + Send + Sync>,
}

impl GhidraSerialFilterFactory {
    /// Constructs a new factory wrapping `global_filter` and installs it as the process-wide
    /// singleton.
    ///
    /// Port of `GhidraSerialFilterFactory()`. Java's no-arg constructor builds its own
    /// `GhidraObjectInputFilter`; since [`GhidraObjectInputFilter`] is ported as a trait with no
    /// concrete default implementor in this crate (see that module's doc comment), the filter is
    /// supplied by the caller instead.
    ///
    /// Returns `Err` if a factory instance has already been installed, mirroring Java throwing
    /// `IllegalStateException("Serial filter factory has previously been instantiated")`.
    pub fn new(
        global_filter: Arc<dyn GhidraObjectInputFilter + Send + Sync>,
    ) -> Result<Arc<Self>, String> {
        let factory = Arc::new(Self { global_filter });
        match FILTER_FACTORY_REF.set(factory.clone()) {
            Ok(()) => Ok(factory),
            Err(_) => Err("Serial filter factory has previously been instantiated".to_string()),
        }
    }

    /// Returns the already-installed factory singleton, installing one built from
    /// `build_global_filter` if none exists yet.
    ///
    /// Port of `GhidraSerialFilterFactory.getOrInstallInstance()`. Java's version additionally
    /// calls `ObjectInputFilter.Config.setSerialFilterFactory(newFactory)` when it installs a new
    /// factory, registering it with the JVM; there is no equivalent registration to perform here
    /// (see the type-level doc comment).
    ///
    /// `build_global_filter` is only invoked if no factory is already installed (mirroring "If a
    /// new factory is installed it will have an uninitialized `GhidraObjectInputFilter`
    /// instance" -- callers control what "uninitialized" means for their filter type).
    pub fn get_or_install_instance(
        build_global_filter: impl FnOnce() -> Arc<dyn GhidraObjectInputFilter + Send + Sync>,
    ) -> Arc<Self> {
        if let Some(existing) = FILTER_FACTORY_REF.get() {
            return existing.clone();
        }
        let candidate = Arc::new(Self {
            global_filter: build_global_filter(),
        });
        match FILTER_FACTORY_REF.set(candidate.clone()) {
            Ok(()) => candidate,
            // Lost a race with another thread installing a factory first; use theirs, matching
            // Java's `synchronized` method (which never lets this race happen in the first
            // place) in spirit: exactly one factory instance is ever observed by any caller.
            Err(_) => FILTER_FACTORY_REF.get().unwrap().clone(),
        }
    }

    /// Returns the global filter this factory always folds into every merge.
    ///
    /// Port of the package-private `GhidraSerialFilterFactory.getSerialFilter()`.
    pub(crate) fn get_serial_filter(&self) -> &Arc<dyn GhidraObjectInputFilter + Send + Sync> {
        &self.global_filter
    }

    /// Merges `current` and `requested` with this factory's global filter, which is always
    /// applied.
    ///
    /// Port of `GhidraSerialFilterFactory.apply(ObjectInputFilter, ObjectInputFilter)`.
    pub fn apply(
        &self,
        current: Option<Arc<dyn ObjectInputFilter>>,
        requested: Option<Arc<dyn ObjectInputFilter>>,
    ) -> Arc<dyn ObjectInputFilter> {
        let global: Arc<dyn ObjectInputFilter> =
            Arc::new(GhidraFilterAdapter(self.global_filter.clone()));
        match (current, requested) {
            (None, None) => global,
            (None, Some(requested)) => merge(requested, global),
            (Some(current), None) => merge(current, global),
            (Some(current), Some(requested)) => merge(merge(current, requested), global),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::ghidra_object_input_filter::{
        MAXARRAY_DEFAULT, MAXBYTES_DEFAULT, MAXDEPTH_DEFAULT, MAXREFS_DEFAULT,
    };

    struct AlwaysStatus(FilterStatus);
    impl ObjectInputFilter for AlwaysStatus {
        fn check_input(&self, _info: &FilterInfo) -> FilterStatus {
            self.0
        }
    }

    struct StubGlobalFilter;
    impl GhidraObjectInputFilter for StubGlobalFilter {
        fn max_array(&self) -> i64 {
            MAXARRAY_DEFAULT
        }
        fn max_refs(&self) -> i64 {
            MAXREFS_DEFAULT
        }
        fn max_depth(&self) -> i64 {
            MAXDEPTH_DEFAULT
        }
        fn max_bytes(&self) -> i64 {
            MAXBYTES_DEFAULT
        }
        fn is_allowed_remote_interface(&self, _interface_name: &str) -> bool {
            false
        }
        fn pattern_filter_initialized(&self) -> bool {
            // Always undecided from `check_input`'s default impl, since these merge-logic tests
            // don't exercise `check_input`'s own algorithm -- only `apply`'s composition of it
            // with `current`/`requested`.
            false
        }
        fn pattern_filter_check(&self, _info: &FilterInfo) -> FilterStatus {
            FilterStatus::Undecided
        }
    }

    fn undecided_info() -> FilterInfo {
        FilterInfo::default()
    }

    #[test]
    fn merged_filter_rejects_if_either_side_rejects() {
        let a: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));
        let b: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Rejected));
        let merged = merge(a, b);
        assert_eq!(merged.check_input(&undecided_info()), FilterStatus::Rejected);

        let a: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Rejected));
        let b: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));
        let merged = merge(a, b);
        assert_eq!(merged.check_input(&undecided_info()), FilterStatus::Rejected);
    }

    #[test]
    fn merged_filter_allows_if_either_side_allows_and_neither_rejects() {
        let a: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));
        let b: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Undecided));
        let merged = merge(a, b);
        assert_eq!(merged.check_input(&undecided_info()), FilterStatus::Allowed);
    }

    #[test]
    fn merged_filter_is_undecided_if_both_sides_undecided() {
        let a: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Undecided));
        let b: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Undecided));
        let merged = merge(a, b);
        assert_eq!(merged.check_input(&undecided_info()), FilterStatus::Undecided);
    }

    #[test]
    fn apply_with_no_current_or_requested_returns_the_global_filter() {
        let factory = GhidraSerialFilterFactory {
            global_filter: Arc::new(StubGlobalFilter),
        };
        let result = factory.apply(None, None);
        // The stub global filter's `check_input` default impl returns `Undecided` for an
        // uninitialized pattern filter, regardless of `info` -- confirming `apply` actually
        // dispatched to the global filter and not e.g. always returning `Allowed`.
        assert_eq!(result.check_input(&undecided_info()), FilterStatus::Undecided);
    }

    /// A global filter that rejects every class-named candidate (its `pattern_filter_check`
    /// never allows, and once "initialized", `GhidraObjectInputFilter::check_input`'s default
    /// logic rejects any class-named candidate no filter step explicitly allowed). Used to prove
    /// `apply`'s result really does dispatch through the global filter rather than only through
    /// `current`/`requested`.
    struct RejectingGlobalFilter;
    impl GhidraObjectInputFilter for RejectingGlobalFilter {
        fn max_array(&self) -> i64 {
            MAXARRAY_DEFAULT
        }
        fn max_refs(&self) -> i64 {
            MAXREFS_DEFAULT
        }
        fn max_depth(&self) -> i64 {
            MAXDEPTH_DEFAULT
        }
        fn max_bytes(&self) -> i64 {
            MAXBYTES_DEFAULT
        }
        fn is_allowed_remote_interface(&self, _interface_name: &str) -> bool {
            false
        }
        fn pattern_filter_initialized(&self) -> bool {
            true
        }
        fn pattern_filter_check(&self, _info: &FilterInfo) -> FilterStatus {
            FilterStatus::Undecided
        }
    }

    #[test]
    fn apply_folds_in_the_global_filter_even_when_current_and_requested_both_allow() {
        let factory = GhidraSerialFilterFactory {
            global_filter: Arc::new(RejectingGlobalFilter),
        };
        let current: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));
        let requested: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));

        let result = factory.apply(Some(current), Some(requested));

        // The global filter's own rejection wins even though both `current` and `requested`
        // allow -- exactly the property Java's constructor doc comment describes ("Our filter
        // is always applied").
        assert_eq!(
            result.check_input(&FilterInfo {
                serial_class_name: Some("some.Class".to_string()),
                ..Default::default()
            }),
            FilterStatus::Rejected
        );
    }

    #[test]
    fn apply_allows_when_global_is_undecided_and_current_or_requested_allow() {
        // `StubGlobalFilter::pattern_filter_initialized` is `false`, so its `check_input` is
        // unconditionally `Undecided` (the default impl's lazy-initialization early return) --
        // it never rejects, letting `current`/`requested` decide.
        let factory = GhidraSerialFilterFactory {
            global_filter: Arc::new(StubGlobalFilter),
        };
        let current: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));
        let requested: Arc<dyn ObjectInputFilter> = Arc::new(AlwaysStatus(FilterStatus::Allowed));

        let result = factory.apply(Some(current), Some(requested));

        assert_eq!(
            result.check_input(&FilterInfo {
                serial_class_name: Some("some.Class".to_string()),
                ..Default::default()
            }),
            FilterStatus::Allowed
        );
    }

    #[test]
    fn get_serial_filter_returns_the_configured_global_filter() {
        let factory = GhidraSerialFilterFactory {
            global_filter: Arc::new(StubGlobalFilter),
        };
        // `pattern_filter_initialized` is `false` on `StubGlobalFilter`; confirm the returned
        // reference really is that same filter by checking its distinguishing behavior.
        assert!(!factory.get_serial_filter().pattern_filter_initialized());
    }

    #[test]
    fn constructing_a_second_factory_after_one_is_already_installed_fails() {
        // `FILTER_FACTORY_REF` is a process-wide static, so -- to keep this test independent of
        // whatever other tests in this binary might do with `GhidraSerialFilterFactory::new` --
        // this only asserts the *second* install in a row fails, without assuming a pristine
        // starting state.
        let first = GhidraSerialFilterFactory::new(Arc::new(StubGlobalFilter));
        // Either this is the first install ever in this test binary (Ok) or some earlier test
        // already installed one (Err); either way, a second attempt right after must fail.
        let _ = first;
        let second = GhidraSerialFilterFactory::new(Arc::new(StubGlobalFilter));
        // `Result::unwrap_err` would require `Arc<GhidraSerialFilterFactory>: Debug`, which it
        // isn't (the trait object field it wraps doesn't require `Debug`); match instead.
        match second {
            Ok(_) => panic!("expected a second install to fail"),
            Err(message) => assert!(message.contains("previously been instantiated")),
        }
    }

    #[test]
    fn get_or_install_instance_reuses_an_existing_installation() {
        // Ensure some factory is installed (independent of whether this test binary already
        // installed one via another test).
        let installed = GhidraSerialFilterFactory::get_or_install_instance(|| Arc::new(StubGlobalFilter));
        let reused = GhidraSerialFilterFactory::get_or_install_instance(|| {
            panic!("build_global_filter must not be called when a factory is already installed")
        });
        assert!(Arc::ptr_eq(&installed, &reused));
    }
}
