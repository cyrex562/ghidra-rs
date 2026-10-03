//! Port of `ghidra.features.base.replace.SearchAndReplaceHandler`.
//!
//! Base class for discoverable search-and-replace handlers. A handler is responsible for
//! searching one or more specific program elements (a [`SearchType`]) for a given search pattern
//! and generating the appropriate `QuickFix`es.
//!
//! # Shape
//!
//! Java is an `abstract class` that carries both state (a `Set<SearchType>` field) and behaviour
//! (one abstract method, two concrete methods), with 6 in-repo subclasses (the
//! `*SearchAndReplaceHandler` classes under `ghidra/features/base/replace/handler/`, not yet
//! ported). Per this crate's composition-over-inheritance convention (see
//! [`QuickFix`](crate::feature::base::quickfix::QuickFix)/`QuickFixState` for the precedent this
//! mirrors), it splits into [`SearchAndReplaceHandlerState`] (the shared field) and the
//! [`SearchAndReplaceHandler`] trait (the abstract method, plus the concrete methods as trait
//! defaults built on top of the state accessor).
//!
//! # Seams
//!
//! * **Cycle.** `SearchType` holds a reference back to the `SearchAndReplaceHandler` that
//!   produced it (`SearchType.handler`), and `SearchAndReplaceHandler.getSearchAndReplaceTypes`
//!   returns `SearchType`s -- a genuine cycle, which is why this class comes up now (a cut
//!   point). It is cut by stubbing the forward reference:
//!   [`SearchType`](crate::feature::seam_stubs::SearchType) is ported here as a minimal
//!   placeholder *without* the back-reference field (see that struct's own docs).
//! * **`SearchAndReplaceQuery`.** Ported immediately after this class in the same batch, at
//!   [`search_and_replace_query`](super::search_and_replace_query); this file now uses that real
//!   type directly rather than a placeholder.
//! * **`find_all`'s `Accumulator<QuickFix>` parameter.** `SearchAndReplaceQuery.findAll` (the
//!   very next class in this batch) fans out to a heterogeneous, runtime-discovered set of
//!   handlers (`Set<SearchAndReplaceHandler>`, one per `SearchType.getHandler()`) and calls
//!   `handler.findAll(...)` on each -- genuinely polymorphic, so `SearchAndReplaceHandler` must
//!   support `Box<dyn SearchAndReplaceHandler>`/`&dyn SearchAndReplaceHandler`. That requires
//!   every trait method, including `find_all`, to be object-safe. `Accumulator<T>`'s `add_all`
//!   took an `impl IntoIterator` argument, which is not object-safe; it was given a `where Self:
//!   Sized` bound (excluding it from the vtable, harmless to every existing concrete/generic
//!   caller) so that `dyn Accumulator<T>` itself becomes constructible. `find_all` accumulates
//!   `Box<dyn QuickFix>` (Java's `QuickFix` is ported as a trait, not a concrete type -- see
//!   [`QuickFix`](crate::feature::base::quickfix::QuickFix)), so its parameter is `&mut dyn
//!   Accumulator<Box<dyn QuickFix>>`.

use super::search_and_replace_query::SearchAndReplaceQuery;
use crate::feature::base::quickfix::QuickFix;
use crate::feature::seam_stubs::SearchType;
use crate::program::model::listing::Program;
use crate::util::datastruct::Accumulator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Shared mutable state for a [`SearchAndReplaceHandler`], mirroring the private `types` field
/// Java declares directly on the abstract `SearchAndReplaceHandler` class.
#[derive(Default)]
pub struct SearchAndReplaceHandlerState {
    types: Vec<SearchType>,
}

impl SearchAndReplaceHandlerState {
    /// Java field initializer: `private Set<SearchType> types = new HashSet<>();`.
    ///
    /// Modeled as a `Vec` rather than a set: Java's `SearchType` does not override
    /// `equals`/`hashCode`, so its `HashSet` is really an identity set, and every real caller
    /// only ever adds distinct, freshly constructed `SearchType`s -- a `Vec` reproduces that
    /// observable behavior without inventing identity semantics this crate has no idiomatic
    /// equivalent for.
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    /// Java: `getSearchAndReplaceTypes()`.
    pub fn search_and_replace_types(&self) -> &[SearchType] {
        &self.types
    }

    /// Java: `protected void addType(SearchType type)`.
    pub fn add_type(&mut self, search_type: SearchType) {
        self.types.push(search_type);
    }
}

/// Port of the abstract `ghidra.features.base.replace.SearchAndReplaceHandler`.
///
/// Java also `implements ExtensionPoint`; that interface has no methods (a pure discovery
/// marker), so it is not modeled as a supertrait bound here -- nothing would be added to
/// implementors.
pub trait SearchAndReplaceHandler {
    /// Accessor for the embedded [`SearchAndReplaceHandlerState`]; the default methods below are
    /// built on top of this pair, the way Java's concrete methods read/write the base class's
    /// private field directly.
    fn state(&self) -> &SearchAndReplaceHandlerState;
    /// Mutable accessor for the embedded [`SearchAndReplaceHandlerState`].
    fn state_mut(&mut self) -> &mut SearchAndReplaceHandlerState;

    /// Performs the search for the pattern and options specified by `query`. As matches are
    /// found, appropriate `QuickFix`es are added to `accumulator`.
    ///
    /// Mirrors `SearchAndReplaceHandler.findAll(Program, SearchAndReplaceQuery,
    /// Accumulator<QuickFix>, TaskMonitor)`.
    fn find_all(
        &self,
        program: &dyn Program,
        query: &SearchAndReplaceQuery,
        accumulator: &mut dyn Accumulator<Box<dyn QuickFix>>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Returns the set of [`SearchType`]s this handler supports.
    ///
    /// Mirrors `SearchAndReplaceHandler.getSearchAndReplaceTypes()`.
    fn search_and_replace_types(&self) -> &[SearchType] {
        self.state().search_and_replace_types()
    }

    /// Registers a [`SearchType`] this handler supports.
    ///
    /// Mirrors `SearchAndReplaceHandler.addType(SearchType)` (`protected` in Java; exposed here
    /// as a normal trait default method, since Rust has no protected-visibility equivalent).
    fn add_type(&mut self, search_type: SearchType) {
        self.state_mut().add_type(search_type);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopHandler {
        state: SearchAndReplaceHandlerState,
    }

    impl NoopHandler {
        fn new() -> Self {
            Self {
                state: SearchAndReplaceHandlerState::new(),
            }
        }
    }

    struct VecAccumulator<T> {
        items: Vec<T>,
    }

    impl<T> Accumulator<T> for VecAccumulator<T> {
        fn add(&mut self, item: T) {
            self.items.push(item);
        }
        fn get_progress(&self) -> usize {
            self.items.len()
        }
    }

    impl SearchAndReplaceHandler for NoopHandler {
        fn state(&self) -> &SearchAndReplaceHandlerState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut SearchAndReplaceHandlerState {
            &mut self.state
        }

        fn find_all(
            &self,
            _program: &dyn Program,
            _query: &SearchAndReplaceQuery,
            _accumulator: &mut dyn Accumulator<Box<dyn QuickFix>>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    #[test]
    fn starts_with_no_search_types() {
        let handler = NoopHandler::new();
        assert!(handler.search_and_replace_types().is_empty());
    }

    #[test]
    fn add_type_accumulates() {
        let mut handler = NoopHandler::new();
        handler.add_type(SearchType::new("Symbols", "Symbol names"));
        handler.add_type(SearchType::new("Comments", "Listing comments"));
        let types = handler.search_and_replace_types();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].name(), "Symbols");
        assert_eq!(types[1].description(), "Listing comments");
    }

    /// Minimal `Program`; only `get_name`/`get_language_id` are non-default, mirroring the same
    /// pattern `TestProgram` uses in `program::database::code::test_support`.
    struct TestProgram;
    impl crate::framework::model::DomainObject for TestProgram {}
    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    #[test]
    fn find_all_default_noop_returns_ok() {
        let mut handler = NoopHandler::new();
        handler.add_type(SearchType::new("Symbols", "Symbol names"));
        let mut acc: VecAccumulator<Box<dyn QuickFix>> = VecAccumulator { items: Vec::new() };
        let query = SearchAndReplaceQuery::new("x", "y", [], false, true, false, 10).expect("valid pattern");
        let program = TestProgram;
        let monitor = crate::util::task::DummyMonitor;
        let result = handler.find_all(&program, &query, &mut acc, &monitor);
        assert!(result.is_ok());
        assert_eq!(acc.items.len(), 0);
    }

    /// `SearchAndReplaceQuery.findAll` (the next class in this batch) fans out over a
    /// heterogeneous, runtime-discovered set of handlers, so `SearchAndReplaceHandler` must be
    /// usable as a trait object.
    #[test]
    fn usable_as_trait_object() {
        let handler: Box<dyn SearchAndReplaceHandler> = Box::new(NoopHandler::new());
        assert!(handler.search_and_replace_types().is_empty());
        let mut acc: VecAccumulator<Box<dyn QuickFix>> = VecAccumulator { items: Vec::new() };
        let query = SearchAndReplaceQuery::new("x", "y", [], false, true, false, 10).expect("valid pattern");
        let program = TestProgram;
        let monitor = crate::util::task::DummyMonitor;
        let result = handler.find_all(&program, &query, &mut acc, &monitor);
        assert!(result.is_ok());
    }
}
