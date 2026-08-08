//! A view over a trace's namespace symbols.
//!
//! Port of `ghidra.trace.model.symbol.TraceNamespaceSymbolView`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java interface extends `TraceSymbolNoDuplicatesView<TraceNamespaceSymbol>`, itself
//! unported; see [`TraceSymbolNoDuplicatesView`](crate::trace::seam_stubs::TraceSymbolNoDuplicatesView)
//! for why that supertrait is a marker here.

use std::sync::Arc;

use thiserror::Error;

use crate::program::model::symbol::SourceType;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::seam_stubs::TraceSymbolNoDuplicatesView;
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Error produced by [`TraceNamespaceSymbolView::add`].
///
/// Combines the two checked exceptions declared on the Java method
/// `TraceNamespaceSymbolView.add(String, TraceNamespaceSymbol, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum AddNamespaceError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// A view over a trace's namespace symbols.
pub trait TraceNamespaceSymbolView: TraceSymbolNoDuplicatesView {
    /// Add a new namespace symbol.
    ///
    /// # Errors
    /// Returns [`AddNamespaceError::Duplicate`] if `name` is duplicated in `parent`, or
    /// [`AddNamespaceError::InvalidInput`] if `name` is not a valid symbol name.
    fn add(
        &self,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceNamespaceSymbol>, AddNamespaceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::{Namespace, NamespaceType, Symbol, SymbolType};
    use crate::program::model::address::Address;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct MockNamespaceSymbol {
        id: i64,
        name: String,
    }

    impl Namespace for MockNamespaceSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_type(&self) -> NamespaceType {
            NamespaceType::Namespace
        }
        fn is_global(&self) -> bool {
            self.id == crate::program::model::symbol::GLOBAL_NAMESPACE_ID
        }
    }

    impl Symbol for MockNamespaceSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl TraceSymbol for MockNamespaceSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }
        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn set_pinned(&mut self, _pinned: bool) {}
        fn is_pinned(&self) -> bool {
            false
        }
    }

    impl TraceNamespaceSymbol for MockNamespaceSymbol {
        fn get_parent_trace_namespace_symbol(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }
        fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }
        fn get_path(&self) -> Vec<String> {
            vec![self.name.clone()]
        }
    }

    /// A view that records names added under each parent (by ID), rejecting duplicates within a
    /// parent and empty names, to prove the trait's error wiring and object-safety.
    struct MockView {
        next_id: Mutex<i64>,
        taken: Mutex<HashSet<(i64, String)>>,
    }

    impl TraceSymbolNoDuplicatesView for MockView {}

    impl TraceNamespaceSymbolView for MockView {
        fn add(
            &self,
            name: &str,
            parent: &dyn TraceNamespaceSymbol,
            _source: SourceType,
        ) -> Result<Arc<dyn TraceNamespaceSymbol>, AddNamespaceError> {
            if name.is_empty() {
                return Err(InvalidInputException::with_message("name must not be empty").into());
            }
            let key = (Namespace::get_id(parent), name.to_string());
            if !self.taken.lock().unwrap().insert(key) {
                return Err(DuplicateNameException::with_message(name).into());
            }
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            Ok(Arc::new(MockNamespaceSymbol { id, name: name.to_string() }))
        }
    }

    fn make_view() -> MockView {
        MockView { next_id: Mutex::new(1), taken: Mutex::new(HashSet::new()) }
    }

    fn global() -> MockNamespaceSymbol {
        MockNamespaceSymbol { id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID, name: "Global".to_string() }
    }

    #[test]
    fn add_creates_a_new_namespace_symbol() {
        let view = make_view();
        let parent = global();
        let sym = view.add("child", &parent, SourceType::UserDefined).expect("add should succeed");
        assert_eq!(Symbol::get_name(sym.as_ref()), "child");
    }

    #[test]
    fn add_rejects_duplicate_name_in_same_parent() {
        let view = make_view();
        let parent = global();
        view.add("child", &parent, SourceType::UserDefined).expect("first add should succeed");
        let result = view.add("child", &parent, SourceType::UserDefined);
        match result {
            Err(AddNamespaceError::Duplicate(_)) => {}
            Ok(_) => panic!("expected Duplicate error, got Ok"),
            Err(e) => panic!("expected Duplicate error, got {e}"),
        }
    }

    #[test]
    fn add_rejects_invalid_name() {
        let view = make_view();
        let parent = global();
        let result = view.add("", &parent, SourceType::UserDefined);
        match result {
            Err(AddNamespaceError::InvalidInput(e)) => assert!(e.0.contains("empty")),
            Ok(_) => panic!("expected InvalidInput error, got Ok"),
            Err(e) => panic!("expected InvalidInput error, got {e}"),
        }
    }

    #[test]
    fn is_object_safe_and_boxed_dyn_dispatches_add() {
        let view = make_view();
        let parent = global();
        let boxed: Box<dyn TraceNamespaceSymbolView> = Box::new(view);
        let sym = boxed.add("nested", &parent, SourceType::UserDefined).expect("add should succeed");
        assert_eq!(Symbol::get_name(sym.as_ref()), "nested");
    }
}
