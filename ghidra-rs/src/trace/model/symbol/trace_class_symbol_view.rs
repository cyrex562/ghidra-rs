//! A view over a trace's class symbols.
//!
//! Port of `ghidra.trace.model.symbol.TraceClassSymbolView`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java interface extends `TraceSymbolNoDuplicatesView<TraceClassSymbol>`; see
//! [`TraceSymbolNoDuplicatesView`](crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView).

use std::sync::Arc;

use thiserror::Error;

use crate::program::model::symbol::SourceType;
use crate::trace::model::symbol::trace_class_symbol::TraceClassSymbol;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView;
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Error produced by [`TraceClassSymbolView::add`].
///
/// Combines the two checked exceptions declared on the Java method
/// `TraceClassSymbolView.add(String, TraceNamespaceSymbol, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum AddClassError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// A view over a trace's class symbols.
pub trait TraceClassSymbolView: TraceSymbolNoDuplicatesView {
    /// Add a new class symbol.
    ///
    /// # Errors
    /// Returns [`AddClassError::Duplicate`] if `name` is duplicated in `parent`, or
    /// [`AddClassError::InvalidInput`] if `name` is not a valid symbol name.
    fn add(
        &self,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceClassSymbol>, AddClassError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::listing::ghidra_class::GhidraClass;
    use crate::program::model::symbol::{Namespace, NamespaceType, Symbol, SymbolType};
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;
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

    struct MockClassSymbol {
        id: i64,
        name: String,
    }

    impl Namespace for MockClassSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled; see TraceNamespaceSymbol trait docs")
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
            NamespaceType::Class
        }
        fn is_global(&self) -> bool {
            false
        }
    }

    impl Symbol for MockClassSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Class
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
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

    impl TraceSymbol for MockClassSymbol {
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

    impl TraceNamespaceSymbol for MockClassSymbol {
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

    impl GhidraClass for MockClassSymbol {}

    impl TraceClassSymbol for MockClassSymbol {}

    /// A view that records names added under each parent (by ID), rejecting duplicates within a
    /// parent and empty names, to prove the trait's error wiring and object-safety.
    struct MockView {
        next_id: Mutex<i64>,
        taken: Mutex<HashSet<(i64, String)>>,
    }

    impl TraceSymbolView for MockView {
        fn get_manager(&self) -> Box<dyn TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all(&self, _include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_children_named(&self, _name: &str, _parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_children(&self, _parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_named(&self, _name: &str) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_with_matching_name(&self, _glob: &str, _case_sensitive: bool) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn scan_by_name(&self, _start_name: &str) -> Box<dyn Iterator<Item = Arc<dyn TraceSymbol>> + '_> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceSymbolNoDuplicatesView for MockView {}

    impl TraceClassSymbolView for MockView {
        fn add(
            &self,
            name: &str,
            parent: &dyn TraceNamespaceSymbol,
            _source: SourceType,
        ) -> Result<Arc<dyn TraceClassSymbol>, AddClassError> {
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
            Ok(Arc::new(MockClassSymbol { id, name: name.to_string() }))
        }
    }

    fn make_view() -> MockView {
        MockView { next_id: Mutex::new(1), taken: Mutex::new(HashSet::new()) }
    }

    fn global() -> MockNamespaceSymbol {
        MockNamespaceSymbol { id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID, name: "Global".to_string() }
    }

    #[test]
    fn add_creates_a_new_class_symbol() {
        let view = make_view();
        let parent = global();
        let sym = view.add("MyClass", &parent, SourceType::UserDefined).expect("add should succeed");
        assert_eq!(Symbol::get_name(sym.as_ref()), "MyClass");
        assert_eq!(GhidraClass::get_type(sym.as_ref()), NamespaceType::Class);
    }

    #[test]
    fn add_rejects_duplicate_name_in_same_parent() {
        let view = make_view();
        let parent = global();
        view.add("MyClass", &parent, SourceType::UserDefined).expect("first add should succeed");
        let result = view.add("MyClass", &parent, SourceType::UserDefined);
        match result {
            Err(AddClassError::Duplicate(_)) => {}
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
            Err(AddClassError::InvalidInput(e)) => assert!(e.0.contains("empty")),
            Ok(_) => panic!("expected InvalidInput error, got Ok"),
            Err(e) => panic!("expected InvalidInput error, got {e}"),
        }
    }

    #[test]
    fn is_object_safe_and_boxed_dyn_dispatches_add() {
        let view = make_view();
        let parent = global();
        let boxed: Box<dyn TraceClassSymbolView> = Box::new(view);
        let sym = boxed.add("Nested", &parent, SourceType::UserDefined).expect("add should succeed");
        assert_eq!(Symbol::get_name(sym.as_ref()), "Nested");
    }
}
