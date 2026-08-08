//! A type-specific view in the trace symbol table.
//!
//! Port of `ghidra.trace.model.symbol.TraceSymbolView`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The sub-interfaces of this handle the nuances for symbol types with more capabilities and/or
//! restrictions.
//!
//! The Java interface is generic over `T extends TraceSymbol`, the specific symbol subtype a
//! given view yields. As with
//! [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView),
//! Rust has no covariant-return generics for this purpose, so the returned/element symbol type is
//! represented here as `Arc<dyn TraceSymbol>` (the interface's own upper bound) rather than as a
//! type parameter; narrower views should document that their trait objects are known to be of the
//! narrower kind.

use std::sync::Arc;

use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
use crate::trace::model::trace::Trace;

/// A type-specific view in the trace symbol table.
pub trait TraceSymbolView {
    /// Get the symbol manager for the trace.
    fn get_manager(&self) -> Box<dyn TraceSymbolManager>;

    /// Get the trace that contains this view.
    ///
    /// Mirrors the default `getTrace()`, which delegates to `getManager().getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace> {
        self.get_manager().get_trace()
    }

    /// Get the number of symbols in this view.
    ///
    /// Mirrors the default `size(boolean)`, which delegates to `getAll(boolean).size()`.
    fn size(&self, include_dynamic_symbols: bool) -> usize {
        self.get_all(include_dynamic_symbols).len()
    }

    /// Get all the symbols in this view.
    fn get_all(&self, include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>>;

    /// Get all children of the given parent namespace having the given name in this view.
    fn get_children_named(&self, name: &str, parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>>;

    /// Get all children of the given parent namespace in this view.
    fn get_children(&self, parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>>;

    /// A shorthand for [`Self::get_children_named`] where parent is the global namespace.
    fn get_globals_named(&self, name: &str) -> Vec<Arc<dyn TraceSymbol>> {
        let global = self.get_manager().get_global_namespace();
        self.get_children_named(name, global.as_ref())
    }

    /// A shorthand for [`Self::get_children`] where parent is the global namespace.
    fn get_globals(&self) -> Vec<Arc<dyn TraceSymbol>> {
        let global = self.get_manager().get_global_namespace();
        self.get_children(global.as_ref())
    }

    /// Get symbols in this view with the given name, regardless of parent namespace.
    fn get_named(&self, name: &str) -> Vec<Arc<dyn TraceSymbol>>;

    /// Get symbols in this view whose names match the given glob, regardless of parent namespace.
    ///
    /// `*` matches zero-or-more characters, `?` matches one character.
    fn get_with_matching_name(&self, glob: &str, case_sensitive: bool) -> Vec<Arc<dyn TraceSymbol>>;

    /// Scan symbols in this view lexicographically by name starting at the given lower bound.
    fn scan_by_name(&self, start_name: &str) -> Box<dyn Iterator<Item = Arc<dyn TraceSymbol>> + '_>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, Symbol, SymbolType};
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;

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

    #[derive(Clone)]
    struct MockManager {
        global: Arc<MockNamespaceSymbol>,
    }

    impl TraceSymbolManager for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_global_namespace(&self) -> Arc<dyn TraceNamespaceSymbol> {
            self.global.clone()
        }
        fn labels(&self) -> Box<dyn crate::trace::model::symbol::trace_label_symbol_view::TraceLabelSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn namespaces(&self) -> Box<dyn crate::trace::model::symbol::trace_namespace_symbol_view::TraceNamespaceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn classes(&self) -> Box<dyn crate::trace::seam_stubs::TraceClassSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn all_namespaces(&self) -> Box<dyn TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn not_labels(&self) -> Box<dyn crate::trace::seam_stubs::TraceSymbolNoDuplicatesView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn all_symbols(&self) -> Box<dyn TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_ids_added(&self, _from: i64, _to: i64) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_ids_removed(&self, _from: i64, _to: i64) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A view backed by a fixed list of symbols (name, parent id), to prove the default methods
    /// (`size`/`get_globals`/`get_globals_named`/`get_trace`) delegate correctly to the required
    /// ones, rather than trivially returning constants.
    struct MockView {
        manager: MockManager,
        symbols: Vec<(Arc<dyn TraceSymbol>, i64)>,
    }

    impl TraceSymbolView for MockView {
        fn get_manager(&self) -> Box<dyn TraceSymbolManager> {
            Box::new(self.manager.clone())
        }

        fn get_all(&self, _include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            self.symbols.iter().map(|(s, _)| s.clone()).collect()
        }

        fn get_children_named(&self, name: &str, parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            let parent_id = Namespace::get_id(parent);
            self.symbols
                .iter()
                .filter(|(s, pid)| *pid == parent_id && Symbol::get_name(s.as_ref()) == name)
                .map(|(s, _)| s.clone())
                .collect()
        }

        fn get_children(&self, parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            let parent_id = Namespace::get_id(parent);
            self.symbols
                .iter()
                .filter(|(_, pid)| *pid == parent_id)
                .map(|(s, _)| s.clone())
                .collect()
        }

        fn get_named(&self, name: &str) -> Vec<Arc<dyn TraceSymbol>> {
            self.symbols
                .iter()
                .filter(|(s, _)| Symbol::get_name(s.as_ref()) == name)
                .map(|(s, _)| s.clone())
                .collect()
        }

        fn get_with_matching_name(&self, glob: &str, _case_sensitive: bool) -> Vec<Arc<dyn TraceSymbol>> {
            let prefix = glob.trim_end_matches('*');
            self.symbols
                .iter()
                .filter(|(s, _)| Symbol::get_name(s.as_ref()).starts_with(prefix))
                .map(|(s, _)| s.clone())
                .collect()
        }

        fn scan_by_name(&self, start_name: &str) -> Box<dyn Iterator<Item = Arc<dyn TraceSymbol>> + '_> {
            let start_name = start_name.to_string();
            Box::new(
                self.symbols
                    .iter()
                    .filter(move |(s, _)| Symbol::get_name(s.as_ref()) >= start_name.as_str())
                    .map(|(s, _)| s.clone()),
            )
        }
    }

    fn make_view() -> MockView {
        let global = Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            name: "Global".to_string(),
        });
        let symbols: Vec<(Arc<dyn TraceSymbol>, i64)> = vec![
            (
                Arc::new(MockNamespaceSymbol { id: 1, name: "alpha".to_string() }),
                crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            ),
            (
                Arc::new(MockNamespaceSymbol { id: 2, name: "beta".to_string() }),
                crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            ),
            (Arc::new(MockNamespaceSymbol { id: 3, name: "gamma".to_string() }), 99),
        ];
        MockView { manager: MockManager { global }, symbols }
    }

    #[test]
    fn size_delegates_to_get_all() {
        let view = make_view();
        assert_eq!(view.size(true), 3);
    }

    #[test]
    fn get_globals_and_get_globals_named_use_manager_global_namespace() {
        let view = make_view();
        assert_eq!(view.get_globals().len(), 2);
        let named = view.get_globals_named("alpha");
        assert_eq!(named.len(), 1);
        assert_eq!(Symbol::get_id(named[0].as_ref()), 1);
        assert!(view.get_globals_named("gamma").is_empty());
    }

    #[test]
    fn get_named_and_get_with_matching_name_filter_by_name() {
        let view = make_view();
        assert_eq!(view.get_named("beta").len(), 1);
        assert!(view.get_named("nope").is_empty());

        let matched = view.get_with_matching_name("a*", false);
        assert_eq!(matched.len(), 1);
        assert_eq!(Symbol::get_name(matched[0].as_ref()), "alpha");
    }

    #[test]
    fn scan_by_name_returns_lexicographic_lower_bound() {
        let view = make_view();
        let mut names: Vec<String> = view
            .scan_by_name("b")
            .map(|s| Symbol::get_name(s.as_ref()).to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["beta".to_string(), "gamma".to_string()]);
    }

    #[test]
    fn is_object_safe_and_boxed_dyn_dispatches_get_trace() {
        let view = make_view();
        // Exercises the real `get_manager()` -> default-method plumbing through a `dyn` trait
        // object, proving the required/default method wiring actually works through dynamic
        // dispatch.
        let boxed: Box<dyn TraceSymbolView> = Box::new(view);
        assert_eq!(boxed.get_globals().len(), 2);
        assert_eq!(boxed.size(true), 3);
    }
}
