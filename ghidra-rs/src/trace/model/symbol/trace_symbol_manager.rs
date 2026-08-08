//! The symbol table for traces.
//!
//! Port of `ghidra.trace.model.symbol.TraceSymbolManager`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! Currently, functions are not supported, so effectively the only symbol types possible in a
//! trace are labels, namespaces, and classes. Global variables are partially implemented, but as
//! they are not finished, even in
//! [`Program`](crate::program::model::listing::program::Program), they are not available in
//! traces, either.
//!
//! This manager supports a "fluid" API syntax. The methods on this manager narrow the scope in
//! terms of the symbol type; each returns a view, the methods of which operate on that type
//! specifically.
//!
//! [`Self::all_namespaces`], [`Self::not_labels`], and [`Self::all_symbols`] are generic in Java
//! (`TraceSymbolView<? extends TraceNamespaceSymbol>`,
//! `TraceSymbolNoDuplicatesView<? extends TraceSymbol>`, `TraceSymbolView<? extends TraceSymbol>`).
//! Following the convention set by
//! [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView),
//! the element type is erased to the view traits' own upper bound rather than represented as a
//! Rust generic. [`Self::classes`] returns
//! [`TraceClassSymbolView`](crate::trace::model::symbol::trace_class_symbol_view::TraceClassSymbolView)
//! directly, since (unlike the other three) it is not itself generic in Java.
//!
//! [`Self::get_symbol_by_id`] is covariantly typed `TraceSymbol` in Java; it is kept at the wider
//! [`Symbol`] here, matching the placeholder this port replaces (see
//! [`TraceReference::get_associated_symbol`](crate::trace::model::symbol::trace_reference::TraceReference::get_associated_symbol),
//! the one existing caller).

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::symbol::Symbol;
use crate::trace::model::symbol::trace_label_symbol_view::TraceLabelSymbolView;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_namespace_symbol_view::TraceNamespaceSymbolView;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;
use crate::trace::model::trace::Trace;
use crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView;
use crate::trace::model::symbol::trace_class_symbol_view::TraceClassSymbolView;

/// Orders symbols so that primary symbols sort first.
///
/// Mirrors the static field `TraceSymbolManager.PRIMALITY_COMPARATOR`.
pub fn primality_compare(a: &dyn TraceSymbol, b: &dyn TraceSymbol) -> Ordering {
    match (a.is_primary(), b.is_primary()) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

/// The symbol table for traces.
pub trait TraceSymbolManager {
    /// Get the trace for this manager.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get a symbol by its unique identifier.
    ///
    /// The identifier is only unique within this trace.
    ///
    /// See the module-level documentation for why this returns [`Symbol`] rather than the
    /// covariant `TraceSymbol`.
    fn get_symbol_by_id(&self, _symbol_id: i64) -> Option<Arc<dyn Symbol>> {
        None
    }

    /// Get the trace's global namespace.
    fn get_global_namespace(&self) -> Arc<dyn TraceNamespaceSymbol>;

    /// Get a view of the labels in the trace.
    fn labels(&self) -> Box<dyn TraceLabelSymbolView>;

    /// Get a view of the namespaces in the trace.
    fn namespaces(&self) -> Box<dyn TraceNamespaceSymbolView>;

    /// Get a view of the classes in the trace.
    fn classes(&self) -> Box<dyn TraceClassSymbolView>;

    /// Get a view of all the namespaces (including classes) in the trace.
    fn all_namespaces(&self) -> Box<dyn TraceSymbolView>;

    /// Get a view of all the symbols except labels in the trace.
    ///
    /// This method is somewhat vestigial. At one point, functions were partially implemented, so
    /// this would have contained functions, variables, etc. As the manager now only supports
    /// labels, namespaces, and classes, this is essentially the same as [`Self::all_namespaces`].
    fn not_labels(&self) -> Box<dyn TraceSymbolNoDuplicatesView>;

    /// Get a view of all symbols in the trace.
    fn all_symbols(&self) -> Box<dyn TraceSymbolView>;

    /// Get the set of unique symbol IDs that are added going from one snapshot to another.
    fn get_ids_added(&self, from: i64, to: i64) -> Vec<i64>;

    /// Get the set of unique symbol IDs that are removed going from one snapshot to another.
    fn get_ids_removed(&self, from: i64, to: i64) -> Vec<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, SymbolType};
    use crate::program::model::address::Address;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::collections::{BTreeMap, HashSet};

    struct MockSymbol {
        id: i64,
        primary: bool,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> &str {
            "mock_symbol"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl TraceSymbol for MockSymbol {
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

    /// A manager backed by a per-snapshot set of live symbol IDs, to prove
    /// [`TraceSymbolManager::get_ids_added`]/[`TraceSymbolManager::get_ids_removed`] compute a
    /// real set difference (rather than trivially returning an empty/constant result), and that a
    /// [`TraceSymbolManager::get_symbol_by_id`] override actually looks symbols up.
    struct MockManager {
        global: Arc<MockNamespaceSymbol>,
        symbols: BTreeMap<i64, Arc<MockSymbol>>,
        snapshots: BTreeMap<i64, HashSet<i64>>,
    }

    impl TraceSymbolManager for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_by_id(&self, symbol_id: i64) -> Option<Arc<dyn Symbol>> {
            self.symbols.get(&symbol_id).map(|s| s.clone() as Arc<dyn Symbol>)
        }

        fn get_global_namespace(&self) -> Arc<dyn TraceNamespaceSymbol> {
            self.global.clone()
        }

        fn labels(&self) -> Box<dyn TraceLabelSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn namespaces(&self) -> Box<dyn TraceNamespaceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn classes(&self) -> Box<dyn TraceClassSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn all_namespaces(&self) -> Box<dyn TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn not_labels(&self) -> Box<dyn TraceSymbolNoDuplicatesView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn all_symbols(&self) -> Box<dyn TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ids_added(&self, from: i64, to: i64) -> Vec<i64> {
            let before = self.snapshots.get(&from).cloned().unwrap_or_default();
            let after = self.snapshots.get(&to).cloned().unwrap_or_default();
            let mut added: Vec<i64> = after.difference(&before).copied().collect();
            added.sort_unstable();
            added
        }

        fn get_ids_removed(&self, from: i64, to: i64) -> Vec<i64> {
            let before = self.snapshots.get(&from).cloned().unwrap_or_default();
            let after = self.snapshots.get(&to).cloned().unwrap_or_default();
            let mut removed: Vec<i64> = before.difference(&after).copied().collect();
            removed.sort_unstable();
            removed
        }
    }

    fn make_manager() -> MockManager {
        let global = Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            name: "Global".to_string(),
        });
        let mut symbols = BTreeMap::new();
        symbols.insert(1, Arc::new(MockSymbol { id: 1, primary: true }));
        symbols.insert(2, Arc::new(MockSymbol { id: 2, primary: false }));
        let mut snapshots = BTreeMap::new();
        snapshots.insert(0, HashSet::from([1]));
        snapshots.insert(1, HashSet::from([1, 2]));
        snapshots.insert(2, HashSet::from([2]));
        MockManager { global, symbols, snapshots }
    }

    #[test]
    fn primality_compare_sorts_primary_symbols_first() {
        let primary = MockSymbol { id: 1, primary: true };
        let secondary = MockSymbol { id: 2, primary: false };
        assert_eq!(primality_compare(&primary, &secondary), Ordering::Less);
        assert_eq!(primality_compare(&secondary, &primary), Ordering::Greater);
        assert_eq!(primality_compare(&primary, &primary), Ordering::Equal);
        assert_eq!(primality_compare(&secondary, &secondary), Ordering::Equal);
    }

    #[test]
    fn get_symbol_by_id_default_reports_not_found() {
        struct DefaultManager;
        impl TraceSymbolManager for DefaultManager {
            fn get_trace(&self) -> Box<dyn Trace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_global_namespace(&self) -> Arc<dyn TraceNamespaceSymbol> {
                unimplemented!("not exercised by this smoke test")
            }
            fn labels(&self) -> Box<dyn TraceLabelSymbolView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn namespaces(&self) -> Box<dyn TraceNamespaceSymbolView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn classes(&self) -> Box<dyn TraceClassSymbolView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn all_namespaces(&self) -> Box<dyn TraceSymbolView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn not_labels(&self) -> Box<dyn TraceSymbolNoDuplicatesView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn all_symbols(&self) -> Box<dyn TraceSymbolView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_ids_added(&self, _from: i64, _to: i64) -> Vec<i64> {
                Vec::new()
            }
            fn get_ids_removed(&self, _from: i64, _to: i64) -> Vec<i64> {
                Vec::new()
            }
        }

        assert!(DefaultManager.get_symbol_by_id(42).is_none());
    }

    #[test]
    fn get_symbol_by_id_override_looks_up_real_symbol() {
        let mgr = make_manager();
        let found = mgr.get_symbol_by_id(1).expect("symbol 1 should be found");
        assert_eq!(found.get_id(), 1);
        assert!(mgr.get_symbol_by_id(999).is_none());
    }

    #[test]
    fn get_ids_added_and_removed_diff_real_snapshots() {
        let mgr = make_manager();
        assert_eq!(mgr.get_ids_added(0, 1), vec![2]);
        assert_eq!(mgr.get_ids_removed(0, 1), Vec::<i64>::new());
        assert_eq!(mgr.get_ids_added(1, 2), Vec::<i64>::new());
        assert_eq!(mgr.get_ids_removed(1, 2), vec![1]);
    }

    #[test]
    fn is_object_safe_and_boxed_dyn_dispatches() {
        let mgr = make_manager();
        let boxed: Box<dyn TraceSymbolManager> = Box::new(mgr);
        assert_eq!(
            Namespace::get_name(boxed.get_global_namespace().as_ref()),
            "Global"
        );
        assert_eq!(boxed.get_ids_added(0, 1), vec![2]);
        assert_eq!(boxed.get_symbol_by_id(2).map(|s| s.get_id()), Some(2));
    }
}
