//! A symbol view for things with an address in stack or register space, but not associated with a
//! trace thread.
//!
//! Port of `ghidra.trace.model.symbol.TraceSymbolWithAddressView`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! This class is somewhat vestigial. It would be used to index parameters, locals, and global
//! variables by their storage addresses. However, functions (and thus parameters and locals) are
//! no longer supported. Furthermore, global variables are not fully implemented, yet.
//!
//! The Java interface is generic over `T extends TraceSymbol`, the specific symbol subtype a
//! given view yields. As with
//! [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView),
//! Rust has no covariant-return generics for this purpose, so the returned/element symbol type is
//! represented here as `Arc<dyn TraceSymbol>` (the interface's own upper bound) rather than as a
//! type parameter; narrower views should document that their trait objects are known to be of the
//! narrower kind.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;

/// A symbol view for things with an address in stack or register space, but not associated with a
/// trace thread.
pub trait TraceSymbolWithAddressView: TraceSymbolView {
    /// Get the child of the given parent having the given name at the given address.
    fn get_child_with_name_at(
        &self,
        name: &str,
        address: &Address,
        parent: &dyn TraceNamespaceSymbol,
    ) -> Option<Arc<dyn TraceSymbol>>;

    /// A shorthand for [`Self::get_child_with_name_at`] where the parent is the global namespace.
    fn get_global_with_name_at(&self, name: &str, address: &Address) -> Option<Arc<dyn TraceSymbol>> {
        let global = self.get_manager().get_global_namespace();
        self.get_child_with_name_at(name, address, global.as_ref())
    }

    /// Get symbols in this view intersecting the given address range.
    fn get_intersecting(&self, range: &AddressRange, include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>>;

    /// Get symbols in this view containing the given address.
    fn get_at(&self, address: &Address, include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>>;

    /// Check if this view contains any symbols at the given address.
    fn has_at(&self, address: &Address, include_dynamic_symbols: bool) -> bool {
        !self.get_at(address, include_dynamic_symbols).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, Symbol, SymbolType};
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::thread::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;

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

        fn classes(&self) -> Box<dyn crate::trace::model::symbol::trace_class_symbol_view::TraceClassSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn all_namespaces(&self) -> Box<dyn TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn not_labels(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView> {
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

    /// A view that only ever holds one symbol, keyed by (address, name), to prove the default
    /// methods delegate correctly rather than trivially returning constants.
    struct MockView {
        space: Arc<AddressSpace>,
        symbol: Arc<dyn TraceSymbol>,
        symbol_name: String,
        symbol_address: Address,
        manager: MockManager,
        get_at_calls: RefCell<u32>,
    }

    impl TraceSymbolView for MockView {
        fn get_manager(&self) -> Box<dyn TraceSymbolManager> {
            Box::new(self.manager.clone())
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

    impl TraceSymbolWithAddressView for MockView {
        fn get_child_with_name_at(
            &self,
            name: &str,
            address: &Address,
            _parent: &dyn TraceNamespaceSymbol,
        ) -> Option<Arc<dyn TraceSymbol>> {
            if name == self.symbol_name && *address == self.symbol_address {
                Some(self.symbol.clone())
            } else {
                None
            }
        }

        fn get_intersecting(&self, range: &AddressRange, _include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            if range.contains(&self.symbol_address) {
                vec![self.symbol.clone()]
            } else {
                Vec::new()
            }
        }

        fn get_at(&self, address: &Address, include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            *self.get_at_calls.borrow_mut() += 1;
            self.get_intersecting(
                &AddressRange::new(address.clone(), address.clone()),
                include_dynamic_symbols,
            )
        }
    }

    fn make_view() -> MockView {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        let global = Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            name: "Global".to_string(),
        });
        MockView {
            space,
            symbol: Arc::new(MockNamespaceSymbol {
                id: 42,
                name: "sym".to_string(),
            }),
            symbol_name: "sym".to_string(),
            symbol_address: addr,
            manager: MockManager { global },
            get_at_calls: RefCell::new(0),
        }
    }

    #[test]
    fn get_child_with_name_at_matches_exact_key() {
        let view = make_view();
        let parent = view.manager.get_global_namespace();
        let found = view.get_child_with_name_at("sym", &view.symbol_address, parent.as_ref());
        assert!(found.is_some());
        assert_eq!(Symbol::get_id(found.unwrap().as_ref()), 42);

        assert!(view
            .get_child_with_name_at("nope", &view.symbol_address, parent.as_ref())
            .is_none());
    }

    #[test]
    fn get_global_with_name_at_uses_manager_global_namespace() {
        let view = make_view();
        let symbol_address = view.symbol_address.clone();
        // Exercises the real `TraceSymbolView::get_manager()` default path (boxed manager),
        // proving the trait-object plumbing between the two traits actually works.
        let boxed: Box<dyn TraceSymbolWithAddressView> = Box::new(view);
        let found = boxed.get_global_with_name_at("sym", &symbol_address);
        assert!(found.is_some());
        assert!(boxed.get_global_with_name_at("nope", &symbol_address).is_none());
    }

    #[test]
    fn has_at_delegates_to_get_at_and_reports_presence() {
        let view = make_view();
        assert!(view.has_at(&view.symbol_address, true));
        assert_eq!(*view.get_at_calls.borrow(), 1);

        let elsewhere = view.space.address(0x2000);
        assert!(!view.has_at(&elsewhere, true));
        assert_eq!(*view.get_at_calls.borrow(), 2);
    }

    #[test]
    fn get_intersecting_reports_symbol_in_range() {
        let view = make_view();
        let range = AddressRange::new(view.symbol_address.clone(), view.symbol_address.clone());
        let found = view.get_intersecting(&range, true);
        assert_eq!(found.len(), 1);

        let elsewhere = view.space.address(0x2000);
        let miss_range = AddressRange::new(elsewhere.clone(), elsewhere);
        assert!(view.get_intersecting(&miss_range, true).is_empty());
    }
}
