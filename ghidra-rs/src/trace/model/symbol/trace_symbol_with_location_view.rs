use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::Register;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{TracePlatform, TraceRegisterUtils, TraceThread};

/// A symbol view for things bound by an address range and lifespan.
///
/// Port of `ghidra.trace.model.symbol.TraceSymbolWithLocationView`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface is generic over `T extends TraceSymbol`, the specific symbol subtype a
/// given view yields. As with
/// [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView),
/// Rust has no covariant-return generics for this purpose, so the returned/element symbol type is
/// represented here as `Arc<dyn TraceSymbol>` (the interface's own upper bound) rather than as a
/// type parameter; narrower views should document that their trait objects are known to be of the
/// narrower kind.
///
/// The Java overloads of `getChildWithNameAt`/`getIntersecting`/`getAt` cannot be represented as
/// same-named Rust methods (Rust has no overloading), so each overload is given a distinct,
/// descriptive name below.
///
/// The register-taking overloads resolve a register's address space and conventional range via
/// the not-yet-ported static `TraceRegisterUtils`/`TracePlatform` methods. Following the
/// convention established by
/// [`TraceSpaceMixin`](crate::trace::util::trace_space_mixin::TraceSpaceMixin), callers must
/// supply an implementation of the
/// [`TraceRegisterUtils`](crate::trace::seam_stubs::TraceRegisterUtils) placeholder trait via
/// [`Self::trace_register_utils`].
///
/// `getAt`/`hasAt` construct a `Lifespan.at(snap)` in Java. Following the precedent set by
/// [`TraceBreakpointManager`](crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager)
/// (see that module's docs), this crate's [`Lifespan`] is a trait with no concrete,
/// generically-constructible implementor yet, so there is no way to build that span from just a
/// `snap` inside a default method body. [`Self::get_at`] is therefore a required method here
/// rather than a default delegating to [`Self::get_intersecting`]; [`Self::has_at`] remains a
/// default, delegating to [`Self::get_at`] (which performs the same single-address query).
pub trait TraceSymbolWithLocationView: TraceSymbolView {
    /// The `TraceRegisterUtils` instance used to resolve a register's address space. Mirrors the
    /// static `TraceRegisterUtils.getRegisterAddressSpace` calls made by the Java default
    /// methods.
    fn trace_register_utils(&self) -> &dyn TraceRegisterUtils;

    /// Get the child of the given parent having the given name at the given point.
    fn get_child_with_name_at(
        &self,
        name: &str,
        snap: i64,
        address: &Address,
        parent: &dyn TraceNamespaceSymbol,
    ) -> Option<Arc<dyn TraceSymbol>>;

    /// Get the child of the given parent having the given name at the given register's min
    /// address.
    ///
    /// Mirrors the Java overload
    /// `getChildWithNameAt(String, TracePlatform, long, TraceThread, Register,
    /// TraceNamespaceSymbol)`.
    fn get_child_with_name_at_register(
        &self,
        name: &str,
        platform: &dyn TracePlatform,
        snap: i64,
        thread: &dyn TraceThread,
        register: &Register,
        parent: &dyn TraceNamespaceSymbol,
    ) -> Option<Arc<dyn TraceSymbol>> {
        let space = self
            .trace_register_utils()
            .get_register_address_space(thread, 0, false)?;
        let range = platform.get_conventional_register_range(&space, register);
        self.get_child_with_name_at(name, snap, range.min_address(), parent)
    }

    /// Get the child of the given parent having the given name at the given register's min
    /// address, using the trace's host platform.
    ///
    /// Mirrors the Java overload
    /// `getChildWithNameAt(String, long, TraceThread, Register, TraceNamespaceSymbol)`.
    fn get_child_with_name_at_thread(
        &self,
        name: &str,
        snap: i64,
        thread: &dyn TraceThread,
        register: &Register,
        parent: &dyn TraceNamespaceSymbol,
    ) -> Option<Arc<dyn TraceSymbol>> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_child_with_name_at_register(name, platform.as_ref(), snap, thread, register, parent)
    }

    /// A shorthand for [`Self::get_child_with_name_at`] where the parent is the global namespace.
    fn get_global_with_name_at(
        &self,
        name: &str,
        snap: i64,
        address: &Address,
    ) -> Option<Arc<dyn TraceSymbol>> {
        let global = self.get_manager().get_global_namespace();
        self.get_child_with_name_at(name, snap, address, global.as_ref())
    }

    /// Get symbols in this view intersecting the given box.
    fn get_intersecting(
        &self,
        span: &dyn Lifespan,
        range: &AddressRange,
        include_dynamic_symbols: bool,
        forward: bool,
    ) -> Vec<Arc<dyn TraceSymbol>>;

    /// Get symbols in this view intersecting the given register.
    ///
    /// Mirrors the Java overload
    /// `getIntersecting(TracePlatform, Lifespan, TraceThread, Register, boolean, boolean)`.
    fn get_intersecting_register(
        &self,
        platform: &dyn TracePlatform,
        span: &dyn Lifespan,
        thread: &dyn TraceThread,
        register: &Register,
        include_dynamic_symbols: bool,
        forward: bool,
    ) -> Vec<Arc<dyn TraceSymbol>> {
        let Some(space) = self
            .trace_register_utils()
            .get_register_address_space(thread, 0, false)
        else {
            return Vec::new();
        };
        let range = platform.get_conventional_register_range(&space, register);
        self.get_intersecting(span, &range, include_dynamic_symbols, forward)
    }

    /// Get symbols in this view intersecting the given register, using the trace's host
    /// platform.
    ///
    /// Mirrors the Java overload
    /// `getIntersecting(Lifespan, TraceThread, Register, boolean, boolean)`.
    fn get_intersecting_thread(
        &self,
        span: &dyn Lifespan,
        thread: &dyn TraceThread,
        register: &Register,
        include_dynamic_symbols: bool,
        forward: bool,
    ) -> Vec<Arc<dyn TraceSymbol>> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_intersecting_register(
            platform.as_ref(),
            span,
            thread,
            register,
            include_dynamic_symbols,
            forward,
        )
    }

    /// Get symbols in this view at the given point.
    ///
    /// The result should be ordered with the primary symbol first. This is a required method
    /// rather than a default delegating to [`Self::get_intersecting`]; see the trait-level
    /// documentation for why.
    fn get_at(&self, snap: i64, address: &Address, include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>>;

    /// Get symbols in this view at the given register's min address.
    ///
    /// Mirrors the Java overload `getAt(TracePlatform, long, TraceThread, Register, boolean)`.
    fn get_at_register(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        thread: &dyn TraceThread,
        register: &Register,
        include_dynamic_symbols: bool,
    ) -> Vec<Arc<dyn TraceSymbol>> {
        let Some(space) = self
            .trace_register_utils()
            .get_register_address_space(thread, 0, false)
        else {
            return Vec::new();
        };
        let range = platform.get_conventional_register_range(&space, register);
        self.get_at(snap, range.min_address(), include_dynamic_symbols)
    }

    /// Get symbols in this view at the given register's min address, using the trace's host
    /// platform.
    ///
    /// Mirrors the Java overload `getAt(long, TraceThread, Register, boolean)`.
    fn get_at_thread(
        &self,
        snap: i64,
        thread: &dyn TraceThread,
        register: &Register,
        include_dynamic_symbols: bool,
    ) -> Vec<Arc<dyn TraceSymbol>> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_at_register(platform.as_ref(), snap, thread, register, include_dynamic_symbols)
    }

    /// Check if this view contains any symbols at the given point.
    fn has_at(&self, snap: i64, address: &Address, include_dynamic_symbols: bool) -> bool {
        !self.get_at(snap, address, include_dynamic_symbols).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, Symbol, SymbolType};
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
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

        fn all_namespaces(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_view::TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn not_labels(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn all_symbols(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_view::TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ids_added(&self, _from: i64, _to: i64) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ids_removed(&self, _from: i64, _to: i64) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A view that only ever holds one symbol, keyed by (snap, address, name), to prove the
    /// default methods delegate correctly.
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

    impl TraceSymbolWithLocationView for MockView {
        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            unimplemented!("not exercised by this smoke test (address-based overloads only)")
        }

        fn get_child_with_name_at(
            &self,
            name: &str,
            snap: i64,
            address: &Address,
            _parent: &dyn TraceNamespaceSymbol,
        ) -> Option<Arc<dyn TraceSymbol>> {
            if name == self.symbol_name && snap == 0 && *address == self.symbol_address {
                Some(self.symbol.clone())
            } else {
                None
            }
        }

        fn get_intersecting(
            &self,
            _span: &dyn Lifespan,
            range: &AddressRange,
            _include_dynamic_symbols: bool,
            _forward: bool,
        ) -> Vec<Arc<dyn TraceSymbol>> {
            if range.contains(&self.symbol_address) {
                vec![self.symbol.clone()]
            } else {
                Vec::new()
            }
        }

        fn get_at(&self, snap: i64, address: &Address, include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            *self.get_at_calls.borrow_mut() += 1;
            self.get_intersecting(
                &MockLifespan { min: snap, max: snap },
                &AddressRange::new(address.clone(), address.clone()),
                include_dynamic_symbols,
                true,
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
        let found = view.get_child_with_name_at("sym", 0, &view.symbol_address, parent.as_ref());
        assert!(found.is_some());
        assert_eq!(Symbol::get_id(found.unwrap().as_ref()), 42);

        assert!(view
            .get_child_with_name_at("nope", 0, &view.symbol_address, parent.as_ref())
            .is_none());
    }

    #[test]
    fn get_global_with_name_at_uses_manager_global_namespace() {
        let view = make_view();
        let symbol_address = view.symbol_address.clone();
        // Exercises the real `TraceSymbolView::get_manager()` default path (boxed manager),
        // proving the trait-object plumbing between the two traits actually works.
        let boxed: Box<dyn TraceSymbolWithLocationView> = Box::new(view);
        let found = boxed.get_global_with_name_at("sym", 0, &symbol_address);
        assert!(found.is_some());
        assert!(boxed.get_global_with_name_at("nope", 0, &symbol_address).is_none());
    }

    #[test]
    fn has_at_delegates_to_get_at_and_reports_presence() {
        let view = make_view();
        assert!(view.has_at(0, &view.symbol_address, true));
        assert_eq!(*view.get_at_calls.borrow(), 1);

        let elsewhere = view.space.address(0x2000);
        assert!(!view.has_at(0, &elsewhere, true));
        assert_eq!(*view.get_at_calls.borrow(), 2);
    }

    #[test]
    fn get_intersecting_reports_symbol_in_range() {
        let view = make_view();
        let range = AddressRange::new(view.symbol_address.clone(), view.symbol_address.clone());
        let span = MockLifespan { min: 0, max: 0 };
        let found = view.get_intersecting(&span, &range, true, true);
        assert_eq!(found.len(), 1);

        let elsewhere = view.space.address(0x2000);
        let miss_range = AddressRange::new(elsewhere.clone(), elsewhere);
        assert!(view.get_intersecting(&span, &miss_range, true, true).is_empty());
    }
}
