//! A symbol view where names cannot be duplicated and things have an address.
//!
//! Port of `ghidra.trace.model.symbol.TraceSymbolWithAddressNoDuplicatesView`.
//!
//! It was selected as a dependency-cycle cut-point. It introduces no new
//! methods beyond its two supertraits, so its contract is captured entirely
//! by requiring both as bounds -- every type implementing both
//! [`TraceSymbolWithAddressView`] and [`TraceSymbolNoDuplicatesView`]
//! automatically satisfies this trait via the blanket impl below, mirroring
//! how any `TraceSymbolWithAddressNoDuplicatesView` instance in Java is
//! usable wherever either supertrait is expected.

use crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView;
use crate::trace::model::symbol::trace_symbol_with_address_view::TraceSymbolWithAddressView;

/// A symbol view where names cannot be duplicated and things have an address.
pub trait TraceSymbolWithAddressNoDuplicatesView:
    TraceSymbolWithAddressView + TraceSymbolNoDuplicatesView
{
}

impl<T: TraceSymbolWithAddressView + TraceSymbolNoDuplicatesView + ?Sized> TraceSymbolWithAddressNoDuplicatesView for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::merge::DataTypeManagerOwner;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressFactory, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, Symbol, SymbolType};
    use crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager;
    use crate::trace::model::listing::TraceCodeManager;
    use crate::trace::model::modules::{TraceModuleManager, TraceStaticMappingManager};
    use crate::trace::model::program::TraceProgramView;
    use crate::trace::model::symbol::trace_equate_manager::TraceEquateManager;
    use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;
    use crate::trace::model::target::trace_object_manager::TraceObjectManager;
    use crate::trace::model::thread::TraceThreadManager;
    use crate::trace::model::time::trace_time_manager::TraceTimeManager;
    use crate::trace::model::trace::{Trace, TraceProgramViewListener};
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use crate::trace::model::guest::trace_platform_manager::TracePlatformManager;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceMemoryManager, TraceRegisterContextManager, TraceStackManager,
        TraceThread, TraceVariableSnapProgramView,
    };
    use crate::util::lock_hold::{Lock, LockHold};
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

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

    struct FakeLock;

    impl Lock for FakeLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockTrace {
        lock: FakeLock,
    }

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {}
        fn get_emulator_cache_version(&self) -> i64 {
            0
        }
        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}
        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}
        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }
        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }
    }

    #[derive(Clone)]
    struct MockManager {
        global: Arc<MockNamespaceSymbol>,
    }

    impl TraceSymbolManager for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace { lock: FakeLock })
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

    /// A view backed by a single symbol keyed by (address, name), used to prove the blanket
    /// impl is usable as a trait object dispatching methods from *both* supertraits, not just
    /// one.
    struct MockView {
        symbol: Arc<dyn TraceSymbol>,
        symbol_name: String,
        symbol_address: Address,
        manager: MockManager,
    }

    impl TraceSymbolView for MockView {
        fn get_manager(&self) -> Box<dyn TraceSymbolManager> {
            Box::new(self.manager.clone())
        }
        fn get_all(&self, _include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            vec![self.symbol.clone()]
        }
        fn get_children_named(&self, name: &str, _parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            if name == self.symbol_name {
                vec![self.symbol.clone()]
            } else {
                Vec::new()
            }
        }
        fn get_children(&self, _parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            vec![self.symbol.clone()]
        }
        fn get_named(&self, name: &str) -> Vec<Arc<dyn TraceSymbol>> {
            self.get_children_named(name, self.manager.global.as_ref())
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
            self.get_intersecting(
                &AddressRange::new(address.clone(), address.clone()),
                include_dynamic_symbols,
            )
        }
    }

    impl TraceSymbolNoDuplicatesView for MockView {}

    fn make_view() -> MockView {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        let global = Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            name: "Global".to_string(),
        });
        MockView {
            symbol: Arc::new(MockNamespaceSymbol { id: 42, name: "sym".to_string() }),
            symbol_name: "sym".to_string(),
            symbol_address: addr,
            manager: MockManager { global },
        }
    }

    #[test]
    fn usable_as_trait_object_dispatching_both_supertraits() {
        let view = make_view();
        let symbol_address = view.symbol_address.clone();
        let boxed: Box<dyn TraceSymbolWithAddressNoDuplicatesView> = Box::new(view);

        // From TraceSymbolWithAddressView.
        let by_address = boxed.get_global_with_name_at("sym", &symbol_address);
        assert!(by_address.is_some());
        assert_eq!(Symbol::get_id(by_address.unwrap().as_ref()), 42);

        // From TraceSymbolNoDuplicatesView.
        let by_name = boxed.get_global_named("sym");
        assert!(by_name.is_some());
        assert_eq!(Symbol::get_id(by_name.unwrap().as_ref()), 42);

        assert!(boxed.get_global_named("nope").is_none());
    }
}
