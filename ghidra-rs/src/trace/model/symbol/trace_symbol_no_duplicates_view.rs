//! A symbol view where names cannot be duplicated within the same parent namespace.
//!
//! Port of `ghidra.trace.model.symbol.TraceSymbolNoDuplicatesView`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java interface is generic over `T extends TraceSymbol`, the specific symbol subtype a
//! given view yields. As with
//! [`TraceSymbolView`](crate::trace::model::symbol::trace_symbol_view::TraceSymbolView), Rust has
//! no covariant-return generics for this purpose, so the returned symbol type is represented here
//! as `Arc<dyn TraceSymbol>` (the interface's own upper bound) rather than as a type parameter.

use std::sync::Arc;

use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;
use crate::util::lock_hold::LockHold;

/// A symbol view where names cannot be duplicated within the same parent namespace.
pub trait TraceSymbolNoDuplicatesView: TraceSymbolView {
    /// Get the child of the given parent having the given name.
    ///
    /// Mirrors the default `getChildNamed(String, TraceNamespaceSymbol)`, which reads the first
    /// (and only, by the "no duplicates" contract) result of
    /// [`TraceSymbolView::get_children_named`] under the trace's read lock.
    fn get_child_named(&self, name: &str, parent: &dyn TraceNamespaceSymbol) -> Option<Arc<dyn TraceSymbol>> {
        let manager = self.get_manager();
        let trace = manager.get_trace();
        let _hold = trace.lock_read();
        self.get_children_named(name, parent).into_iter().next()
    }

    /// A shorthand for [`Self::get_child_named`] where parent is the global namespace.
    fn get_global_named(&self, name: &str) -> Option<Arc<dyn TraceSymbol>> {
        let global = self.get_manager().get_global_namespace();
        self.get_child_named(name, global.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::merge::DataTypeManagerOwner;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressFactory};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, Symbol, SymbolType};
    use crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager;
    use crate::trace::model::listing::TraceCodeManager;
    use crate::trace::model::modules::{TraceModuleManager, TraceStaticMappingManager};
    use crate::trace::model::program::TraceProgramView;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::trace::model::target::trace_object_manager::TraceObjectManager;
    use crate::trace::model::thread::TraceThreadManager;
    use crate::trace::model::time::trace_time_manager::TraceTimeManager;
    use crate::trace::model::trace::{Trace, TraceProgramViewListener};
    use crate::trace::model::symbol::trace_equate_manager::TraceEquateManager;
    use crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use crate::trace::model::guest::trace_platform_manager::TracePlatformManager;
    use crate::trace::model::program::TraceVariableSnapProgramView;
    use crate::trace::model::stack::trace_stack_manager::TraceStackManager;
    use crate::trace::model::property::TraceAddressPropertyManager;
    use crate::trace::model::memory::trace_memory_manager::TraceMemoryManager;
    use crate::trace::model::thread::TraceThread;
    use crate::trace::seam_stubs::{
        TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceRegisterContextManager,
    };
    use crate::util::lock_hold::Lock;
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
        fn not_labels(&self) -> Box<dyn TraceSymbolNoDuplicatesView> {
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
    /// delegate to `get_children_named` (and the global-namespace shorthand delegates to the
    /// manager's global namespace) rather than trivially returning constants.
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

    impl TraceSymbolNoDuplicatesView for MockView {}

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
            (Arc::new(MockNamespaceSymbol { id: 2, name: "alpha".to_string() }), 99),
        ];
        MockView { manager: MockManager { global }, symbols }
    }

    #[test]
    fn get_child_named_returns_first_matching_child() {
        let view = make_view();
        let parent = MockNamespaceSymbol { id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID, name: "Global".to_string() };
        let found = view.get_child_named("alpha", &parent).expect("should find symbol 1");
        assert_eq!(Symbol::get_id(found.as_ref()), 1);
    }

    #[test]
    fn get_child_named_returns_none_when_absent() {
        let view = make_view();
        let parent = MockNamespaceSymbol { id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID, name: "Global".to_string() };
        assert!(view.get_child_named("missing", &parent).is_none());
    }

    #[test]
    fn get_global_named_uses_manager_global_namespace() {
        let view = make_view();
        // "alpha" exists under both the global namespace (id 1) and a non-global parent (id 2);
        // this proves get_global_named scopes to the manager's global namespace rather than
        // returning any symbol with a matching name.
        let found = view.get_global_named("alpha").expect("should find the global-scoped symbol");
        assert_eq!(Symbol::get_id(found.as_ref()), 1);
    }

    #[test]
    fn is_object_safe_and_boxed_dyn_dispatches_get_global_named() {
        let view = make_view();
        let boxed: Box<dyn TraceSymbolNoDuplicatesView> = Box::new(view);
        let found = boxed.get_global_named("alpha").expect("should find symbol 1");
        assert_eq!(Symbol::get_id(found.as_ref()), 1);
    }
}
