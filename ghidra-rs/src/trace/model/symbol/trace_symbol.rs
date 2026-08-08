use std::sync::Arc;

use crate::program::model::symbol::Symbol;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_reference::TraceReference;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceThread;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// A trace symbol.
///
/// Port of `ghidra.trace.model.symbol.TraceSymbol`.
///
/// It was selected as a dependency-cycle cut-point: [`TraceNamespaceSymbol`] extends this trait,
/// while this trait's `getParentNamespace()`/`getParentSymbol()` are covariantly overridden to
/// return `TraceNamespaceSymbol`.
///
/// This is essentially the equivalent concept of [`Symbol`] from a
/// [`Program`](crate::program::model::listing::program::Program). One important distinction is
/// that in the trace implementation, the symbol and the object it describes are the same. For
/// example, in a `Program`, a `Namespace` and its symbol are two different things -- to get the
/// namespace you would invoke `Symbol::getObject()`. That is unnecessary, though permissible,
/// with a trace, because [`TraceNamespaceSymbol`] extends both `Namespace` and this trait.
///
/// `getParentNamespace()` and `getParentSymbol()` are covariantly overridden in Java to both
/// return `TraceNamespaceSymbol` instead of `Namespace`/`Symbol` respectively. Rust has no
/// covariant trait-method override, so both are exposed here under distinct names,
/// [`TraceSymbol::get_parent_trace_namespace`] and [`TraceSymbol::get_parent_trace_symbol`],
/// rather than redeclaring [`Symbol::get_parent_namespace`]. The latter defaults to delegating to
/// the former, since in the trace model a namespace and its symbol are the same object.
/// Implementors should still implement `Symbol::get_parent_namespace` themselves (delegating to
/// `get_parent_trace_namespace`), mirroring the Java override.
///
/// `getReferences(TaskMonitor)`/`getReferences()` are re-declared in Java to covariantly return
/// `TraceReference[]` instead of `Reference[]`. Since the ported [`Symbol`] trait does not carry
/// those methods at all, they are simply new methods here:
/// [`TraceSymbol::get_references_with_monitor`] and [`TraceSymbol::get_references`]. The Java
/// docs note `getReferenceCollection()` is preferred, as it retrieves references lazily; that is
/// ported as [`TraceSymbol::get_reference_collection`].
///
/// `isPinned()`/`setPinned(boolean)` are re-abstracted (without a default) in Java, with docs
/// noting traces do not support moving memory, so pinning is meaningless and unsupported. Since
/// the ported [`Symbol`] trait does not carry these methods either, they are simply new abstract
/// methods here.
pub trait TraceSymbol: Symbol {
    /// Get the trace to which this symbol belongs.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// If in register space, get the thread associated with this symbol.
    fn get_thread(&self) -> Option<Box<dyn TraceThread>>;

    /// Covariant override of `Symbol::get_parent_namespace()`; see the trait-level documentation.
    fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>>;

    /// Covariant override of `Symbol::get_parent_symbol()`; see the trait-level documentation.
    /// Defaults to delegating to [`TraceSymbol::get_parent_trace_namespace`], since in the trace
    /// model a namespace and its symbol are the same object.
    fn get_parent_trace_symbol(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
        self.get_parent_trace_namespace()
    }

    /// Get all memory references to the address of this symbol, using the given monitor.
    ///
    /// For traces, [`TraceSymbol::get_reference_collection`] is preferred, as it retrieves
    /// references lazily.
    fn get_references_with_monitor(&self, monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>>;

    /// Get all memory references to the address of this symbol.
    fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>>;

    /// Get all memory references to the address of this symbol, using a dummy monitor.
    ///
    /// For traces, [`TraceSymbol::get_reference_collection`] is preferred, as it retrieves
    /// references lazily.
    fn get_references(&self) -> Vec<Arc<dyn TraceReference>> {
        self.get_references_with_monitor(&DummyMonitor)
    }

    /// Sets whether this symbol is pinned. Traces do not support moving memory, so pinning is
    /// meaningless and unsupported; implementors are expected to no-op or reject this.
    fn set_pinned(&mut self, pinned: bool);

    /// Returns true if this symbol is pinned. Traces do not support moving memory, so pinning is
    /// meaningless and unsupported; implementors are expected to always report `false`.
    fn is_pinned(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressFactory};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::model::symbol::{Namespace, NamespaceType, SourceType, SymbolType};
    use crate::app::merge::DataTypeManagerOwner;
    use crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager;
    use crate::trace::model::listing::TraceCodeManager;
    use crate::trace::model::modules::{TraceModuleManager, TraceStaticMappingManager};
    use crate::trace::model::program::TraceProgramView;
    use crate::trace::model::time::trace_time_manager::TraceTimeManager;
    use crate::trace::model::trace::TraceProgramViewListener;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use crate::trace::model::target::trace_object_manager::TraceObjectManager;
    use crate::trace::model::thread::TraceThreadManager;
    use crate::trace::model::symbol::trace_equate_manager::TraceEquateManager;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceMemoryManager,
        TracePlatformManager, TraceReferenceManager, TraceRegisterContextManager,
        TraceStackManager, TraceVariableSnapProgramView,
    };
    use crate::util::lock_hold::{Lock, LockHold};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    struct MockTrace;

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
            unimplemented!("not exercised by this smoke test")
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockNamespaceSymbol {
        id: i64,
        name: String,
    }

    impl Namespace for MockNamespaceSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled")
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
            Box::new(MockTrace)
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

    struct MockSymbol {
        id: i64,
        parent: Option<Arc<dyn TraceNamespaceSymbol>>,
        pinned: AtomicBool,
        monitor_calls: AtomicU32,
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
            true
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_id(&self) -> i64 {
            self.parent
                .as_ref()
                .map(|p| Symbol::get_id(p.as_ref()))
                .unwrap_or(-1)
        }
    }

    impl TraceSymbol for MockSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace)
        }

        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }

        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            self.parent.clone()
        }

        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            self.monitor_calls.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }

        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }

        fn set_pinned(&mut self, pinned: bool) {
            self.pinned.store(pinned, Ordering::SeqCst);
        }

        fn is_pinned(&self) -> bool {
            self.pinned.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe_and_delegates_defaults() {
        let mut sym = MockSymbol {
            id: 7,
            parent: None,
            pinned: AtomicBool::new(false),
            monitor_calls: AtomicU32::new(0),
        };

        // Symbol supertrait methods remain reachable through the trait object.
        assert_eq!(Symbol::get_id(&sym), 7);

        // `set_pinned`/`is_pinned` are real abstract methods on this trait (not on `Symbol`).
        assert!(!sym.is_pinned());
        sym.set_pinned(true);
        assert!(sym.is_pinned());

        // `get_references()` defaults to delegating to `get_references_with_monitor` with a
        // dummy monitor.
        assert_eq!(sym.monitor_calls.load(Ordering::SeqCst), 0);
        let refs = sym.get_references();
        assert!(refs.is_empty());
        assert_eq!(sym.monitor_calls.load(Ordering::SeqCst), 1);

        let boxed: Box<dyn TraceSymbol> = Box::new(sym);
        let _: Box<dyn Trace> = boxed.get_trace();
        assert!(boxed.get_thread().is_none());
    }

    #[test]
    fn get_parent_trace_symbol_defaults_to_get_parent_trace_namespace() {
        let parent: Arc<dyn TraceNamespaceSymbol> = Arc::new(MockNamespaceSymbol {
            id: 1,
            name: "parent".to_string(),
        });
        let sym = MockSymbol {
            id: 2,
            parent: Some(parent.clone()),
            pinned: AtomicBool::new(false),
            monitor_calls: AtomicU32::new(0),
        };

        let via_symbol = sym.get_parent_trace_symbol();
        let via_namespace = sym.get_parent_trace_namespace();
        assert!(via_symbol.is_some());
        assert_eq!(
            Symbol::get_id(via_symbol.unwrap().as_ref()),
            Symbol::get_id(via_namespace.unwrap().as_ref())
        );
        assert_eq!(sym.get_parent_id(), 1);
    }
}
