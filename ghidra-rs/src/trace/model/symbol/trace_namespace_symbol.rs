use std::sync::Arc;

use crate::program::model::symbol::Namespace;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;

/// A trace namespace symbol.
///
/// Port of `ghidra.trace.model.symbol.TraceNamespaceSymbol`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface `extends TraceSymbol, Namespace` and declares two identity defaults that
/// are not modeled here:
/// - `default TraceNamespaceSymbol getSymbol()` (covariantly overriding `Namespace::getSymbol()`,
///   normally `Arc<dyn Symbol>`) returns `this`, reflecting that in a trace, unlike a `Program`,
///   a namespace and its symbol are the same object (see the `TraceSymbol` javadoc).
/// - `default TraceNamespaceSymbol getObject()` (covariantly overriding `Symbol::getObject()`)
///   likewise returns `this`.
///
/// Rust has no covariant trait-method override, and reproducing either default would require
/// implementors to hand back `Arc<Self>`/`Box<Self>` from `&self`, which is not expressible for a
/// `dyn`-safe trait. Implementors should keep the identity contract in mind when implementing
/// [`Namespace::get_symbol`] and [`Symbol::as_namespace`](crate::program::model::symbol::Symbol::as_namespace).
///
/// `Namespace::get_parent_namespace()` is covariantly overridden in Java to return
/// `TraceNamespaceSymbol` instead of `Namespace`; that override is exposed here under a distinct
/// name, [`TraceNamespaceSymbol::get_parent_trace_namespace_symbol`], rather than redeclaring
/// [`Namespace::get_parent_namespace`]. Implementors should still implement
/// `Namespace::get_parent_namespace` (delegating to `get_parent_trace_namespace_symbol`),
/// mirroring the Java override.
///
/// The Java source also re-declares `@Override Trace getTrace()`, purely restating the abstract
/// method it inherits from [`TraceSymbol`] with no new semantics; that is not redeclared here
/// since [`TraceSymbol::get_trace`] already covers it as a supertrait method.
///
/// `Namespace::is_global()` is re-abstracted (without a default) in the Java source; Rust
/// implementors are simply expected to override the [`Namespace::is_global`] default in their own
/// `impl Namespace` block, which requires no change to this trait.
pub trait TraceNamespaceSymbol: TraceSymbol + Namespace {
    /// This is the covariant override of `Namespace::getParentNamespace()` in the Java source;
    /// see the trait-level documentation for why it is exposed under a distinct name here.
    fn get_parent_trace_namespace_symbol(&self) -> Option<Arc<dyn TraceNamespaceSymbol>>;

    /// Get the children of this namespace.
    fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>>;

    /// Gets the full path name for this symbol as an ordered array of strings ending with the
    /// symbol name.
    ///
    /// Mirrors the re-declared `Symbol::getPath()` override.
    fn get_path(&self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSetView};
    use crate::program::model::symbol::{
        NamespaceType, SetParentNamespaceError, SourceType, Symbol, SymbolType,
    };
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;

    struct MockTrace;

    impl crate::framework::model::DomainObject for MockTrace {}

    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {}

        fn get_emulator_cache_version(&self) -> i64 {
            0
        }

        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_equate_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform_manager(&self) -> Box<dyn crate::trace::seam_stubs::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_object_manager(&self) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_reference_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(&self) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(&self, _snap: i64) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program_view(&self) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_program_view_listener(&mut self, _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn crate::trace::model::trace::TraceProgramViewListener) {}

        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }

        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockTraceSymbol;

    impl Symbol for MockTraceSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_name(&self) -> &str {
            "mock_child"
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::Default
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl TraceSymbol for MockTraceSymbol {
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
        parent: Option<Arc<dyn TraceNamespaceSymbol>>,
        children: Vec<Arc<dyn TraceSymbol>>,
    }

    impl Namespace for MockNamespaceSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled; see trait docs")
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent
                .clone()
                .map(|p| p as Arc<dyn Namespace>)
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
            self.parent
                .as_ref()
                .map(|p| Symbol::get_id(p.as_ref()))
                .unwrap_or(-1)
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
            self.parent.clone()
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
            self.parent.clone()
        }

        fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>> {
            self.children.clone()
        }

        fn get_path(&self) -> Vec<String> {
            let mut path = match &self.parent {
                Some(p) => p.get_path(),
                None => Vec::new(),
            };
            path.push(self.name.clone());
            path
        }
    }

    fn make_global() -> Arc<MockNamespaceSymbol> {
        Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            name: "Global".to_string(),
            parent: None,
            children: Vec::new(),
        })
    }

    #[test]
    fn trait_object_usage_is_object_safe_and_reports_hierarchy() {
        let global = make_global();
        let child: Box<dyn TraceNamespaceSymbol> = Box::new(MockNamespaceSymbol {
            id: 1,
            name: "child".to_string(),
            parent: Some(global.clone() as Arc<dyn TraceNamespaceSymbol>),
            children: vec![Arc::new(MockTraceSymbol) as Arc<dyn TraceSymbol>],
        });

        assert!(!Namespace::is_global(child.as_ref()));
        assert!(Namespace::is_global(global.as_ref()));
        assert_eq!(child.get_path(), vec!["Global".to_string(), "child".to_string()]);
        assert_eq!(child.get_children().len(), 1);
        assert!(child.get_parent_trace_namespace_symbol().is_some());
        let _: Box<dyn Trace> = child.get_trace();
    }

    #[test]
    fn narrows_to_namespace_via_supertrait() {
        let global = make_global();
        let ns: &dyn Namespace = global.as_ref();
        assert_eq!(ns.get_name(), "Global");
        assert!(ns.is_global());

        // Sanity: AddressSetView / AddressSet remain usable alongside the trait, since
        // `Namespace::get_body` defaults to an empty set.
        let body: Box<dyn AddressSetView> = Box::new(AddressSet::new());
        assert!(body.is_empty());
        let _: Result<(), SetParentNamespaceError> =
            Err(SetParentNamespaceError::InvalidInput(
                crate::util::exception::InvalidInputException::new(),
            ));
    }
}
