use std::sync::Arc;

use crate::format::seam_stubs::DebugInfoProviderRegistry;
use crate::program::model::listing::Program;

/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DebugInfoProviderCreatorContext`.
///
/// Information that might be needed to create a new [`DebugInfoProvider`](crate::format::dwarf::external::debug_info_provider::DebugInfoProvider) instance.
#[derive(Clone)]
pub struct DebugInfoProviderCreatorContext {
    /// The registry used to create debug info providers.
    pub registry: Arc<dyn DebugInfoProviderRegistry>,
    /// The program for which debug info is being created.
    pub program: Arc<dyn Program>,
}

impl DebugInfoProviderCreatorContext {
    /// Creates a new DebugInfoProviderCreatorContext with the given registry and program.
    pub fn new(
        registry: Arc<dyn DebugInfoProviderRegistry>,
        program: Arc<dyn Program>,
    ) -> Self {
        DebugInfoProviderCreatorContext { registry, program }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRegistry;

    impl DebugInfoProviderRegistry for MockRegistry {
        fn get_instance(&self) -> Box<dyn DebugInfoProviderRegistry> {
            Box::new(MockRegistry)
        }

        fn register(&self, _test_func: &dyn std::any::Any, _create_func: &dyn std::any::Any) {}

        fn new_context(
            &self,
            _program: &dyn Program,
        ) -> Box<dyn std::any::Any> {
            Box::new("test_context")
        }

        fn create(
            &self,
            _name: &str,
            _context: &dyn std::any::Any,
        ) -> Box<dyn crate::format::dwarf::external::debug_info_provider::DebugInfoProvider> {
            Box::new(MockProvider)
        }
    }

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    struct MockProvider;

    impl crate::format::dwarf::external::debug_info_provider::DebugInfoProvider for MockProvider {
        fn get_name(&self) -> String {
            "test_provider".to_string()
        }

        fn get_descriptive_name(&self) -> String {
            "Test Provider".to_string()
        }

        fn get_status(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> crate::format::dwarf::external::debug_info_provider_status::DebugInfoProviderStatus {
            crate::format::dwarf::external::debug_info_provider_status::DebugInfoProviderStatus::Valid
        }
    }

    #[test]
    fn creator_context_holds_registry_and_program() {
        let registry: Arc<dyn DebugInfoProviderRegistry> = Arc::new(MockRegistry);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let context = DebugInfoProviderCreatorContext::new(registry, program);

        assert_eq!(context.program.get_language_id(), "x86");
    }

    #[test]
    fn creator_context_clone_shares_references() {
        let registry: Arc<dyn DebugInfoProviderRegistry> = Arc::new(MockRegistry);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let context1 = DebugInfoProviderCreatorContext::new(registry.clone(), program.clone());
        let context2 = context1.clone();

        assert_eq!(context2.program.get_language_id(), "x86");
    }
}
