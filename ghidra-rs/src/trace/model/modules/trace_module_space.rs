//! Port of `ghidra.trace.model.modules.TraceModuleSpace`.

use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::modules::trace_module_operations::TraceModuleOperations;

/// A `TraceModuleOperations` scoped to a single address space.
pub trait TraceModuleSpace: TraceModuleOperations {
    /// Get the address space this scopes module/section queries to.
    fn get_address_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::modules::trace_module::TraceModule;
    use crate::trace::model::modules::trace_section::TraceSection;

    struct MockSpaceTrace {
        space: Arc<AddressSpace>,
    }

    impl TraceModuleOperations for MockSpaceTrace {
        fn get_all_modules(&self) -> Vec<Box<dyn TraceModule>> {
            Vec::new()
        }

        fn get_loaded_modules(&self, _snap: i64) -> Vec<Box<dyn TraceModule>> {
            Vec::new()
        }

        fn get_modules_at(&self, _snap: i64, _address: &Address) -> Vec<Box<dyn TraceModule>> {
            Vec::new()
        }

        fn get_modules_intersecting(
            &self,
            _lifespan: &dyn Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceModule>> {
            Vec::new()
        }

        fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_sections_at(&self, _snap: i64, _address: &Address) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_sections_intersecting(
            &self,
            _lifespan: &dyn Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }
    }

    impl TraceModuleSpace for MockSpaceTrace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    #[test]
    fn reports_its_own_address_space() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let trace = MockSpaceTrace { space: space.clone() };
        assert_eq!(trace.get_address_space().name(), "ram");
        assert!(Arc::ptr_eq(&trace.get_address_space(), &space));
    }

    #[test]
    fn trait_object_is_object_safe() {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        let trace = MockSpaceTrace { space };
        let obj: &dyn TraceModuleSpace = &trace;
        assert_eq!(obj.get_address_space().space_type(), AddressSpaceType::Register);
        assert!(obj.get_all_modules().is_empty());
    }
}
