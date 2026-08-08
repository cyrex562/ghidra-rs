//! Port of `ghidra.trace.util.TraceSpaceMixin`.

use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{TraceRegisterUtils, TraceThread};

/// Adds conveniences for getting the thread and frame level, if applicable, from an object's
/// address space.
///
/// Port of `ghidra.trace.util.TraceSpaceMixin`.
///
/// The default methods delegate to `TraceRegisterUtils.getThread`/`getFrameLevel`, which is not
/// yet ported; callers must supply an implementation of the
/// [`TraceRegisterUtils`](crate::trace::seam_stubs::TraceRegisterUtils) placeholder trait via
/// [`Self::trace_register_utils`].
pub trait TraceSpaceMixin {
    /// Get the trace containing the object.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the object's address space.
    fn get_address_space(&self) -> Arc<AddressSpace>;

    /// The `TraceRegisterUtils` instance used to resolve the thread and frame level. Mirrors the
    /// static `TraceRegisterUtils` calls made by the Java default methods.
    fn trace_register_utils(&self) -> &dyn TraceRegisterUtils;

    /// Get the thread denoted by the object's address space.
    fn get_thread(&self) -> Box<dyn TraceThread> {
        self.trace_register_utils()
            .get_thread(self.get_trace().as_ref(), &self.get_address_space())
    }

    /// Get the frame level denoted by the object's address space.
    ///
    /// Note this will return 0 if the frame level is not applicable. This is the same as the
    /// innermost frame level when it is applicable. To distinguish whether or not a 0 return
    /// value is applicable, you must examine the path or schema.
    fn get_frame_level(&self) -> i32 {
        self.trace_register_utils()
            .get_frame_level(self.get_trace().as_ref(), &self.get_address_space())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    struct MockTrace;

    impl crate::framework::model::DomainObject for MockTrace {}

    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }

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

        fn get_base_address_factory(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
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

        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(
            &self,
        ) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(
            &self,
        ) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program_view(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_time_viewport(
            &self,
        ) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
        }

        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
        }

        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }

        fn lock_write(
            &self,
        ) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockThread;
    impl TraceThread for MockThread {}

    struct MockRegisterUtils;
    impl TraceRegisterUtils for MockRegisterUtils {
        fn get_thread(&self, _trace: &dyn Trace, space: &Arc<AddressSpace>) -> Box<dyn TraceThread> {
            assert_eq!(space.name(), "register");
            Box::new(MockThread)
        }

        fn get_frame_level(&self, _trace: &dyn Trace, space: &Arc<AddressSpace>) -> i32 {
            if space.name() == "register" { 2 } else { 0 }
        }

        fn get_register_address_space(
            &self,
            _thread: &dyn TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn buffer_for_value(
            &self,
            _register: &crate::program::model::lang::Register,
            _value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }

        fn finish_buffer(
            &self,
            _buf: &[u8],
            _register: &crate::program::model::lang::Register,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockSpaceObject {
        space: Arc<AddressSpace>,
        utils: MockRegisterUtils,
    }

    impl TraceSpaceMixin for MockSpaceObject {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace)
        }

        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }

        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.utils
        }
    }

    #[test]
    fn default_methods_delegate_to_trace_register_utils() {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        let obj = MockSpaceObject { space, utils: MockRegisterUtils };

        assert_eq!(obj.get_frame_level(), 2);
        let _thread = obj.get_thread();
    }

    #[test]
    fn trait_object_is_object_safe() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let obj = MockSpaceObject { space, utils: MockRegisterUtils };
        let dyn_obj: &dyn TraceSpaceMixin = &obj;

        assert_eq!(dyn_obj.get_frame_level(), 0);
        assert_eq!(dyn_obj.get_address_space().name(), "ram");
    }
}
