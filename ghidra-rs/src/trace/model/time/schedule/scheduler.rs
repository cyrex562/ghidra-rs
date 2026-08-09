//! A generator of an emulator's thread schedule.
//!
//! Port of `ghidra.trace.model.time.schedule.Scheduler`.
//!
//! Java's default `run(Trace, TraceThread, PcodeMachine<?>, TaskMonitor)` method is not ported.
//! It drives a machine purely through `PcodeThread<?>`/`PcodeMachine<?>` wildcard-typed
//! operations (`getThread(path, true)`, `getFrame()`, `finishInstruction()`, `stepInstruction()`,
//! `dropInstruction()`), none of which are exposed by this crate's type-erased
//! [`ErasedPcodeMachine`](crate::pcode::emu::pcode_machine::ErasedPcodeMachine)/
//! [`ErasedPcodeThread`](crate::pcode::emu::pcode_thread::ErasedPcodeThread) (bare marker traits,
//! by design: see [`Step`]'s module docs for why growing a marker trait like this to cover one
//! caller's needs is avoided -- it would ripple into every implementor across the crate). The
//! nested `RunResult` interface and `RecordRunResult` record that `run()` would construct and
//! return are, for the same reason, left as the existing placeholders in
//! [`crate::app::seam_stubs`] rather than duplicated here. Only the abstract
//! `nextSlice(Trace)` method and the `oneThread(TraceThread)` static factory -- which depend on
//! neither -- are ported below.

use crate::trace::model::time::schedule::step::Step;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{self, TraceThread};

/// A generator of an emulator's thread schedule.
///
/// Port of `ghidra.trace.model.time.schedule.Scheduler`.
pub trait Scheduler {
    /// Get the next step to schedule.
    ///
    /// Mirrors `Scheduler.nextSlice(Trace)`.
    fn next_slice(&self, trace: &dyn Trace) -> Box<dyn Step>;
}

/// Create a scheduler that allocates all slices to a single thread.
///
/// Mirrors the static factory `Scheduler.oneThread(TraceThread)`.
pub fn one_thread(thread: Option<Box<dyn TraceThread>>) -> Box<dyn Scheduler> {
    let key = thread.map_or(-1, |t| t.get_key());

    struct OneThreadScheduler {
        key: i64,
    }

    impl Scheduler for OneThreadScheduler {
        fn next_slice(&self, _trace: &dyn Trace) -> Box<dyn Step> {
            seam_stubs::tick_step_new(self.key, 1000)
        }
    }

    Box::new(OneThreadScheduler { key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::merge::DataTypeManagerOwner;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::util::lock_hold::{Lock, LockHold};

    struct MockThread {
        key: i64,
    }
    impl TraceThread for MockThread {
        fn get_key(&self) -> i64 {
            self.key
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    /// A `Trace` whose members are never called: `next_slice` on a one-thread scheduler ignores
    /// its `trace` argument entirely (mirroring Java's `oneThread` anonymous class), so every
    /// member here just needs to type-check, not run.
    struct UnusedTrace;

    impl DomainObject for UnusedTrace {}

    impl DataTypeManagerOwner for UnusedTrace {
        fn get_data_type_manager(&self) -> &dyn DataTypeManager {
            static MANAGER: MockDataTypeManager = MockDataTypeManager;
            &MANAGER
        }
    }

    impl DataTypeManagerDomainObject for UnusedTrace {}

    impl Trace for UnusedTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_address_property_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager>
        {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_platform_manager(
            &self,
        ) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_register_context_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_static_mapping_manager(&self) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_symbol_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
            unreachable!("next_slice ignores its trace argument")
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
            unreachable!("next_slice ignores its trace argument")
        }
        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            unreachable!("next_slice ignores its trace argument")
        }
        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unreachable!("next_slice ignores its trace argument")
        }
    }

    #[test]
    #[should_panic(expected = "TickStep is not yet ported: new(3, 1000)")]
    fn one_thread_next_slice_uses_threads_key() {
        // Documents the cycle-break seam: Scheduler::one_thread()'s next_slice() delegates to the
        // not-yet-ported TickStep constructor (mirroring Step::nop(); see the `step` module's
        // test of the same seam). Once TickStep lands, this should be replaced with a real
        // assertion that next_slice() yields a 1000-tick step for the given thread's key,
        // matching Java's `Scheduler.oneThread(thread).nextSlice(trace)` returning
        // `new TickStep(key, 1000)`.
        let scheduler = one_thread(Some(Box::new(MockThread { key: 3 })));
        scheduler.next_slice(&UnusedTrace);
    }

    #[test]
    #[should_panic(expected = "TickStep is not yet ported: new(-1, 1000)")]
    fn one_thread_defaults_missing_thread_to_key_minus_one() {
        // Mirrors Java's `long key = thread == null ? -1 : thread.getKey();` branch.
        let scheduler = one_thread(None);
        scheduler.next_slice(&UnusedTrace);
    }
}
