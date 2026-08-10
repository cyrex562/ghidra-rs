//! A trace access shim.
//!
//! Port of `ghidra.pcode.exec.trace.data.PcodeTraceAccess`.

use crate::pcode::emu::ErasedPcodeThread;
use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
use crate::pcode::exec::trace::data::pcode_trace_registers_access::PcodeTraceRegistersAccess;
use crate::pcode::seam_stubs::{DefaultPcodeTraceThreadAccess, PcodeTraceMemoryAccess};
use crate::program::model::lang::language::Language;
use crate::trace::model::thread::TraceThread;

/// A trace access shim.
///
/// This encapsulates the source or destination "coordinates" of a trace to simplify access to
/// that trace by p-code operations. This is also meant to encapsulate certain conventions, e.g.,
/// writes are effective from the destination snapshot into the indefinite future, and meant to
/// protect p-code executor/emulator states from future re-factorings of the Trace API.
///
/// While, technically anything can be behind the shim, the default implementations are backed by
/// a trace. The shim is associated with a chosen platform and snapshot. All methods are with
/// respect to that platform. In particular the addresses must all be in spaces of the platform's
/// language. Note that the platform may be the trace's host platform.
pub trait PcodeTraceAccess: Send + Sync {
    /// Derive an access for writing a snapshot, where this access was the emulator's source.
    ///
    /// `snap` is the destination snapshot key.
    fn derive_for_write(&self, snap: i64) -> Box<dyn PcodeTraceAccess>;

    /// Get the language of the associated platform.
    fn get_language(&self) -> Box<dyn Language>;

    /// Get the data-access shim for use in an emulator's shared state.
    fn get_data_for_shared_state(&self) -> Box<dyn PcodeTraceMemoryAccess>;

    /// Get the data-access shim for use in an emulator thread's local state.
    ///
    /// `thread` is the emulator's thread, and `frame` is the frame, usually 0.
    fn get_data_for_local_state(
        &self,
        thread: &dyn ErasedPcodeThread,
        frame: i32,
    ) -> Box<dyn PcodeTraceRegistersAccess>;

    /// Get the data-access shim for use in an emulator thread's local state.
    ///
    /// `thread` is the trace thread associated with the emulator's thread, and `frame` is the
    /// frame, usually 0.
    fn get_data_for_local_state_for_trace_thread(
        &self,
        thread: &dyn TraceThread,
        frame: i32,
    ) -> Box<dyn PcodeTraceRegistersAccess>;

    /// Construct a new trace thread data-access shim.
    ///
    /// `shared` is the shared (memory) state, and `local` is the local (register) state.
    fn new_pcode_trace_thread_access(
        &self,
        shared: Box<dyn PcodeTraceMemoryAccess>,
        local: Box<dyn PcodeTraceRegistersAccess>,
    ) -> Box<dyn PcodeTraceDataAccess> {
        Box::new(DefaultPcodeTraceThreadAccess::new(shared, local))
    }

    /// Get the data-access shim for use in an executor having thread context.
    ///
    /// **NOTE:** Do not use this shim for an emulator thread's local state. Use
    /// [`get_data_for_local_state`](Self::get_data_for_local_state) instead. This shim is meant
    /// for use in stand-alone executors, e.g., for evaluating Sleigh expressions. Most likely,
    /// the thread is the active thread in the UI.
    ///
    /// `thread` is the trace thread for context, if applicable, or `None`, and `frame` is the
    /// frame.
    fn get_data_for_thread_state(
        &self,
        thread: Option<&dyn TraceThread>,
        frame: i32,
    ) -> Box<dyn PcodeTraceDataAccess> {
        let Some(thread) = thread else {
            return self.get_data_for_shared_state();
        };
        self.new_pcode_trace_thread_access(
            self.get_data_for_shared_state(),
            self.get_data_for_local_state_for_trace_thread(thread, frame),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
    use std::sync::Arc;

    use crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess;
    use crate::program::model::address::{Address, AddressRange, AddressSetView};
    use crate::trace::model::memory::trace_memory_state::TraceMemoryState;

    /// Data-access methods aren't exercised by these tests -- only construction and the
    /// `PcodeTraceAccess`/`new_pcode_trace_thread_access` wiring are.
    macro_rules! impl_unexercised_data_access {
        ($ty:ty) => {
            impl PcodeTraceDataAccess for $ty {
                fn get_language(&self) -> Box<dyn Language> {
                    unimplemented!("not exercised by these tests")
                }
                fn set_state(&mut self, _range: &AddressRange, _state: TraceMemoryState) {
                    unimplemented!("not exercised by these tests")
                }
                fn get_viewport_state(&self, _range: &AddressRange) -> TraceMemoryState {
                    unimplemented!("not exercised by these tests")
                }
                fn intersect_view_known(
                    &self,
                    _view: &dyn AddressSetView,
                    _use_full_spans: bool,
                ) -> Box<dyn AddressSetView> {
                    unimplemented!("not exercised by these tests")
                }
                fn put_bytes(&mut self, _start: &Address, _buf: &[u8]) -> usize {
                    unimplemented!("not exercised by these tests")
                }
                fn get_bytes(&self, _start: &Address, _buf: &mut [u8]) -> usize {
                    unimplemented!("not exercised by these tests")
                }
                fn translate(&self, _address: &Address) -> Address {
                    unimplemented!("not exercised by these tests")
                }
                fn get_property_access<T>(
                    &self,
                    _name: &str,
                ) -> Box<dyn PcodeTracePropertyAccess<T>>
                where
                    T: 'static,
                {
                    unimplemented!("not exercised by these tests")
                }
            }
        };
    }

    struct FakeMemoryAccess;
    impl_unexercised_data_access!(FakeMemoryAccess);
    impl PcodeTraceMemoryAccess for FakeMemoryAccess {}

    struct FakeRegistersAccess;
    impl_unexercised_data_access!(FakeRegistersAccess);
    impl PcodeTraceRegistersAccess for FakeRegistersAccess {
        fn initialize_thread_context(&self, _thread: &mut dyn ErasedPcodeThread) {}
    }

    struct FakeTraceThread;

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for FakeTraceThread {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl crate::trace::model::target::iface::TraceObjectInterface for FakeTraceThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for FakeTraceThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            0
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: crate::trace::model::lifespan::Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            true
        }
    }

    /// Tracks how many times each method is invoked, so the default methods'
    /// [`PcodeTraceAccess::get_data_for_thread_state`] wiring can be checked against Java's
    /// short-circuit-on-null-thread behavior, not just checked for "it compiles".
    #[derive(Default, Clone)]
    struct CallCounts {
        derive_for_write_snap: Arc<AtomicI64>,
        shared_state_calls: Arc<AtomicU32>,
        local_state_by_trace_thread_calls: Arc<AtomicU32>,
        new_thread_access_calls: Arc<AtomicU32>,
    }

    struct FakeTraceAccess {
        calls: CallCounts,
    }

    impl PcodeTraceAccess for FakeTraceAccess {
        fn derive_for_write(&self, snap: i64) -> Box<dyn PcodeTraceAccess> {
            self.calls.derive_for_write_snap.store(snap, Ordering::SeqCst);
            Box::new(FakeTraceAccess { calls: self.calls.clone() })
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn get_data_for_shared_state(&self) -> Box<dyn PcodeTraceMemoryAccess> {
            self.calls.shared_state_calls.fetch_add(1, Ordering::SeqCst);
            Box::new(FakeMemoryAccess)
        }

        fn get_data_for_local_state(
            &self,
            _thread: &dyn ErasedPcodeThread,
            _frame: i32,
        ) -> Box<dyn PcodeTraceRegistersAccess> {
            unimplemented!("not exercised by these tests")
        }

        fn get_data_for_local_state_for_trace_thread(
            &self,
            _thread: &dyn TraceThread,
            _frame: i32,
        ) -> Box<dyn PcodeTraceRegistersAccess> {
            self.calls.local_state_by_trace_thread_calls.fetch_add(1, Ordering::SeqCst);
            Box::new(FakeRegistersAccess)
        }

        fn new_pcode_trace_thread_access(
            &self,
            shared: Box<dyn PcodeTraceMemoryAccess>,
            local: Box<dyn PcodeTraceRegistersAccess>,
        ) -> Box<dyn PcodeTraceDataAccess> {
            self.calls.new_thread_access_calls.fetch_add(1, Ordering::SeqCst);
            // Defer to the default impl so it's still exercised (constructs a real
            // `DefaultPcodeTraceThreadAccess`), just with our call counted first.
            Box::new(DefaultPcodeTraceThreadAccess::new(shared, local))
        }
    }

    #[test]
    fn test_derive_for_write_threads_snap_into_new_instance() {
        let access = FakeTraceAccess { calls: CallCounts::default() };
        let derived = access.derive_for_write(42);
        assert_eq!(access.calls.derive_for_write_snap.load(Ordering::SeqCst), 42);
        // Java's `deriveForWrite` returns a fresh, independently-usable shim -- verify the
        // derived shim is itself a working `PcodeTraceAccess` by deriving again from it.
        let _ = derived.derive_for_write(43);
        assert_eq!(access.calls.derive_for_write_snap.load(Ordering::SeqCst), 43);
    }

    #[test]
    fn test_get_data_for_thread_state_none_short_circuits_to_shared() {
        // Mirrors `PcodeTraceAccess.getDataForThreadState`: a null thread must return
        // `getDataForSharedState()` directly, without touching per-thread register state or
        // constructing a `DefaultPcodeTraceThreadAccess` multiplexer.
        let access = FakeTraceAccess { calls: CallCounts::default() };
        let _data: Box<dyn PcodeTraceDataAccess> = access.get_data_for_thread_state(None, 0);

        assert_eq!(access.calls.shared_state_calls.load(Ordering::SeqCst), 1);
        assert_eq!(access.calls.local_state_by_trace_thread_calls.load(Ordering::SeqCst), 0);
        assert_eq!(access.calls.new_thread_access_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_get_data_for_thread_state_some_multiplexes_shared_and_local() {
        // Mirrors `PcodeTraceAccess.getDataForThreadState`: a non-null thread must combine
        // `getDataForSharedState()` and `getDataForLocalState(thread, frame)` via
        // `newPcodeTraceThreadAccess`.
        let access = FakeTraceAccess { calls: CallCounts::default() };
        let thread = FakeTraceThread;
        let _data: Box<dyn PcodeTraceDataAccess> =
            access.get_data_for_thread_state(Some(&thread), 7);

        assert_eq!(access.calls.shared_state_calls.load(Ordering::SeqCst), 1);
        assert_eq!(access.calls.local_state_by_trace_thread_calls.load(Ordering::SeqCst), 1);
        assert_eq!(access.calls.new_thread_access_calls.load(Ordering::SeqCst), 1);
    }
}
