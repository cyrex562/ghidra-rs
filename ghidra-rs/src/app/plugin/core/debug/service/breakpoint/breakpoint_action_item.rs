use crate::app::services::debugger_logical_breakpoint_service::BreakpointCommandFuture;
use crate::program::model::address::{Address, AddressOverflowException, AddressRange};

/// An invocation is planning an action on a breakpoint.
///
/// Port of `ghidra.app.plugin.core.debug.service.breakpoint.BreakpointActionItem`. Java is an
/// `interface` with 1 abstract method and 8 in-repo implementors, so this becomes a `trait`
/// (rule R-interface-open-ext-point / cycle cut point).
///
/// See `BreakpointActionSet` (not yet ported).
pub trait BreakpointActionItem {
    /// Perform the action.
    ///
    /// Returns the future for the action. Synchronous invocations can just return an
    /// already-completed future (Java's `AsyncUtils.NIL`).
    fn execute(&self) -> BreakpointCommandFuture;
}

/// Compute a range from an address and length.
///
/// Port of `BreakpointActionItem.range(Address, long)`. Java catches `AddressOverflowException`
/// and rethrows as an unchecked `AssertionError`; mirrored here by panicking, since callers treat
/// an overflowing breakpoint range as a programming error, not a recoverable condition.
pub fn range(address: &Address, length: u64) -> AddressRange {
    AddressRange::from_start_len(address.clone(), length)
        .unwrap_or_else(|e: AddressOverflowException| {
            panic!("BreakpointActionItem::range: address range overflow: {e}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn range_computes_expected_bounds() {
        let space = ram_space();
        let start = space.address(0x1000);
        let r = range(&start, 0x10);
        assert_eq!(r.min_address(), &start);
        assert_eq!(r.length(), 0x10);
        assert_eq!(r.max_address(), &space.address(0x100f));
    }

    #[test]
    #[should_panic(expected = "address range overflow")]
    fn range_panics_on_overflow() {
        let space = ram_space();
        let start = space.address(space.max_offset());
        range(&start, 2);
    }

    struct RecordingActionItem {
        executed: Arc<AtomicBool>,
    }

    impl BreakpointActionItem for RecordingActionItem {
        fn execute(&self) -> BreakpointCommandFuture {
            self.executed.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    #[test]
    fn execute_runs_synchronous_action() {
        let executed = Arc::new(AtomicBool::new(false));
        let item = RecordingActionItem {
            executed: executed.clone(),
        };
        let future: Pin<Box<dyn Future<Output = ()> + Send>> = item.execute();
        futures_lite_block_on(future);
        assert!(executed.load(Ordering::SeqCst));
    }

    /// Minimal same-thread executor for a `Future<Output = ()>` that never actually yields
    /// (this test's futures complete immediately), avoiding a dependency on an async runtime
    /// crate just to drive a smoke test.
    fn futures_lite_block_on(mut future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {}
            Poll::Pending => panic!("test future did not complete synchronously"),
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let executed = Arc::new(AtomicBool::new(false));
        let item: Box<dyn BreakpointActionItem> = Box::new(RecordingActionItem {
            executed: executed.clone(),
        });
        futures_lite_block_on(item.execute());
        assert!(executed.load(Ordering::SeqCst));
    }
}
