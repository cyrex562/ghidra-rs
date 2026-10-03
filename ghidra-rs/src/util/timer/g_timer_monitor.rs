/// Monitor object returned from a `GTimer::schedule()` call.
pub trait GTimerMonitor: Send + Sync {
    /// Cancels the scheduled runnable associated with this monitor if it has not already run.
    /// Returns true if the scheduled runnable was cancelled before it had a chance to execute.
    fn cancel(&self) -> bool;

    /// Return true if the scheduled runnable has completed.
    fn did_run(&self) -> bool;

    /// Return true if the scheduled runnable was cancelled before it had a chance to run.
    fn was_cancelled(&self) -> bool;
}

/// A "do nothing" [`GTimerMonitor`], mirroring Java's `GTimerMonitor.DUMMY` anonymous
/// implementation.
pub struct DummyGTimerMonitor;

impl GTimerMonitor for DummyGTimerMonitor {
    fn cancel(&self) -> bool {
        false
    }

    fn did_run(&self) -> bool {
        false
    }

    fn was_cancelled(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn dummy_monitor_never_cancels_or_runs() {
        let monitor = DummyGTimerMonitor;
        assert!(!monitor.cancel());
        assert!(!monitor.did_run());
        assert!(!monitor.was_cancelled());
    }

    struct RanMonitor {
        cancelled: AtomicBool,
        ran: AtomicBool,
    }

    impl GTimerMonitor for RanMonitor {
        fn cancel(&self) -> bool {
            if self.ran.load(Ordering::SeqCst) {
                return false;
            }
            self.cancelled.store(true, Ordering::SeqCst);
            true
        }

        fn did_run(&self) -> bool {
            self.ran.load(Ordering::SeqCst)
        }

        fn was_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn cancel_before_run_succeeds() {
        let monitor = RanMonitor { cancelled: AtomicBool::new(false), ran: AtomicBool::new(false) };
        assert!(monitor.cancel());
        assert!(monitor.was_cancelled());
        assert!(!monitor.did_run());
    }

    #[test]
    fn cancel_after_run_fails() {
        let monitor = RanMonitor { cancelled: AtomicBool::new(false), ran: AtomicBool::new(true) };
        assert!(!monitor.cancel());
        assert!(!monitor.was_cancelled());
        assert!(monitor.did_run());
    }

    #[test]
    fn as_trait_object() {
        let monitor: Box<dyn GTimerMonitor> = Box::new(DummyGTimerMonitor);
        assert!(!monitor.cancel());
        assert!(!monitor.did_run());
    }
}
