use crate::util::task::MonitoredRunnable;

/// A [`MonitoredRunnable`] that has a method which may need to be run on the Swing AWT
/// thread. Pass a `SwingRunnable` to the run manager if follow-on work needs to be done
/// after `monitored_run` completes.
///
/// Port of `ghidra.util.task.SwingRunnable`.
pub trait SwingRunnable: MonitoredRunnable {
    /// Callback on the swing thread.
    fn swing_run(&self, is_cancelled: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::{DummyMonitor, TaskMonitor};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct TestSwingRunnable {
        ran: Arc<AtomicBool>,
        swing_ran: Arc<AtomicBool>,
        swing_cancelled: Arc<AtomicBool>,
    }

    impl MonitoredRunnable for TestSwingRunnable {
        fn monitored_run(&self, _monitor: &dyn TaskMonitor) {
            self.ran.store(true, Ordering::SeqCst);
        }
    }

    impl SwingRunnable for TestSwingRunnable {
        fn swing_run(&self, is_cancelled: bool) {
            self.swing_ran.store(true, Ordering::SeqCst);
            self.swing_cancelled.store(is_cancelled, Ordering::SeqCst);
        }
    }

    #[test]
    fn swing_runnable_runs_both_callbacks_as_trait_object() {
        let ran = Arc::new(AtomicBool::new(false));
        let swing_ran = Arc::new(AtomicBool::new(false));
        let swing_cancelled = Arc::new(AtomicBool::new(true));

        let runnable: Arc<dyn SwingRunnable> = Arc::new(TestSwingRunnable {
            ran: ran.clone(),
            swing_ran: swing_ran.clone(),
            swing_cancelled: swing_cancelled.clone(),
        });

        let monitor = DummyMonitor;
        runnable.monitored_run(&monitor);
        runnable.swing_run(false);

        assert!(ran.load(Ordering::SeqCst));
        assert!(swing_ran.load(Ordering::SeqCst));
        assert!(!swing_cancelled.load(Ordering::SeqCst));
    }
}
