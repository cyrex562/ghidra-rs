//! Monitor used by Headless Analyzer for "timeout" functionality.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use crate::util::exception::CancelledException;
use crate::util::task::{CancelledListener, TaskMonitor};

/// Monitor used by Headless Analyzer for "timeout" functionality.
///
/// Port of `ghidra.app.util.headless.HeadlessTimedTaskMonitor`.
///
/// A background thread is started that automatically cancels the monitor after
/// `timeout_secs` seconds, unless [`HeadlessTimedTaskMonitor::cancel`] is called first, in
/// which case the background thread is woken early and never fires.
pub struct HeadlessTimedTaskMonitor {
    is_cancelled: Arc<AtomicBool>,
    timer: Arc<(Mutex<bool>, Condvar)>,
}

impl HeadlessTimedTaskMonitor {
    /// Creates a new monitor that automatically cancels itself after `timeout_secs` seconds.
    pub fn new(timeout_secs: u64) -> Self {
        let is_cancelled = Arc::new(AtomicBool::new(false));
        let timer = Arc::new((Mutex::new(false), Condvar::new()));

        let is_cancelled_ref = Arc::clone(&is_cancelled);
        let timer_ref = Arc::clone(&timer);
        thread::spawn(move || {
            let (stopped, condvar) = &*timer_ref;
            let guard = stopped.lock().unwrap();
            let (_guard, wait_result) = condvar
                .wait_timeout_while(guard, Duration::from_secs(timeout_secs), |stopped| {
                    !*stopped
                })
                .unwrap();
            if wait_result.timed_out() {
                is_cancelled_ref.store(true, Ordering::SeqCst);
            }
        });

        HeadlessTimedTaskMonitor { is_cancelled, timer }
    }
}

impl TaskMonitor for HeadlessTimedTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled.load(Ordering::SeqCst)
    }

    fn set_show_progress_value(&self, _show: bool) {}

    fn set_message(&self, _message: &str) {}

    fn get_message(&self) -> String {
        String::new()
    }

    fn set_progress(&self, _value: i64) {}

    fn initialize(&self, _max: i64) {}

    fn set_maximum(&self, _max: i64) {}

    fn get_maximum(&self) -> i64 {
        0
    }

    fn set_indeterminate(&self, _indeterminate: bool) {}

    fn is_indeterminate(&self) -> bool {
        false
    }

    fn check_cancelled(&self) -> Result<(), CancelledException> {
        if self.is_cancelled() {
            return Err(CancelledException::default());
        }
        Ok(())
    }

    fn increment_progress(&self, _amount: i64) {}

    fn get_progress(&self) -> i64 {
        0
    }

    fn cancel(&self) {
        let (stopped, condvar) = &*self.timer;
        let mut stopped = stopped.lock().unwrap();
        *stopped = true;
        condvar.notify_all();
        drop(stopped);
        self.is_cancelled.store(true, Ordering::SeqCst);
    }

    fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}

    fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}

    fn set_cancel_enabled(&self, _enable: bool) {}

    fn is_cancel_enabled(&self) -> bool {
        true
    }

    fn clear_cancelled(&self) {
        self.is_cancelled.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_not_cancelled_initially() {
        let monitor = HeadlessTimedTaskMonitor::new(60);
        assert!(!monitor.is_cancelled());
        monitor.cancel();
    }

    #[test]
    fn test_check_cancelled_ok_when_not_cancelled() {
        let monitor = HeadlessTimedTaskMonitor::new(60);
        assert!(monitor.check_cancelled().is_ok());
        monitor.cancel();
    }

    #[test]
    fn test_manual_cancel_sets_cancelled() {
        let monitor = HeadlessTimedTaskMonitor::new(60);
        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_err());
    }

    #[test]
    fn test_clear_cancelled_resets_flag() {
        let monitor = HeadlessTimedTaskMonitor::new(60);
        monitor.cancel();
        assert!(monitor.is_cancelled());
        monitor.clear_cancelled();
        assert!(!monitor.is_cancelled());
    }

    #[test]
    fn test_timeout_cancels_monitor() {
        let monitor = HeadlessTimedTaskMonitor::new(0);
        let start = Instant::now();
        while !monitor.is_cancelled() && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_default_stub_values() {
        let monitor = HeadlessTimedTaskMonitor::new(60);
        assert_eq!(monitor.get_message(), "");
        assert_eq!(monitor.get_maximum(), 0);
        assert_eq!(monitor.get_progress(), 0);
        assert!(!monitor.is_indeterminate());
        assert!(monitor.is_cancel_enabled());
        monitor.cancel();
    }
}
