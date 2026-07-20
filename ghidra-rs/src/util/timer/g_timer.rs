use super::{DummyGTimerMonitor, GTimerMonitor};
use crate::util::msg::Msg;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// A callback scheduled for execution by a [`GTimer`].
///
/// Mirrors Java's `Runnable`: it may be invoked more than once when scheduled as a
/// repeating runnable.
pub type GTimerCallback = Box<dyn FnMut() + Send + 'static>;

/// Schedules callbacks to run after some delay, optionally repeating.
///
/// Mirrors `ghidra.util.timer.GTimer`'s static scheduling API, recast as a trait so
/// callers can be decoupled from a single global timer implementation.
pub trait GTimer: Send + Sync {
    /// Schedules a callback for execution after the specified delay. A delay value less
    /// than 0 causes this timer to schedule nothing.
    ///
    /// Returns a [`GTimerMonitor`] which allows the caller to cancel the timer and check
    /// its status.
    fn schedule_runnable(&self, delay_millis: i64, callback: GTimerCallback)
        -> Box<dyn GTimerMonitor>;

    /// Schedules a callback for **repeated** execution after the specified delay. A delay
    /// value less than 0 causes this timer to schedule nothing.
    ///
    /// Returns a [`GTimerMonitor`] which allows the caller to cancel the timer and check
    /// its status.
    ///
    /// # Panics
    ///
    /// Panics if `period_millis <= 0`, mirroring Java's `IllegalArgumentException`.
    fn schedule_repeating_runnable(
        &self,
        delay_millis: i64,
        period_millis: i64,
        callback: GTimerCallback,
    ) -> Box<dyn GTimerMonitor>;
}

struct GTimerTask {
    cancelled: Arc<AtomicBool>,
    ran: Arc<AtomicBool>,
}

impl GTimerMonitor for GTimerTask {
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

fn run_callback(callback: &mut GTimerCallback) {
    if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| callback())) {
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        Msg::show_error("GTimer", "Unexpected Exception", &message);
    }
}

/// A [`GTimer`] implementation that schedules work on a dedicated OS thread per task,
/// mirroring the JVM's `java.util.Timer` daemon-thread semantics closely enough for the
/// port's purposes.
pub struct StdGTimer;

impl GTimer for StdGTimer {
    fn schedule_runnable(
        &self,
        delay_millis: i64,
        mut callback: GTimerCallback,
    ) -> Box<dyn GTimerMonitor> {
        if delay_millis < 0 {
            return Box::new(DummyGTimerMonitor);
        }

        let cancelled = Arc::new(AtomicBool::new(false));
        let ran = Arc::new(AtomicBool::new(false));

        let thread_cancelled = Arc::clone(&cancelled);
        let thread_ran = Arc::clone(&ran);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(delay_millis as u64));
            if thread_cancelled.load(Ordering::SeqCst) {
                return;
            }
            run_callback(&mut callback);
            thread_ran.store(true, Ordering::SeqCst);
        });

        Box::new(GTimerTask { cancelled, ran })
    }

    fn schedule_repeating_runnable(
        &self,
        delay_millis: i64,
        period_millis: i64,
        mut callback: GTimerCallback,
    ) -> Box<dyn GTimerMonitor> {
        if delay_millis < 0 {
            return Box::new(DummyGTimerMonitor);
        }
        assert!(period_millis > 0, "period must be > 0");

        let cancelled = Arc::new(AtomicBool::new(false));
        let ran = Arc::new(AtomicBool::new(false));

        let thread_cancelled = Arc::clone(&cancelled);
        let thread_ran = Arc::clone(&ran);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(delay_millis as u64));
            loop {
                if thread_cancelled.load(Ordering::SeqCst) {
                    return;
                }
                run_callback(&mut callback);
                thread_ran.store(true, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(period_millis as u64));
            }
        });

        Box::new(GTimerTask { cancelled, ran })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration as StdDuration;

    struct MockGTimer;

    impl GTimer for MockGTimer {
        fn schedule_runnable(
            &self,
            delay_millis: i64,
            mut callback: GTimerCallback,
        ) -> Box<dyn GTimerMonitor> {
            if delay_millis < 0 {
                return Box::new(DummyGTimerMonitor);
            }
            callback();
            Box::new(GTimerTask {
                cancelled: Arc::new(AtomicBool::new(false)),
                ran: Arc::new(AtomicBool::new(true)),
            })
        }

        fn schedule_repeating_runnable(
            &self,
            _delay_millis: i64,
            _period_millis: i64,
            _callback: GTimerCallback,
        ) -> Box<dyn GTimerMonitor> {
            Box::new(DummyGTimerMonitor)
        }
    }

    #[test]
    fn mock_timer_is_object_safe_and_runs_immediately() {
        let timer: Box<dyn GTimer> = Box::new(MockGTimer);
        let (tx, rx) = mpsc::channel();
        let monitor = timer.schedule_runnable(0, Box::new(move || tx.send(()).unwrap()));
        rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
        assert!(monitor.did_run());
    }

    #[test]
    fn negative_delay_schedules_nothing() {
        let timer = StdGTimer;
        let (tx, rx) = mpsc::channel::<()>();
        let monitor = timer.schedule_runnable(-1, Box::new(move || tx.send(()).unwrap()));
        assert!(rx.recv_timeout(StdDuration::from_millis(100)).is_err());
        assert!(!monitor.did_run());
        assert!(!monitor.was_cancelled());
        assert!(!monitor.cancel());
    }

    #[test]
    fn scheduled_runnable_runs_and_reports_did_run() {
        let timer = StdGTimer;
        let (tx, rx) = mpsc::channel();
        let monitor = timer.schedule_runnable(10, Box::new(move || tx.send(()).unwrap()));
        rx.recv_timeout(StdDuration::from_secs(2))
            .expect("callback should have run");
        // Give the spawned thread a moment to flip the ran flag after the send.
        thread::sleep(StdDuration::from_millis(20));
        assert!(monitor.did_run());
        assert!(!monitor.was_cancelled());
    }

    #[test]
    fn cancel_before_delay_elapses_prevents_run() {
        let timer = StdGTimer;
        let (tx, rx) = mpsc::channel::<()>();
        let monitor = timer.schedule_runnable(200, Box::new(move || tx.send(()).unwrap()));
        assert!(monitor.cancel());
        assert!(rx.recv_timeout(StdDuration::from_millis(400)).is_err());
        assert!(!monitor.did_run());
        assert!(monitor.was_cancelled());
    }

    #[test]
    fn repeating_runnable_fires_multiple_times_until_cancelled() {
        let timer = StdGTimer;
        let (tx, rx) = mpsc::channel();
        let monitor = timer.schedule_repeating_runnable(
            5,
            10,
            Box::new(move || {
                let _ = tx.send(());
            }),
        );
        rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
        rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
        rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
        assert!(monitor.cancel());
        assert!(monitor.did_run());
    }
}
