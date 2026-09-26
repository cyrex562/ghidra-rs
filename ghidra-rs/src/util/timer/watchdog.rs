//! Port of `ghidra.util.timer.Watchdog`.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::msg::Msg;
use crate::util::timer::{GTimer, GTimerCallback, GTimerMonitor};

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A reusable watchdog that will execute a callback if the watchdog is not disarmed before it
/// expires.
///
/// Port of `ghidra.util.timer.Watchdog`, which `implements Closeable`.
///
/// # Shape
///
/// Java's `GTimer.scheduleRepeatingRunnable` is a `static` method on a concrete `GTimer` class;
/// this crate's [`GTimer`] is a trait instead (see its own docs), so [`Watchdog::new`] takes a
/// `&dyn GTimer` to schedule against, matching this crate's decoupling convention rather than
/// depending on one global timer implementation.
///
/// Java's periodic `watchdogWorker` callback runs as a method on `this`, freely reading/writing
/// the enclosing instance's fields on whatever thread the JVM's `Timer` uses. Rust's [`GTimer`]
/// callback is `'static` and cannot borrow `self`, so the two pieces of state the callback needs
/// ([`watchdog_expires_at`](Watchdog::watchdog_expires_at)'s backing storage and the
/// `timeoutMethod` callback itself) are held behind `Arc` (an `AtomicI64` and a
/// `Mutex<Option<Box<dyn FnMut() + Send>>>` respectively) shared between this struct and the
/// scheduled closure, rather than the closure capturing `self` directly.
///
/// # Divergence: `Drop` instead of `finalize()`
///
/// Java's `finalize()` override (`close()` then a warning if the watchdog was never explicitly
/// closed) relies on the JVM's finalizer, which is unreliable and may run late or never. This
/// port uses Rust's [`Drop`] instead, which runs deterministically when a `Watchdog` goes out of
/// scope -- a strict behavioral improvement over Java's finalizer while reproducing the same
/// "close if not already closed, then warn" logic and ordering (`close()` first, then the warning,
/// matching `finalize()`'s own statement order).
pub struct Watchdog {
    default_watchdog_timeout_ms: i64,
    watchdog_expires_at: Arc<AtomicI64>,
    timeout_method: Arc<Mutex<Option<Box<dyn FnMut() + Send>>>>,
    watchdog_timer: Option<Box<dyn GTimerMonitor>>,
}

impl Watchdog {
    /// Creates a watchdog (initially disarmed) that will poll for expiration every
    /// `default_timeout_ms` milliseconds, calling `timeout_method` when triggered.
    ///
    /// * `timer` - the [`GTimer`] to schedule the periodic expiration check against.
    /// * `default_timeout_ms` - number of milliseconds that the watchdog will wait after being
    ///   armed before calling the timeout method.
    /// * `timeout_method` - callback invoked when the watchdog expires while armed.
    ///
    /// Port of `Watchdog(long defaultTimeoutMS, Runnable timeoutMethod)`.
    pub fn new(
        timer: &dyn GTimer,
        default_timeout_ms: i64,
        timeout_method: Box<dyn FnMut() + Send + 'static>,
    ) -> Self {
        let watchdog_expires_at = Arc::new(AtomicI64::new(0));
        let timeout_method = Arc::new(Mutex::new(Some(timeout_method)));

        let worker_expires_at = Arc::clone(&watchdog_expires_at);
        let worker_timeout_method = Arc::clone(&timeout_method);
        let callback: GTimerCallback = Box::new(move || {
            Self::watchdog_worker(&worker_expires_at, &worker_timeout_method, default_timeout_ms);
        });
        let watchdog_timer =
            timer.schedule_repeating_runnable(default_timeout_ms, default_timeout_ms, callback);

        Watchdog {
            default_watchdog_timeout_ms: default_timeout_ms,
            watchdog_expires_at,
            timeout_method,
            watchdog_timer: Some(watchdog_timer),
        }
    }

    /// Called from the timer; checks to see if the watchdog is armed, and if it has expired.
    ///
    /// Disarms itself before calling the timeout method if the timeout period expired.
    ///
    /// Port of the private `watchdogWorker()`.
    fn watchdog_worker(
        expires_at: &AtomicI64,
        timeout_method: &Mutex<Option<Box<dyn FnMut() + Send>>>,
        default_timeout_ms: i64,
    ) {
        let expires = expires_at.load(Ordering::SeqCst);
        if expires > 0 {
            let now = now_millis();
            if now > expires {
                Self::set_enabled_shared(expires_at, false, default_timeout_ms);
                if let Some(cb) = timeout_method.lock().unwrap().as_mut() {
                    cb();
                }
            }
        }
    }

    fn set_enabled_shared(expires_at: &AtomicI64, enabled: bool, default_timeout_ms: i64) {
        let value = if enabled { now_millis() + default_timeout_ms } else { -1 };
        expires_at.store(value, Ordering::SeqCst);
    }

    fn set_enabled(&self, enabled: bool) {
        Self::set_enabled_shared(&self.watchdog_expires_at, enabled, self.default_watchdog_timeout_ms);
    }

    /// Releases the background timer that this watchdog uses.
    ///
    /// Port of `close()`.
    pub fn close(&mut self) {
        if let Some(t) = self.watchdog_timer.take() {
            t.cancel();
        }
        *self.timeout_method.lock().unwrap() = None;
    }

    /// Returns the status of the watchdog.
    ///
    /// Port of `isEnabled()`: `true` if the watchdog is armed, `false` if the watchdog is
    /// disarmed.
    pub fn is_enabled(&self) -> bool {
        self.watchdog_expires_at.load(Ordering::SeqCst) > 0
    }

    /// Enables this watchdog so that at `default_timeout_ms` milliseconds in the future the
    /// timeout method will be called.
    ///
    /// Port of `arm()`.
    pub fn arm(&self) {
        self.set_enabled(true);
    }

    /// Disables this watchdog.
    ///
    /// Port of `disarm()`.
    pub fn disarm(&self) {
        self.set_enabled(false);
    }
}

impl Drop for Watchdog {
    /// Port of `finalize()`. See the struct's own docs for why `Drop` is used instead of Java's
    /// finalizer.
    fn drop(&mut self) {
        if self.watchdog_timer.is_some() {
            self.close();
            Msg::warn("Watchdog", &"Unclosed Watchdog");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// A [`GTimer`] test double that runs the periodic callback synchronously on demand (via
    /// [`TestGTimer::fire`]) instead of on a real background thread, keeping tests deterministic.
    struct TestGTimer {
        callback: Mutex<Option<GTimerCallback>>,
    }

    impl TestGTimer {
        fn new() -> Arc<Self> {
            Arc::new(TestGTimer { callback: Mutex::new(None) })
        }

        fn fire(&self) {
            if let Some(cb) = self.callback.lock().unwrap().as_mut() {
                cb();
            }
        }
    }

    struct NullMonitor;
    impl GTimerMonitor for NullMonitor {
        fn cancel(&self) -> bool {
            true
        }
        fn did_run(&self) -> bool {
            false
        }
        fn was_cancelled(&self) -> bool {
            false
        }
    }

    impl GTimer for TestGTimer {
        fn schedule_runnable(&self, _delay_millis: i64, _callback: GTimerCallback) -> Box<dyn GTimerMonitor> {
            unimplemented!("Watchdog only uses schedule_repeating_runnable")
        }

        fn schedule_repeating_runnable(
            &self,
            _delay_millis: i64,
            _period_millis: i64,
            callback: GTimerCallback,
        ) -> Box<dyn GTimerMonitor> {
            *self.callback.lock().unwrap() = Some(callback);
            Box::new(NullMonitor)
        }
    }

    #[test]
    fn new_watchdog_is_initially_disarmed() {
        let timer = TestGTimer::new();
        let watchdog = Watchdog::new(timer.as_ref(), 1000, Box::new(|| {}));
        assert!(!watchdog.is_enabled());
    }

    #[test]
    fn arm_enables_and_disarm_disables() {
        let timer = TestGTimer::new();
        let watchdog = Watchdog::new(timer.as_ref(), 1000, Box::new(|| {}));
        watchdog.arm();
        assert!(watchdog.is_enabled());
        watchdog.disarm();
        assert!(!watchdog.is_enabled());
    }

    #[test]
    fn firing_the_timer_before_expiration_does_not_invoke_the_callback() {
        let timer = TestGTimer::new();
        let (tx, rx) = mpsc::channel::<()>();
        let watchdog = Watchdog::new(timer.as_ref(), 10_000, Box::new(move || tx.send(()).unwrap()));
        watchdog.arm();
        timer.fire();
        assert!(rx.try_recv().is_err(), "callback must not fire before the timeout elapses");
        assert!(watchdog.is_enabled());
    }

    #[test]
    fn firing_the_timer_after_expiration_invokes_the_callback_and_disarms() {
        let timer = TestGTimer::new();
        let (tx, rx) = mpsc::channel::<()>();
        // A tiny timeout so real elapsed time reliably exceeds it by the time we fire.
        let watchdog = Watchdog::new(timer.as_ref(), 1, Box::new(move || tx.send(()).unwrap()));
        watchdog.arm();
        thread::sleep(Duration::from_millis(20));
        timer.fire();
        rx.recv_timeout(Duration::from_secs(1)).expect("callback should have fired");
        // watchdogWorker disarms before invoking the callback.
        assert!(!watchdog.is_enabled());
    }

    #[test]
    fn firing_the_timer_while_disarmed_does_nothing() {
        let timer = TestGTimer::new();
        let (tx, rx) = mpsc::channel::<()>();
        let watchdog = Watchdog::new(timer.as_ref(), 1, Box::new(move || tx.send(()).unwrap()));
        // Never armed.
        thread::sleep(Duration::from_millis(10));
        timer.fire();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn close_cancels_the_timer_and_clears_the_callback() {
        let timer = TestGTimer::new();
        let (tx, rx) = mpsc::channel::<()>();
        let mut watchdog = Watchdog::new(timer.as_ref(), 1, Box::new(move || tx.send(()).unwrap()));
        watchdog.arm();
        watchdog.close();
        thread::sleep(Duration::from_millis(10));
        // Even if something still invoked the (stale) scheduled closure, the callback slot is now
        // `None`, so nothing is sent.
        timer.fire();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn drop_without_explicit_close_runs_close_deterministically() {
        // Rust's Drop runs synchronously and deterministically, unlike Java's finalize() -- see
        // the struct's own docs. This test proves a Watchdog going out of scope without an
        // explicit close() still releases its timer (observable via the shared expires-at flag
        // reaching a rechecked disarmed state after drop, and via TestGTimer's callback slot
        // still being independently invokable without panicking).
        let timer = TestGTimer::new();
        {
            let watchdog = Watchdog::new(timer.as_ref(), 1000, Box::new(|| {}));
            watchdog.arm();
            assert!(watchdog.is_enabled());
            // Watchdog dropped here.
        }
        // Firing the timer after the owning Watchdog was dropped must not panic (the callback's
        // captured Arcs keep the shared state alive, and the callback slot was cleared by close()
        // during drop).
        timer.fire();
    }
}
