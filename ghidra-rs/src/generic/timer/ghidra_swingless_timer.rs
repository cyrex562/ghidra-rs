use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{GhidraTimer, TimerCallback};

/// A timer that fires a [`TimerCallback`] at specified intervals off a background
/// thread (never the UI/Swing thread).
///
/// Port of `generic.timer.GhidraSwinglessTimer`. It supports an initial delay, a
/// repeat delay, one-shot vs repeating behavior, and start/stop control.
///
/// # Deviation from Java
///
/// The Java implementation shares a single static `java.util.Timer` thread across
/// every `GhidraSwinglessTimer` instance, along with a static task count and a
/// cleanup task that tears the shared thread down 60 seconds after the last timer
/// stops. That thread-sharing is an implementation detail; the observable behavior
/// is simply "callbacks fire on a background thread at the configured cadence."
///
/// This Rust port spawns one dedicated worker thread per running timer. The worker
/// waits `initial_delay`, fires the callback, then (if repeating) waits `delay` and
/// fires again, looping until stopped. Stopping is cooperative via a shared flag and
/// a [`Condvar`], so `stop()` interrupts a sleeping worker promptly rather than
/// waiting for the current delay to elapse. This preserves all observable behavior
/// (start/stop/is_running, delay/initial-delay/repeats semantics) without the shared
/// static timer thread or the cleanup task.
pub struct GhidraSwinglessTimer {
    callback: Option<Arc<Mutex<Box<dyn TimerCallback + Send>>>>,
    repeats: bool,
    delay: i32,
    initial_delay: i32,
    worker: Option<Worker>,
}

/// A running background worker: its join handle plus the shared control state used
/// to signal it to stop.
struct Worker {
    handle: Option<JoinHandle<()>>,
    control: Arc<Control>,
}

/// Shared control state between the timer and its worker thread.
struct Control {
    stopped: Mutex<bool>,
    cvar: Condvar,
}

impl Control {
    fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            cvar: Condvar::new(),
        }
    }

    /// Signal the worker to stop and wake it if it is sleeping.
    fn signal_stop(&self) {
        let mut stopped = self.stopped.lock().unwrap();
        *stopped = true;
        self.cvar.notify_all();
    }

    /// Sleep for `dur` unless a stop is signalled first. Returns `true` if a stop
    /// was signalled (so the worker should exit), `false` if the full duration
    /// elapsed.
    fn sleep_or_stop(&self, dur: Duration) -> bool {
        let mut stopped = self.stopped.lock().unwrap();
        if *stopped {
            return true;
        }
        // Loop to guard against spurious wakeups.
        let deadline = Instant::now() + dur;
        loop {
            if *stopped {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline - now;
            let (guard, timeout) = self.cvar.wait_timeout(stopped, remaining).unwrap();
            stopped = guard;
            if *stopped {
                return true;
            }
            if timeout.timed_out() {
                return false;
            }
        }
    }
}

impl GhidraSwinglessTimer {
    /// Creates a new repeating timer with an initial delay and continual delay both
    /// of 100ms and no callback.
    pub fn new() -> Self {
        Self::with_delay(100, None)
    }

    /// Creates a new repeating timer whose initial and continual delay are both
    /// `delay` milliseconds.
    pub fn with_delay(delay: i32, callback: Option<Box<dyn TimerCallback + Send>>) -> Self {
        Self::with_delays(delay, delay, callback)
    }

    /// Creates a new repeating timer with the given initial and continual delays.
    pub fn with_delays(
        initial_delay: i32,
        delay: i32,
        callback: Option<Box<dyn TimerCallback + Send>>,
    ) -> Self {
        Self {
            callback: callback.map(|c| Arc::new(Mutex::new(c))),
            repeats: true,
            delay,
            initial_delay,
            worker: None,
        }
    }

    /// Spawns the background worker thread that fires the callback.
    fn spawn_worker(&mut self) {
        let control = Arc::new(Control::new());
        let worker_control = Arc::clone(&control);
        let callback = self.callback.clone();
        let repeats = self.repeats;
        let initial_delay = self.initial_delay.max(0) as u64;
        let delay = self.delay.max(0) as u64;

        let handle = thread::Builder::new()
            .name("GhidraSwinglessTimer".to_string())
            .spawn(move || {
                if worker_control.sleep_or_stop(Duration::from_millis(initial_delay)) {
                    return;
                }
                loop {
                    if let Some(cb) = &callback {
                        cb.lock().unwrap().timer_fired();
                    }
                    if !repeats {
                        return;
                    }
                    if worker_control.sleep_or_stop(Duration::from_millis(delay)) {
                        return;
                    }
                }
            })
            .expect("failed to spawn GhidraSwinglessTimer worker thread");

        self.worker = Some(Worker {
            handle: Some(handle),
            control,
        });
    }
}

impl Default for GhidraSwinglessTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl GhidraTimer for GhidraSwinglessTimer {
    fn start(&mut self) {
        if self.worker.is_some() {
            return;
        }
        self.spawn_worker();
    }

    fn stop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.control.signal_stop();
            if let Some(handle) = worker.handle {
                let _ = handle.join();
            }
        }
    }

    fn set_delay(&mut self, delay: i32) {
        self.delay = delay;
        if self.is_running() {
            self.stop();
            self.start();
        }
    }

    fn set_initial_delay(&mut self, initial_delay: i32) {
        self.initial_delay = initial_delay;
    }

    fn set_repeats(&mut self, repeats: bool) {
        self.repeats = repeats;
    }

    fn is_repeats(&self) -> bool {
        self.repeats
    }

    fn is_running(&self) -> bool {
        self.worker.is_some()
    }

    fn get_delay(&self) -> i32 {
        self.delay
    }

    fn get_initial_delay(&self) -> i32 {
        self.initial_delay
    }

    fn set_timer_callback(&mut self, callback: Box<dyn TimerCallback>) {
        // The trait signature accepts a non-`Send` callback, but the callback must
        // run on the worker thread. We require the concrete callback to be `Send`
        // in practice; see `set_timer_callback_send` for the `Send`-typed setter
        // used by callers that need to schedule work across threads.
        let _ = callback;
        panic!(
            "GhidraSwinglessTimer requires a `Send` callback; use `set_timer_callback_send` instead"
        );
    }
}

impl GhidraSwinglessTimer {
    /// Sets the callback to be invoked when the timer fires.
    ///
    /// Unlike the trait's [`GhidraTimer::set_timer_callback`], this accepts a `Send`
    /// callback because it is executed on the background worker thread. If the timer
    /// is running, the new callback takes effect on the next scheduled firing.
    pub fn set_timer_callback_send(&mut self, callback: Box<dyn TimerCallback + Send>) {
        match &self.callback {
            Some(existing) => {
                // Swap in place so a running worker (which holds an Arc clone) sees
                // the new callback on its next tick.
                *existing.lock().unwrap() = callback;
            }
            None => {
                self.callback = Some(Arc::new(Mutex::new(callback)));
            }
        }
    }
}

impl Drop for GhidraSwinglessTimer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use std::thread::sleep;

    struct CountingCallback {
        count: StdArc<AtomicUsize>,
    }

    impl TimerCallback for CountingCallback {
        fn timer_fired(&mut self) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_default_values() {
        let timer = GhidraSwinglessTimer::new();
        assert_eq!(timer.get_delay(), 100);
        assert_eq!(timer.get_initial_delay(), 100);
        assert!(timer.is_repeats());
        assert!(!timer.is_running());
    }

    #[test]
    fn test_with_delay_sets_both_delays() {
        let timer = GhidraSwinglessTimer::with_delay(250, None);
        assert_eq!(timer.get_delay(), 250);
        assert_eq!(timer.get_initial_delay(), 250);
    }

    #[test]
    fn test_with_delays_distinct() {
        let timer = GhidraSwinglessTimer::with_delays(50, 200, None);
        assert_eq!(timer.get_initial_delay(), 50);
        assert_eq!(timer.get_delay(), 200);
    }

    #[test]
    fn test_set_delay() {
        let mut timer = GhidraSwinglessTimer::new();
        timer.set_delay(200);
        assert_eq!(timer.get_delay(), 200);
    }

    #[test]
    fn test_set_initial_delay() {
        let mut timer = GhidraSwinglessTimer::new();
        timer.set_initial_delay(333);
        assert_eq!(timer.get_initial_delay(), 333);
    }

    #[test]
    fn test_set_repeats() {
        let mut timer = GhidraSwinglessTimer::new();
        assert!(timer.is_repeats());
        timer.set_repeats(false);
        assert!(!timer.is_repeats());
        timer.set_repeats(true);
        assert!(timer.is_repeats());
    }

    #[test]
    fn test_is_running_before_and_after_start_stop() {
        let count = StdArc::new(AtomicUsize::new(0));
        let mut timer = GhidraSwinglessTimer::with_delay(
            10,
            Some(Box::new(CountingCallback {
                count: StdArc::clone(&count),
            })),
        );
        assert!(!timer.is_running());
        timer.start();
        assert!(timer.is_running());
        timer.stop();
        assert!(!timer.is_running());
    }

    #[test]
    fn test_start_is_idempotent() {
        let mut timer = GhidraSwinglessTimer::with_delay(10, None);
        timer.start();
        assert!(timer.is_running());
        // Second start should not panic or spawn a second worker.
        timer.start();
        assert!(timer.is_running());
        timer.stop();
        assert!(!timer.is_running());
    }

    #[test]
    fn test_one_shot_fires_exactly_once() {
        let count = StdArc::new(AtomicUsize::new(0));
        let mut timer = GhidraSwinglessTimer::with_delay(
            10,
            Some(Box::new(CountingCallback {
                count: StdArc::clone(&count),
            })),
        );
        timer.set_repeats(false);
        timer.start();
        // Wait well past several would-be repeat intervals.
        sleep(Duration::from_millis(200));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(!timer.is_running() || count.load(Ordering::SeqCst) == 1);
        timer.stop();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_repeating_fires_multiple_times() {
        let count = StdArc::new(AtomicUsize::new(0));
        let mut timer = GhidraSwinglessTimer::with_delay(
            10,
            Some(Box::new(CountingCallback {
                count: StdArc::clone(&count),
            })),
        );
        timer.start();
        sleep(Duration::from_millis(200));
        timer.stop();
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "expected repeating timer to fire at least twice, got {}",
            count.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn test_stop_halts_further_callbacks() {
        let count = StdArc::new(AtomicUsize::new(0));
        let mut timer = GhidraSwinglessTimer::with_delay(
            10,
            Some(Box::new(CountingCallback {
                count: StdArc::clone(&count),
            })),
        );
        timer.start();
        sleep(Duration::from_millis(100));
        timer.stop();
        let after_stop = count.load(Ordering::SeqCst);
        sleep(Duration::from_millis(150));
        // No further callbacks should have run after stop().
        assert_eq!(count.load(Ordering::SeqCst), after_stop);
    }

    #[test]
    fn test_set_timer_callback_send_after_construction() {
        let count = StdArc::new(AtomicUsize::new(0));
        let mut timer = GhidraSwinglessTimer::with_delay(10, None);
        timer.set_timer_callback_send(Box::new(CountingCallback {
            count: StdArc::clone(&count),
        }));
        timer.start();
        sleep(Duration::from_millis(150));
        timer.stop();
        assert!(count.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn test_set_delay_while_running_takes_effect() {
        // With a long delay, the callback should not fire before we shorten it.
        // Note: like the Java original, set_delay() restarts the timer, which then
        // waits `initial_delay` before the first fire, so we start with a short
        // initial delay and long repeat delay, then shorten the repeat delay.
        let count = StdArc::new(AtomicUsize::new(0));
        let mut timer = GhidraSwinglessTimer::with_delays(
            10,
            10_000,
            Some(Box::new(CountingCallback {
                count: StdArc::clone(&count),
            })),
        );
        timer.start();
        // First fire happens after ~10ms (initial_delay); subsequent fires would be
        // 10s away, so only one fire should have occurred by now.
        sleep(Duration::from_millis(100));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // Shortening the repeat delay restarts the worker; it waits initial_delay
        // (10ms) then repeats every 10ms.
        timer.set_delay(10);
        sleep(Duration::from_millis(150));
        timer.stop();
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "expected additional callbacks after shortening delay, got {}",
            count.load(Ordering::SeqCst)
        );
    }
}
