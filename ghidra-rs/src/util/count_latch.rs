use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Latch with a count that can be incremented and decremented.
///
/// Threads that call [`wait`][CountLatch::wait] block until the count reaches zero.
///
/// Port of `ghidra.util.CountLatch`.
pub struct CountLatch {
    state: Mutex<i32>,
    cond: Condvar,
}

impl CountLatch {
    /// Creates a new `CountLatch` with an initial count of 0.
    pub fn new() -> Self {
        CountLatch {
            state: Mutex::new(0),
            cond: Condvar::new(),
        }
    }

    /// Increments the latch count.
    pub fn increment(&self) {
        let mut count = self.state.lock().unwrap();
        *count += 1;
    }

    /// Decrements the latch count, releasing any waiting threads when the count reaches 0.
    ///
    /// Has no effect if the count is already 0.
    pub fn decrement(&self) {
        let mut count = self.state.lock().unwrap();
        if *count == 0 {
            return;
        }
        *count -= 1;
        if *count == 0 {
            self.cond.notify_all();
        }
    }

    /// Returns the current latch count.
    pub fn get_count(&self) -> i32 {
        *self.state.lock().unwrap()
    }

    /// Blocks the current thread until the latch count reaches zero.
    pub fn wait(&self) {
        let guard = self.state.lock().unwrap();
        drop(self.cond.wait_while(guard, |c| *c > 0).unwrap());
    }

    /// Blocks until the count reaches zero or `timeout` elapses.
    ///
    /// Returns `true` if the count reached zero, `false` if the timeout elapsed first.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let guard = self.state.lock().unwrap();
        let (_guard, result) = self
            .cond
            .wait_timeout_while(guard, timeout, |c| *c > 0)
            .unwrap();
        !result.timed_out()
    }
}

impl Default for CountLatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn no_wait_initially() {
        let latch = CountLatch::new();
        assert!(latch.wait_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn waits_when_count_not_zero() {
        let latch = CountLatch::new();
        latch.increment();
        assert!(!latch.wait_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn no_wait_after_increment_then_decrement() {
        let latch = CountLatch::new();
        latch.increment();
        latch.decrement();
        assert!(latch.wait_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn decrement_below_zero_is_noop() {
        let latch = CountLatch::new();
        latch.decrement();
        assert_eq!(latch.get_count(), 0);
    }

    #[test]
    fn multiple_increments_require_matching_decrements() {
        let latch = CountLatch::new();
        latch.increment();
        latch.increment();
        latch.decrement();
        assert!(!latch.wait_timeout(Duration::from_millis(10)));
        latch.decrement();
        assert!(latch.wait_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn get_count_tracks_changes() {
        let latch = CountLatch::new();
        assert_eq!(latch.get_count(), 0);
        latch.increment();
        assert_eq!(latch.get_count(), 1);
        latch.increment();
        assert_eq!(latch.get_count(), 2);
        latch.decrement();
        assert_eq!(latch.get_count(), 1);
        latch.decrement();
        assert_eq!(latch.get_count(), 0);
    }

    #[test]
    fn default_creates_zero_count_latch() {
        let latch = CountLatch::default();
        assert_eq!(latch.get_count(), 0);
        assert!(latch.wait_timeout(Duration::from_millis(1)));
    }

    #[test]
    fn wait_timeout_returns_true_when_unblocked_by_decrement() {
        let latch = Arc::new(CountLatch::new());
        latch.increment();

        let latch2 = Arc::clone(&latch);
        let handle = thread::spawn(move || latch2.wait_timeout(Duration::from_secs(1)));

        thread::sleep(Duration::from_millis(10));
        latch.decrement();
        assert!(handle.join().unwrap());
    }

    #[test]
    fn blocking_wait_returns_when_count_reaches_zero() {
        let latch = Arc::new(CountLatch::new());
        latch.increment();

        let latch2 = Arc::clone(&latch);
        let handle = thread::spawn(move || latch2.wait());

        thread::sleep(Duration::from_millis(10));
        latch.decrement();
        handle.join().unwrap();
    }
}
