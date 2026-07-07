use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Synchronizes and tracks progress of items being processed by a concurrent queue.
///
/// Provides wait methods for when one item is completed or all items are completed.
pub struct ProgressTracker {
    inner: Arc<TrackerInner>,
}

struct TrackerInner {
    state: Mutex<TrackerState>,
    done_cond: Condvar,
    item_cond: Condvar,
}

struct TrackerState {
    total_count: i64,
    in_progress_count: i64,
    completed_or_cancelled_count: i64,
    next_id: i64,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TrackerInner {
                state: Mutex::new(TrackerState {
                    total_count: 0,
                    in_progress_count: 0,
                    completed_or_cancelled_count: 0,
                    next_id: 0,
                }),
                done_cond: Condvar::new(),
                item_cond: Condvar::new(),
            }),
        }
    }

    pub fn items_added(&self, n: i64) {
        let mut state = self.inner.state.lock().unwrap();
        state.total_count += n;
    }

    pub fn item_started(&self) {
        let mut state = self.inner.state.lock().unwrap();
        state.in_progress_count += 1;
    }

    pub fn in_progress_item_completed_or_cancelled(&self) {
        let mut state = self.inner.state.lock().unwrap();
        state.completed_or_cancelled_count += 1;
        state.in_progress_count -= 1;
        if state.completed_or_cancelled_count == state.total_count {
            self.inner.done_cond.notify_all();
        }
        self.inner.item_cond.notify_all();
    }

    pub fn never_started_items_removed(&self, n: i64) {
        let mut state = self.inner.state.lock().unwrap();
        state.completed_or_cancelled_count += n;
        if state.completed_or_cancelled_count == state.total_count {
            self.inner.done_cond.notify_all();
        }
        self.inner.item_cond.notify_all();
    }

    pub fn is_done(&self) -> bool {
        let state = self.inner.state.lock().unwrap();
        state.completed_or_cancelled_count == state.total_count
    }

    pub fn wait_until_done(&self) {
        let mut state = self.inner.state.lock().unwrap();
        while state.completed_or_cancelled_count != state.total_count {
            state = self.inner.done_cond.wait(state).unwrap();
        }
    }

    pub fn wait_until_done_timeout(&self, timeout: Duration) -> bool {
        let mut state = self.inner.state.lock().unwrap();
        let start = std::time::Instant::now();
        while state.completed_or_cancelled_count != state.total_count {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return false;
            }
            let (new_state, result) = self
                .inner
                .done_cond
                .wait_timeout(state, timeout - elapsed)
                .unwrap();
            state = new_state;
            if result.timed_out() {
                return state.completed_or_cancelled_count == state.total_count;
            }
        }
        true
    }

    pub fn wait_for_next(&self) {
        let state = self.inner.state.lock().unwrap();
        if state.completed_or_cancelled_count != state.total_count {
            let _unused = self.inner.item_cond.wait(state).unwrap();
        }
    }

    pub fn get_next_id(&self) -> i64 {
        let mut state = self.inner.state.lock().unwrap();
        state.next_id += 1;
        state.next_id
    }

    pub fn get_total_item_count(&self) -> i64 {
        self.inner.state.lock().unwrap().total_count
    }

    pub fn get_completed_item_count(&self) -> i64 {
        self.inner
            .state
            .lock()
            .unwrap()
            .completed_or_cancelled_count
    }

    pub fn get_in_progress_count(&self) -> i64 {
        self.inner.state.lock().unwrap().in_progress_count
    }
}

impl Default for ProgressTracker {
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
    fn test_initial_state() {
        let tracker = ProgressTracker::new();
        assert_eq!(tracker.get_total_item_count(), 0);
        assert_eq!(tracker.get_completed_item_count(), 0);
        assert_eq!(tracker.get_in_progress_count(), 0);
        // 0 completed == 0 total means done
        assert!(tracker.is_done());
    }

    #[test]
    fn test_items_added() {
        let tracker = ProgressTracker::new();
        tracker.items_added(5);
        assert_eq!(tracker.get_total_item_count(), 5);
        assert!(!tracker.is_done());
    }

    #[test]
    fn test_item_started() {
        let tracker = ProgressTracker::new();
        tracker.items_added(3);
        tracker.item_started();
        assert_eq!(tracker.get_in_progress_count(), 1);
    }

    #[test]
    fn test_in_progress_item_completed_updates_counts() {
        let tracker = ProgressTracker::new();
        tracker.items_added(2);
        tracker.item_started();
        tracker.item_started();
        tracker.in_progress_item_completed_or_cancelled();
        assert_eq!(tracker.get_completed_item_count(), 1);
        assert_eq!(tracker.get_in_progress_count(), 1);
        assert!(!tracker.is_done());
    }

    #[test]
    fn test_all_completed_is_done() {
        let tracker = ProgressTracker::new();
        tracker.items_added(2);
        tracker.item_started();
        tracker.item_started();
        tracker.in_progress_item_completed_or_cancelled();
        tracker.in_progress_item_completed_or_cancelled();
        assert_eq!(tracker.get_completed_item_count(), 2);
        assert_eq!(tracker.get_in_progress_count(), 0);
        assert!(tracker.is_done());
    }

    #[test]
    fn test_never_started_items_removed() {
        let tracker = ProgressTracker::new();
        tracker.items_added(3);
        tracker.never_started_items_removed(3);
        assert_eq!(tracker.get_completed_item_count(), 3);
        assert!(tracker.is_done());
    }

    #[test]
    fn test_mixed_completed_and_removed() {
        let tracker = ProgressTracker::new();
        tracker.items_added(3);
        tracker.item_started();
        tracker.in_progress_item_completed_or_cancelled();
        tracker.never_started_items_removed(2);
        assert_eq!(tracker.get_completed_item_count(), 3);
        assert!(tracker.is_done());
    }

    #[test]
    fn test_get_next_id_increments() {
        let tracker = ProgressTracker::new();
        assert_eq!(tracker.get_next_id(), 1);
        assert_eq!(tracker.get_next_id(), 2);
        assert_eq!(tracker.get_next_id(), 3);
    }

    #[test]
    fn test_wait_until_done_timeout_already_done() {
        let tracker = ProgressTracker::new();
        // 0 == 0, already done
        let result = tracker.wait_until_done_timeout(Duration::from_millis(50));
        assert!(result);
    }

    #[test]
    fn test_wait_until_done_timeout_not_done() {
        let tracker = ProgressTracker::new();
        tracker.items_added(1);
        let result = tracker.wait_until_done_timeout(Duration::from_millis(20));
        assert!(!result);
    }

    #[test]
    fn test_wait_until_done_signals_on_completion() {
        let tracker = Arc::new(ProgressTracker::new());
        tracker.items_added(1);
        tracker.item_started();
        let t = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            t.in_progress_item_completed_or_cancelled();
        });
        tracker.wait_until_done();
        handle.join().unwrap();
        assert!(tracker.is_done());
    }

    #[test]
    fn test_wait_for_next_returns_on_completion() {
        let tracker = Arc::new(ProgressTracker::new());
        tracker.items_added(2);
        tracker.item_started();
        let t = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            t.in_progress_item_completed_or_cancelled();
        });
        tracker.wait_for_next();
        handle.join().unwrap();
        assert_eq!(tracker.get_completed_item_count(), 1);
    }

    #[test]
    fn test_default_equals_new() {
        let tracker = ProgressTracker::default();
        assert!(tracker.is_done());
        assert_eq!(tracker.get_total_item_count(), 0);
    }
}
