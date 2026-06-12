use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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
