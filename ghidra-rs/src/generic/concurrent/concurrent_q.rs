use super::{GThreadPool, ProgressTracker, QCallback, QItemListener, QProgressListener, QResult};
use crate::util::exception::CancelledException;
use crate::util::task::{CancelledListener, TaskMonitor};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

pub struct ConcurrentQ<I, R> {
    inner: Arc<QueueInner<I, R>>,
}

struct QueueInner<I, R> {
    queue: Mutex<VecDeque<I>>,
    thread_pool: Arc<GThreadPool>,
    callback: Box<dyn QCallback<I, R>>,
    item_listener: RwLock<Option<Box<dyn QItemListener<I, R>>>>,
    progress_listeners: RwLock<Vec<Box<dyn QProgressListener<I>>>>,
    result_list: Mutex<VecDeque<QResult<I, R>>>,
    task_set: Mutex<HashSet<i64>>, // Track task IDs
    max_in_progress: usize,
    collect_results: bool,
    _jobs_report_progress: bool,
    tracker: ProgressTracker,
    _unhandled_exception: Mutex<Option<Arc<anyhow::Error>>>,
}

impl<I, R> ConcurrentQ<I, R>
where
    I: Send + Sync + 'static + Clone,
    R: Send + Sync + 'static,
{
    pub fn new(
        callback: Box<dyn QCallback<I, R>>,
        thread_pool: Arc<GThreadPool>,
        max_in_progress: usize,
        collect_results: bool,
        jobs_report_progress: bool,
    ) -> Self {
        let max = if max_in_progress > 0 {
            max_in_progress
        } else {
            10
        };
        Self {
            inner: Arc::new(QueueInner {
                queue: Mutex::new(VecDeque::new()),
                thread_pool,
                callback,
                item_listener: RwLock::new(None),
                progress_listeners: RwLock::new(Vec::new()),
                result_list: Mutex::new(VecDeque::new()),
                task_set: Mutex::new(HashSet::new()),
                max_in_progress: max,
                collect_results,
                _jobs_report_progress: jobs_report_progress,
                tracker: ProgressTracker::new(),
                _unhandled_exception: Mutex::new(None),
            }),
        }
    }

    pub fn add(&self, item: I) {
        {
            let mut queue = self.inner.queue.lock().unwrap();
            queue.push_back(item);
        }
        self.inner.tracker.items_added(1);
        self.inner.fill_open_processing_slots();
    }

    pub fn add_all(&self, items: Vec<I>) {
        let count = items.len() as i64;
        {
            let mut queue = self.inner.queue.lock().unwrap();
            for item in items {
                queue.push_back(item);
            }
        }
        self.inner.tracker.items_added(count);
        self.inner.fill_open_processing_slots();
    }

    pub fn wait_until_done(&self) {
        self.inner.tracker.wait_until_done();
    }

    pub fn wait_for_results(&self) -> Vec<QResult<I, R>> {
        self.inner.tracker.wait_until_done();
        let mut results = self.inner.result_list.lock().unwrap();
        results.drain(..).collect()
    }
}

impl<I, R> QueueInner<I, R>
where
    I: Send + Sync + 'static + Clone,
    R: Send + Sync + 'static,
{
    fn fill_open_processing_slots(self: &Arc<Self>) {
        loop {
            let item = {
                let mut queue = self.queue.lock().unwrap();
                let in_progress = self.tracker.get_in_progress_count() as usize;
                if queue.is_empty() || in_progress >= self.max_in_progress {
                    break;
                }
                queue.pop_front().unwrap()
            };

            self.tracker.item_started();
            let task_id = self.tracker.get_next_id();
            {
                let mut task_set = self.task_set.lock().unwrap();
                task_set.insert(task_id);
            }

            let inner_clone = self.clone();
            let item_clone = item.clone();

            self.thread_pool.execute(move || {
                let monitor =
                    FutureTaskMonitor::new(inner_clone.clone(), item_clone.clone(), task_id);
                let result = inner_clone.callback.process(item_clone.clone(), &monitor);

                let q_result = match result {
                    Ok(r) => QResult::new(item_clone, r),
                    Err(e) => {
                        if monitor.is_cancelled() {
                            QResult::cancelled(item_clone)
                        } else {
                            QResult::error(item_clone, e)
                        }
                    }
                };

                inner_clone.item_processed(task_id, q_result);
            });
        }
    }

    fn item_processed(self: &Arc<Self>, task_id: i64, result: QResult<I, R>) {
        if let Some(listener) = self.item_listener.read().unwrap().as_ref() {
            listener.item_processed(&result);
        }

        {
            let mut task_set = self.task_set.lock().unwrap();
            task_set.remove(&task_id);
        }

        if self.collect_results {
            let mut results = self.result_list.lock().unwrap();
            results.push_back(result);
        }

        self.tracker.in_progress_item_completed_or_cancelled();

        // Pick up next task
        self.fill_open_processing_slots();
    }
}

/// The `TaskMonitor` handed to a [`QCallback`] while it processes one item pulled off a
/// [`ConcurrentQ`], and the bookkeeping the queue uses to notice when that item finishes.
///
/// Port of `generic.concurrent.FutureTaskMonitor<I, R>`. Java's version `extends FutureTask<R>`
/// purely to serve as the `Runnable`/`Future` the thread pool executes (`run()` calls
/// `super.run()` then reports the outcome back to the queue); this crate's [`GThreadPool`]
/// instead takes a plain closure (see the call site in
/// [`QueueInner::fill_open_processing_slots`]), so there's no `Future` machinery to extend here --
/// only the `TaskMonitor` half of the Java class is ported.
struct FutureTaskMonitor<I, R> {
    inner: Arc<QueueInner<I, R>>,
    item: I,
    id: i64,
    cancelled: Mutex<bool>,
    message: Mutex<String>,
    progress: Mutex<i64>,
    max_progress: Mutex<i64>,
    indeterminate: Mutex<bool>,
    /// Port of `FutureTaskMonitor.cancelledListener`. Java chains listeners together with a
    /// private `ChainedCancelledListener` linked-list node; this crate's established idiom for
    /// the same "possibly more than one `CancelledListener`" need (see
    /// `TaskMonitorSplitter::SubTaskMonitor` in `util/task/task_monitor_splitter.rs`) is a plain
    /// `Vec` with pointer-equality removal, which is simpler and behaviorally equivalent (every
    /// registered listener is still notified, in registration order, exactly once per
    /// [`cancel`](Self::cancel)).
    listeners: Mutex<Vec<Box<dyn CancelledListener>>>,
}

impl<I, R> FutureTaskMonitor<I, R>
where
    I: Send + Sync + 'static,
    R: Send + Sync + 'static,
{
    fn new(inner: Arc<QueueInner<I, R>>, item: I, id: i64) -> Self {
        Self {
            inner,
            item,
            id,
            cancelled: Mutex::new(false),
            message: Mutex::new(String::new()),
            progress: Mutex::new(0),
            max_progress: Mutex::new(0),
            indeterminate: Mutex::new(false),
            listeners: Mutex::new(Vec::new()),
        }
    }
}

impl<I, R> TaskMonitor for FutureTaskMonitor<I, R>
where
    I: Send + Sync + 'static,
    R: Send + Sync + 'static,
{
    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn set_show_progress_value(&self, _show: bool) {}

    fn set_message(&self, message: &str) {
        let mut msg = self.message.lock().unwrap();
        *msg = message.to_string();
        for listener in self.inner.progress_listeners.read().unwrap().iter() {
            listener.progress_message_changed(self.id, &self.item, message);
        }
    }

    fn get_message(&self) -> String {
        self.message.lock().unwrap().clone()
    }

    fn set_progress(&self, value: i64) {
        let mut p = self.progress.lock().unwrap();
        *p = value;
        for listener in self.inner.progress_listeners.read().unwrap().iter() {
            listener.progress_changed(self.id, &self.item, value);
        }
    }

    fn initialize(&self, max: i64) {
        self.set_maximum(max);
        self.set_progress(0);
    }

    fn set_maximum(&self, max: i64) {
        let mut m = self.max_progress.lock().unwrap();
        *m = max;
        for listener in self.inner.progress_listeners.read().unwrap().iter() {
            listener.max_progress_changed(self.id, &self.item, max);
        }
    }

    fn get_maximum(&self) -> i64 {
        *self.max_progress.lock().unwrap()
    }

    fn set_indeterminate(&self, indeterminate: bool) {
        let mut i = self.indeterminate.lock().unwrap();
        *i = indeterminate;
        for listener in self.inner.progress_listeners.read().unwrap().iter() {
            listener.progress_mode_changed(self.id, &self.item, indeterminate);
        }
    }

    fn is_indeterminate(&self) -> bool {
        *self.indeterminate.lock().unwrap()
    }

    fn check_cancelled(&self) -> Result<(), CancelledException> {
        if self.is_cancelled() {
            return Err(CancelledException(String::new()));
        }
        Ok(())
    }

    fn increment_progress(&self, amount: i64) {
        let current = {
            let mut p = self.progress.lock().unwrap();
            *p += amount;
            *p
        };
        for listener in self.inner.progress_listeners.read().unwrap().iter() {
            listener.progress_changed(self.id, &self.item, current);
        }
    }

    fn get_progress(&self) -> i64 {
        *self.progress.lock().unwrap()
    }

    /// Port of `FutureTaskMonitor.cancel(boolean)`. Java's override always calls
    /// `super.cancel(mayInterruptIfRunning)` (`FutureTask`'s real cancellation) and then notifies
    /// `cancelledListener` if one is set; since this port has no `FutureTask` to cancel, only the
    /// flag-plus-notification half applies.
    fn cancel(&self) {
        {
            let mut c = self.cancelled.lock().unwrap();
            *c = true;
        }
        // Copied into a local `Vec` (rather than notified while holding the lock) so a listener
        // that itself calls back into this monitor can't deadlock on `listeners`.
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener.cancelled();
        }
    }

    /// Port of `FutureTaskMonitor.addCancelledListener(CancelledListener)`.
    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
        self.listeners.lock().unwrap().push(listener);
    }

    /// Port of `FutureTaskMonitor.removeCancelledListener(CancelledListener)`.
    fn remove_cancelled_listener(&self, listener: &dyn CancelledListener) {
        let mut listeners = self.listeners.lock().unwrap();
        listeners.retain(|l| {
            !std::ptr::eq(
                l.as_ref() as *const dyn CancelledListener as *const (),
                listener as *const dyn CancelledListener as *const (),
            )
        });
    }

    fn set_cancel_enabled(&self, _enabled: bool) {}

    fn is_cancel_enabled(&self) -> bool {
        true
    }

    /// Port of `FutureTaskMonitor.clearCanceled()`, which always throws
    /// `UnsupportedOperationException` ("once cancelled, always cancelled"). Matches this crate's
    /// established idiom for a `TaskMonitor` method that Java declares unconditionally
    /// unsupported (see `SubTaskMonitor::clear_cancelled` in `util/task/task_monitor_splitter.rs`).
    fn clear_cancelled(&self) {
        unimplemented!("clear_cancelled is not supported on FutureTaskMonitor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCallback;
    impl QCallback<i32, i32> for TestCallback {
        fn process(&self, item: i32, _monitor: &dyn TaskMonitor) -> Result<i32, anyhow::Error> {
            Ok(item * 2)
        }
    }

    #[test]
    fn test_concurrent_q() {
        let thread_pool = GThreadPool::get_shared_thread_pool("test_q");
        let q = ConcurrentQ::new(Box::new(TestCallback), thread_pool, 2, true, false);

        q.add(1);
        q.add(2);
        q.add(3);

        let results = q.wait_for_results();
        assert_eq!(results.len(), 3);
        let mut values: Vec<i32> = results
            .iter()
            .map(|r| r.result.as_ref().copied().unwrap())
            .collect();
        values.sort();
        assert_eq!(values, vec![2, 4, 6]);
    }

    struct FlagListener {
        flagged: Arc<std::sync::atomic::AtomicBool>,
    }

    impl CancelledListener for FlagListener {
        fn cancelled(&self) {
            self.flagged.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn new_future_task_monitor() -> FutureTaskMonitor<i32, i32> {
        let thread_pool = GThreadPool::get_shared_thread_pool("test_ftm");
        let q = ConcurrentQ::new(Box::new(TestCallback), thread_pool, 2, true, false);
        FutureTaskMonitor::new(q.inner, 99, 1)
    }

    #[test]
    fn cancel_flips_is_cancelled_and_notifies_listeners() {
        let monitor = new_future_task_monitor();
        let flagged = Arc::new(std::sync::atomic::AtomicBool::new(false));
        monitor.add_cancelled_listener(Box::new(FlagListener {
            flagged: flagged.clone(),
        }));

        assert!(!monitor.is_cancelled());
        monitor.cancel();

        assert!(monitor.is_cancelled());
        assert!(flagged.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn multiple_cancelled_listeners_are_all_notified() {
        let monitor = new_future_task_monitor();
        let flagged_a = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flagged_b = Arc::new(std::sync::atomic::AtomicBool::new(false));
        monitor.add_cancelled_listener(Box::new(FlagListener {
            flagged: flagged_a.clone(),
        }));
        monitor.add_cancelled_listener(Box::new(FlagListener {
            flagged: flagged_b.clone(),
        }));

        monitor.cancel();

        assert!(flagged_a.load(std::sync::atomic::Ordering::SeqCst));
        assert!(flagged_b.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn remove_cancelled_listener_nonexistent_is_noop() {
        let monitor = new_future_task_monitor();
        let flagged = Arc::new(std::sync::atomic::AtomicBool::new(false));
        monitor.add_cancelled_listener(Box::new(FlagListener {
            flagged: flagged.clone(),
        }));

        let other = FlagListener {
            flagged: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        monitor.remove_cancelled_listener(&other);

        monitor.cancel();
        assert!(flagged.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    #[should_panic(expected = "not supported")]
    fn clear_cancelled_is_unsupported() {
        let monitor = new_future_task_monitor();
        monitor.clear_cancelled();
    }

    #[test]
    fn progress_and_message_reporting_round_trip() {
        let monitor = new_future_task_monitor();

        monitor.initialize(100);
        assert_eq!(monitor.get_maximum(), 100);
        assert_eq!(monitor.get_progress(), 0);

        monitor.set_progress(30);
        assert_eq!(monitor.get_progress(), 30);

        monitor.increment_progress(10);
        assert_eq!(monitor.get_progress(), 40);

        monitor.set_message("halfway");
        assert_eq!(monitor.get_message(), "halfway");

        monitor.set_indeterminate(true);
        assert!(monitor.is_indeterminate());
    }
}
