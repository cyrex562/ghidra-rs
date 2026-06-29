pub mod concurrent_q;
pub mod listener_set;
pub mod progress_tracker;
pub mod reentry_guard;
pub mod thread_pool;

pub use concurrent_q::ConcurrentQ;
pub use listener_set::ConcurrentListenerSet;
pub use progress_tracker::ProgressTracker;
pub use reentry_guard::{Guarded, ReentryGuard};
pub use thread_pool::GThreadPool;

use crate::util::task::TaskMonitor;
use std::sync::Arc;

pub trait QCallback<I, R>: Send + Sync {
    fn process(&self, item: I, monitor: &dyn TaskMonitor) -> Result<R, anyhow::Error>;
}

pub struct QResult<I, R> {
    pub item: I,
    pub result: Option<R>,
    pub error: Option<Arc<anyhow::Error>>,
    pub is_cancelled: bool,
}

impl<I, R> QResult<I, R> {
    pub fn new(item: I, result: R) -> Self {
        Self {
            item,
            result: Some(result),
            error: None,
            is_cancelled: false,
        }
    }

    pub fn error(item: I, error: anyhow::Error) -> Self {
        Self {
            item,
            result: None,
            error: Some(Arc::new(error)),
            is_cancelled: false,
        }
    }

    pub fn cancelled(item: I) -> Self {
        Self {
            item,
            result: None,
            error: None,
            is_cancelled: true,
        }
    }

    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }
}

pub trait QItemListener<I, R>: Send + Sync {
    fn item_processed(&self, result: &QResult<I, R>);
}

pub trait QProgressListener<I>: Send + Sync {
    fn task_started(&self, id: i64, item: &I);
    fn task_ended(&self, id: i64, item: &I, total_count: i64, completed_count: i64);
    fn progress_changed(&self, id: i64, item: &I, current_progress: i64);
    fn max_progress_changed(&self, id: i64, item: &I, max_progress: i64);
    fn progress_mode_changed(&self, id: i64, item: &I, indeterminate: bool);
    fn progress_message_changed(&self, id: i64, item: &I, message: &str);
}
