use super::{QCallback, QRunnable};
use crate::util::task::TaskMonitor;

/// Adapts a [`QRunnable<I>`] (a callback with no useful return value) to a [`QCallback<I, ()>`]
/// (a callback that produces a result), so a `QRunnable` can be handed to APIs -- like
/// [`crate::generic::concurrent::ConcurrentQ`] -- that are built around `QCallback`.
///
/// Port of `generic.concurrent.QRunnableAdapter<I>`.
///
/// Java's `process` returns `Object` and always returns `null` after running the wrapped
/// `QRunnable`; the natural Rust analogue of "no useful value" is `()`, so this implements
/// `QCallback<I, ()>` rather than `QCallback<I, Object>`.
pub struct QRunnableAdapter<I> {
    runnable: Box<dyn QRunnable<I>>,
}

impl<I> QRunnableAdapter<I> {
    /// Port of `QRunnableAdapter(QRunnable<I>)`.
    pub fn new(runnable: Box<dyn QRunnable<I>>) -> Self {
        Self { runnable }
    }
}

impl<I> QCallback<I, ()> for QRunnableAdapter<I> {
    /// Port of `QRunnableAdapter.process(I, TaskMonitor)`.
    fn process(&self, item: I, monitor: &dyn TaskMonitor) -> Result<(), anyhow::Error> {
        self.runnable.run(item, monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    struct RecordingRunnable {
        sum: Arc<AtomicI32>,
    }

    impl QRunnable<i32> for RecordingRunnable {
        fn run(&self, item: i32, _monitor: &dyn TaskMonitor) -> Result<(), anyhow::Error> {
            self.sum.fetch_add(item, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn process_runs_the_wrapped_runnable_and_returns_unit() {
        let sum = Arc::new(AtomicI32::new(0));
        let adapter = QRunnableAdapter::new(Box::new(RecordingRunnable { sum: sum.clone() }) as Box<dyn QRunnable<i32>>);
        let monitor = DummyMonitor;

        let result = adapter.process(5, &monitor);

        assert!(result.is_ok());
        assert_eq!(sum.load(Ordering::SeqCst), 5);
    }

    struct FailingRunnable;
    impl QRunnable<i32> for FailingRunnable {
        fn run(&self, _item: i32, _monitor: &dyn TaskMonitor) -> Result<(), anyhow::Error> {
            anyhow::bail!("boom")
        }
    }

    #[test]
    fn process_propagates_the_wrapped_runnables_error() {
        let adapter = QRunnableAdapter::new(Box::new(FailingRunnable) as Box<dyn QRunnable<i32>>);
        let monitor = DummyMonitor;

        let result = adapter.process(1, &monitor);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "boom");
    }

    #[test]
    fn adapter_can_be_used_as_a_qcallback_trait_object() {
        let sum = Arc::new(AtomicI32::new(0));
        let callback: Box<dyn QCallback<i32, ()>> =
            Box::new(QRunnableAdapter::new(Box::new(RecordingRunnable { sum: sum.clone() }) as Box<dyn QRunnable<i32>>));
        let monitor = DummyMonitor;

        callback.process(7, &monitor).unwrap();

        assert_eq!(sum.load(Ordering::SeqCst), 7);
    }
}
