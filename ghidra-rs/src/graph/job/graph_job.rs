//! Port of `ghidra.graph.job.GraphJob`.

use std::rc::Rc;

use super::graph_job_listener::GraphJobListener;

/// A graph job is an item of work that needs to be performed on a graph (for example, a layout
/// animation), run one at a time by a job runner.
///
/// Corresponds to `ghidra.graph.job.GraphJob`.
pub trait GraphJob {
    /// Tells this job to do its work.
    ///
    /// Java documents that this call happens on the Swing thread, and that the job must call the
    /// given listener on that same thread when it is finished. The job may finish later (after an
    /// animation, say), so it keeps the shared `listener` until then; see [`GraphJobListener`].
    ///
    /// Java: `void execute(GraphJobListener listener)`.
    fn execute(&mut self, listener: Rc<dyn GraphJobListener>);

    /// Returns true if the job can be told to stop running, but to still perform any final work
    /// before being done.
    ///
    /// Java: `boolean canShortcut()`.
    fn can_shortcut(&self) -> bool;

    /// Tells this job to stop running, but to still perform any final work before being done.
    ///
    /// If the job is multi-threaded, it must end its thread and work before returning from this
    /// method; if that cannot be done in a timely manner, [`GraphJob::can_shortcut`] should return
    /// false.
    ///
    /// Java: `void shortcut()`.
    fn shortcut(&mut self);

    /// Returns true if this job has finished its work.
    ///
    /// Java: `boolean isFinished()`.
    fn is_finished(&self) -> bool;

    /// Call to immediately stop this job, ignoring any exceptions or state issues that arise.
    ///
    /// Java: `void dispose()`.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A job that finishes only when told to (via `complete` or `shortcut`), keeping its listener
    /// in between the way Java's `AbstractAnimatorJob` keeps `finishedListener`.
    #[derive(Default)]
    struct DeferredJob {
        listener: Option<Rc<dyn GraphJobListener>>,
        finished: bool,
        shortcut: bool,
    }

    impl DeferredJob {
        fn complete(&mut self) {
            self.finished = true;
            if let Some(listener) = self.listener.clone() {
                listener.job_finished(self);
            }
        }
    }

    impl GraphJob for DeferredJob {
        fn execute(&mut self, listener: Rc<dyn GraphJobListener>) {
            self.listener = Some(listener);
        }
        fn can_shortcut(&self) -> bool {
            true
        }
        fn shortcut(&mut self) {
            self.shortcut = true;
            self.complete();
        }
        fn is_finished(&self) -> bool {
            self.finished
        }
        fn dispose(&mut self) {
            self.finished = true;
        }
    }

    #[derive(Default)]
    struct CountingListener {
        count: Cell<u32>,
    }

    impl GraphJobListener for CountingListener {
        fn job_finished(&self, job: &dyn GraphJob) {
            assert!(job.is_finished(), "listener called before the job reported finished");
            self.count.set(self.count.get() + 1);
        }
    }

    #[test]
    fn listener_kept_from_execute_is_called_when_job_later_finishes() {
        let listener = Rc::new(CountingListener::default());
        let mut job = DeferredJob::default();
        job.execute(listener.clone());
        assert!(!job.is_finished());
        assert_eq!(listener.count.get(), 0);

        job.complete();
        assert!(job.is_finished());
        assert_eq!(listener.count.get(), 1);
    }

    #[test]
    fn shortcut_still_performs_final_work_and_notifies() {
        let listener = Rc::new(CountingListener::default());
        let mut job = DeferredJob::default();
        job.execute(listener.clone());
        assert!(job.can_shortcut());
        job.shortcut();
        assert!(job.shortcut);
        assert!(job.is_finished());
        assert_eq!(listener.count.get(), 1);
    }

    #[test]
    fn shortcut_before_execute_has_no_listener_to_notify() {
        // Java's AbstractAnimatorJob: "a null listener implies we were shortcut before we were
        // started".
        let mut job = DeferredJob::default();
        job.shortcut();
        assert!(job.is_finished());
    }

    #[test]
    fn dispose_stops_without_notifying() {
        let listener = Rc::new(CountingListener::default());
        let mut job: Box<dyn GraphJob> = Box::new(DeferredJob::default());
        job.execute(listener.clone());
        job.dispose();
        assert!(job.is_finished());
        assert_eq!(listener.count.get(), 0);
    }
}
