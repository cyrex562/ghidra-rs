//! Port of `ghidra.graph.job.GraphJobListener`.

use super::graph_job::GraphJob;

/// A listener notified when a [`GraphJob`] has finished its work.
///
/// A job keeps the listener it was given in [`GraphJob::execute`] and calls it back later (for
/// example when an animation completes), so listeners are handed to jobs as a shared
/// `Rc<dyn GraphJobListener>` and are notified through `&self`; an implementor that must change
/// state on notification (such as a job runner starting its next job) uses interior mutability.
/// Taking `&self` also keeps a job that finishes synchronously, from inside `execute`, from
/// conflicting with a borrow its runner already holds.
///
/// Corresponds to `ghidra.graph.job.GraphJobListener`.
pub trait GraphJobListener {
    /// Called when `job` has finished.
    ///
    /// Java: `void jobFinished(GraphJob job)`.
    fn job_finished(&self, job: &dyn GraphJob);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct NamedJob(&'static str);

    impl GraphJob for NamedJob {
        fn execute(&mut self, listener: Rc<dyn GraphJobListener>) {
            listener.job_finished(self);
        }
        fn can_shortcut(&self) -> bool {
            false
        }
        fn shortcut(&mut self) {}
        fn is_finished(&self) -> bool {
            true
        }
        fn dispose(&mut self) {}
    }

    /// Records the address of each finished job, the way Java's `GraphJobRunner` compares the
    /// finished job against its current job by identity.
    #[derive(Default)]
    struct Recorder {
        finished: RefCell<Vec<*const ()>>,
    }

    impl GraphJobListener for Recorder {
        fn job_finished(&self, job: &dyn GraphJob) {
            self.finished.borrow_mut().push(job as *const dyn GraphJob as *const ());
        }
    }

    #[test]
    fn listener_is_told_which_job_finished() {
        let recorder = Rc::new(Recorder::default());
        let mut a = NamedJob("a");
        let mut b = NamedJob("b");
        a.execute(recorder.clone());
        b.execute(recorder.clone());

        let finished = recorder.finished.borrow();
        assert_eq!(finished.len(), 2);
        assert_eq!(finished[0], &a as *const NamedJob as *const ());
        assert_eq!(finished[1], &b as *const NamedJob as *const ());
        assert_eq!((a.0, b.0), ("a", "b"));
    }
}
