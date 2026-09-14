//! Port of `ghidra.util.worker.PriorityJob`.
//!
//! An abstract `Job` that also carries a strictly-increasing "priority" -- really an insertion
//! sequence number, assigned once at construction from a process-wide counter -- used by a
//! `Worker` (not yet ported) to break ties between otherwise-equal-priority queued jobs in
//! first-come-first-served order.
//!
//! # Shape
//!
//! Java's `abstract class PriorityJob extends Job` adds one field (`id`) and no new abstract
//! methods on top of `Job`'s own single abstract `run`. Per this crate's composition-over-
//! inheritance convention (matching [`Job`]/[`JobBase`]'s own split), this becomes [`PriorityJobBase`]
//! (the `id` field, plus `Job`'s inherited `base: JobBase`, plus the concrete methods Java's class
//! already gives real bodies to) and the [`PriorityJob`] trait (extending [`Job`], requiring a
//! [`PriorityJob::priority_job_base`] accessor a concrete job implements by holding a
//! `priority_base: PriorityJobBase` field).
//!
//! # `nextID`/`getNextID()`: a process-wide atomic counter
//!
//! Java's `private static int nextID = 1; static synchronized long getNextID() { return
//! nextID++; }` is a class-wide (JVM-process-wide) counter, `synchronized` for thread safety.
//! This port uses a single [`static@NEXT_ID`] [`AtomicU64`], mirroring the same "every
//! `PriorityJobBase` constructed anywhere gets a distinct, strictly-increasing id" semantics
//! without needing a lock. Widened from Java's `int` (`nextID`) to `u64` to sidestep the (already
//! practically-unreachable) `int` overflow Java's version accepts implicitly; `getPriority()`'s
//! return type (`long` in Java) becomes `u64` accordingly. Like the JVM's own counter, this is
//! genuinely process-wide (shared by every test in this process too) -- see
//! `distinct_instances_get_strictly_increasing_ids`'s use of *relative* ordering rather than
//! exact values, for exactly that reason.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use crate::util::worker::job::{Job, JobBase};

/// Process-wide counter backing [`PriorityJobBase::next_id`]. Mirrors the Java `static int
/// nextID = 1` field: starts at 1, mirrored below via [`PriorityJobBase::new`]'s first fetch.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The state Java's `PriorityJob` abstract class adds on top of `Job`: a fixed id assigned at
/// construction time from the process-wide [`static@NEXT_ID`] counter.
///
/// Port of the field/concrete-method surface of `ghidra.util.worker.PriorityJob`.
pub struct PriorityJobBase {
    /// `Job`'s own inherited state, held by composition (mirrors `extends Job`).
    pub job_base: JobBase,
    id: u64,
}

impl PriorityJobBase {
    /// Constructs a fresh `PriorityJobBase`, assigning it the next id from the process-wide
    /// counter.
    ///
    /// Port of `PriorityJob()`: `id = getNextID();`.
    pub fn new() -> Self {
        PriorityJobBase { job_base: JobBase::new(), id: Self::next_id() }
    }

    /// Port of the `static synchronized long getNextID()`.
    fn next_id() -> u64 {
        NEXT_ID.fetch_add(1, Ordering::SeqCst)
    }

    /// Port of `PriorityJob.getPriority()`.
    pub fn get_priority(&self) -> u64 {
        self.id
    }

    /// Port of the `protected long getID()`. Rust has no protected visibility; kept `pub` per
    /// this crate's established convention for such members (see [`JobBase::set_task_monitor`]'s
    /// own docs on the same point).
    pub fn get_id(&self) -> u64 {
        self.id
    }
}

impl Default for PriorityJobBase {
    fn default() -> Self {
        Self::new()
    }
}

/// A unit of work a `Worker` executes on a background thread, additionally carrying an
/// insertion-order priority for tie-breaking among otherwise-equal-priority jobs.
///
/// Port of `ghidra.util.worker.PriorityJob`.
pub trait PriorityJob: Job {
    /// The shared state a concrete job holds via composition (`priority_base: PriorityJobBase`),
    /// standing in for Java's inherited `PriorityJob` fields.
    fn priority_job_base(&self) -> &PriorityJobBase;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct CountingJob {
        priority_base: PriorityJobBase,
    }

    impl CountingJob {
        fn new() -> Self {
            CountingJob { priority_base: PriorityJobBase::new() }
        }
    }

    impl Job for CountingJob {
        fn job_base(&self) -> &JobBase {
            &self.priority_base.job_base
        }

        fn run(&self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            self.priority_base.job_base.set_completed();
            Ok(())
        }
    }

    impl PriorityJob for CountingJob {
        fn priority_job_base(&self) -> &PriorityJobBase {
            &self.priority_base
        }
    }

    #[test]
    fn new_priority_job_base_is_uncompleted_and_has_an_id() {
        let base = PriorityJobBase::new();
        assert!(!base.job_base.is_completed());
        assert!(base.get_id() > 0);
    }

    #[test]
    fn get_priority_matches_get_id() {
        let base = PriorityJobBase::new();
        assert_eq!(base.get_priority(), base.get_id());
    }

    #[test]
    fn distinct_instances_get_strictly_increasing_ids() {
        // Relative ordering only: NEXT_ID is process-wide (shared across the whole test binary),
        // so exact values depend on test execution order/parallelism, but two ids fetched in
        // sequence on this thread are always strictly increasing.
        let a = PriorityJobBase::new();
        let b = PriorityJobBase::new();
        let c = PriorityJobBase::new();
        assert!(a.get_id() < b.get_id());
        assert!(b.get_id() < c.get_id());
    }

    #[test]
    fn concrete_priority_job_runs_through_both_trait_surfaces() {
        let job = CountingJob::new();
        assert!(!job.job_base().is_completed());

        let result = job.run(&DummyMonitor);

        assert!(result.is_ok());
        assert!(job.job_base().is_completed());
        assert!(job.priority_job_base().get_priority() > 0);
    }

    #[test]
    fn usable_as_a_trait_object() {
        let job: Box<dyn PriorityJob> = Box::new(CountingJob::new());
        assert!(job.run(&DummyMonitor).is_ok());
        assert!(job.job_base().is_completed());
        assert!(job.priority_job_base().get_id() > 0);
    }
}
