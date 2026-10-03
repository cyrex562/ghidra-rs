//! A timer for asynchronous scheduled tasks.
//!
//! Port of `ghidra.async.AsyncTimer`.

use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;

use super::async_utils::nil;

/// A future that completes at a scheduled time, analogous to the `CompletableFuture<Void>`
/// returned throughout this class.
pub type AsyncTimerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The current wall-clock time in milliseconds since the Unix epoch, analogous to
/// `System.currentTimeMillis()`.
fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is set before the Unix epoch")
        .as_millis() as i64
}

/// A timer for asynchronous scheduled tasks.
///
/// Port of `ghidra.async.AsyncTimer`. This object provides futures which complete at specified
/// times. This is useful for pausing amid a chain of callback actions, i.e., between iterations
/// of a loop.
///
/// A delay is achieved using [`mark`](Self::mark), then [`Mark::after`]:
///
/// ```rust,no_run
/// # use ghidra_rs::util::async_timer::AsyncTimer;
/// # async fn example(timer: &AsyncTimer) {
/// timer.mark().after(1000).await;
/// # }
/// ```
///
/// [`mark`](Self::mark) marks the current system time; all calls to the mark's
/// [`after`](Mark::after) schedule futures relative to this mark. Scheduling a timed sequence of
/// actions is best accomplished using times relative to a single mark:
///
/// ```rust,no_run
/// # use ghidra_rs::util::async_timer::AsyncTimer;
/// # async fn example(timer: &AsyncTimer) {
/// let mark = timer.mark();
/// mark.after(1000).await;
/// // do_task_at_one_second();
/// mark.after(2000).await;
/// // do_task_at_two_seconds();
/// # }
/// ```
///
/// This provides slightly more precise scheduling than delaying for a fixed period between
/// tasks.
///
/// # Divergence from Java
///
/// Java's `AsyncTimer` is backed by a single dedicated (daemon) thread, plus, for the "already
/// past" case, `AsyncUtils.nil()` (an already-completed future returned with no dispatch at
/// all). Since Tokio's runtime already supplies the scheduling thread pool, this port has no
/// `thread` field of its own; every [`AsyncTimerFuture`] this type hands back is driven by
/// whatever Tokio runtime the caller awaits it on.
pub struct AsyncTimer;

impl AsyncTimer {
    /// Create a new timer.
    ///
    /// Except to reduce contention among threads, most applications need only create one timer
    /// instance. See [`AsyncTimer::default_timer`].
    pub fn new() -> Self {
        AsyncTimer
    }

    /// The shared default timer, analogous to the Java static field `AsyncTimer.DEFAULT_TIMER`.
    pub fn default_timer() -> &'static AsyncTimer {
        static DEFAULT_TIMER: OnceLock<AsyncTimer> = OnceLock::new();
        DEFAULT_TIMER.get_or_init(AsyncTimer::new)
    }

    /// Schedule a task to run when the current time has passed a given time.
    ///
    /// This method returns immediately, giving a future result. The future completes "soon
    /// after" the current system time passes the given time in milliseconds. There is some
    /// minimal overhead, but the scheduler endeavors to complete the future as close to the
    /// given time as possible. The actual scheduled time will not precede the requested time.
    ///
    /// `time_millis` is the time after which the returned future completes.
    pub fn at_system_time(&self, time_millis: i64) -> AsyncTimerFuture {
        if time_millis - now_millis() <= 0 {
            return Box::pin(nil());
        }

        // Java re-reads `System.currentTimeMillis()` here instead of reusing the value from the
        // check above. If enough time elapses between the two reads that `delta` crosses zero,
        // Java's real behavior is to dispatch the (still trivially quick) task on its background
        // `thread` executor rather than a `delayedExecutor`, a distinction that only matters for
        // *which* executor runs it, not *when* it completes -- both routes still complete right
        // away, with no further delay. This port has no separate executors to route between (see
        // the struct docs), so the faithfully-preserved double read collapses to the same
        // near-immediate completion either way.
        let delta = time_millis - now_millis();
        if delta <= 0 {
            return Box::pin(nil());
        }

        let dur = Duration::from_millis(delta as u64);
        Box::pin(async move {
            tokio::time::sleep(dur).await;
        })
    }

    /// Mark the current system time.
    pub fn mark(&self) -> Mark<'_> {
        Mark { timer: self, mark: now_millis() }
    }
}

impl Default for AsyncTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// A marked point in time, from which delays can be scheduled.
///
/// Port of `AsyncTimer.Mark`, Java's non-static inner class. Only [`AsyncTimer::mark`]
/// constructs one, mirroring the `protected` Java constructor.
pub struct Mark<'a> {
    timer: &'a AsyncTimer,
    mark: i64,
}

impl<'a> Mark<'a> {
    /// Schedule a task to run when the given number of milliseconds has passed since this mark.
    ///
    /// The method returns immediately, giving a future result. The future completes "soon
    /// after" the requested interval since the mark passes. There is some minimal overhead, but
    /// the scheduler endeavors to complete the future as close to the given time as possible.
    /// The actual scheduled time will not precede the requested time.
    ///
    /// `interval_millis` is the interval after which the returned future completes.
    pub fn after(&self, interval_millis: i64) -> AsyncTimerFuture {
        self.timer.at_system_time(self.mark + interval_millis)
    }

    /// Time a future out after the given interval.
    ///
    /// `future` is the (already-running) task whose value is expected within `millis`;
    /// `value_if_late` supplies the value to use if it doesn't complete in time. Returns the
    /// future's value, or the late value if it times out.
    ///
    /// Mirrors `CompletableFuture.anyOf(future, after(millis)).thenApply(v -> future.isDone() ?
    /// future.getNow(null) : valueIfLate.get())`: whichever of the two races completes first
    /// triggers the decision, but Java re-checks `future.isDone()` at that point rather than
    /// trusting which race member actually fired -- so a `future` that finishes at (almost) the
    /// same moment as the timeout still wins. [`JoinHandle::is_finished`] is the direct analogue
    /// of `isDone()`, preserving that same re-check here.
    pub async fn time_out<T: Send + 'static>(
        &self,
        mut future: JoinHandle<T>,
        millis: i64,
        value_if_late: impl FnOnce() -> T,
    ) -> T {
        tokio::select! {
            result = &mut future => result.unwrap_or_else(|_| value_if_late()),
            _ = self.after(millis) => {
                if future.is_finished() {
                    (&mut future).await.unwrap_or_else(|_| value_if_late())
                } else {
                    value_if_late()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[tokio::test]
    async fn at_system_time_in_the_past_completes_immediately() {
        let timer = AsyncTimer::new();
        let start = Instant::now();
        timer.at_system_time(now_millis() - 10_000).await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn at_system_time_in_the_future_waits_at_least_the_requested_interval() {
        let timer = AsyncTimer::new();
        let target = now_millis() + 60;
        let start = Instant::now();
        timer.at_system_time(target).await;
        // "The actual scheduled time will not precede the requested time."
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn default_timer_returns_the_same_instance_every_call() {
        let a: *const AsyncTimer = AsyncTimer::default_timer();
        let b: *const AsyncTimer = AsyncTimer::default_timer();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn mark_after_schedules_relative_to_the_mark_not_the_call_time() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        // Let some real time pass after the mark before scheduling from it.
        tokio::time::sleep(Duration::from_millis(30)).await;

        let start = Instant::now();
        // Since 30ms has already elapsed since `mark`, waiting 40ms more from the mark should
        // take roughly 10ms from *now*, not a full 40ms.
        mark.after(40).await;
        assert!(start.elapsed() < Duration::from_millis(35));
    }

    #[tokio::test]
    async fn mark_after_in_the_past_completes_immediately() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        tokio::time::sleep(Duration::from_millis(30)).await;

        let start = Instant::now();
        mark.after(1).await;
        assert!(start.elapsed() < Duration::from_millis(20));
    }

    #[tokio::test]
    async fn time_out_returns_the_futures_value_when_it_finishes_in_time() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            42
        });

        let result = mark.time_out(handle, 500, || -1).await;
        assert_eq!(42, result);
    }

    #[tokio::test]
    async fn time_out_returns_the_late_value_when_the_future_is_too_slow() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            42
        });

        let result = mark.time_out(handle, 30, || -1).await;
        assert_eq!(-1, result);
    }

    #[tokio::test]
    async fn time_out_prefers_the_futures_value_even_when_it_finishes_right_at_the_deadline() {
        // Exercises the `future.is_finished()` re-check quirk: a `future` that's already done
        // by the time the decision is made wins, no matter which race branch (in select!, or
        // Java's anyOf) happened to poll ready first.
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        let started = Arc::new(AtomicBool::new(false));
        let started_writer = Arc::clone(&started);
        let handle = tokio::spawn(async move {
            started_writer.store(true, Ordering::SeqCst);
            7
        });
        // Give the spawned task a real chance to run and finish before racing the timeout.
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;

        let result = mark.time_out(handle, 0, || -1).await;
        assert_eq!(7, result);
    }
}
