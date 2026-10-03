//! Port of `generic.cache.CachingPool`.
//!
//! A thread-safe pool that knows how to create instances as needed. When clients are done with
//! the pooled item they call [`release`](CachingPool::release), enabling reuse in the future.
//!
//! Calling [`set_cleanup_timeout`](CachingPool::set_cleanup_timeout) with a non-negative value
//! starts a timer when [`release`](CachingPool::release) is called, to
//! [`dispose`](BasicFactory::dispose) any objects in the pool. By default, the cleanup timer does
//! not run.
//!
//! Once [`dispose`](CachingPool::dispose) has been called on this pool, items created or released
//! will no longer be pooled.
//!
//! ## `Arc<dyn GTimer>`, not a global static timer
//!
//! Java's cleanup timer is scheduled via the static `GTimer.scheduleRunnable(...)`, backed by a
//! single process-wide `Timer`. This crate's [`GTimer`] is a trait/seam rather than a global
//! (see `util::timer`'s own module docs), so this pool takes a `Arc<dyn GTimer>` at construction
//! -- [`new`](CachingPool::new) defaults to [`StdGTimer`], matching Java's real-world behavior,
//! while [`with_timer`](CachingPool::with_timer) allows a substitute for testing.
//!
//! ## Quirk: the cleanup timer disposes cached items *without removing them*
//!
//! Java's private `disposeCachedItems()`:
//! ```java
//! private synchronized void disposeCachedItems() {
//!     for (T t : cache) {
//!         factory.dispose(t);
//!     }
//! }
//! ```
//! iterates `cache` calling `factory.dispose(t)` on every item, but **never removes any item from
//! `cache`**. When called from [`dispose()`](CachingPool::dispose) this is harmless (`isDisposed`
//! is set `true` first, so [`get()`](CachingPool::get) never again looks at `cache`). But when
//! this same method fires from the **idle cleanup timer** (`isDisposed` still `false`), the
//! now-disposed items are left sitting in `cache` -- and a subsequent `get()` (`cache.isEmpty() ||
//! isDisposed` both false) pops one right back out and hands it to a caller, even though
//! `factory.dispose()` already ran on it. This is a real, reachable bug in the upstream class,
//! faithfully reproduced here rather than silently fixed (e.g. by clearing the cache on cleanup);
//! see `cleanup_timer_disposes_without_removing_quirk` below.

use super::BasicFactory;
use crate::util::timer::{GTimer, GTimerMonitor, StdGTimer};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Sentinel disabling the cleanup timer. Port of the private `CachingPool.TIMEOUT` constant.
const TIMEOUT: i64 = -1;

struct PoolInner<T> {
    cache: VecDeque<T>,
    is_disposed: bool,
    dispose_timeout: i64,
    timer_monitor: Option<Box<dyn GTimerMonitor>>,
}

/// Port of `generic.cache.CachingPool<T>`. See the module docs for the `Arc<dyn GTimer>` seam and
/// the faithfully-preserved cleanup-timer quirk.
pub struct CachingPool<T> {
    factory: Arc<dyn BasicFactory<T>>,
    timer: Arc<dyn GTimer>,
    inner: Arc<Mutex<PoolInner<T>>>,
}

impl<T: Clone + Send + 'static> CachingPool<T> {
    /// Creates a new pool that uses the given factory to create new items as needed. Port of
    /// `CachingPool(BasicFactory<T>)`. Uses [`StdGTimer`] for the cleanup timer.
    pub fn new(factory: Box<dyn BasicFactory<T>>) -> Self {
        Self::with_timer(factory, Arc::new(StdGTimer))
    }

    /// As [`new`](Self::new), but with an explicit [`GTimer`] -- primarily for tests that want a
    /// deterministic or fast-forwarding timer instead of [`StdGTimer`]'s real OS-thread delays.
    pub fn with_timer(factory: Box<dyn BasicFactory<T>>, timer: Arc<dyn GTimer>) -> Self {
        CachingPool {
            factory: Arc::from(factory),
            timer,
            inner: Arc::new(Mutex::new(PoolInner {
                cache: VecDeque::new(),
                is_disposed: false,
                dispose_timeout: TIMEOUT,
                timer_monitor: None,
            })),
        }
    }

    /// Sets the time to wait for released items to be disposed by this pool by calling
    /// [`BasicFactory::dispose`]. A negative timeout value signals to disable the cleanup task.
    /// Port of `CachingPool.setCleanupTimeout(long)`.
    ///
    /// When clients call [`get`](Self::get), the timer will not be running. It will be restarted
    /// again once [`release`](Self::release) has been called.
    pub fn set_cleanup_timeout(&self, timeout_millis: i64) {
        let mut inner = self.inner.lock().unwrap();
        inner.dispose_timeout = timeout_millis;
    }

    /// Returns a cached or new `T`. Port of `CachingPool.get()`.
    ///
    /// # Errors
    /// Returns an error if there is a problem instantiating a new instance.
    pub fn get(&self) -> Result<T, anyhow::Error> {
        let mut inner = self.inner.lock().unwrap();
        Self::stop_cleanup_timer(&mut inner);
        if inner.cache.is_empty() || inner.is_disposed {
            return self.factory.create();
        }
        // Java's `cache` is an `ArrayDeque` used as a stack (`push`/`pop`, both operating on the
        // head): most-recently-released item returned first.
        Ok(inner.cache.pop_front().expect("checked non-empty above"))
    }

    /// Signals that the given object is no longer being used. The object will be placed back
    /// into the pool until it is disposed via the cleanup timer, if it is running. Port of
    /// `CachingPool.release(T)`.
    pub fn release(&self, item: T) {
        let mut inner = self.inner.lock().unwrap();
        self.restart_cleanup_timer(&mut inner);
        if inner.is_disposed {
            self.factory.dispose(item);
            return;
        }
        inner.cache.push_front(item);
    }

    /// Triggers all pooled objects to be disposed via this pool's factory. Future calls to
    /// [`get`](Self::get) will still create new objects, but the internal cache will no longer be
    /// used. Port of `CachingPool.dispose()`.
    pub fn dispose(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::stop_cleanup_timer(&mut inner);
        inner.is_disposed = true;
        dispose_cached_items(&inner.cache, self.factory.as_ref());
    }

    fn stop_cleanup_timer(inner: &mut PoolInner<T>) {
        if let Some(mon) = inner.timer_monitor.take() {
            mon.cancel();
        }
    }

    fn restart_cleanup_timer(&self, inner: &mut PoolInner<T>) {
        if let Some(mon) = inner.timer_monitor.take() {
            mon.cancel();
        }
        let inner_arc = Arc::clone(&self.inner);
        let factory_arc = Arc::clone(&self.factory);
        let delay = inner.dispose_timeout;
        inner.timer_monitor = Some(self.timer.schedule_runnable(
            delay,
            Box::new(move || {
                let guard = inner_arc.lock().unwrap();
                // See the module docs: this faithfully never removes items from `cache`.
                dispose_cached_items(&guard.cache, factory_arc.as_ref());
            }),
        ));
    }
}

/// Port of the private `CachingPool.disposeCachedItems()`. See the module docs for the
/// faithfully-preserved "disposes without removing" quirk.
fn dispose_cached_items<T: Clone>(cache: &VecDeque<T>, factory: &dyn BasicFactory<T>) {
    for t in cache {
        factory.dispose(t.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct CountingFactory {
        created: AtomicUsize,
        disposed: AtomicUsize,
    }

    impl CountingFactory {
        fn new() -> Arc<Self> {
            Arc::new(CountingFactory { created: AtomicUsize::new(0), disposed: AtomicUsize::new(0) })
        }
    }

    impl BasicFactory<usize> for CountingFactory {
        fn create(&self) -> Result<usize, anyhow::Error> {
            Ok(self.created.fetch_add(1, Ordering::SeqCst) + 1)
        }
        fn dispose(&self, _item: usize) {
            self.disposed.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct ArcFactory(Arc<CountingFactory>);
    impl BasicFactory<usize> for ArcFactory {
        fn create(&self) -> Result<usize, anyhow::Error> {
            self.0.create()
        }
        fn dispose(&self, item: usize) {
            self.0.dispose(item)
        }
    }

    #[test]
    fn get_creates_a_new_item_when_cache_empty() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        let item = pool.get().unwrap();
        assert_eq!(item, 1);
        assert_eq!(factory.created.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn release_then_get_reuses_the_same_item_without_creating_anew() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        let item = pool.get().unwrap();
        pool.release(item);
        let item2 = pool.get().unwrap();
        assert_eq!(item2, item);
        assert_eq!(factory.created.load(Ordering::SeqCst), 1, "reused, not recreated");
    }

    #[test]
    fn release_is_lifo_like_javas_deque_push_pop() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        let a = pool.get().unwrap();
        let b = pool.get().unwrap();
        pool.release(a);
        pool.release(b);
        // `release` = `Deque.push` (addFirst), `get` = `Deque.pop` (removeFirst): the
        // most-recently-released item comes back first.
        assert_eq!(pool.get().unwrap(), b);
        assert_eq!(pool.get().unwrap(), a);
    }

    #[test]
    fn dispose_marks_pool_disposed_and_disposes_cached_items() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        let item = pool.get().unwrap();
        pool.release(item);
        pool.dispose();
        assert_eq!(factory.disposed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_after_dispose_always_creates_new_items() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        let item = pool.get().unwrap();
        pool.release(item);
        pool.dispose();

        let item2 = pool.get().unwrap();
        // Item 1 was created, released, then disposed; a fresh item is created post-dispose.
        assert_eq!(item2, 2);
        assert_eq!(factory.created.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn release_after_dispose_disposes_immediately_rather_than_caching() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        pool.dispose();
        pool.release(42);
        assert_eq!(factory.disposed.load(Ordering::SeqCst), 1);
        // Nothing was cached: the next get() creates fresh rather than returning 42.
        let item = pool.get().unwrap();
        assert_eq!(item, 1);
    }

    /// Faithful reproduction of the real Java quirk documented at the top of this module: once
    /// the idle cleanup timer fires (as opposed to an explicit `dispose()` call), the disposed
    /// item is *not* removed from the cache -- a subsequent `get()` still hands it back, and no
    /// new item is created.
    #[test]
    fn cleanup_timer_disposes_without_removing_quirk() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        pool.set_cleanup_timeout(20);

        let item = pool.get().unwrap();
        pool.release(item); // starts the cleanup timer

        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            factory.disposed.load(Ordering::SeqCst),
            1,
            "the idle cleanup timer must have fired and disposed the cached item"
        );

        // The "disposed" item is still sitting in the cache (the bug): get() hands it back
        // instead of creating a fresh one.
        let item_again = pool.get().unwrap();
        assert_eq!(item_again, item, "get() returns the already-disposed cached item");
        assert_eq!(factory.created.load(Ordering::SeqCst), 1, "no new item was ever created");
    }

    #[test]
    fn cleanup_timer_disabled_by_default_never_disposes() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        let item = pool.get().unwrap();
        pool.release(item);

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(factory.disposed.load(Ordering::SeqCst), 0, "no cleanup timeout was set");
        assert_eq!(pool.get().unwrap(), item);
    }

    #[test]
    fn set_cleanup_timeout_negative_disables_the_timer() {
        let factory = CountingFactory::new();
        let pool = CachingPool::new(Box::new(ArcFactory(factory.clone())));
        pool.set_cleanup_timeout(20);
        pool.set_cleanup_timeout(-1); // disable again before any release() schedules it

        let item = pool.get().unwrap();
        pool.release(item);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(factory.disposed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn factory_create_error_propagates() {
        struct FailingFactory;
        impl BasicFactory<usize> for FailingFactory {
            fn create(&self) -> Result<usize, anyhow::Error> {
                Err(anyhow::anyhow!("boom"))
            }
            fn dispose(&self, _item: usize) {}
        }
        let pool = CachingPool::new(Box::new(FailingFactory));
        let result = pool.get();
        assert!(result.is_err());
    }
}
