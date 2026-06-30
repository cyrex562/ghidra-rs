use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;

/// A fence that completes when all participating tasks complete.
///
/// Provides a Rust/tokio shorthand analogous to Java's
/// `CompletableFuture.allOf(...)`.
///
/// # Example
/// ```rust,no_run
/// use ghidra_rs::util::async_fence::AsyncFence;
///
/// async fn process_all(items: &[u32]) {
///     let fence = AsyncFence::new();
///     for &item in items {
///         fence.include(tokio::spawn(async move { /* process item */ }));
///     }
///     fence.ready().await.unwrap();
/// }
/// ```
///
/// Port of `ghidra.async.AsyncFence`.
pub struct AsyncFence {
    inner: Mutex<FenceInner>,
}

struct FenceInner {
    /// Wrapped task handles awaited by [`AsyncFence::ready`].
    handles: Vec<JoinHandle<()>>,
    /// One flag per participant; set to `true` when its wrapper task finishes.
    flags: Vec<Arc<AtomicBool>>,
    /// Set to `true` once [`AsyncFence::ready`] has been called.
    sealed: bool,
}

impl AsyncFence {
    /// Creates a new empty `AsyncFence`.
    pub fn new() -> Self {
        AsyncFence {
            inner: Mutex::new(FenceInner {
                handles: Vec::new(),
                flags: Vec::new(),
                sealed: false,
            }),
        }
    }

    /// Includes a participant in this fence.
    ///
    /// The task's result is ignored. Panics if [`ready`][Self::ready] has already been called.
    ///
    /// # Panics
    /// Panics if called after [`ready`][Self::ready], or if called outside a Tokio runtime.
    pub fn include<T: Send + 'static>(&self, handle: JoinHandle<T>) -> &Self {
        let flag = Arc::new(AtomicBool::new(false));
        let flag2 = flag.clone();
        let wrapped = tokio::spawn(async move {
            let _ = handle.await;
            flag2.store(true, Ordering::Release);
        });
        {
            let mut inner = self.inner.lock().unwrap();
            assert!(!inner.sealed, "include called after ready()");
            inner.handles.push(wrapped);
            inner.flags.push(flag);
        }
        self
    }

    /// Returns a task handle that completes when all participants have completed.
    ///
    /// May only be called once. The returned [`JoinHandle`] must be awaited to drive completion.
    ///
    /// # Panics
    /// Panics if called more than once, or if called outside a Tokio runtime.
    pub fn ready(&self) -> JoinHandle<()> {
        let handles: Vec<JoinHandle<()>> = {
            let mut inner = self.inner.lock().unwrap();
            assert!(!inner.sealed, "ready() called more than once");
            inner.sealed = true;
            inner.handles.drain(..).collect()
        };
        tokio::spawn(async move {
            for h in handles {
                let _ = h.await;
            }
        })
    }

    /// Diagnostic: returns the number of participants that have not yet completed.
    ///
    /// In Java, `getPending()` returns the actual `CompletableFuture` objects; here Rust's type
    /// erasure means only a count is available.
    pub fn pending_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.flags.iter().filter(|f| !f.load(Ordering::Acquire)).count()
    }
}

impl Default for AsyncFence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn empty_fence_completes_immediately() {
        let fence = AsyncFence::new();
        fence.ready().await.unwrap();
    }

    #[tokio::test]
    async fn single_participant_is_awaited() {
        let fence = AsyncFence::new();
        let (tx, rx) = oneshot::channel::<()>();
        fence.include(tokio::spawn(async move { rx.await.unwrap() }));
        let ready = fence.ready();
        tx.send(()).unwrap();
        ready.await.unwrap();
    }

    #[tokio::test]
    async fn all_participants_must_complete() {
        let fence = AsyncFence::new();
        let (tx1, rx1) = oneshot::channel::<()>();
        let (tx2, rx2) = oneshot::channel::<()>();
        fence.include(tokio::spawn(async move { rx1.await.unwrap() }));
        fence.include(tokio::spawn(async move { rx2.await.unwrap() }));
        let ready = fence.ready();
        tx1.send(()).unwrap();
        tx2.send(()).unwrap();
        ready.await.unwrap();
    }

    #[tokio::test]
    async fn pending_count_decreases_as_tasks_finish() {
        let fence = AsyncFence::new();
        let (tx, rx) = oneshot::channel::<()>();
        fence.include(tokio::spawn(async move { rx.await.unwrap() }));
        // Give the wrapper task time to register
        tokio::task::yield_now().await;
        assert_eq!(fence.pending_count(), 1);
        tx.send(()).unwrap();
        // Allow wrapper task to set the flag
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(fence.pending_count(), 0);
    }

    #[tokio::test]
    async fn pending_count_is_zero_for_empty_fence() {
        let fence = AsyncFence::new();
        assert_eq!(fence.pending_count(), 0);
    }

    #[tokio::test]
    #[should_panic(expected = "include called after ready()")]
    async fn include_after_ready_panics() {
        let fence = AsyncFence::new();
        let _ = fence.ready();
        fence.include(tokio::spawn(async {}));
    }

    #[tokio::test]
    #[should_panic(expected = "ready() called more than once")]
    async fn ready_called_twice_panics() {
        let fence = AsyncFence::new();
        let _ = fence.ready();
        let _ = fence.ready();
    }

    #[tokio::test]
    async fn default_creates_empty_fence() {
        let fence = AsyncFence::default();
        assert_eq!(fence.pending_count(), 0);
        fence.ready().await.unwrap();
    }

    #[tokio::test]
    async fn chained_includes() {
        let fence = AsyncFence::new();
        let (tx1, rx1) = oneshot::channel::<()>();
        let (tx2, rx2) = oneshot::channel::<()>();
        fence
            .include(tokio::spawn(async move { rx1.await.unwrap() }))
            .include(tokio::spawn(async move { rx2.await.unwrap() }));
        let ready = fence.ready();
        tx1.send(()).unwrap();
        tx2.send(()).unwrap();
        ready.await.unwrap();
    }
}
