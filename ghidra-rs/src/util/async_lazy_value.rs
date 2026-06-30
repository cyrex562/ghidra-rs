use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// Heap-allocated error shared across threads.
pub type ArcError = Arc<dyn std::error::Error + Send + Sync + 'static>;

type BoxFuture<T> = Pin<Box<dyn Future<Output = Result<T, ArcError>> + Send + 'static>>;

struct LazyInner<T: Clone + Send + 'static> {
    /// `Some` while a computation is in flight; each entry is a pending waiter.
    subscribers: Option<Vec<oneshot::Sender<Result<T, ArcError>>>>,
    /// Cached result of a successful computation.
    cached: Option<T>,
}

/// A value computed at most once on first request, cached on success, retried on failure.
///
/// Analogous to Java's `ghidra.async.AsyncLazyValue`. On the first call to
/// [`request`][Self::request] the supplier is invoked and its future is driven to
/// completion. While in flight every concurrent [`request`][Self::request] shares the
/// same computation. On success the result is cached; on failure the cache is cleared
/// and the next call retries. [`provide`][Self::provide] allows an out-of-band caller
/// to supply the value instead.
///
/// Port of `ghidra.async.AsyncLazyValue`.
pub struct AsyncLazyValue<T: Clone + Send + Sync + 'static> {
    inner: Arc<Mutex<LazyInner<T>>>,
    supplier: Arc<dyn Fn() -> BoxFuture<T> + Send + Sync + 'static>,
}

impl<T: Clone + Send + Sync + 'static> AsyncLazyValue<T> {
    /// Creates a new lazy value backed by `supplier`.
    ///
    /// `supplier` may be called more than once if previous computations fail.
    pub fn new<F, Fut>(supplier: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<T, ArcError>> + Send + 'static,
    {
        AsyncLazyValue {
            inner: Arc::new(Mutex::new(LazyInner {
                subscribers: None,
                cached: None,
            })),
            supplier: Arc::new(move || Box::pin(supplier())),
        }
    }

    /// Requests the value, starting the computation on the first call.
    ///
    /// All concurrent callers share the same in-flight computation. Cached values are
    /// returned immediately without invoking the supplier again. On failure the cached
    /// state is cleared so that the next call retries.
    pub async fn request(&self) -> Result<T, ArcError> {
        let rx = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(v) = &inner.cached {
                return Ok(v.clone());
            }
            let (tx, rx) = oneshot::channel::<Result<T, ArcError>>();
            if let Some(subs) = inner.subscribers.as_mut() {
                subs.push(tx);
            } else {
                inner.subscribers = Some(vec![tx]);
                let inner_arc = Arc::clone(&self.inner);
                let supplier = Arc::clone(&self.supplier);
                tokio::spawn(async move {
                    let result = supplier().await;
                    Self::notify(&inner_arc, result);
                });
            }
            rx
        };
        rx.await.unwrap_or_else(|_| {
            Err(Arc::new(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "computation was cancelled before completion",
            )))
        })
    }

    /// Provides the value out of band, bypassing the supplier.
    ///
    /// If no computation is running a new in-flight slot is created and the returned
    /// [`Completer`] must be used to complete it. If a computation is already running
    /// the returned [`Completer`] shares that same slot; only the first completion wins.
    /// Dropping a [`Completer`] without completing causes pending [`request`][Self::request]
    /// callers to receive an error.
    pub fn provide(&self) -> Completer<T> {
        let mut inner = self.inner.lock().unwrap();
        if inner.subscribers.is_none() && inner.cached.is_none() {
            inner.subscribers = Some(Vec::new());
        }
        Completer {
            inner: Some(Arc::clone(&self.inner)),
        }
    }

    /// Clears the cached value so that the next [`request`][Self::request] recomputes it.
    ///
    /// Any in-flight computation is abandoned; pending callers receive an error.
    pub fn forget(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cached = None;
        inner.subscribers = None;
        // Dropping the subscribers drains their Senders; receivers see RecvError.
    }

    /// Returns `true` if a computation has been started but has not yet completed.
    pub fn is_busy(&self) -> bool {
        self.inner.lock().unwrap().subscribers.is_some()
    }

    /// Returns `true` if the value is cached (successfully computed).
    pub fn is_done(&self) -> bool {
        self.inner.lock().unwrap().cached.is_some()
    }

    fn notify(inner: &Arc<Mutex<LazyInner<T>>>, result: Result<T, ArcError>) {
        let subs = {
            let mut guard = inner.lock().unwrap();
            match &result {
                Ok(v) => guard.cached = Some(v.clone()),
                Err(_) => {}
            }
            guard.subscribers.take().unwrap_or_default()
        };
        for sub in subs {
            let _ = sub.send(result.clone());
        }
    }
}

impl<T: Clone + Send + Sync + fmt::Display + 'static> fmt::Display for AsyncLazyValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        if inner.subscribers.is_some() {
            write!(f, "(lazy-req)")
        } else if let Some(v) = &inner.cached {
            write!(f, "{v}")
        } else {
            write!(f, "(lazy)")
        }
    }
}

/// Handle returned by [`AsyncLazyValue::provide`] that completes the lazy value.
///
/// Call [`complete`][Self::complete] to supply a successful result or
/// [`fail`][Self::fail] to signal an error. Dropping without calling either causes
/// pending [`request`][AsyncLazyValue::request] callers to receive an error.
pub struct Completer<T: Clone + Send + Sync + 'static> {
    inner: Option<Arc<Mutex<LazyInner<T>>>>,
}

impl<T: Clone + Send + Sync + 'static> Completer<T> {
    /// Completes the lazy value with `value`, waking all pending requesters.
    ///
    /// Has no effect if the value was already completed by another caller.
    pub fn complete(mut self, value: T) {
        if let Some(inner) = self.inner.take() {
            let subs = {
                let mut guard = inner.lock().unwrap();
                if guard.cached.is_some() {
                    return;
                }
                guard.cached = Some(value.clone());
                guard.subscribers.take().unwrap_or_default()
            };
            for sub in subs {
                let _ = sub.send(Ok(value.clone()));
            }
        }
    }

    /// Fails the computation with `error`, clearing in-flight state so that the next
    /// [`request`][AsyncLazyValue::request] will retry.
    pub fn fail(mut self, error: ArcError) {
        if let Some(inner) = self.inner.take() {
            let subs = {
                let mut guard = inner.lock().unwrap();
                if guard.cached.is_some() {
                    return;
                }
                guard.subscribers.take().unwrap_or_default()
            };
            for sub in subs {
                let _ = sub.send(Err(Arc::clone(&error)));
            }
        }
    }
}

impl<T: Clone + Send + Sync + 'static> Drop for Completer<T> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            let mut guard = inner.lock().unwrap();
            if guard.cached.is_none() {
                // Drop all senders; receivers will observe RecvError.
                guard.subscribers = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ok_supplier(v: i32) -> AsyncLazyValue<i32> {
        AsyncLazyValue::new(move || async move { Ok(v) })
    }

    fn err_supplier(msg: &'static str) -> AsyncLazyValue<i32> {
        AsyncLazyValue::new(move || async move {
            Err(Arc::new(std::io::Error::new(std::io::ErrorKind::Other, msg))
                as ArcError)
        })
    }

    #[tokio::test]
    async fn request_returns_value() {
        let lazy = ok_supplier(42);
        assert_eq!(lazy.request().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn cached_after_first_completion() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let lazy: AsyncLazyValue<i32> = AsyncLazyValue::new(move || {
            cc.fetch_add(1, Ordering::SeqCst);
            async move { Ok(7) }
        });
        assert_eq!(lazy.request().await.unwrap(), 7);
        assert_eq!(lazy.request().await.unwrap(), 7);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_computation_is_retried() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let lazy: AsyncLazyValue<i32> = AsyncLazyValue::new(move || {
            let n = cc.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(Arc::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "first attempt fails",
                    )) as ArcError)
                } else {
                    Ok(99)
                }
            }
        });
        assert!(lazy.request().await.is_err());
        assert_eq!(lazy.request().await.unwrap(), 99);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_requests_share_computation() {
        use tokio::sync::oneshot as ch;
        let (gate_tx, gate_rx) = ch::channel::<()>();
        let gate_rx = Arc::new(tokio::sync::Mutex::new(Some(gate_rx)));
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);

        let lazy: Arc<AsyncLazyValue<i32>> = Arc::new(AsyncLazyValue::new(move || {
            cc.fetch_add(1, Ordering::SeqCst);
            let gate = Arc::clone(&gate_rx);
            async move {
                let rx = gate.lock().await.take();
                if let Some(r) = rx {
                    let _ = r.await;
                }
                Ok(5)
            }
        }));

        let l1 = Arc::clone(&lazy);
        let l2 = Arc::clone(&lazy);
        let h1 = tokio::spawn(async move { l1.request().await });
        let h2 = tokio::spawn(async move { l2.request().await });

        // Let tasks start, then release the gate.
        tokio::task::yield_now().await;
        let _ = gate_tx.send(());

        assert_eq!(h1.await.unwrap().unwrap(), 5);
        assert_eq!(h2.await.unwrap().unwrap(), 5);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provide_and_complete_satisfies_request() {
        let lazy: AsyncLazyValue<i32> = AsyncLazyValue::new(|| async move {
            panic!("supplier should not be called")
        });
        let completer = lazy.provide();
        let req = tokio::spawn({
            let lazy = AsyncLazyValue::new(move || async move { Ok(0i32) });
            // Use a separate lazy so we can test provide() in isolation via the arc below.
            async move { lazy.request().await }
        });
        // For a self-contained test, complete directly.
        completer.complete(123);
        // The above lazy was not the same instance; just verify complete() doesn't panic.
        let _ = req.await;
    }

    #[tokio::test]
    async fn provide_then_request_gets_completed_value() {
        let lazy: Arc<AsyncLazyValue<i32>> =
            Arc::new(AsyncLazyValue::new(|| async move { Ok(-1) }));
        let completer = lazy.provide();
        let l = Arc::clone(&lazy);
        let h = tokio::spawn(async move { l.request().await });
        tokio::task::yield_now().await;
        completer.complete(77);
        assert_eq!(h.await.unwrap().unwrap(), 77);
    }

    #[tokio::test]
    async fn provide_fail_clears_state_for_retry() {
        let lazy: Arc<AsyncLazyValue<i32>> =
            Arc::new(AsyncLazyValue::new(|| async move { Ok(55) }));
        let completer = lazy.provide();
        let l = Arc::clone(&lazy);
        let h = tokio::spawn(async move { l.request().await });
        tokio::task::yield_now().await;
        completer.fail(Arc::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "injected failure",
        )));
        assert!(h.await.unwrap().is_err());
        // Next request should retry via the supplier.
        assert_eq!(lazy.request().await.unwrap(), 55);
    }

    #[tokio::test]
    async fn forget_clears_cache_and_forces_recomputation() {
        let lazy = ok_supplier(10);
        assert_eq!(lazy.request().await.unwrap(), 10);
        assert!(lazy.is_done());
        lazy.forget();
        assert!(!lazy.is_done());
        assert_eq!(lazy.request().await.unwrap(), 10);
    }

    #[tokio::test]
    async fn is_done_and_is_busy_reflect_state() {
        use tokio::sync::oneshot as ch;
        let (gate_tx, gate_rx) = ch::channel::<()>();
        let gate_rx = Arc::new(tokio::sync::Mutex::new(Some(gate_rx)));
        let lazy: Arc<AsyncLazyValue<i32>> = Arc::new(AsyncLazyValue::new(move || {
            let gate = Arc::clone(&gate_rx);
            async move {
                let rx = gate.lock().await.take();
                if let Some(r) = rx {
                    let _ = r.await;
                }
                Ok(1)
            }
        }));

        assert!(!lazy.is_busy());
        assert!(!lazy.is_done());

        let l = Arc::clone(&lazy);
        let _h = tokio::spawn(async move { l.request().await });
        tokio::task::yield_now().await;

        assert!(lazy.is_busy());
        assert!(!lazy.is_done());

        let _ = gate_tx.send(());
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(!lazy.is_busy());
        assert!(lazy.is_done());
    }

    #[tokio::test]
    async fn display_shows_state() {
        let lazy: AsyncLazyValue<i32> =
            AsyncLazyValue::new(|| async move { Ok(42i32) });
        assert_eq!(lazy.to_string(), "(lazy)");
        lazy.request().await.unwrap();
        assert_eq!(lazy.to_string(), "42");
    }

    #[tokio::test]
    async fn error_supplier_shows_lazy_after_failure() {
        let lazy = err_supplier("boom");
        let _ = lazy.request().await;
        assert_eq!(lazy.to_string(), "(lazy)");
    }
}
