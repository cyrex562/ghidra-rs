use std::error::Error;
use std::sync::Arc;

use tokio::sync::oneshot;

use super::async_lazy_value::ArcError;

/// A unit of work that can be handed to an [`AsyncUtils`] executor, analogous to Java's
/// `java.util.concurrent.Executor`.
pub trait AsyncExecutor: Send + Sync {
    /// Runs `command` according to this executor's dispatch policy.
    fn execute(&self, command: Box<dyn FnOnce() + Send>);
}

/// Runs commands synchronously on the calling thread, analogous to
/// `AsyncUtils.DIRECT_EXECUTOR`.
pub struct DirectExecutor;

impl AsyncExecutor for DirectExecutor {
    fn execute(&self, command: Box<dyn FnOnce() + Send>) {
        command();
    }
}

/// Runs commands on the Tokio work-stealing thread pool, analogous to
/// `AsyncUtils.FRAMEWORK_EXECUTOR` (`Executors.newWorkStealingPool()`).
///
/// Requires a running Tokio runtime, matching the executor's original role as the framework's
/// background async work pool.
pub struct FrameworkExecutor;

impl AsyncExecutor for FrameworkExecutor {
    fn execute(&self, command: Box<dyn FnOnce() + Send>) {
        tokio::spawn(async move { command() });
    }
}

/// A wrapper that carries only another error as its cause, with no information of its own.
///
/// Rust analogue of Java's `CompletionException`/`ExecutionException`, which
/// [`AsyncUtils::unwrap_throwable`] peels away to find the real cause.
#[derive(Debug)]
pub struct WrappedError(Box<dyn Error + Send + Sync>);

impl WrappedError {
    /// Wraps `cause`, mirroring `new CompletionException(cause)` / `new ExecutionException(cause)`.
    pub fn new(cause: Box<dyn Error + Send + Sync>) -> Self {
        WrappedError(cause)
    }

    fn into_cause(self) -> Box<dyn Error + Send + Sync> {
        self.0
    }
}

impl std::fmt::Display for WrappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wrapped: {}", self.0)
    }
}

impl Error for WrappedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Some conveniences when dealing with Rust's async futures/tasks.
///
/// Port of `ghidra.async.AsyncUtils`. The Java interface is a namespace of static constants and
/// helper methods (never itself implemented polymorphically); it was pulled out as a trait here
/// to cut a dependency cycle -- callers depend on `Arc<dyn AsyncUtils>` / `&dyn AsyncUtils`
/// rather than a single concrete provider, so this type and its dependents can be ported and
/// tested independently of each other.
///
/// `CLEANER` (`java.lang.ref.Cleaner`) has no port here: Rust's `Drop` trait is the idiomatic
/// replacement and nothing in the crate yet needs GC-style finalization callbacks.
///
/// `nil()`, `copy_to`, and `unwrap_throwable`'s `TemperamentalRunnable`/`TemperamentalSupplier`
/// siblings are generic and so cannot be object-safe trait methods; `nil()` and `copy_to` are
/// free functions in this module instead (mirroring [`super::data_converter::swap_bytes`]
/// alongside [`super::data_converter::DataConverter`]).
pub trait AsyncUtils: Send + Sync {
    /// The shared executor for background async work, analogous to
    /// `AsyncUtils.FRAMEWORK_EXECUTOR`.
    fn framework_executor(&self) -> Arc<dyn AsyncExecutor> {
        Arc::new(FrameworkExecutor)
    }

    /// The executor that dispatches onto the UI thread, analogous to
    /// `AsyncUtils.SWING_EXECUTOR` (`SwingExecutorService.LATER`).
    ///
    /// `SwingExecutorService` (see [`crate::util::seam_stubs::SwingExecutorServiceLike`]) is not
    /// yet ported and there is no UI-thread runtime concept in the crate yet, so the default
    /// here runs synchronously like [`Self::direct_executor`]; a real implementation should
    /// dispatch onto the UI event loop instead.
    fn swing_executor(&self) -> Arc<dyn AsyncExecutor> {
        Arc::new(DirectExecutor)
    }

    /// The executor that runs its command synchronously on the calling thread, analogous to
    /// `AsyncUtils.DIRECT_EXECUTOR`.
    fn direct_executor(&self) -> Arc<dyn AsyncExecutor> {
        Arc::new(DirectExecutor)
    }

    /// Unwraps [`WrappedError`] chains to get the real cause, analogous to
    /// `AsyncUtils.unwrapThrowable`.
    fn unwrap_throwable(&self, e: Box<dyn Error + Send + Sync>) -> Box<dyn Error + Send + Sync> {
        let mut cur = e;
        loop {
            match cur.downcast::<WrappedError>() {
                Ok(wrapped) => cur = wrapped.into_cause(),
                Err(orig) => return orig,
            }
        }
    }
}

/// Default [`AsyncUtils`] provider: framework work runs on Tokio, the UI and direct executors
/// both run synchronously (see [`AsyncUtils::swing_executor`]).
pub struct DefaultAsyncUtils;

impl AsyncUtils for DefaultAsyncUtils {}

/// Returns an already-completed unit future, analogous to `AsyncUtils.nil()`.
///
/// Java's version returns a `CompletableFuture<T>` completed with `null`; Rust has no
/// universal null, so this completes with `()`, matching every real call site, which only
/// ever depends on the returned future's completion, never a (null) value it carries.
pub fn nil() -> impl std::future::Future<Output = ()> + Send {
    std::future::ready(())
}

/// Builds a handler that copies a result into `dest`, analogous to
/// `AsyncUtils.copyTo(CompletableFuture<T>)` for use with `.handle(...)`-style callbacks:
///
/// ```rust,no_run
/// # use ghidra_rs::util::async_utils::copy_to;
/// # use tokio::sync::oneshot;
/// # async fn example<T: Clone + Send + 'static>(source: Result<T, ghidra_rs::util::ArcError>) {
/// let (tx, _rx) = oneshot::channel();
/// let copied = copy_to(tx)(source);
/// # }
/// ```
///
/// `dest` completes identically to the handled result, which is returned unchanged so the
/// caller's own future still behaves as if `copy_to` were never inserted.
pub fn copy_to<T: Clone>(
    dest: oneshot::Sender<Result<T, ArcError>>,
) -> impl FnOnce(Result<T, ArcError>) -> Result<T, ArcError> {
    move |result| {
        let _ = dest.send(result.clone());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Mock `AsyncUtils` overriding `framework_executor`, proving the trait is object-safe and
    /// that overriding a default method actually changes dispatched behavior.
    struct CountingAsyncUtils {
        count: Arc<AtomicUsize>,
    }

    struct CountingExecutor {
        count: Arc<AtomicUsize>,
    }

    impl AsyncExecutor for CountingExecutor {
        fn execute(&self, command: Box<dyn FnOnce() + Send>) {
            self.count.fetch_add(1, Ordering::SeqCst);
            command();
        }
    }

    impl AsyncUtils for CountingAsyncUtils {
        fn framework_executor(&self) -> Arc<dyn AsyncExecutor> {
            Arc::new(CountingExecutor {
                count: Arc::clone(&self.count),
            })
        }
    }

    #[test]
    fn direct_executor_runs_inline() {
        let utils: Box<dyn AsyncUtils> = Box::new(DefaultAsyncUtils);
        let ran = Arc::new(Mutex::new(false));
        let ran2 = Arc::clone(&ran);
        utils
            .direct_executor()
            .execute(Box::new(move || *ran2.lock().unwrap() = true));
        assert!(*ran.lock().unwrap());
    }

    #[test]
    fn overridden_framework_executor_is_dispatched_through_trait_object() {
        let count = Arc::new(AtomicUsize::new(0));
        let utils: Box<dyn AsyncUtils> = Box::new(CountingAsyncUtils {
            count: Arc::clone(&count),
        });
        let sum = Arc::new(Mutex::new(0));
        let sum2 = Arc::clone(&sum);
        utils
            .framework_executor()
            .execute(Box::new(move || *sum2.lock().unwrap() += 41));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(*sum.lock().unwrap(), 41);
    }

    #[test]
    fn unwrap_throwable_peels_nested_wrappers() {
        let utils = DefaultAsyncUtils;
        let root: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, "root cause"));
        let wrapped: Box<dyn Error + Send + Sync> = Box::new(WrappedError::new(Box::new(
            WrappedError::new(root),
        )));
        let unwrapped = utils.unwrap_throwable(wrapped);
        assert_eq!(unwrapped.to_string(), "root cause");
    }

    #[test]
    fn unwrap_throwable_passes_through_unwrapped_errors() {
        let utils = DefaultAsyncUtils;
        let plain: Box<dyn Error + Send + Sync> =
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, "plain"));
        let unwrapped = utils.unwrap_throwable(plain);
        assert_eq!(unwrapped.to_string(), "plain");
    }

    #[tokio::test]
    async fn nil_completes_immediately() {
        nil().await;
    }

    #[tokio::test]
    async fn copy_to_forwards_success_and_completes_dest() {
        let (tx, rx) = oneshot::channel::<Result<i32, ArcError>>();
        let handler = copy_to(tx);
        let result = handler(Ok(7));
        assert_eq!(result.unwrap(), 7);
        assert_eq!(rx.await.unwrap().unwrap(), 7);
    }

    #[tokio::test]
    async fn copy_to_forwards_failure_and_completes_dest_exceptionally() {
        let (tx, rx) = oneshot::channel::<Result<i32, ArcError>>();
        let handler = copy_to(tx);
        let err: ArcError = Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
        let result = handler(Err(err));
        assert!(result.is_err());
        let dest_result = rx.await.unwrap();
        assert!(dest_result.is_err());
        assert_eq!(dest_result.unwrap_err().to_string(), "boom");
    }
}
