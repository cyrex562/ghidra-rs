use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// Handles errors that occur when a queued listener invocation panics.
///
/// Port of `ghidra.util.datastruct.ListenerErrorHandler`.
pub trait ListenerErrorHandler: Send + 'static {
    /// Called when a listener invocation panics.
    ///
    /// `payload` is the panic value captured by [`std::panic::catch_unwind`].
    fn handle_error(&self, payload: Box<dyn Any + Send>);
}

/// Default error handler: logs the panic message via `tracing::error!`.
///
/// Equivalent to the anonymous `DefaultListenerErrorHandler` created by
/// `DataStructureErrorHandlerFactory.createListenerErrorHandler()`.
pub struct DefaultListenerErrorHandler;

impl ListenerErrorHandler for DefaultListenerErrorHandler {
    fn handle_error(&self, payload: Box<dyn Any + Send>) {
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_owned()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "(unknown panic payload)".to_owned()
        };
        tracing::error!("Listener caused unexpected exception: {}", msg);
    }
}

type Task<L> = Box<dyn FnOnce(&mut L) + Send>;

/// A listener wrapper that queues invocations onto a dedicated background thread.
///
/// Port of `ghidra.util.datastruct.PrivatelyQueuedListener<P>`.
///
/// In Java, this class used a dynamic proxy (`java.lang.reflect.Proxy`) to intercept
/// arbitrary method calls on the listener interface `P` and dispatch them to the
/// wrapped listener on a private executor thread. Rust does not support dynamic proxies;
/// callers instead submit closures via [`queue`][Self::queue] that are applied to the
/// wrapped listener on the background thread.
///
/// All listener methods are assumed to return `()` (void), matching Java's constraint
/// that only void-return listener methods make sense with the async queue.
///
/// The background thread runs until this struct is dropped, which closes the channel
/// and allows the thread to drain queued tasks before exiting.
pub struct PrivatelyQueuedListener<L: Send + 'static> {
    sender: mpsc::Sender<Task<L>>,
    error_handler: Arc<Mutex<Box<dyn ListenerErrorHandler>>>,
}

impl<L: Send + 'static> PrivatelyQueuedListener<L> {
    /// Creates a new `PrivatelyQueuedListener` backed by a single named background thread
    /// with the default error handler.
    ///
    /// Port of `PrivatelyQueuedListener(Class<P>, String threadNamePattern, P out)`.
    pub fn new(thread_name: impl Into<String>, listener: L) -> Self {
        Self::with_error_handler(thread_name, listener, DefaultListenerErrorHandler)
    }

    /// Creates a new `PrivatelyQueuedListener` with a custom error handler.
    ///
    /// Port of `PrivatelyQueuedListener(Class<P>, Executor, P out)` combined with
    /// explicit error handler injection (the executor is always a single named thread
    /// in this port).
    pub fn with_error_handler<H: ListenerErrorHandler>(
        thread_name: impl Into<String>,
        listener: L,
        error_handler: H,
    ) -> Self {
        let handler: Arc<Mutex<Box<dyn ListenerErrorHandler>>> =
            Arc::new(Mutex::new(Box::new(error_handler)));
        let handler_thread = Arc::clone(&handler);
        let (sender, receiver) = mpsc::channel::<Task<L>>();
        thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                let mut out = listener;
                while let Ok(task) = receiver.recv() {
                    if let Err(payload) =
                        panic::catch_unwind(AssertUnwindSafe(|| task(&mut out)))
                    {
                        handler_thread.lock().unwrap().handle_error(payload);
                    }
                }
            })
            .expect("failed to spawn listener thread");
        Self { sender, error_handler: handler }
    }

    /// Replaces the error handler used for subsequent listener invocations.
    ///
    /// Port of `PrivatelyQueuedListener.setErrorHandler`.
    pub fn set_error_handler<H: ListenerErrorHandler>(&self, handler: H) {
        *self.error_handler.lock().unwrap() = Box::new(handler);
    }

    /// Queues a closure to be called on the wrapped listener on the background thread.
    ///
    /// If the background thread has already exited, the call is silently dropped.
    /// All methods invoked through this mechanism must return `()`.
    pub fn queue<F: FnOnce(&mut L) + Send + 'static>(&self, f: F) {
        let _ = self.sender.send(Box::new(f));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, mpsc};

    /// Sends a no-op task and waits for it to complete, ensuring all prior tasks
    /// have been processed by the background thread.
    fn fence<L: Send + 'static>(pql: &PrivatelyQueuedListener<L>) {
        let (tx, rx) = mpsc::sync_channel::<()>(0);
        pql.queue(move |_| tx.send(()).unwrap());
        rx.recv().unwrap();
    }

    struct SharedCounter {
        value: Arc<Mutex<i32>>,
    }

    impl SharedCounter {
        fn new() -> (Self, Arc<Mutex<i32>>) {
            let v = Arc::new(Mutex::new(0));
            (Self { value: Arc::clone(&v) }, v)
        }
        fn increment(&mut self) {
            *self.value.lock().unwrap() += 1;
        }
        fn add(&mut self, n: i32) {
            *self.value.lock().unwrap() += n;
        }
    }

    #[test]
    fn test_queue_invokes_listener() {
        let (listener, value) = SharedCounter::new();
        let pql = PrivatelyQueuedListener::new("test-invoke", listener);
        pql.queue(|l| l.increment());
        pql.queue(|l| l.increment());
        pql.queue(|l| l.add(10));
        fence(&pql);
        assert_eq!(*value.lock().unwrap(), 12);
    }

    #[test]
    fn test_queue_preserves_order() {
        let log: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        struct Recorder {
            log: Arc<Mutex<Vec<i32>>>,
        }
        impl Recorder {
            fn record(&mut self, n: i32) {
                self.log.lock().unwrap().push(n);
            }
        }
        let log_clone = Arc::clone(&log);
        let pql = PrivatelyQueuedListener::new("test-order", Recorder { log: log_clone });
        for i in 0..5i32 {
            pql.queue(move |l| l.record(i));
        }
        fence(&pql);
        assert_eq!(*log.lock().unwrap(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_panic_calls_error_handler() {
        struct PanicListener;
        let caught: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let caught_clone = Arc::clone(&caught);

        struct TrackingHandler {
            flag: Arc<Mutex<bool>>,
        }
        impl ListenerErrorHandler for TrackingHandler {
            fn handle_error(&self, _payload: Box<dyn Any + Send>) {
                *self.flag.lock().unwrap() = true;
            }
        }

        let pql = PrivatelyQueuedListener::with_error_handler(
            "test-panic",
            PanicListener,
            TrackingHandler { flag: caught_clone },
        );
        pql.queue(|_| panic!("intentional panic"));
        fence(&pql);
        assert!(*caught.lock().unwrap(), "error handler should have been called on panic");
    }

    #[test]
    fn test_thread_continues_after_panic() {
        let (listener, value) = SharedCounter::new();
        let pql = PrivatelyQueuedListener::new("test-continue", listener);
        pql.queue(|_| panic!("should not stop the thread"));
        pql.queue(|l| l.add(99));
        fence(&pql);
        assert_eq!(*value.lock().unwrap(), 99, "thread should keep running after a panic");
    }

    #[test]
    fn test_set_error_handler_replaces_handler() {
        struct PanicListener;
        let second_called: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let second_clone = Arc::clone(&second_called);

        struct FirstHandler;
        impl ListenerErrorHandler for FirstHandler {
            fn handle_error(&self, _payload: Box<dyn Any + Send>) {}
        }

        struct SecondHandler {
            flag: Arc<Mutex<bool>>,
        }
        impl ListenerErrorHandler for SecondHandler {
            fn handle_error(&self, _payload: Box<dyn Any + Send>) {
                *self.flag.lock().unwrap() = true;
            }
        }

        let pql = PrivatelyQueuedListener::with_error_handler(
            "test-set-handler",
            PanicListener,
            FirstHandler,
        );
        pql.set_error_handler(SecondHandler { flag: second_clone });
        pql.queue(|_| panic!("after set_error_handler"));
        fence(&pql);
        assert!(*second_called.lock().unwrap(), "second handler should have been called");
    }

    #[test]
    fn test_drop_closes_channel_gracefully() {
        let (listener, value) = SharedCounter::new();
        let pql = PrivatelyQueuedListener::new("test-drop", listener);
        pql.queue(|l| l.add(7));
        fence(&pql);
        drop(pql);
        assert_eq!(*value.lock().unwrap(), 7);
    }
}
