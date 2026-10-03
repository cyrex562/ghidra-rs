use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::framework::remote::{EventType, RepositoryChangeEvent};
use crate::framework::store::FileSystemListener;

/// The subset of `ghidra.framework.client.RepositoryAdapter`'s package-private surface that
/// `RepositoryChangeDispatcher` depends on.
///
/// [`RepositoryAdapter`](super::RepositoryAdapter)'s doc comment already calls out that the
/// package-private `getEvents` and `processOpenHandleCountUpdateEvent` members exist only to
/// support this dispatcher and are deliberately excluded from that trait's public surface. Rather
/// than growing that already-ported, documented trait to cover them, this dispatcher depends on
/// its own narrow seam so callers of `RepositoryAdapter` are not forced to implement
/// dispatcher-only plumbing.
pub trait RepositoryEventSource: Send + Sync {
    /// Mirrors `RepositoryAdapter.getName()`; used only to name the dispatcher thread.
    fn get_name(&self) -> String;

    /// Mirrors `RepositoryAdapter.getEvents()`. Blocks until an event occurs. The real Java
    /// method is declared to throw only `InterruptedIOException` (e.g. because the underlying
    /// repository handle was closed); any `Err` here is treated the same way -- the dispatch
    /// loop quietly stops.
    fn get_events(&self) -> io::Result<Vec<RepositoryChangeEvent>>;

    /// Mirrors `RepositoryAdapter.processOpenHandleCountUpdateEvent(RepositoryChangeEvent)`.
    fn process_open_handle_count_update_event(&self, event: &RepositoryChangeEvent);
}

/// Dispatches [`RepositoryChangeEvent`]s received from a [`RepositoryEventSource`] to a
/// registered [`FileSystemListener`] on a dedicated background thread.
///
/// Port of the package-private `ghidra.framework.client.RepositoryChangeDispatcher`, which
/// `implements Runnable` and runs a loop of `repAdapter.getEvents()` -> `processEvents(...)` on
/// a daemon thread named `"RepChangeDispatcher-" + repAdapter.getName()`.
///
/// Made `pub` (rather than crate-private) since Rust has no direct equivalent of Java's
/// package-private visibility and other already-ported siblings in this module follow the same
/// convention.
///
/// # Faithfully-reproduced quirks
///
/// The Java `thread` field is a single `volatile Thread thread` used purely as an "is some
/// thread currently the active dispatcher" flag: `run()`'s loop condition (`while (thread !=
/// null)`) reads the *instance* field on every iteration rather than comparing against
/// `Thread.currentThread()`. `stop()` sets the field to `null`; `start()` calls `stop()` and then
/// assigns a brand new `Thread` to the same field. If an old thread is still blocked inside
/// `getEvents()` when `stop()` followed by `start()` happens, that old thread will observe the
/// field flipped back to non-null by the *new* generation and resume running -- concurrently with
/// the new thread -- even though `stop()` was called on it. This is reproduced here with a single
/// `Arc<AtomicBool>` shared across every thread this dispatcher ever spawns (rather than a fresh
/// flag per generation); see `restart_reactivates_stale_blocked_thread_due_to_shared_running_flag`
/// below.
///
/// Additionally, `stop()`'s call to `thread.interrupt()` is commented in the Java source as "may
/// have no affect on pending RMI call" -- i.e. even upstream, `stop()` is not guaranteed to
/// unblock a thread parked inside a blocking `getEvents()` call. Rust has no equivalent of
/// `Thread.interrupt()` for an arbitrary blocking call, so `stop()` here only clears the shared
/// flag and forgets the join handle, which is at least as faithful as the Java behavior it is
/// modeling.
pub struct RepositoryChangeDispatcher {
    rep_adapter: Arc<dyn RepositoryEventSource>,
    listener: Arc<Mutex<Option<Box<dyn FileSystemListener + Send>>>>,
    active: Arc<AtomicBool>,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl RepositoryChangeDispatcher {
    /// Creates a new dispatcher for the given event source. Mirrors
    /// `RepositoryChangeDispatcher(RepositoryAdapter repAdapter)`.
    pub fn new(rep_adapter: Arc<dyn RepositoryEventSource>) -> Self {
        Self {
            rep_adapter,
            listener: Arc::new(Mutex::new(None)),
            active: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
        }
    }

    /// Sets (or clears, via `None`) the listener that receives dispatched file-system change
    /// notifications. Mirrors `setFileChangeListener(FileSystemListener)`.
    pub fn set_file_change_listener(&self, listener: Option<Box<dyn FileSystemListener + Send>>) {
        *self.listener.lock().unwrap() = listener;
    }

    /// Stops the dispatch thread, if one is running. Mirrors `synchronized void stop()`.
    pub fn stop(&self) {
        let mut handle = self.handle.lock().unwrap();
        if handle.is_some() {
            self.active.store(false, Ordering::SeqCst);
            *handle = None;
        }
    }

    /// (Re)starts the dispatch thread. Mirrors `synchronized void start()`, which always calls
    /// `stop()` first.
    pub fn start(&self) {
        self.stop();
        self.active.store(true, Ordering::SeqCst);

        let rep_adapter = Arc::clone(&self.rep_adapter);
        let listener = Arc::clone(&self.listener);
        let active = Arc::clone(&self.active);
        let name = rep_adapter.get_name();

        let join = thread::Builder::new()
            .name(format!("RepChangeDispatcher-{name}"))
            .spawn(move || run(rep_adapter.as_ref(), &listener, &active))
            .expect("failed to spawn RepositoryChangeDispatcher thread");

        *self.handle.lock().unwrap() = Some(join);
    }
}

/// Mirrors `RepositoryChangeDispatcher.run()`.
fn run(
    rep_adapter: &dyn RepositoryEventSource,
    listener: &Mutex<Option<Box<dyn FileSystemListener + Send>>>,
    active: &AtomicBool,
) {
    while active.load(Ordering::SeqCst) {
        match rep_adapter.get_events() {
            Ok(events) => process_events(rep_adapter, listener, active, events),
            // Mirrors `catch (InterruptedIOException e) { // ignore }`.
            Err(_) => break,
        }
    }
}

/// Mirrors `RepositoryChangeDispatcher.processEvents(RepositoryChangeEvent[])`.
fn process_events(
    rep_adapter: &dyn RepositoryEventSource,
    listener: &Mutex<Option<Box<dyn FileSystemListener + Send>>>,
    active: &AtomicBool,
    events: Vec<RepositoryChangeEvent>,
) {
    let guard = listener.lock().unwrap();
    // Mirrors `if (changeListener == null) { return; }`. Note that this early return happens
    // *before* the switch below, so REP_OPEN_HANDLE_COUNT events -- which don't even involve
    // `changeListener` -- are also silently dropped whenever no listener is registered. That is
    // the real Java behavior (see `RepositoryChangeDispatcher.java`), faithfully reproduced here
    // rather than "fixed" to route handle-count updates unconditionally.
    let Some(change_listener) = guard.as_ref() else {
        return;
    };

    for event in events {
        if !active.load(Ordering::SeqCst) {
            break;
        }
        dispatch_event(rep_adapter, change_listener.as_ref(), &event);
    }
}

fn dispatch_event(
    rep_adapter: &dyn RepositoryEventSource,
    change_listener: &dyn FileSystemListener,
    event: &RepositoryChangeEvent,
) {
    let parent_path = event.parent_path.as_deref().unwrap_or("");
    let name = event.name.as_deref().unwrap_or("");
    let new_parent_path = event.new_parent_path.as_deref().unwrap_or("");
    let new_name = event.new_name.as_deref().unwrap_or("");

    match event.event_type {
        EventType::OpenHandleCount => {
            rep_adapter.process_open_handle_count_update_event(event);
        }
        EventType::FolderCreated => change_listener.folder_created(parent_path, name),
        EventType::FolderDeleted => change_listener.folder_deleted(parent_path, name),
        EventType::FolderMoved => change_listener.folder_moved(parent_path, name, new_parent_path),
        EventType::FolderRenamed => change_listener.folder_renamed(parent_path, name, new_name),
        EventType::ItemChanged => change_listener.item_changed(parent_path, name),
        EventType::ItemCreated => change_listener.item_created(parent_path, name),
        EventType::ItemDeleted => change_listener.item_deleted(parent_path, name),
        EventType::ItemMoved => {
            change_listener.item_moved(parent_path, name, new_parent_path, new_name)
        }
        EventType::ItemRenamed => change_listener.item_renamed(parent_path, name, new_name),
        // Mirrors the Java `switch` having no `default` case: any event type not explicitly
        // listed (here, only `EventType::Null`, which never appears in a real event stream) is
        // silently ignored.
        EventType::Null => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A [`RepositoryEventSource`] driven entirely by a test-controlled channel: each call to
    /// `get_events` blocks on `recv()` for the next scripted response. Once the sender is
    /// dropped, any blocked/future call receives an `Err`, so background threads always
    /// terminate cleanly without needing an explicit "stop" signal.
    struct ScriptedEventSource {
        name: String,
        rx: Mutex<mpsc::Receiver<io::Result<Vec<RepositoryChangeEvent>>>>,
        call_count: AtomicUsize,
        handle_count_updates: Mutex<Vec<RepositoryChangeEvent>>,
    }

    impl ScriptedEventSource {
        fn new(name: &str) -> (Arc<Self>, mpsc::Sender<io::Result<Vec<RepositoryChangeEvent>>>) {
            let (tx, rx) = mpsc::channel();
            let source = Arc::new(Self {
                name: name.to_string(),
                rx: Mutex::new(rx),
                call_count: AtomicUsize::new(0),
                handle_count_updates: Mutex::new(Vec::new()),
            });
            (source, tx)
        }
    }

    impl RepositoryEventSource for ScriptedEventSource {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_events(&self) -> io::Result<Vec<RepositoryChangeEvent>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            self.rx
                .lock()
                .unwrap()
                .recv()
                .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::Other, "channel closed")))
        }

        fn process_open_handle_count_update_event(&self, event: &RepositoryChangeEvent) {
            self.handle_count_updates.lock().unwrap().push(event.clone());
        }
    }

    #[derive(Default)]
    struct RecordingListener {
        log: Mutex<Vec<String>>,
    }

    impl FileSystemListener for RecordingListener {
        fn folder_created(&self, parent_path: &str, name: &str) {
            self.log.lock().unwrap().push(format!("folder_created:{parent_path}:{name}"));
        }
        fn item_created(&self, parent_path: &str, name: &str) {
            self.log.lock().unwrap().push(format!("item_created:{parent_path}:{name}"));
        }
        fn folder_deleted(&self, parent_path: &str, folder_name: &str) {
            self.log.lock().unwrap().push(format!("folder_deleted:{parent_path}:{folder_name}"));
        }
        fn folder_moved(&self, parent_path: &str, folder_name: &str, new_parent_path: &str) {
            self.log
                .lock()
                .unwrap()
                .push(format!("folder_moved:{parent_path}:{folder_name}:{new_parent_path}"));
        }
        fn folder_renamed(&self, parent_path: &str, old_folder_name: &str, new_folder_name: &str) {
            self.log.lock().unwrap().push(format!(
                "folder_renamed:{parent_path}:{old_folder_name}:{new_folder_name}"
            ));
        }
        fn item_deleted(&self, folder_path: &str, item_name: &str) {
            self.log.lock().unwrap().push(format!("item_deleted:{folder_path}:{item_name}"));
        }
        fn item_renamed(&self, folder_path: &str, old_item_name: &str, new_item_name: &str) {
            self.log
                .lock()
                .unwrap()
                .push(format!("item_renamed:{folder_path}:{old_item_name}:{new_item_name}"));
        }
        fn item_moved(&self, parent_path: &str, name: &str, new_parent_path: &str, new_name: &str) {
            self.log
                .lock()
                .unwrap()
                .push(format!("item_moved:{parent_path}:{name}:{new_parent_path}:{new_name}"));
        }
        fn item_changed(&self, parent_path: &str, item_name: &str) {
            self.log.lock().unwrap().push(format!("item_changed:{parent_path}:{item_name}"));
        }
        fn synchronize(&self) {
            self.log.lock().unwrap().push("synchronize".to_string());
        }
    }

    /// Polls `condition` until it returns `true`, or panics after `timeout` elapses. Used instead
    /// of a fixed sleep so assertions about background-thread activity are not flaky under load,
    /// while still converging near-instantly in the common case.
    fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            if Instant::now() >= deadline {
                panic!("condition not met within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn dispatches_various_event_types_to_listener() {
        let (source, tx) = ScriptedEventSource::new("MyRepo");
        let dispatcher = RepositoryChangeDispatcher::new(source);
        let listener = Arc::new(RecordingListener::default());

        // set_file_change_listener takes ownership of the Box, so wrap a clone-able Arc inside a
        // thin forwarding adapter to keep a handle for assertions after the dispatcher owns it.
        struct Forward(Arc<RecordingListener>);
        impl FileSystemListener for Forward {
            fn folder_created(&self, p: &str, n: &str) {
                self.0.folder_created(p, n)
            }
            fn item_created(&self, p: &str, n: &str) {
                self.0.item_created(p, n)
            }
            fn folder_deleted(&self, p: &str, n: &str) {
                self.0.folder_deleted(p, n)
            }
            fn folder_moved(&self, p: &str, n: &str, np: &str) {
                self.0.folder_moved(p, n, np)
            }
            fn folder_renamed(&self, p: &str, o: &str, n: &str) {
                self.0.folder_renamed(p, o, n)
            }
            fn item_deleted(&self, p: &str, n: &str) {
                self.0.item_deleted(p, n)
            }
            fn item_renamed(&self, p: &str, o: &str, n: &str) {
                self.0.item_renamed(p, o, n)
            }
            fn item_moved(&self, p: &str, n: &str, np: &str, nn: &str) {
                self.0.item_moved(p, n, np, nn)
            }
            fn item_changed(&self, p: &str, n: &str) {
                self.0.item_changed(p, n)
            }
            fn synchronize(&self) {
                self.0.synchronize()
            }
        }

        dispatcher.set_file_change_listener(Some(Box::new(Forward(Arc::clone(&listener)))));

        let events = vec![
            RepositoryChangeEvent::new(
                EventType::FolderCreated,
                Some("/a".into()),
                Some("b".into()),
                None,
                None,
            ),
            RepositoryChangeEvent::new(
                EventType::ItemMoved,
                Some("/a/b".into()),
                Some("c.gdt".into()),
                Some("/x".into()),
                Some("c2.gdt".into()),
            ),
            RepositoryChangeEvent::new(
                EventType::ItemDeleted,
                Some("/x".into()),
                Some("c2.gdt".into()),
                None,
                None,
            ),
        ];

        tx.send(Ok(events)).unwrap();
        dispatcher.start();

        wait_until(Duration::from_secs(2), || listener.log.lock().unwrap().len() >= 3);
        drop(tx);

        let log = listener.log.lock().unwrap();
        assert_eq!(
            log.as_slice(),
            &[
                "folder_created:/a:b".to_string(),
                "item_moved:/a/b:c.gdt:/x:c2.gdt".to_string(),
                "item_deleted:/x:c2.gdt".to_string(),
            ]
        );

        dispatcher.stop();
    }

    #[test]
    fn open_handle_count_event_routes_to_rep_adapter_not_listener() {
        let (source, tx) = ScriptedEventSource::new("MyRepo");
        let dispatcher = RepositoryChangeDispatcher::new(Arc::clone(&source) as Arc<dyn RepositoryEventSource>);
        let listener = Arc::new(RecordingListener::default());

        struct Forward(Arc<RecordingListener>);
        impl FileSystemListener for Forward {
            fn folder_created(&self, p: &str, n: &str) {
                self.0.folder_created(p, n)
            }
            fn item_created(&self, p: &str, n: &str) {
                self.0.item_created(p, n)
            }
            fn folder_deleted(&self, p: &str, n: &str) {
                self.0.folder_deleted(p, n)
            }
            fn folder_moved(&self, p: &str, n: &str, np: &str) {
                self.0.folder_moved(p, n, np)
            }
            fn folder_renamed(&self, p: &str, o: &str, n: &str) {
                self.0.folder_renamed(p, o, n)
            }
            fn item_deleted(&self, p: &str, n: &str) {
                self.0.item_deleted(p, n)
            }
            fn item_renamed(&self, p: &str, o: &str, n: &str) {
                self.0.item_renamed(p, o, n)
            }
            fn item_moved(&self, p: &str, n: &str, np: &str, nn: &str) {
                self.0.item_moved(p, n, np, nn)
            }
            fn item_changed(&self, p: &str, n: &str) {
                self.0.item_changed(p, n)
            }
            fn synchronize(&self) {
                self.0.synchronize()
            }
        }
        dispatcher.set_file_change_listener(Some(Box::new(Forward(Arc::clone(&listener)))));

        let event = RepositoryChangeEvent::new(
            EventType::OpenHandleCount,
            None,
            Some("42".into()),
            None,
            None,
        );
        tx.send(Ok(vec![event.clone()])).unwrap();
        dispatcher.start();

        wait_until(Duration::from_secs(2), || {
            !source.handle_count_updates.lock().unwrap().is_empty()
        });
        drop(tx);

        assert_eq!(source.handle_count_updates.lock().unwrap().as_slice(), &[event]);
        assert!(listener.log.lock().unwrap().is_empty());

        dispatcher.stop();
    }

    /// Mirrors the real Java behavior of `processEvents`: the `changeListener == null` check
    /// happens *before* the switch that would otherwise route `REP_OPEN_HANDLE_COUNT` events to
    /// `repAdapter.processOpenHandleCountUpdateEvent`. So with no listener registered at all,
    /// even handle-count events (which don't touch the listener) are dropped on the floor.
    #[test]
    fn missing_listener_drops_open_handle_count_event_too() {
        let (source, tx) = ScriptedEventSource::new("MyRepo");
        let dispatcher = RepositoryChangeDispatcher::new(Arc::clone(&source) as Arc<dyn RepositoryEventSource>);
        // Deliberately never call set_file_change_listener.

        let event = RepositoryChangeEvent::new(
            EventType::OpenHandleCount,
            None,
            Some("7".into()),
            None,
            None,
        );
        tx.send(Ok(vec![event])).unwrap();
        // A second batch that would be observable if the first were (incorrectly) processed.
        tx.send(Ok(vec![RepositoryChangeEvent::new(
            EventType::OpenHandleCount,
            None,
            Some("8".into()),
            None,
            None,
        )]))
        .unwrap();
        dispatcher.start();

        // Give the dispatch thread ample opportunity to have drained both batches.
        wait_until(Duration::from_secs(1), || source.call_count.load(Ordering::SeqCst) >= 3);
        drop(tx);

        assert!(source.handle_count_updates.lock().unwrap().is_empty());

        dispatcher.stop();
    }

    #[test]
    fn stop_before_start_is_noop() {
        let (source, _tx) = ScriptedEventSource::new("MyRepo");
        let dispatcher = RepositoryChangeDispatcher::new(source);
        // Must not panic even though start() was never called.
        dispatcher.stop();
        dispatcher.stop();
    }

    #[test]
    fn get_events_error_ends_dispatch_loop_without_processing_further() {
        let (source, tx) = ScriptedEventSource::new("MyRepo");
        let dispatcher = RepositoryChangeDispatcher::new(Arc::clone(&source) as Arc<dyn RepositoryEventSource>);
        dispatcher.set_file_change_listener(Some(Box::new(RecordingListener::default())));

        tx.send(Err(io::Error::new(io::ErrorKind::Interrupted, "closed"))).unwrap();
        dispatcher.start();

        wait_until(Duration::from_secs(2), || source.call_count.load(Ordering::SeqCst) >= 1);
        // The thread should have exited after the single Err and made no further get_events
        // calls; give it a brief window to (incorrectly) call again before asserting it didn't.
        thread::sleep(Duration::from_millis(50));
        assert_eq!(source.call_count.load(Ordering::SeqCst), 1);

        dispatcher.stop();
    }

    /// Faithfully reproduces the real Java quirk described in this module's doc comment: the
    /// dispatch thread's "should I keep running" flag is a single field shared by every thread
    /// generation, not a fresh flag minted per `start()` call. If `stop()` is called while a
    /// thread is still blocked inside `get_events()`, and `start()` is called again before that
    /// blocked call returns, the stale thread will see the flag flipped back to "running" by the
    /// *new* generation and resume dispatching -- even though it was told to stop.
    #[test]
    fn restart_reactivates_stale_blocked_thread_due_to_shared_running_flag() {
        let (source, tx) = ScriptedEventSource::new("MyRepo");
        let dispatcher = RepositoryChangeDispatcher::new(Arc::clone(&source) as Arc<dyn RepositoryEventSource>);
        let listener = Arc::new(RecordingListener::default());

        struct Forward(Arc<RecordingListener>);
        impl FileSystemListener for Forward {
            fn folder_created(&self, p: &str, n: &str) {
                self.0.folder_created(p, n)
            }
            fn item_created(&self, p: &str, n: &str) {
                self.0.item_created(p, n)
            }
            fn folder_deleted(&self, p: &str, n: &str) {
                self.0.folder_deleted(p, n)
            }
            fn folder_moved(&self, p: &str, n: &str, np: &str) {
                self.0.folder_moved(p, n, np)
            }
            fn folder_renamed(&self, p: &str, o: &str, n: &str) {
                self.0.folder_renamed(p, o, n)
            }
            fn item_deleted(&self, p: &str, n: &str) {
                self.0.item_deleted(p, n)
            }
            fn item_renamed(&self, p: &str, o: &str, n: &str) {
                self.0.item_renamed(p, o, n)
            }
            fn item_moved(&self, p: &str, n: &str, np: &str, nn: &str) {
                self.0.item_moved(p, n, np, nn)
            }
            fn item_changed(&self, p: &str, n: &str) {
                self.0.item_changed(p, n)
            }
            fn synchronize(&self) {
                self.0.synchronize()
            }
        }
        dispatcher.set_file_change_listener(Some(Box::new(Forward(Arc::clone(&listener)))));

        // Step 1: start() spawns the "old" thread, which immediately calls get_events() and
        // blocks on the (empty) channel.
        dispatcher.start();
        wait_until(Duration::from_secs(2), || source.call_count.load(Ordering::SeqCst) >= 1);

        // Step 2: stop() while the old thread is still blocked inside get_events(). This can't
        // actually unblock it (mirrors the Java `thread.interrupt()` call's documented "may have
        // no affect on pending RMI call").
        dispatcher.stop();

        // Step 3: start() again *before* the old thread's blocked call returns. This flips the
        // *shared* running flag back to true and spawns a new "current" thread.
        dispatcher.start();

        // Step 4: only now let the old thread's blocked get_events() call return. Per the real
        // Java `while (thread != null)` check reading the shared instance field, the old thread
        // observes "running" again and dispatches this event -- despite stop() having been called
        // on it in between.
        tx.send(Ok(vec![RepositoryChangeEvent::new(
            EventType::FolderCreated,
            Some("/a".into()),
            Some("b".into()),
            None,
            None,
        )]))
        .unwrap();

        wait_until(Duration::from_secs(2), || !listener.log.lock().unwrap().is_empty());
        assert_eq!(listener.log.lock().unwrap().as_slice(), &["folder_created:/a:b".to_string()]);

        // Both the reactivated old thread and the new thread now loop back around and call
        // get_events() again, proving more than one thread is concurrently alive and driven by
        // the same shared flag.
        wait_until(Duration::from_secs(2), || source.call_count.load(Ordering::SeqCst) >= 3);

        drop(tx);
        dispatcher.stop();
    }
}
