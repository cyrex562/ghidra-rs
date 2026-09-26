//! Port of `ghidra.framework.store.FileSystemEventManager`.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::framework::store::FileSystemListener;

const STOPPED: u8 = 0;
const RUNNING: u8 = 1;
const DISPOSED: u8 = 2;

/// A listener handle stored by [`FileSystemEventManager`]. Java's `List<FileSystemListener>`
/// stores plain object references and removes by `equals()` (identity, by default); `Arc`'s
/// pointer identity plays the same role here via [`Arc::ptr_eq`] in
/// [`FileSystemEventManager::remove`].
pub type ListenerHandle = Arc<dyn FileSystemListener + Send + Sync>;

/// One buffered notification, corresponding to one of the private `FileSystemEvent` subclasses in
/// the Java source.
enum Event {
    ItemMoved { parent_path: String, name: String, new_parent_path: String, new_name: String },
    ItemRenamed { parent_path: String, item_name: String, new_name: String },
    ItemDeleted { parent_path: String, item_name: String },
    FolderRenamed { parent_path: String, folder_name: String, new_folder_name: String },
    FolderMoved { parent_path: String, folder_name: String, new_parent_path: String },
    FolderDeleted { parent_path: String, folder_name: String },
    ItemCreated { parent_path: String, item_name: String },
    FolderCreated { parent_path: String, folder_name: String },
    ItemChanged { parent_path: String, item_name: String },
    Synchronize,
    /// Stands in for the private `MarkerEvent`, used by [`FileSystemEventManager::flush_events`]
    /// to detect when all previously queued events have been processed. Mirrors its
    /// `CountDownLatch`-based `waitForEvent`/`dispatch` via a `Condvar` pair instead; like the
    /// Java version, [`Event::dispatch`] is never called for this variant (see
    /// [`Event::process`]).
    Marker(Arc<(Mutex<bool>, Condvar)>),
}

impl Event {
    fn dispatch(&self, listener: &(dyn FileSystemListener + Send + Sync)) {
        match self {
            Event::ItemMoved { parent_path, name, new_parent_path, new_name } => {
                listener.item_moved(parent_path, name, new_parent_path, new_name)
            }
            Event::ItemRenamed { parent_path, item_name, new_name } => {
                listener.item_renamed(parent_path, item_name, new_name)
            }
            Event::ItemDeleted { parent_path, item_name } => listener.item_deleted(parent_path, item_name),
            Event::FolderRenamed { parent_path, folder_name, new_folder_name } => {
                listener.folder_renamed(parent_path, folder_name, new_folder_name)
            }
            Event::FolderMoved { parent_path, folder_name, new_parent_path } => {
                listener.folder_moved(parent_path, folder_name, new_parent_path)
            }
            Event::FolderDeleted { parent_path, folder_name } => {
                listener.folder_deleted(parent_path, folder_name)
            }
            Event::ItemCreated { parent_path, item_name } => listener.item_created(parent_path, item_name),
            Event::FolderCreated { parent_path, folder_name } => {
                listener.folder_created(parent_path, folder_name)
            }
            Event::ItemChanged { parent_path, item_name } => listener.item_changed(parent_path, item_name),
            Event::Synchronize => listener.synchronize(),
            Event::Marker(_) => {
                // Mirrors `MarkerEvent.dispatch`: intentionally does nothing.
            }
        }
    }

    /// Mirrors `FileSystemEvent.process`/`MarkerEvent.process`.
    fn process(&self, listeners: &[ListenerHandle]) {
        if let Event::Marker(pair) = self {
            let (lock, cvar) = &**pair;
            let mut done = lock.lock().unwrap();
            *done = true;
            cvar.notify_all();
            return;
        }
        for listener in listeners {
            self.dispatch(listener.as_ref());
        }
    }
}

/// Maintains a list of [`FileSystemListener`]s. This type, acting as a `FileSystemListener`
/// itself, simply relays each callback to all listeners within its list. Employs either a
/// synchronous or asynchronous notification mechanism. Once disposed, event dispatching will
/// discontinue.
///
/// Mirrors `ghidra.framework.store.FileSystemEventManager`. Java's `LinkedBlockingQueue` +
/// dedicated daemon `Thread` + `Thread.interrupt()`/`queue.clear()` disposal sequence is
/// represented here with an `std::sync::mpsc` channel and an `AtomicU8` thread-state flag: the
/// background thread checks the state flag both before and after receiving each event, so events
/// received after [`dispose`](Self::dispose) has run are discarded rather than dispatched --
/// achieving the same observable "queued-but-undelivered events are discarded" behavior as Java's
/// `eventQueue.clear()`, via a different mechanism appropriate for a channel-based queue. Java's
/// per-object `synchronized` locking is represented with per-field `Mutex`/`AtomicU8` guards
/// rather than a single re-entrant lock; the class's public methods do not call each other in a
/// way that would require re-entrancy, so this is behaviorally equivalent for this type.
pub struct FileSystemEventManager {
    listeners: Arc<Mutex<Vec<ListenerHandle>>>,
    sender: Mutex<Option<Sender<Event>>>,
    state: Arc<AtomicU8>,
    thread: Mutex<Option<JoinHandle<()>>>,
    async_dispatch_enabled: bool,
}

impl FileSystemEventManager {
    /// Constructor.
    ///
    /// `enable_asynchronous_dispatching`: if true a separate dispatch thread will be used to
    /// notify listeners. If false, blocking notification will be performed. Events are
    /// immediately discarded in the absence of any listener(s).
    pub fn new(enable_asynchronous_dispatching: bool) -> Self {
        Self {
            listeners: Arc::new(Mutex::new(Vec::new())),
            sender: Mutex::new(None),
            state: Arc::new(AtomicU8::new(STOPPED)),
            thread: Mutex::new(None),
            async_dispatch_enabled: enable_asynchronous_dispatching,
        }
    }

    /// Return true if asynchronous event processing is enabled.
    pub fn is_asynchronous(&self) -> bool {
        self.async_dispatch_enabled
    }

    /// Discontinue event dispatching and terminate the dispatch thread if it exists.
    pub fn dispose(&self) {
        self.state.store(DISPOSED, Ordering::SeqCst);
        if self.async_dispatch_enabled {
            // Dropping the sender causes the background thread's `recv()` to eventually return
            // `Err` once any buffered events are drained; those drained events are discarded
            // rather than dispatched because `run` re-checks `state` before processing each one.
            *self.sender.lock().unwrap() = None;
        }
    }

    fn start_dispatch_thread(&self) {
        if !self.async_dispatch_enabled {
            return;
        }
        let mut sender_guard = self.sender.lock().unwrap();
        // Only starts when the first listener is added.
        if self.state.load(Ordering::SeqCst) == STOPPED {
            let (tx, rx) = mpsc::channel::<Event>();
            self.state.store(RUNNING, Ordering::SeqCst);
            let listeners = self.listeners.clone();
            let state = self.state.clone();
            let handle = thread::Builder::new()
                .name("File System Listener".to_string())
                .spawn(move || {
                    while let Ok(event) = rx.recv() {
                        if state.load(Ordering::SeqCst) != RUNNING {
                            break;
                        }
                        let snapshot = listeners.lock().unwrap().clone();
                        event.process(&snapshot);
                    }
                })
                .expect("failed to spawn File System Listener thread");
            *sender_guard = Some(tx);
            *self.thread.lock().unwrap() = Some(handle);
        }
    }

    /// Add a listener to this list.
    pub fn add(&self, listener: ListenerHandle) {
        self.start_dispatch_thread(); // if async_dispatch_enabled
        self.listeners.lock().unwrap().push(listener);
    }

    /// Remove a listener from this list, by pointer identity (mirrors Java's default,
    /// identity-based `equals()`).
    pub fn remove(&self, listener: &ListenerHandle) {
        self.listeners
            .lock()
            .unwrap()
            .retain(|l| !Arc::ptr_eq(l, listener));
    }

    /// Queue the specified event if the listener thread is running. Returns true if queued, else
    /// false if the listener thread is not running.
    fn queue_event(&self, ev: Event) -> bool {
        if self.state.load(Ordering::SeqCst) == RUNNING {
            if let Some(sender) = self.sender.lock().unwrap().as_ref() {
                return sender.send(ev).is_ok();
            }
        }
        false
    }

    fn handle_event(&self, e: Event) {
        if self.state.load(Ordering::SeqCst) == DISPOSED {
            return;
        }
        if self.async_dispatch_enabled {
            // If there are no listeners the event will be discarded (i.e. listener thread not
            // running).
            self.queue_event(e);
        } else {
            // Process in a synchronous fashion in the current thread.
            let snapshot = self.listeners.lock().unwrap().clone();
            e.process(&snapshot);
        }
    }

    /// Blocks until all currently queued events have been processed.
    ///
    /// Note: callers should only use this method when [`is_asynchronous`](Self::is_asynchronous)
    /// returns true, since this type cannot track when non-threaded events have finished
    /// broadcasting to listeners.
    ///
    /// Returns true if the events were processed within `timeout`; false if a timeout occurred.
    pub fn flush_events(&self, timeout: Duration) -> bool {
        if !self.async_dispatch_enabled {
            return true; // each thread processes its own event
        }

        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        if !self.queue_event(Event::Marker(pair.clone())) {
            // Events are not queuing since there are no listeners or dispose has occurred.
            return true;
        }

        let (lock, cvar) = &*pair;
        let guard = lock.lock().unwrap();
        let (_guard, wait_result) = cvar.wait_timeout_while(guard, timeout, |done| !*done).unwrap();
        !wait_result.timed_out()
    }
}

impl FileSystemListener for FileSystemEventManager {
    fn folder_created(&self, parent_path: &str, name: &str) {
        self.handle_event(Event::FolderCreated {
            parent_path: parent_path.to_string(),
            folder_name: name.to_string(),
        });
    }

    fn item_created(&self, parent_path: &str, name: &str) {
        self.handle_event(Event::ItemCreated {
            parent_path: parent_path.to_string(),
            item_name: name.to_string(),
        });
    }

    fn folder_deleted(&self, parent_path: &str, folder_name: &str) {
        self.handle_event(Event::FolderDeleted {
            parent_path: parent_path.to_string(),
            folder_name: folder_name.to_string(),
        });
    }

    fn folder_moved(&self, parent_path: &str, folder_name: &str, new_parent_path: &str) {
        self.handle_event(Event::FolderMoved {
            parent_path: parent_path.to_string(),
            folder_name: folder_name.to_string(),
            new_parent_path: new_parent_path.to_string(),
        });
    }

    fn folder_renamed(&self, parent_path: &str, old_folder_name: &str, new_folder_name: &str) {
        self.handle_event(Event::FolderRenamed {
            parent_path: parent_path.to_string(),
            folder_name: old_folder_name.to_string(),
            new_folder_name: new_folder_name.to_string(),
        });
    }

    fn item_deleted(&self, folder_path: &str, item_name: &str) {
        self.handle_event(Event::ItemDeleted {
            parent_path: folder_path.to_string(),
            item_name: item_name.to_string(),
        });
    }

    fn item_renamed(&self, folder_path: &str, old_item_name: &str, new_item_name: &str) {
        self.handle_event(Event::ItemRenamed {
            parent_path: folder_path.to_string(),
            item_name: old_item_name.to_string(),
            new_name: new_item_name.to_string(),
        });
    }

    fn item_moved(&self, parent_path: &str, name: &str, new_parent_path: &str, new_name: &str) {
        self.handle_event(Event::ItemMoved {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
            new_parent_path: new_parent_path.to_string(),
            new_name: new_name.to_string(),
        });
    }

    fn item_changed(&self, parent_path: &str, item_name: &str) {
        self.handle_event(Event::ItemChanged {
            parent_path: parent_path.to_string(),
            item_name: item_name.to_string(),
        });
    }

    /// Note: synchronize calls will only work when using a threaded event queue. Unlike every
    /// other `FileSystemListener` method here, this deliberately bypasses
    /// [`handle_event`](Self::handle_event) entirely: in synchronous mode (`async_dispatch_enabled
    /// == false`), a `synchronize()` call is silently dropped rather than dispatched immediately
    /// to listeners, which is exactly what the Java source does (`if (asyncDispatchEnabled) {
    /// queueEvent(...); }`, with no `else` branch calling listeners directly).
    fn synchronize(&self) {
        if self.async_dispatch_enabled {
            self.queue_event(Event::Synchronize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct RecordingListener {
        events: StdMutex<Vec<String>>,
    }

    impl FileSystemListener for RecordingListener {
        fn folder_created(&self, parent_path: &str, name: &str) {
            self.events.lock().unwrap().push(format!("folder_created:{parent_path}:{name}"));
        }
        fn item_created(&self, parent_path: &str, name: &str) {
            self.events.lock().unwrap().push(format!("item_created:{parent_path}:{name}"));
        }
        fn folder_deleted(&self, parent_path: &str, folder_name: &str) {
            self.events.lock().unwrap().push(format!("folder_deleted:{parent_path}:{folder_name}"));
        }
        fn folder_moved(&self, parent_path: &str, folder_name: &str, new_parent_path: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("folder_moved:{parent_path}:{folder_name}:{new_parent_path}"));
        }
        fn folder_renamed(&self, parent_path: &str, old_folder_name: &str, new_folder_name: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("folder_renamed:{parent_path}:{old_folder_name}:{new_folder_name}"));
        }
        fn item_deleted(&self, folder_path: &str, item_name: &str) {
            self.events.lock().unwrap().push(format!("item_deleted:{folder_path}:{item_name}"));
        }
        fn item_renamed(&self, folder_path: &str, old_item_name: &str, new_item_name: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("item_renamed:{folder_path}:{old_item_name}:{new_item_name}"));
        }
        fn item_moved(&self, parent_path: &str, name: &str, new_parent_path: &str, new_name: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("item_moved:{parent_path}:{name}:{new_parent_path}:{new_name}"));
        }
        fn item_changed(&self, parent_path: &str, item_name: &str) {
            self.events.lock().unwrap().push(format!("item_changed:{parent_path}:{item_name}"));
        }
        fn synchronize(&self) {
            self.events.lock().unwrap().push("synchronize".to_string());
        }
    }

    #[test]
    fn synchronous_dispatch_is_immediate() {
        let mgr = FileSystemEventManager::new(false);
        assert!(!mgr.is_asynchronous());
        let listener = Arc::new(RecordingListener::default());
        let handle: ListenerHandle = listener.clone();
        mgr.add(handle);

        mgr.item_created("/a", "b.txt");

        assert_eq!(listener.events.lock().unwrap().as_slice(), &["item_created:/a:b.txt".to_string()]);
    }

    #[test]
    fn synchronous_flush_events_returns_true_immediately() {
        let mgr = FileSystemEventManager::new(false);
        assert!(mgr.flush_events(Duration::from_millis(1)));
    }

    #[test]
    fn synchronous_synchronize_is_dropped_silently() {
        let mgr = FileSystemEventManager::new(false);
        let listener = Arc::new(RecordingListener::default());
        let handle: ListenerHandle = listener.clone();
        mgr.add(handle);

        mgr.synchronize();

        assert!(listener.events.lock().unwrap().is_empty());
    }

    #[test]
    fn async_dispatch_delivers_and_flush_waits_for_completion() {
        let mgr = FileSystemEventManager::new(true);
        assert!(mgr.is_asynchronous());
        let listener = Arc::new(RecordingListener::default());
        let handle: ListenerHandle = listener.clone();
        mgr.add(handle);

        mgr.item_created("/a", "b.txt");
        mgr.item_deleted("/a", "b.txt");

        assert!(mgr.flush_events(Duration::from_secs(5)));

        let events = listener.events.lock().unwrap();
        assert_eq!(events.as_slice(), &["item_created:/a:b.txt".to_string(), "item_deleted:/a:b.txt".to_string()]);
    }

    #[test]
    fn async_synchronize_is_queued_but_not_dispatched_to_listeners() {
        // Mirrors `SynchronizeEvent.dispatch` calling `listener.syncronize()`, so unlike the
        // synchronous case, async mode *does* eventually reach the listener.
        let mgr = FileSystemEventManager::new(true);
        let listener = Arc::new(RecordingListener::default());
        let handle: ListenerHandle = listener.clone();
        mgr.add(handle);

        mgr.synchronize();
        assert!(mgr.flush_events(Duration::from_secs(5)));

        assert_eq!(listener.events.lock().unwrap().as_slice(), &["synchronize".to_string()]);
    }

    #[test]
    fn events_are_discarded_with_no_listeners_registered() {
        let mgr = FileSystemEventManager::new(true);
        // No listener added, so the dispatch thread never starts; events are simply discarded.
        mgr.item_created("/a", "b.txt");
        // flush_events with no listeners/dispatch thread returns true immediately (queue_event
        // returns false since state is still Stopped).
        assert!(mgr.flush_events(Duration::from_millis(50)));
    }

    #[test]
    fn dispose_halts_future_dispatch() {
        let mgr = FileSystemEventManager::new(true);
        let listener = Arc::new(RecordingListener::default());
        let handle: ListenerHandle = listener.clone();
        mgr.add(handle);
        mgr.item_created("/a", "one.txt");
        assert!(mgr.flush_events(Duration::from_secs(5)));

        mgr.dispose();
        mgr.item_created("/a", "two.txt");
        // No way to flush after dispose (flush_events short-circuits to true since queueing
        // fails), but give any stray processing a moment, then verify nothing new arrived.
        std::thread::sleep(Duration::from_millis(50));

        let events = listener.events.lock().unwrap();
        assert_eq!(events.as_slice(), &["item_created:/a:one.txt".to_string()]);
    }

    #[test]
    fn remove_listener_stops_future_notifications() {
        let mgr = FileSystemEventManager::new(false);
        let listener = Arc::new(RecordingListener::default());
        let handle: ListenerHandle = listener.clone();
        mgr.add(handle.clone());
        mgr.remove(&handle);

        mgr.item_created("/a", "b.txt");

        assert!(listener.events.lock().unwrap().is_empty());
    }
}
