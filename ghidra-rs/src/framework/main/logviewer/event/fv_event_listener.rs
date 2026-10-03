//! Port of `ghidra.framework.main.logviewer.event.FVEventListener`.

use std::sync::{Arc, Mutex};

use super::fv_event::FVEvent;

/// Mirrors `java.util.Observer`, specialized to [`FVEvent`] -- the only argument
/// [`FVEventListener::send`] ever hands to `notifyObservers`. Java's `Observer.update(Observable
/// o, Object arg)` receives the `Observable` source plus an opaque `Object`; every real consumer
/// in this package (`FileViewer`, `ViewportUtility`, ...) immediately downcasts `arg` to
/// `FVEvent`, so this trait is narrowed to that concrete shape rather than modeling `Object`.
pub trait FVObserver: Send + Sync {
    /// Mirrors `Observer.update(Observable, Object)`.
    fn update(&self, source: &FVEventListener, evt: &FVEvent);
}

/// Extension of Java's `Observable` that allows clients to send [`FVEvent`] messages to
/// subscribers.
///
/// Port of `ghidra.framework.main.logviewer.event.FVEventListener`, which `extends
/// java.util.Observable`. Per this crate's composition-over-inheritance convention, that
/// `extends` relationship is modeled by composing the minimal slice of `Observable`'s behavior
/// this class actually uses (`addObserver`/`deleteObserver`/`setChanged`/`notifyObservers`, ...)
/// directly as fields, rather than faking inheritance.
///
/// Note: this "listener" class serves as an event hub, where clients push events to this class
/// and register to receive events from it. The events given to this listener are heterogeneous
/// and serve as a general message-passing system for this API. This class should be replaced by
/// simple object communication using normal method calls -- per the Java class's own doc
/// comment.
pub struct FVEventListener {
    observers: Mutex<Vec<Arc<dyn FVObserver>>>,
    changed: Mutex<bool>,
}

impl FVEventListener {
    /// Creates a listener with no observers registered, matching `Observable`'s implicit
    /// zero-argument construction.
    pub fn new() -> Self {
        Self { observers: Mutex::new(Vec::new()), changed: Mutex::new(false) }
    }

    /// Mirrors `Observable.addObserver(Observer)`. Java throws `NullPointerException` when `o`
    /// is `null`, which has no counterpart for a non-nullable `Arc`; Java also skips the add if
    /// `o` is already present (`Vector.contains`, i.e. by `equals` -- `Observer` implementations
    /// here don't override `equals`, so that's reference identity), reproduced via
    /// [`Arc::ptr_eq`].
    pub fn add_observer(&self, observer: Arc<dyn FVObserver>) {
        let mut observers = self.observers.lock().unwrap();
        if !observers.iter().any(|o| Arc::ptr_eq(o, &observer)) {
            observers.push(observer);
        }
    }

    /// Mirrors `Observable.deleteObserver(Observer)`.
    pub fn delete_observer(&self, observer: &Arc<dyn FVObserver>) {
        let mut observers = self.observers.lock().unwrap();
        observers.retain(|o| !Arc::ptr_eq(o, observer));
    }

    /// Mirrors `Observable.deleteObservers()`.
    pub fn delete_observers(&self) {
        self.observers.lock().unwrap().clear();
    }

    /// Mirrors `Observable.countObservers()`.
    pub fn count_observers(&self) -> usize {
        self.observers.lock().unwrap().len()
    }

    /// Mirrors `Observable.setChanged()`.
    pub fn set_changed(&self) {
        *self.changed.lock().unwrap() = true;
    }

    /// Mirrors `Observable.clearChanged()`.
    pub fn clear_changed(&self) {
        *self.changed.lock().unwrap() = false;
    }

    /// Mirrors `Observable.hasChanged()`.
    pub fn has_changed(&self) -> bool {
        *self.changed.lock().unwrap()
    }

    /// Mirrors `Observable.notifyObservers(Object)`: does nothing unless the changed flag was
    /// set (via [`set_changed`](Self::set_changed)); otherwise snapshots the observer list,
    /// clears the flag, then delivers `evt` to each observer in the snapshot.
    ///
    /// Java bug/quirk: `Observable.notifyObservers` (JDK `java.util.Observable`) walks its
    /// snapshot array from the **last** index down to the first -- i.e. observers are notified
    /// in the *reverse* of their registration order, not the order they were added. That is
    /// faithfully reproduced here (not "fixed" to deliver in registration order); see
    /// [`notify_delivers_in_reverse_registration_order`](
    /// tests::notify_delivers_in_reverse_registration_order) for a dedicated test.
    fn notify_observers(&self, evt: &FVEvent) {
        let snapshot: Vec<Arc<dyn FVObserver>> = {
            let mut changed = self.changed.lock().unwrap();
            if !*changed {
                return;
            }
            *changed = false;
            self.observers.lock().unwrap().clone()
        };
        for observer in snapshot.iter().rev() {
            observer.update(self, evt);
        }
    }

    /// Fires off the given [`FVEvent`] using the appropriate `Observer` methods.
    ///
    /// Mirrors `FVEventListener.send(FVEvent)`: calls `setChanged()` then
    /// `notifyObservers(evt)`.
    pub fn send(&self, evt: &FVEvent) {
        self.set_changed();
        self.notify_observers(evt);
    }
}

impl Default for FVEventListener {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::main::logviewer::event::fv_event::EventType;
    use std::sync::Mutex as StdMutex;

    struct Recorder {
        received: StdMutex<Vec<EventType>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self { received: StdMutex::new(Vec::new()) }
        }

        fn received(&self) -> Vec<EventType> {
            self.received.lock().unwrap().clone()
        }
    }

    impl FVObserver for Recorder {
        fn update(&self, _source: &FVEventListener, evt: &FVEvent) {
            self.received.lock().unwrap().push(evt.event_type);
        }
    }

    #[test]
    fn send_delivers_event_to_registered_observer() {
        let listener = FVEventListener::new();
        let recorder = Arc::new(Recorder::new());
        listener.add_observer(recorder.clone());

        listener.send(&FVEvent::new(EventType::FileChanged, Box::new(())));

        assert_eq!(recorder.received(), vec![EventType::FileChanged]);
    }

    #[test]
    fn send_clears_changed_flag_after_notifying() {
        let listener = FVEventListener::new();
        listener.send(&FVEvent::new(EventType::ReloadFile, Box::new(())));
        assert!(!listener.has_changed());
    }

    #[test]
    fn add_observer_does_not_duplicate_the_same_instance() {
        let listener = FVEventListener::new();
        let recorder = Arc::new(Recorder::new());
        listener.add_observer(recorder.clone());
        listener.add_observer(recorder.clone());

        assert_eq!(listener.count_observers(), 1);
    }

    #[test]
    fn delete_observer_stops_future_notifications() {
        let listener = FVEventListener::new();
        let recorder = Arc::new(Recorder::new());
        let handle: Arc<dyn FVObserver> = recorder.clone();
        listener.add_observer(handle.clone());
        listener.delete_observer(&handle);

        listener.send(&FVEvent::new(EventType::FileChanged, Box::new(())));

        assert!(recorder.received().is_empty());
        assert_eq!(listener.count_observers(), 0);
    }

    #[test]
    fn delete_observers_clears_every_registration() {
        let listener = FVEventListener::new();
        listener.add_observer(Arc::new(Recorder::new()));
        listener.add_observer(Arc::new(Recorder::new()));
        assert_eq!(listener.count_observers(), 2);

        listener.delete_observers();
        assert_eq!(listener.count_observers(), 0);
    }

    /// See the doc comment on [`FVEventListener::notify_observers`]: Java's `Observable`
    /// notifies observers in the reverse of their registration order.
    #[test]
    fn notify_delivers_in_reverse_registration_order() {
        let listener = FVEventListener::new();
        let order = Arc::new(StdMutex::new(Vec::new()));

        struct OrderRecorder {
            id: u32,
            order: Arc<StdMutex<Vec<u32>>>,
        }
        impl FVObserver for OrderRecorder {
            fn update(&self, _source: &FVEventListener, _evt: &FVEvent) {
                self.order.lock().unwrap().push(self.id);
            }
        }

        listener.add_observer(Arc::new(OrderRecorder { id: 1, order: order.clone() }));
        listener.add_observer(Arc::new(OrderRecorder { id: 2, order: order.clone() }));
        listener.add_observer(Arc::new(OrderRecorder { id: 3, order: order.clone() }));

        listener.send(&FVEvent::new(EventType::FileChanged, Box::new(())));

        assert_eq!(*order.lock().unwrap(), vec![3, 2, 1]);
    }

    #[test]
    fn send_without_observers_does_not_panic() {
        let listener = FVEventListener::new();
        listener.send(&FVEvent::new(EventType::FileChanged, Box::new(())));
        assert_eq!(listener.count_observers(), 0);
    }
}
