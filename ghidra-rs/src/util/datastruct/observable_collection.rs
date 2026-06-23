use super::CollectionChangeListener;

/// A guard token for batching collection change notifications.
///
/// While held, implementations may accumulate change events rather than dispatch
/// them immediately. Dropping this guard (equivalent to Java's `AutoCloseable.close()`)
/// signals that batching should end and any pending notifications be dispatched.
pub trait ChangeAggregator {}

/// A collection with attached change-listener support.
///
/// Port of `ghidra.util.datastruct.ObservableCollection`.
///
/// Mirrors Java's `ObservableCollection<E, L extends CollectionChangeListener<? super E>>`:
/// mutations can fire events to registered listeners, and callers may batch events
/// using [`aggregate_changes`][ObservableCollection::aggregate_changes].
pub trait ObservableCollection<E, L>
where
    L: CollectionChangeListener<E>,
{
    /// Register `listener` to receive future change notifications.
    fn add_change_listener(&mut self, listener: L);

    /// Unregister a previously registered `listener`.
    fn remove_change_listener(&mut self, listener: L);

    /// Notify all registered listeners that `element` was modified in place.
    fn notify_modified(&mut self, element: &E);

    /// Begin a change-aggregation window.
    ///
    /// Returns a guard that batches change events while held. Dropping the guard
    /// ends the window and dispatches any accumulated notifications to listeners.
    fn aggregate_changes(&mut self) -> Box<dyn ChangeAggregator + '_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        modified: Vec<i32>,
    }

    impl CollectionChangeListener<i32> for Recorder {
        fn element_modified(&mut self, element: &i32) {
            self.modified.push(*element);
        }
    }

    struct Guard<'a>(&'a mut bool);
    impl ChangeAggregator for Guard<'_> {}
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            *self.0 = true;
        }
    }

    struct SimpleObservable {
        listeners: Vec<Recorder>,
        guard_dropped: bool,
    }

    impl SimpleObservable {
        fn new() -> Self {
            Self { listeners: vec![], guard_dropped: false }
        }
    }

    impl ObservableCollection<i32, Recorder> for SimpleObservable {
        fn add_change_listener(&mut self, listener: Recorder) {
            self.listeners.push(listener);
        }

        fn remove_change_listener(&mut self, _listener: Recorder) {
            self.listeners.pop();
        }

        fn notify_modified(&mut self, element: &i32) {
            for l in &mut self.listeners {
                l.element_modified(element);
            }
        }

        fn aggregate_changes(&mut self) -> Box<dyn ChangeAggregator + '_> {
            Box::new(Guard(&mut self.guard_dropped))
        }
    }

    #[test]
    fn test_add_listener_and_notify() {
        let mut col = SimpleObservable::new();
        col.add_change_listener(Recorder { modified: vec![] });
        col.notify_modified(&7);
        assert_eq!(col.listeners[0].modified, vec![7]);
    }

    #[test]
    fn test_notify_multiple_listeners() {
        let mut col = SimpleObservable::new();
        col.add_change_listener(Recorder { modified: vec![] });
        col.add_change_listener(Recorder { modified: vec![] });
        col.notify_modified(&3);
        assert_eq!(col.listeners[0].modified, vec![3]);
        assert_eq!(col.listeners[1].modified, vec![3]);
    }

    #[test]
    fn test_remove_listener() {
        let mut col = SimpleObservable::new();
        col.add_change_listener(Recorder { modified: vec![] });
        assert_eq!(col.listeners.len(), 1);
        col.remove_change_listener(Recorder { modified: vec![] });
        assert_eq!(col.listeners.len(), 0);
    }

    #[test]
    fn test_aggregate_changes_guard_flushes_on_drop() {
        let mut col = SimpleObservable::new();
        assert!(!col.guard_dropped);
        {
            let _agg = col.aggregate_changes();
        }
        assert!(col.guard_dropped);
    }

    #[test]
    fn test_notify_modified_no_listeners() {
        let mut col = SimpleObservable::new();
        col.notify_modified(&99);
    }
}
