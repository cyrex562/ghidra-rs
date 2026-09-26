//! Port of `ghidra.app.plugin.core.instructionsearch.model.InstructionTableObserver`.

/// Implemented by types wishing to be notified when the instruction table is changed.
///
/// Port of `ghidra.app.plugin.core.instructionsearch.model.InstructionTableObserver`. The Java
/// interface extends `java.util.Observer` only so that it can reuse part of that interface's
/// definition without forcing observables to extend `java.util.Observable`; its own
/// implementors leave `Observer.update(Observable, Object)` empty and rely solely on
/// [`changed`](Self::changed). That inherited `update` method is therefore not part of this
/// trait.
///
/// Notification takes `&self`, matching the crate's other listener traits (e.g.
/// [`ModelChangeListener`](crate::app::plugin::core::function::editor::model_change_listener::ModelChangeListener)):
/// the observable holds its observers in a shared set and notifies each in turn, so an observer
/// that needs to record state does so through interior mutability.
pub trait InstructionTableObserver {
    /// Called when the observed instruction table has changed.
    fn changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Counts notifications, standing in for `InstructionTableModel`, whose `changed()` fires a
    /// table-data-changed event.
    struct CountingObserver {
        count: Cell<usize>,
    }

    impl InstructionTableObserver for CountingObserver {
        fn changed(&self) {
            self.count.set(self.count.get() + 1);
        }
    }

    /// Mirrors `InstructionTableDataObject.notifyObservers()`: every registered observer's
    /// `changed()` is invoked once per notification.
    fn notify_observers(observers: &[&dyn InstructionTableObserver]) {
        for obs in observers {
            obs.changed();
        }
    }

    #[test]
    fn each_registered_observer_is_notified_once_per_change() {
        let a = CountingObserver { count: Cell::new(0) };
        let b = CountingObserver { count: Cell::new(0) };
        notify_observers(&[&a, &b]);
        assert_eq!(a.count.get(), 1);
        assert_eq!(b.count.get(), 1);
        notify_observers(&[&a]);
        assert_eq!(a.count.get(), 2);
        assert_eq!(b.count.get(), 1);
    }
}
