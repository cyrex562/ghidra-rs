use crate::util::exception::CancelledException;

/// Listener notified when the busy state of a component changes.
pub trait BusyListener: Send + Sync {
    fn set_busy(&self, busy: bool);
}

/// Listener notified when a task is cancelled.
pub trait CancelledListener: Send + Sync {
    /// Called when the task is cancelled.
    fn cancelled(&self);
}

/// Generic interface for loading and caching values.
/// The loader fetches a value via `get()` and can clear the cache via `clear()`.
pub trait CachingLoader<T>: Send + Sync {
    /// Loads and returns a value, monitoring progress via the given TaskMonitor.
    fn get(&self, monitor: &dyn TaskMonitor) -> T;

    /// Clears the cached value.
    fn clear(&mut self);
}

pub trait TaskMonitor: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn set_show_progress_value(&self, show: bool);
    fn set_message(&self, message: &str);
    fn get_message(&self) -> String;
    fn set_progress(&self, value: i64);
    fn initialize(&self, max: i64);
    fn set_maximum(&self, max: i64);
    fn get_maximum(&self) -> i64;
    fn set_indeterminate(&self, indeterminate: bool);
    fn is_indeterminate(&self) -> bool;
    fn check_cancelled(&self) -> Result<(), CancelledException>;
    fn increment_progress(&self, amount: i64);
    fn get_progress(&self) -> i64;
    fn cancel(&self);
    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>);
    fn remove_cancelled_listener(&self, listener: &dyn CancelledListener);
    fn set_cancel_enabled(&self, enabled: bool);
    fn is_cancel_enabled(&self) -> bool;
    fn clear_cancelled(&self);
}

pub struct DummyMonitor;

impl TaskMonitor for DummyMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn set_show_progress_value(&self, _show: bool) {}
    fn set_message(&self, _message: &str) {}
    fn get_message(&self) -> String {
        String::new()
    }
    fn set_progress(&self, _value: i64) {}
    fn initialize(&self, _max: i64) {}
    fn set_maximum(&self, _max: i64) {}
    fn get_maximum(&self) -> i64 {
        0
    }
    fn set_indeterminate(&self, _indeterminate: bool) {}
    fn is_indeterminate(&self) -> bool {
        false
    }
    fn check_cancelled(&self) -> Result<(), CancelledException> {
        Ok(())
    }
    fn increment_progress(&self, _amount: i64) {}
    fn get_progress(&self) -> i64 {
        -1
    }
    fn cancel(&self) {}
    fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
    fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
    fn set_cancel_enabled(&self, _enabled: bool) {}
    fn is_cancel_enabled(&self) -> bool {
        true
    }
    fn clear_cancelled(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    struct TrackingBusyListener {
        last: AtomicBool,
    }

    impl BusyListener for TrackingBusyListener {
        fn set_busy(&self, busy: bool) {
            self.last.store(busy, Ordering::SeqCst);
        }
    }

    #[test]
    fn busy_listener_set_busy_true() {
        let l = TrackingBusyListener { last: AtomicBool::new(false) };
        l.set_busy(true);
        assert!(l.last.load(Ordering::SeqCst));
    }

    #[test]
    fn busy_listener_set_busy_false() {
        let l = TrackingBusyListener { last: AtomicBool::new(true) };
        l.set_busy(false);
        assert!(!l.last.load(Ordering::SeqCst));
    }

    #[test]
    fn busy_listener_as_trait_object() {
        let l = TrackingBusyListener { last: AtomicBool::new(false) };
        let obj: &dyn BusyListener = &l;
        obj.set_busy(true);
        assert!(l.last.load(Ordering::SeqCst));
        obj.set_busy(false);
        assert!(!l.last.load(Ordering::SeqCst));
    }

    struct CountingCancelledListener {
        call_count: Mutex<i32>,
    }

    impl CancelledListener for CountingCancelledListener {
        fn cancelled(&self) {
            *self.call_count.lock().unwrap() += 1;
        }
    }

    #[test]
    fn cancelled_listener_called() {
        let l = CountingCancelledListener { call_count: Mutex::new(0) };
        l.cancelled();
        assert_eq!(*l.call_count.lock().unwrap(), 1);
    }

    #[test]
    fn cancelled_listener_called_multiple_times() {
        let l = CountingCancelledListener { call_count: Mutex::new(0) };
        l.cancelled();
        l.cancelled();
        l.cancelled();
        assert_eq!(*l.call_count.lock().unwrap(), 3);
    }

    #[test]
    fn cancelled_listener_as_trait_object() {
        let l: Arc<dyn CancelledListener> = Arc::new(CountingCancelledListener { call_count: Mutex::new(0) });
        l.cancelled();
        let l2 = Arc::clone(&l);
        l2.cancelled();
    }

    struct SimpleCachingLoader {
        value: i32,
        clear_count: std::sync::atomic::AtomicUsize,
    }

    impl CachingLoader<i32> for SimpleCachingLoader {
        fn get(&self, _monitor: &dyn TaskMonitor) -> i32 {
            self.value
        }

        fn clear(&mut self) {
            self.clear_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.value = 0;
        }
    }

    #[test]
    fn caching_loader_get() {
        let loader = SimpleCachingLoader { value: 42, clear_count: std::sync::atomic::AtomicUsize::new(0) };
        let monitor = DummyMonitor;
        assert_eq!(loader.get(&monitor), 42);
    }

    #[test]
    fn caching_loader_clear() {
        let mut loader = SimpleCachingLoader { value: 42, clear_count: std::sync::atomic::AtomicUsize::new(0) };
        loader.clear();
        assert_eq!(loader.value, 0);
        assert_eq!(loader.clear_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn caching_loader_multiple_clears() {
        let mut loader = SimpleCachingLoader { value: 42, clear_count: std::sync::atomic::AtomicUsize::new(0) };
        loader.clear();
        loader.clear();
        loader.clear();
        assert_eq!(loader.clear_count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    struct StringCachingLoader {
        value: String,
    }

    impl CachingLoader<String> for StringCachingLoader {
        fn get(&self, _monitor: &dyn TaskMonitor) -> String {
            self.value.clone()
        }

        fn clear(&mut self) {
            self.value.clear();
        }
    }

    #[test]
    fn caching_loader_generic_string() {
        let loader = StringCachingLoader { value: "test".to_string() };
        let monitor = DummyMonitor;
        assert_eq!(loader.get(&monitor), "test");
    }

    #[test]
    fn caching_loader_string_clear() {
        let mut loader = StringCachingLoader { value: "test".to_string() };
        loader.clear();
        assert_eq!(loader.value, "");
    }
}
