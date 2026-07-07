use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::util::Callback;

/// A synchronization lock that provides read and write methods for acquiring either
/// a shared read access or an exclusive write access.
///
/// This wraps Rust's `std::sync::RwLock` and provides convenient methods to acquire
/// locks that can be used in a pattern similar to Java's try-with-resources.
///
/// # Examples
///
/// Read access:
/// ```ignore
/// let lock = Lock::new("my_lock");
/// {
///     let _guard = lock.read();
///     // shared read access here
/// } // guard is automatically released
/// ```
///
/// Write access:
/// ```ignore
/// {
///     let _guard = lock.write();
///     // exclusive write access here
/// } // guard is automatically released
/// ```
///
/// Port of `ghidra.util.Lock`.
pub struct Lock<T> {
    inner: RwLock<T>,
    name: String,
}

impl<T: Default> Lock<T> {
    /// Creates an instance of a lock for synchronization within Ghidra.
    ///
    /// # Arguments
    /// * `name` - the name of this lock
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            inner: RwLock::new(T::default()),
            name: name.into(),
        }
    }
}

impl<T> Lock<T> {
    /// Creates a lock with an initial value.
    ///
    /// # Arguments
    /// * `name` - the name of this lock
    /// * `value` - the initial value to protect
    pub fn with_value(name: impl Into<String>, value: T) -> Self {
        Self {
            inner: RwLock::new(value),
            name: name.into(),
        }
    }

    /// Acquires the read lock that allows simultaneous access by all read threads.
    /// Will block if any thread already has a write lock.
    ///
    /// Returns a guard that automatically releases the lock when dropped.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.inner.read().unwrap()
    }

    /// Acquires the exclusive write lock that prevents any other thread from
    /// getting a lock while the write lock is held. Will block if any other thread
    /// has either a read or write lock.
    ///
    /// Returns a guard that automatically releases the lock when dropped.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.inner.write().unwrap()
    }

    /// A convenience method for acquiring a read lock, executing a closure,
    /// then releasing the lock.
    ///
    /// # Arguments
    /// * `f` - a function to execute while holding a read lock
    ///
    /// # Returns
    /// The result from the function
    pub fn with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let guard = self.read();
        f(&*guard)
    }

    /// A convenience method for acquiring a write lock, executing a closure,
    /// then releasing the lock.
    ///
    /// # Arguments
    /// * `f` - a function to execute while holding a write lock
    pub fn with_write<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut guard = self.write();
        f(&mut *guard)
    }

    /// A convenience method for acquiring a write lock, executing a closure,
    /// then releasing the lock, returning a result.
    ///
    /// # Arguments
    /// * `f` - a function to execute while holding a write lock
    ///
    /// # Returns
    /// The result from the function
    pub fn with_write_result<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut guard = self.write();
        f(&mut *guard)
    }
}

impl Lock<()> {
    /// Creates a unit lock (synchronization only, no protected value).
    pub fn new_unit(name: impl Into<String>) -> Self {
        Self {
            inner: RwLock::new(()),
            name: name.into(),
        }
    }

    /// Convenience method for acquiring a read lock and executing a callback,
    /// for unit locks.
    pub fn with_read_callback<F>(&self, f: F)
    where
        F: FnOnce(),
    {
        let _guard = self.read();
        f()
    }

    /// Convenience method for acquiring a write lock and executing a callback.
    pub fn with_write_callback(&self, f: Callback) {
        let _guard = self.write();
        f()
    }
}

impl<T> std::fmt::Display for Lock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} Lock", self.name)
    }
}

impl<T> std::fmt::Debug for Lock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} Lock", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn new_lock_can_be_created() {
        let lock = Lock::new_unit("test_lock");
        assert_eq!(lock.to_string(), "test_lock Lock");
    }

    #[test]
    fn display_format_is_name_plus_lock() {
        let lock = Lock::new_unit("my_lock");
        assert_eq!(lock.to_string(), "my_lock Lock");
    }

    #[test]
    fn read_lock_acquired_and_released() {
        let lock = Arc::new(Lock::new_unit("read_test"));
        let lock2 = Arc::clone(&lock);

        let handle = std::thread::spawn(move || {
            let _guard = lock2.read();
            std::thread::sleep(std::time::Duration::from_millis(10));
        });

        std::thread::sleep(std::time::Duration::from_millis(5));
        let _guard = lock.read();
        handle.join().unwrap();
    }

    #[test]
    fn write_lock_blocks_reads() {
        let lock = Arc::new(Lock::with_value("write_test", 0usize));
        let lock2 = Arc::clone(&lock);

        let handle = std::thread::spawn(move || {
            let mut guard = lock2.write();
            *guard = 42;
            std::thread::sleep(std::time::Duration::from_millis(50));
        });

        std::thread::sleep(std::time::Duration::from_millis(10));
        let _guard = lock.read();
        handle.join().unwrap();
        assert_eq!(*lock.read(), 42);
    }

    #[test]
    fn with_read_executes_closure() {
        let lock = Lock::with_value("with_read_test", 42);
        let result = lock.with_read(|value| *value * 2);
        assert_eq!(result, 84);
    }

    #[test]
    fn with_write_executes_closure() {
        let lock = Lock::with_value("with_write_test", 0);
        lock.with_write(|value| {
            *value = 100;
        });
        assert_eq!(*lock.read(), 100);
    }

    #[test]
    fn with_write_result_executes_and_returns() {
        let lock = Lock::with_value("with_write_result_test", vec![1, 2, 3]);
        let len = lock.with_write_result(|vec| {
            vec.push(4);
            vec.len()
        });
        assert_eq!(len, 4);
        assert_eq!(*lock.read(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn with_read_callback_unit_lock() {
        let called = Arc::new(AtomicUsize::new(0));
        let called_clone = Arc::clone(&called);
        let lock = Lock::new_unit("with_read_callback_test");
        lock.with_read_callback(move || {
            called_clone.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(called.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn with_write_callback_unit_lock() {
        let called = Arc::new(AtomicUsize::new(0));
        let called_clone = Arc::clone(&called);
        let lock = Lock::new_unit("with_write_callback_test");
        let callback: Callback = Box::new(move || {
            called_clone.fetch_add(1, Ordering::SeqCst);
        });
        lock.with_write_callback(callback);
        assert_eq!(called.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multiple_reads_can_happen_concurrently() {
        let lock = Arc::new(Lock::with_value("concurrent_reads", 0));
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let lock_clone = Arc::clone(&lock);
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        let _guard = lock_clone.read();
                        std::thread::yield_now();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn lock_with_string_value() {
        let lock = Lock::with_value("string_lock", "hello".to_string());
        lock.with_write(|s| {
            s.push_str(" world");
        });
        let result = lock.with_read(|s| s.clone());
        assert_eq!(result, "hello world");
    }

    #[test]
    fn lock_name_persists() {
        let lock = Lock::new_unit("persistent_name");
        let name = lock.to_string();
        let name2 = lock.to_string();
        assert_eq!(name, name2);
        assert_eq!(name, "persistent_name Lock");
    }
}
