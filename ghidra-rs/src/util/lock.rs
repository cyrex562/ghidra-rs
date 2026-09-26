use std::collections::HashMap;
use std::sync::{Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, ThreadId};
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


/// A reentrant read/write lock providing mutual exclusion only -- it guards no data.
///
/// This is the faithful port of `ghidra.util.Lock`, which `extends ReentrantReadWriteLock`.
/// The reentrancy is not a detail: Ghidra's DB classes routinely call a public method that
/// acquires the lock from inside another method that already holds it (e.g. `DataTypeDB`'s
/// `setName` holds the write lock and then calls `getName`, which takes the read lock). Against
/// a non-reentrant lock that is a guaranteed self-deadlock, and it is not detectable by
/// compiling -- only by running the test, which is how it reached `integration`.
///
/// # Why this carries no payload, unlike [`Lock<T>`]
///
/// `Lock<T>` fuses the lock with the data it guards (`RwLock<T>`), which is the idiomatic Rust
/// shape and is what you want when the lock really does own its data. It cannot be made
/// reentrant: re-entering a write lock would hand out a second `&mut T` while the first is
/// still live, which is instant UB. Java has no such constraint because its lock guards
/// nothing -- the data sits in ordinary fields.
///
/// So the two coexist deliberately: use `Lock<T>` when the lock owns data, and `ReentrantLock`
/// where the Java source used the lock purely for mutual exclusion around fields it does not
/// own. Every `Lock<()>` in this crate was the latter.
///
/// Semantics mirror `ReentrantReadWriteLock`:
/// - the write lock is reentrant for the thread that holds it;
/// - a thread holding the write lock may also take the read lock;
/// - read locks are shared between threads, and a writer waits for all readers to finish;
/// - upgrading (taking the write lock while holding only a read lock) is *not* supported and
///   will block, exactly as it does in Java.
pub struct ReentrantLock {
    state: Mutex<ReentrantState>,
    available: Condvar,
    name: String,
}

#[derive(Default)]
struct ReentrantState {
    writer: Option<ThreadId>,
    write_depth: usize,
    readers: HashMap<ThreadId, usize>,
}

impl ReentrantLock {
    /// Creates a named lock, mirroring `new Lock(String)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            state: Mutex::new(ReentrantState::default()),
            available: Condvar::new(),
            name: name.into(),
        }
    }

    /// The lock's name, as passed to [`ReentrantLock::new`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Acquires the exclusive write lock, blocking until it is available.
    ///
    /// Reentrant: if the calling thread already holds the write lock, this increments its
    /// depth and returns immediately.
    pub fn write(&self) -> ReentrantWriteGuard<'_> {
        let me = thread::current().id();
        let mut state = self.state.lock().unwrap();
        loop {
            if state.writer == Some(me) {
                state.write_depth += 1;
                return ReentrantWriteGuard { lock: self };
            }
            if state.writer.is_none() && state.readers.is_empty() {
                state.writer = Some(me);
                state.write_depth = 1;
                return ReentrantWriteGuard { lock: self };
            }
            state = self.available.wait(state).unwrap();
        }
    }

    /// Acquires a shared read lock, blocking until no other thread holds the write lock.
    ///
    /// A thread that already holds the write lock may take the read lock without blocking --
    /// the case that deadlocks against a plain `RwLock`.
    pub fn read(&self) -> ReentrantReadGuard<'_> {
        let me = thread::current().id();
        let mut state = self.state.lock().unwrap();
        loop {
            if state.writer.is_none() || state.writer == Some(me) {
                *state.readers.entry(me).or_insert(0) += 1;
                return ReentrantReadGuard { lock: self };
            }
            state = self.available.wait(state).unwrap();
        }
    }

    fn release_write(&self) {
        let mut state = self.state.lock().unwrap();
        state.write_depth -= 1;
        if state.write_depth == 0 {
            state.writer = None;
            self.available.notify_all();
        }
    }

    fn release_read(&self) {
        let me = thread::current().id();
        let mut state = self.state.lock().unwrap();
        if let Some(count) = state.readers.get_mut(&me) {
            *count -= 1;
            if *count == 0 {
                state.readers.remove(&me);
            }
        }
        if state.readers.is_empty() {
            self.available.notify_all();
        }
    }
}

impl std::fmt::Debug for ReentrantLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReentrantLock").field("name", &self.name).finish()
    }
}

/// RAII guard for [`ReentrantLock::write`]; releases one level of the write lock on drop.
pub struct ReentrantWriteGuard<'a> {
    lock: &'a ReentrantLock,
}

impl Drop for ReentrantWriteGuard<'_> {
    fn drop(&mut self) {
        self.lock.release_write();
    }
}

/// RAII guard for [`ReentrantLock::read`]; releases one read hold on drop.
pub struct ReentrantReadGuard<'a> {
    lock: &'a ReentrantLock,
}

impl Drop for ReentrantReadGuard<'_> {
    fn drop(&mut self) {
        self.lock.release_read();
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

#[cfg(test)]
mod reentrant_tests {
    use super::ReentrantLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    /// The exact shape that hung the suite: hold the write lock, then take the read lock on the
    /// same thread, as `DataTypeDB::set_name` -> `get_name` does. A plain RwLock self-deadlocks.
    #[test]
    fn read_while_holding_write_on_same_thread() {
        let lock = ReentrantLock::new("dt");
        let _write = lock.write();
        let _read = lock.read();
    }

    #[test]
    fn write_is_reentrant_for_the_owning_thread() {
        let lock = ReentrantLock::new("nested");
        let _outer = lock.write();
        let _inner = lock.write();
    }

    #[test]
    fn nested_write_stays_held_until_the_outermost_guard_drops() {
        let lock = Arc::new(ReentrantLock::new("depth"));
        let outer = lock.write();
        {
            let _inner = lock.write();
        } // inner released; the lock must still be held

        let other = Arc::clone(&lock);
        let grabbed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&grabbed);
        let h = thread::spawn(move || {
            let _w = other.write();
            flag.store(true, Ordering::SeqCst);
        });

        thread::sleep(Duration::from_millis(50));
        assert!(!grabbed.load(Ordering::SeqCst), "another thread took the lock while it was held");
        drop(outer);
        h.join().unwrap();
        assert!(grabbed.load(Ordering::SeqCst));
    }

    #[test]
    fn readers_from_different_threads_share() {
        let lock = Arc::new(ReentrantLock::new("shared"));
        let (tx, rx) = mpsc::channel();
        let a = Arc::clone(&lock);
        let _first = lock.read();
        let h = thread::spawn(move || {
            let _second = a.read();
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("a second reader should not block behind the first");
        h.join().unwrap();
    }

    #[test]
    fn writer_waits_for_an_active_reader() {
        let lock = Arc::new(ReentrantLock::new("excl"));
        let reader = lock.read();
        let other = Arc::clone(&lock);
        let wrote = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&wrote);
        let h = thread::spawn(move || {
            let _w = other.write();
            flag.store(true, Ordering::SeqCst);
        });

        thread::sleep(Duration::from_millis(50));
        assert!(!wrote.load(Ordering::SeqCst), "writer ran while a reader held the lock");
        drop(reader);
        h.join().unwrap();
        assert!(wrote.load(Ordering::SeqCst));
    }

    #[test]
    fn lock_is_reusable_after_release() {
        let lock = ReentrantLock::new("reuse");
        drop(lock.write());
        drop(lock.read());
        drop(lock.write());
    }
}
