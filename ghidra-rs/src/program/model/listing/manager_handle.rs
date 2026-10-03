//! Shared handles to a program's managers.
//!
//! Java hands out a program's managers (`Program.getListing()`, `getSymbolTable()`,
//! `getReferenceManager()`, ...) from a shared `Program` reference, and the managers mutate
//! under the program's domain-object lock. The Rust
//! [`Program`](crate::program::model::listing::Program) trait mirrors that: every manager
//! accessor takes `&self` and returns a [`ManagerGuard`], an exclusive, lock-backed handle to
//! one manager. Two *different* managers can be held at once from one `&Program` (the case
//! `&mut self` accessors could not express), and a mutation made through one handle is visible
//! to every handle obtained afterwards, because they all lock the same manager.
//!
//! Locking is per manager: an implementor stores each manager it exposes in its own
//! [`ManagerCell`] (or in a `RwLock` it already shares with other managers, see
//! [`ManagerGuard::write`]). See `OWNERSHIP_MIGRATION.md`, "Program manager access
//! (2026-09-26)", for why this is per-manager rather than one program-wide lock and how it
//! relates to the snapshot + transaction convention.

use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockWriteGuard};

/// Identifier of the thread that currently holds a [`ManagerCell`]; `0` means "nobody".
static NEXT_THREAD_TOKEN: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static THREAD_TOKEN: Cell<u64> = const { Cell::new(0) };
}

/// A small non-zero token unique to the calling thread.
fn current_thread_token() -> u64 {
    THREAD_TOKEN.with(|token| {
        if token.get() == 0 {
            token.set(NEXT_THREAD_TOKEN.fetch_add(1, Ordering::Relaxed));
        }
        token.get()
    })
}

/// A lock around one manager a program exposes.
///
/// Behaves like a `Mutex<T>` with one difference that matters for the manager accessors: taking
/// the lock again on the thread that already holds it panics with a clear message instead of
/// deadlocking. Before the accessors took `&self`, holding the listing while asking for the
/// listing again was a borrow-check error; this keeps it a loud error, the way `RefCell` does,
/// rather than a silent hang. Other threads simply block until the handle is dropped.
///
/// `T` may be unsized, so a `&ManagerCell<MockListing>` coerces to `&ManagerCell<dyn Listing>`.
pub struct ManagerCell<T: ?Sized> {
    owner: AtomicU64,
    inner: Mutex<T>,
}

impl<T> ManagerCell<T> {
    /// Wrap a manager.
    pub fn new(manager: T) -> Self {
        Self {
            owner: AtomicU64::new(0),
            inner: Mutex::new(manager),
        }
    }

    /// Unwrap the manager.
    pub fn into_inner(self) -> T {
        self.inner.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<T: Default> Default for ManagerCell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> ManagerCell<T> {
    /// Take exclusive access to the manager, blocking while another thread holds it.
    ///
    /// # Panics
    ///
    /// If the calling thread already holds a handle to this manager.
    pub fn lock(&self) -> ManagerGuard<'_, T> {
        let me = current_thread_token();
        if self.owner.load(Ordering::Acquire) == me {
            panic!(
                "program manager is already held on this thread; drop the existing handle before \
                 asking the program for it again"
            );
        }
        let guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.owner.store(me, Ordering::Release);
        ManagerGuard {
            inner: GuardInner::Cell {
                guard,
                owner: &self.owner,
            },
        }
    }

    /// Direct access through an exclusive borrow of the cell; no locking needed.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<T: ?Sized + std::fmt::Debug> std::fmt::Debug for ManagerCell<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerCell").finish_non_exhaustive()
    }
}

enum GuardInner<'a, T: ?Sized> {
    Cell {
        guard: MutexGuard<'a, T>,
        owner: &'a AtomicU64,
    },
    Write(RwLockWriteGuard<'a, T>),
}

/// An exclusive handle to one of a program's managers, returned by the `Program` manager
/// accessors.
///
/// Dereferences (mutably) to the manager. The manager stays locked for as long as the handle
/// lives, so keep handles short-lived: take one, use it, drop it. Handles to different managers
/// are independent.
pub struct ManagerGuard<'a, T: ?Sized> {
    inner: GuardInner<'a, T>,
}

impl<'a, T: ?Sized> ManagerGuard<'a, T> {
    /// Lock a manager held in a [`ManagerCell`]. Same as [`ManagerCell::lock`]; provided so an
    /// accessor can write `Some(ManagerGuard::lock(&self.listing))` and let the cell coerce to
    /// the accessor's `dyn` manager type.
    pub fn lock(cell: &'a ManagerCell<T>) -> Self {
        cell.lock()
    }

    /// Write-lock a manager held in a `RwLock` -- for implementors whose managers are already
    /// shared with other managers as `Arc<RwLock<_>>` (as `ProgramDB`'s are). A poisoned lock is
    /// recovered, as for [`ManagerCell`]; there is no re-entrancy check on this path.
    pub fn write(lock: &'a RwLock<T>) -> Self {
        ManagerGuard {
            inner: GuardInner::Write(lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())),
        }
    }
}

impl<T: ?Sized> Deref for ManagerGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match &self.inner {
            GuardInner::Cell { guard, .. } => guard,
            GuardInner::Write(guard) => guard,
        }
    }
}

impl<T: ?Sized> DerefMut for ManagerGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match &mut self.inner {
            GuardInner::Cell { guard, .. } => guard,
            GuardInner::Write(guard) => guard,
        }
    }
}

impl<T: ?Sized> Drop for ManagerGuard<'_, T> {
    fn drop(&mut self) {
        // Clear the owner while the mutex is still held (the guard field is released after this
        // body runs), so a waiting thread never observes a stale owner of its own.
        if let GuardInner::Cell { owner, .. } = &self.inner {
            owner.store(0, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    trait Counter {
        fn bump(&mut self) -> i32;
        fn value(&self) -> i32;
    }

    struct Simple(i32);

    impl Counter for Simple {
        fn bump(&mut self) -> i32 {
            self.0 += 1;
            self.0
        }

        fn value(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn cell_coerces_to_dyn_and_mutations_persist() {
        let cell = ManagerCell::new(Simple(0));
        {
            let mut handle: ManagerGuard<'_, dyn Counter> = ManagerGuard::lock(&cell);
            assert_eq!(handle.bump(), 1);
        }
        let handle: ManagerGuard<'_, dyn Counter> = ManagerGuard::lock(&cell);
        assert_eq!(handle.value(), 1);
    }

    #[test]
    fn two_cells_can_be_held_at_once() {
        let a = ManagerCell::new(Simple(1));
        let b = ManagerCell::new(Simple(2));
        let mut ha = a.lock();
        let mut hb = b.lock();
        ha.bump();
        hb.bump();
        assert_eq!((ha.value(), hb.value()), (2, 3));
    }

    #[test]
    #[should_panic(expected = "already held on this thread")]
    fn relocking_on_same_thread_panics_instead_of_deadlocking() {
        let cell = ManagerCell::new(Simple(0));
        let _first = cell.lock();
        let _second = cell.lock();
    }

    #[test]
    fn relock_after_drop_is_allowed() {
        let cell = ManagerCell::new(Simple(0));
        drop(cell.lock());
        assert_eq!(cell.lock().value(), 0);
    }

    #[test]
    fn other_threads_wait_for_the_handle() {
        let cell = Arc::new(ManagerCell::new(Simple(0)));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let cell = cell.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        cell.lock().bump();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(cell.lock().value(), 400);
    }

    #[test]
    fn rwlock_backed_handle_writes_through() {
        let lock = RwLock::new(Simple(5));
        ManagerGuard::<dyn Counter>::write(&lock).bump();
        assert_eq!(lock.read().unwrap().value(), 6);
    }
}
