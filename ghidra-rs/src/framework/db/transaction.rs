//! Port of `db.Transaction`.
//!
//! Java's `Transaction` is an abstract `AutoCloseable` providing try-with-resources syntax over
//! a database transaction:
//! ```java
//! try (Transaction tx = dbHandle.openTransaction(dbErrorHandler)) {
//!     // ... Do something
//! }
//! ```
//! Its single abstract method, `endTransaction(boolean)`, is supplied by each concrete call site
//! (e.g. `DBHandle.openTransaction` returns an anonymous subclass whose `endTransaction` calls
//! back into `DBHandle.endTransaction(txId, commit)`; `DomainObjectAdapterDB` has its own
//! `DomainObjectTransaction` subclass, which additionally overrides `isSubTransaction()` to
//! return `true`).
//!
//! Following this crate's composition-over-inheritance convention (and mirroring
//! [`LockHold`](crate::util::lock_hold::LockHold), the existing port of another
//! `AutoCloseable`-shaped Java RAII type), the single abstract method becomes the [`EndTransaction`]
//! trait, and the concrete `Transaction` class becomes a generic RAII guard,
//! [`Transaction<T>`](Transaction), parameterized over its `EndTransaction` implementor. Rust's
//! `Drop` stands in for Java relying on try-with-resources to invoke `close()`; unlike Java,
//! `close`/`abort`/`commit` are also exposed as ordinary methods so callers who are not using a
//! scoped block can still end the transaction explicitly, exactly as Java callers may (and as
//! `DBHandle`'s own javadoc example shows, using `dbHandle.startTransaction()`/
//! `program.endTransaction(txid, true)` directly instead of the try-with-resources form).
//!
//! `endTransaction`'s `boolean` return (whether anything was actually committed) is deliberately
//! discarded by `abort`/`commit`/`close`, matching Java: all three are declared `void` in
//! `Transaction`, even though the abstract `endTransaction` they call returns `boolean`.

/// The operation a [`Transaction`] guard invokes to actually end the underlying database
/// transaction. Stands in for `Transaction`'s single abstract method,
/// `endTransaction(boolean commit)`.
///
/// A concrete implementor typically captures whatever transaction id / handle it needs (mirroring
/// Java's anonymous-subclass call sites in `DBHandle.openTransaction` and
/// `DomainObjectAdapterDB.DomainObjectTransaction`).
pub trait EndTransaction {
    /// End the transaction if it is currently active.
    ///
    /// `commit` is true if changes should be committed, false if all changes in this transaction
    /// should be discarded (rollback). Returns true if changes were committed, false if there was
    /// nothing to commit or `commit` was false.
    fn end_transaction(&mut self, commit: bool) -> bool;
}

/// RAII guard providing scoped-block syntax for opening a database transaction.
///
/// Port of `db.Transaction`. Java relies on `AutoCloseable` plus try-with-resources to guarantee
/// the transaction ends when the block exits (including via exception); this port relies on
/// [`Drop`] for the same guarantee, including across an unwinding panic.
///
/// # Example
/// ```
/// # use ghidra_rs::framework::db::transaction::{EndTransaction, Transaction};
/// struct FakeHandle { committed: Option<bool> }
/// impl EndTransaction for FakeHandle {
///     fn end_transaction(&mut self, commit: bool) -> bool {
///         self.committed = Some(commit);
///         commit
///     }
/// }
/// let handle = FakeHandle { committed: None };
/// {
///     let _tx = Transaction::new(handle);
///     // ... do something ...
/// } // transaction commits here, since `abort_on_close` was never called
/// ```
pub struct Transaction<T: EndTransaction> {
    inner: T,
    /// Whether the transaction should commit (`true`) or roll back (`false`) when it ends.
    /// Defaults to `true`, matching Java's `private boolean commit = true;`.
    commit: bool,
    /// Whether the transaction is still active. Once ended (by `abort`, `commit`, or `close`,
    /// including the implicit `close` performed by `Drop`), further end-attempts are no-ops.
    /// Matches Java's `private boolean open = true;`.
    open: bool,
    /// Matches the value `isSubTransaction()` is overridden to return for a given concrete
    /// subclass in Java (`false` by default; `DomainObjectAdapterDB.DomainObjectTransaction`
    /// overrides it to `true`). Since neither known override carries any extra logic beyond the
    /// fixed return value, it is captured as plain, constructor-supplied state here rather than
    /// as a second trait method.
    sub_transaction: bool,
}

impl<T: EndTransaction> Transaction<T> {
    /// Wraps `inner` in a new, open transaction that will commit on close by default.
    ///
    /// Matches Java's `protected Transaction()` as invoked by a normal (non-sub-transaction)
    /// concrete subclass, e.g. `DBHandle.openTransaction`'s anonymous `Transaction`.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            commit: true,
            open: true,
            sub_transaction: false,
        }
    }

    /// Wraps `inner` in a new, open transaction marked as a sub-transaction of some larger
    /// transaction.
    ///
    /// Matches Java's `protected Transaction()` as invoked by a subclass that overrides
    /// `isSubTransaction()` to return `true`, e.g.
    /// `DomainObjectAdapterDB.DomainObjectTransaction`.
    pub fn new_sub_transaction(inner: T) -> Self {
        Self {
            inner,
            commit: true,
            open: true,
            sub_transaction: true,
        }
    }

    /// Determine if this is a sub-transaction to a larger transaction.
    ///
    /// If true, the larger transaction will not complete until all sub-transactions have ended,
    /// and will roll back upon completion if any sub-transaction did not commit.
    pub fn is_sub_transaction(&self) -> bool {
        self.sub_transaction
    }

    /// Mark transaction for rollback/non-commit upon closing.
    ///
    /// A subsequent call to [`Transaction::commit_on_close`] will alter this state prior to
    /// closing.
    pub fn abort_on_close(&mut self) {
        self.commit = false;
    }

    /// Mark transaction for commit upon closing.
    ///
    /// This state is assumed by default. A subsequent call to [`Transaction::abort_on_close`]
    /// will alter this state prior to closing.
    pub fn commit_on_close(&mut self) {
        self.commit = true;
    }

    /// Mark transaction for rollback/non-commit and end the transaction if it is active.
    pub fn abort(&mut self) {
        if self.open {
            self.open = false;
            self.inner.end_transaction(false);
        }
    }

    /// Mark transaction for commit and end the transaction if it is active.
    pub fn commit(&mut self) {
        if self.open {
            self.open = false;
            self.inner.end_transaction(true);
        }
    }

    /// End this transaction if active, using the current commit-on-close state.
    ///
    /// See [`Transaction::commit_on_close`] / [`Transaction::abort_on_close`]. Called
    /// automatically on drop (see the [`Drop`] impl below), but may also be called explicitly,
    /// matching Java's `AutoCloseable.close()` being callable directly as well as implicitly via
    /// try-with-resources.
    pub fn close(&mut self) {
        if self.open {
            self.open = false;
            self.inner.end_transaction(self.commit);
        }
    }
}

impl<T: EndTransaction> Drop for Transaction<T> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingHandle {
        ended: Vec<bool>,
    }

    impl RecordingHandle {
        fn new() -> Self {
            Self { ended: Vec::new() }
        }
    }

    impl EndTransaction for RecordingHandle {
        fn end_transaction(&mut self, commit: bool) -> bool {
            self.ended.push(commit);
            commit
        }
    }

    #[test]
    fn defaults_to_commit_on_close_and_is_not_a_sub_transaction() {
        let tx = Transaction::new(RecordingHandle::new());
        assert!(!tx.is_sub_transaction());
        drop(tx);
    }

    #[test]
    fn drop_commits_by_default() {
        let mut ended = None;
        {
            struct Probe<'a>(&'a mut Option<bool>);
            impl<'a> EndTransaction for Probe<'a> {
                fn end_transaction(&mut self, commit: bool) -> bool {
                    *self.0 = Some(commit);
                    commit
                }
            }
            let _tx = Transaction::new(Probe(&mut ended));
        }
        assert_eq!(ended, Some(true));
    }

    #[test]
    fn abort_on_close_causes_rollback_on_drop() {
        let mut ended = None;
        {
            struct Probe<'a>(&'a mut Option<bool>);
            impl<'a> EndTransaction for Probe<'a> {
                fn end_transaction(&mut self, commit: bool) -> bool {
                    *self.0 = Some(commit);
                    commit
                }
            }
            let mut tx = Transaction::new(Probe(&mut ended));
            tx.abort_on_close();
        }
        assert_eq!(ended, Some(false));
    }

    #[test]
    fn commit_on_close_after_abort_on_close_reverts_to_commit() {
        let mut ended = None;
        {
            struct Probe<'a>(&'a mut Option<bool>);
            impl<'a> EndTransaction for Probe<'a> {
                fn end_transaction(&mut self, commit: bool) -> bool {
                    *self.0 = Some(commit);
                    commit
                }
            }
            let mut tx = Transaction::new(Probe(&mut ended));
            tx.abort_on_close();
            tx.commit_on_close();
        }
        assert_eq!(ended, Some(true));
    }

    #[test]
    fn explicit_abort_ends_immediately_and_is_idempotent() {
        let mut handle = RecordingHandle::new();
        {
            struct Ref<'a>(&'a mut RecordingHandle);
            impl<'a> EndTransaction for Ref<'a> {
                fn end_transaction(&mut self, commit: bool) -> bool {
                    self.0.end_transaction(commit)
                }
            }
            let mut tx = Transaction::new(Ref(&mut handle));
            tx.abort();
            // A second abort (and the eventual Drop-triggered close) must be a no-op: Java's
            // `open` guard means `endTransaction` runs at most once regardless of how many of
            // `abort`/`commit`/`close` are subsequently invoked.
            tx.abort();
            tx.commit();
        }
        assert_eq!(handle.ended, vec![false]);
    }

    #[test]
    fn explicit_commit_ends_immediately_and_close_after_is_a_no_op() {
        let mut handle = RecordingHandle::new();
        {
            struct Ref<'a>(&'a mut RecordingHandle);
            impl<'a> EndTransaction for Ref<'a> {
                fn end_transaction(&mut self, commit: bool) -> bool {
                    self.0.end_transaction(commit)
                }
            }
            let mut tx = Transaction::new(Ref(&mut handle));
            tx.commit();
            tx.close();
        }
        assert_eq!(handle.ended, vec![true]);
    }

    #[test]
    fn explicit_close_uses_current_commit_state_and_drop_after_is_a_no_op() {
        let mut handle = RecordingHandle::new();
        {
            struct Ref<'a>(&'a mut RecordingHandle);
            impl<'a> EndTransaction for Ref<'a> {
                fn end_transaction(&mut self, commit: bool) -> bool {
                    self.0.end_transaction(commit)
                }
            }
            let mut tx = Transaction::new(Ref(&mut handle));
            tx.abort_on_close();
            tx.close();
        }
        assert_eq!(handle.ended, vec![false]);
    }

    #[test]
    fn sub_transaction_reports_true() {
        let tx = Transaction::new_sub_transaction(RecordingHandle::new());
        assert!(tx.is_sub_transaction());
    }

    #[test]
    fn transaction_ends_on_panic_unwind_matching_try_with_resources() {
        let handle = std::sync::Arc::new(std::sync::Mutex::new(RecordingHandle::new()));
        let handle2 = handle.clone();
        struct Shared(std::sync::Arc<std::sync::Mutex<RecordingHandle>>);
        impl EndTransaction for Shared {
            fn end_transaction(&mut self, commit: bool) -> bool {
                self.0.lock().unwrap().end_transaction(commit)
            }
        }
        let result = std::panic::catch_unwind(move || {
            let _tx = Transaction::new(Shared(handle2));
            panic!("intentional");
        });
        assert!(result.is_err());
        assert_eq!(handle.lock().unwrap().ended, vec![true]);
    }
}
