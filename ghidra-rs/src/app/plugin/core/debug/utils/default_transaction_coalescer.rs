//! Port of `ghidra.app.plugin.core.debug.utils.DefaultTransactionCoalescer`.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::framework::model::DomainObject;
use crate::util::async_debouncer::AsyncDebouncer;
use crate::util::async_timer::AsyncTimer;
use crate::util::msg::Msg;

use super::transaction_coalescer::{CoalescedTx, TransactionCoalescer, TxFactory};

/// Mirrors the `U extends AutoCloseable` bound on the Java class. Ported the same way this
/// crate ports every other bare `AutoCloseable` bound (e.g. `TraceObjectManager`'s
/// `BypassWriteCache`): an explicit `close`. Fallible, mirroring `AutoCloseable.close() throws
/// Exception` -- Java's `Coalescer.settled` catches and logs whatever `tid.close()` throws
/// rather than propagating it, which [`Coalescer::settled`] reproduces via
/// [`Msg::error_with_error`].
pub trait AutoCloseableTx: Send + Sync {
    /// Closes the underlying transaction.
    fn close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Per-round coalescing state: tracks how many entrants are still "inside" the coalesced
/// transaction, and closes the underlying transaction once the last one exits *and* the debounce
/// window has elapsed with no new entrants.
///
/// Port of the private nested `DefaultTransactionCoalescer.Coalescer` class.
///
/// # Differences from Java
/// Java's `debouncer.addListener(this::settled)` captures `this` (the `Coalescer`) with a plain
/// strong reference -- harmless there since the JVM's GC collects the resulting `Coalescer` <->
/// `AsyncDebouncer` listener cycle once both become unreachable. `Arc` cannot collect cycles, so
/// this port's listener closure instead captures a [`Weak`] reference to the [`Coalescer`],
/// upgrading it only when the listener actually fires; if the `Coalescer` were somehow already
/// gone by then there is nothing left to settle, so the upgrade failing is silently a no-op.
struct Coalescer<U: AutoCloseableTx> {
    debouncer: AsyncDebouncer<()>,
    tid: Mutex<Option<U>>,
    active_count: AtomicI32,
}

impl<U: AutoCloseableTx + 'static> Coalescer<U> {
    /// Port of `Coalescer(String description)`.
    fn new<T, F>(
        obj: &T,
        factory: &F,
        description: &str,
        delay_ms: i64,
        tx_cell: Arc<Mutex<Option<Arc<Coalescer<U>>>>>,
    ) -> Arc<Self>
    where
        T: DomainObject,
        F: TxFactory<T, U>,
    {
        let tid = factory.apply(obj, description);
        // Java: `new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, delayMs)`. `AsyncTimer` carries
        // no state of its own (see its own docs), so a fresh instance behaves identically to the
        // shared `DEFAULT_TIMER` here.
        let debouncer = AsyncDebouncer::new(AsyncTimer::new(), delay_ms);

        let coalescer = Arc::new(Coalescer {
            debouncer,
            tid: Mutex::new(Some(tid)),
            active_count: AtomicI32::new(0),
        });

        let weak_self = Arc::downgrade(&coalescer);
        coalescer.debouncer.add_listener(Arc::new(move |_: ()| {
            if let Some(this) = weak_self.upgrade() {
                Coalescer::settled(&this, &tx_cell);
            }
        }));

        coalescer
    }

    /// Port of `Coalescer.enter()`.
    fn enter(&self) {
        self.active_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Port of `Coalescer.exit()`.
    fn exit(&self) {
        if self.active_count.fetch_sub(1, Ordering::SeqCst) - 1 == 0 {
            self.debouncer.contact(());
        }
    }

    /// Port of `Coalescer.settled(Void)`.
    fn settled(self: &Arc<Self>, tx_cell: &Mutex<Option<Arc<Coalescer<U>>>>) {
        let mut guard = tx_cell.lock().unwrap();
        if self.active_count.load(Ordering::SeqCst) == 0 {
            if let Some(mut tid) = self.tid.lock().unwrap().take() {
                if let Err(e) = tid.close() {
                    Msg::error_with_error(
                        "DefaultTransactionCoalescer",
                        &"Could not close transaction: ",
                        e.as_ref(),
                    );
                }
            }
            *guard = None;
        }
    }
}

/// The [`CoalescedTx`] returned from [`DefaultTransactionCoalescer::start`].
///
/// Port of `DefaultTransactionCoalescer.DefaultCoalescedTx`.
///
/// # Preserved bug: operates on "whichever round is current", not "the round it entered"
/// Java's `DefaultCoalescedTx` holds **no** reference to the particular `Coalescer` it entered;
/// `close()` reads the *outer* class's `tx` field fresh, at call time, and calls `exit()` on
/// whatever that currently is -- the Java source flags this itself with a `// TODO: This smells
/// really bad` comment on the `tx == null` guard. If a handle's round has already fully settled
/// (so `tx` moved on to a new, unrelated round) by the time `close()` is finally called, this
/// erroneously decrements the *new* round's `active_count` instead of doing nothing, which can
/// cause that unrelated round's underlying transaction to close early. This port reproduces the
/// bug exactly (see
/// [`stale_close_after_a_new_round_started_affects_the_wrong_round`](tests::stale_close_after_a_new_round_started_affects_the_wrong_round)),
/// rather than capturing "its own" round -- [`DefaultCoalescedTx`] holds only a clone of the
/// shared `tx` cell, exactly like the outer class.
pub struct DefaultCoalescedTx<U: AutoCloseableTx> {
    lock: Arc<Mutex<Option<Arc<Coalescer<U>>>>>,
}

impl<U: AutoCloseableTx + 'static> DefaultCoalescedTx<U> {
    /// Port of `DefaultCoalescedTx(String description)`.
    fn new<T, F>(
        obj: &T,
        factory: &F,
        description: &str,
        delay_ms: i64,
        lock: Arc<Mutex<Option<Arc<Coalescer<U>>>>>,
    ) -> Self
    where
        T: DomainObject,
        F: TxFactory<T, U>,
    {
        {
            let mut guard = lock.lock().unwrap();
            if guard.is_none() {
                *guard = Some(Coalescer::new(obj, factory, description, delay_ms, Arc::clone(&lock)));
            }
            let coalescer = guard.as_ref().unwrap().clone();
            drop(guard);
            coalescer.enter();
        }
        DefaultCoalescedTx { lock }
    }
}

impl<U: AutoCloseableTx + 'static> CoalescedTx for DefaultCoalescedTx<U> {
    /// Port of `DefaultCoalescedTx.close()`. See this type's own doc comment for the "operates on
    /// whatever round is current" bug this faithfully reproduces.
    fn close(&mut self) {
        let guard = self.lock.lock().unwrap();
        let Some(coalescer) = guard.as_ref() else {
            // Java: `// TODO: This smells really bad` -- `tx == null`, so there's nothing to do.
            return;
        };
        let coalescer = Arc::clone(coalescer);
        drop(guard);
        coalescer.exit();
    }
}

/// Coalesces transactions on a [`DomainObject`], so that many short-lived, closely-spaced
/// transactions collapse into a single underlying transaction that only actually closes once
/// activity has quieted down for a configurable delay.
///
/// Port of `ghidra.app.plugin.core.debug.utils.DefaultTransactionCoalescer<T, U>`.
///
/// # Differences from Java
/// Java's `TxFactory<? super T, U>` (contravariant in `T`) is ported as the crate's existing
/// [`TxFactory<T, U>`] directly -- Rust has no use-site variance to model the wildcard, and every
/// real caller supplies a factory keyed to exactly `T` anyway.
pub struct DefaultTransactionCoalescer<T: DomainObject, F: TxFactory<T, U>, U: AutoCloseableTx> {
    obj: T,
    factory: F,
    delay_ms: i64,
    tx: Arc<Mutex<Option<Arc<Coalescer<U>>>>>,
}

impl<T, F, U> DefaultTransactionCoalescer<T, F, U>
where
    T: DomainObject,
    F: TxFactory<T, U>,
    U: AutoCloseableTx + 'static,
{
    /// Port of `DefaultTransactionCoalescer(T obj, TxFactory<? super T, U> factory, int
    /// delayMs)`.
    pub fn new(obj: T, factory: F, delay_ms: i64) -> Self {
        DefaultTransactionCoalescer { obj, factory, delay_ms, tx: Arc::new(Mutex::new(None)) }
    }
}

impl<T, F, U> TransactionCoalescer for DefaultTransactionCoalescer<T, F, U>
where
    T: DomainObject,
    F: TxFactory<T, U>,
    U: AutoCloseableTx + 'static,
{
    /// Port of `DefaultTransactionCoalescer.start(String)`.
    fn start(&self, description: &str) -> Box<dyn CoalescedTx> {
        Box::new(DefaultCoalescedTx::new(
            &self.obj,
            &self.factory,
            description,
            self.delay_ms,
            Arc::clone(&self.tx),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    struct MockObj;
    impl DomainObject for MockObj {}

    /// A fake transaction handle: records opens/closes into shared counters so tests can observe
    /// exactly how many real transactions were opened/closed, and when.
    struct FakeTx {
        id: u32,
        closed: Arc<Mutex<Vec<u32>>>,
    }

    impl AutoCloseableTx for FakeTx {
        fn close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.closed.lock().unwrap().push(self.id);
            Ok(())
        }
    }

    struct FakeTxFactory {
        next_id: AtomicI32,
        opened: Arc<Mutex<Vec<u32>>>,
        closed: Arc<Mutex<Vec<u32>>>,
    }

    impl FakeTxFactory {
        fn new() -> (Self, Arc<Mutex<Vec<u32>>>, Arc<Mutex<Vec<u32>>>) {
            let opened = Arc::new(Mutex::new(Vec::new()));
            let closed = Arc::new(Mutex::new(Vec::new()));
            (
                FakeTxFactory { next_id: AtomicI32::new(0), opened: opened.clone(), closed: closed.clone() },
                opened,
                closed,
            )
        }
    }

    impl TxFactory<MockObj, FakeTx> for FakeTxFactory {
        fn apply(&self, _obj: &MockObj, _description: &str) -> FakeTx {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
            self.opened.lock().unwrap().push(id);
            FakeTx { id, closed: self.closed.clone() }
        }
    }

    /// A [`TxFactory`] whose produced transaction always fails to close, to exercise the
    /// `Msg::error_with_error` logging path. `Send`/`Sync` since `TxFactory: Send + Sync`.
    struct FailingTx;
    impl AutoCloseableTx for FailingTx {
        fn close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("boom".into())
        }
    }
    struct FailingTxFactory;
    impl TxFactory<MockObj, FailingTx> for FailingTxFactory {
        fn apply(&self, _obj: &MockObj, _description: &str) -> FailingTx {
            FailingTx
        }
    }

    #[tokio::test]
    async fn a_single_start_close_pair_opens_and_closes_one_transaction() {
        let (factory, opened, closed) = FakeTxFactory::new();
        let coalescer = DefaultTransactionCoalescer::new(MockObj, factory, 10);

        let mut tx = coalescer.start("test");
        assert_eq!(*opened.lock().unwrap(), vec![0]);
        assert!(closed.lock().unwrap().is_empty());

        tx.close();
        // The transaction is not closed synchronously -- it only closes once the debounce
        // window elapses with active_count still at zero.
        assert!(closed.lock().unwrap().is_empty());

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(*closed.lock().unwrap(), vec![0]);
    }

    #[tokio::test]
    async fn nested_starts_coalesce_into_a_single_underlying_transaction() {
        let (factory, opened, closed) = FakeTxFactory::new();
        let coalescer = DefaultTransactionCoalescer::new(MockObj, factory, 20);

        let mut a = coalescer.start("a");
        let mut b = coalescer.start("b");
        // Only one underlying transaction was opened for both coalesced handles.
        assert_eq!(*opened.lock().unwrap(), vec![0]);

        a.close();
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Closing only one of the two entrants keeps the transaction open (active_count still 1).
        assert!(closed.lock().unwrap().is_empty());

        b.close();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(*closed.lock().unwrap(), vec![0]);
    }

    #[tokio::test]
    async fn a_new_round_starts_after_the_previous_one_settles() {
        let (factory, opened, closed) = FakeTxFactory::new();
        let coalescer = DefaultTransactionCoalescer::new(MockObj, factory, 15);

        let mut first = coalescer.start("first");
        first.close();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*closed.lock().unwrap(), vec![0]);

        let mut second = coalescer.start("second");
        assert_eq!(*opened.lock().unwrap(), vec![0, 1]);
        second.close();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*closed.lock().unwrap(), vec![0, 1]);
    }

    #[tokio::test]
    async fn close_of_a_failing_transaction_is_logged_not_propagated() {
        // Mirrors Java's `catch (Exception e) { Msg.error(...); }` -- close() never panics even
        // though the underlying AutoCloseable's close() always errors.
        let coalescer = DefaultTransactionCoalescer::new(MockObj, FailingTxFactory, 10);
        let mut tx = coalescer.start("test");
        tx.close();
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Reaching here without panicking is the assertion.
    }

    #[tokio::test]
    async fn stale_close_after_a_new_round_started_affects_the_wrong_round() {
        // Faithful reproduction of the "smells really bad" Java bug documented on
        // `DefaultCoalescedTx`: a handle from a round that has already fully settled, when
        // closed *after* a new round has started, erroneously decrements the new round's
        // active_count instead of being a no-op.
        let (factory, opened, closed) = FakeTxFactory::new();
        let coalescer = DefaultTransactionCoalescer::new(MockObj, factory, 15);

        // Round A: two entrants, only one closed -- the other (`stale`) is deliberately never
        // closed via the normal path, so it survives to be misused later.
        let mut a1 = coalescer.start("a1");
        let stale = coalescer.start("a2");
        a1.close();
        // Round A hasn't settled yet (active_count still 1 from `stale`).
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(closed.lock().unwrap().is_empty());

        // Force round A to settle by closing `stale` too, through the *normal* path this once.
        // (We need a second, still-outstanding "stale" handle to demonstrate the bug -- so
        // re-derive it after round A is confirmed closed.)
        let mut stale = stale;
        stale.close();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(*closed.lock().unwrap(), vec![0]);

        // Round B starts fresh. Its own entrant never calls close() -- from the caller's
        // perspective this transaction is still legitimately open.
        let _b = coalescer.start("b");
        assert_eq!(*opened.lock().unwrap(), vec![0, 1]);

        // Build a *second* stale handle manually (the same shape `DefaultCoalescedTx` always
        // has -- just a clone of the shared `tx` cell) representing "a handle whose round
        // already finished," then close it. Per the Java bug, this incorrectly targets round B.
        let stale_from_a = DefaultCoalescedTxTestHandle { lock: coalescer_tx_cell(&coalescer) };
        drop(stale_from_a.close_and_forget());

        tokio::time::sleep(Duration::from_millis(60)).await;
        // Bug reproduced: round B's transaction closed even though its real entrant (`_b`) never
        // called close().
        assert_eq!(*closed.lock().unwrap(), vec![0, 1]);
    }

    /// Test-only helper that reaches into a [`DefaultTransactionCoalescer`]'s private `tx` cell,
    /// standing in for `DefaultTransactionCoalescer.this.tx` -- the exact thing
    /// `DefaultCoalescedTx.close()` reads fresh on every call (the "TODO: smells really bad"
    /// shape). Exists only so the dedicated bug test above can construct an extra, independent
    /// handle over the *same* shared cell, exactly as calling `coalescer.start(..)` a second time
    /// would (minus the `enter()` bookkeeping, which is what makes it "stale").
    struct DefaultCoalescedTxTestHandle<U: AutoCloseableTx> {
        lock: Arc<Mutex<Option<Arc<Coalescer<U>>>>>,
    }

    impl<U: AutoCloseableTx + 'static> DefaultCoalescedTxTestHandle<U> {
        fn close_and_forget(&self) -> bool {
            let guard = self.lock.lock().unwrap();
            let Some(coalescer) = guard.as_ref() else {
                return false;
            };
            let coalescer = Arc::clone(coalescer);
            drop(guard);
            coalescer.exit();
            true
        }
    }

    fn coalescer_tx_cell<T, F, U>(
        coalescer: &DefaultTransactionCoalescer<T, F, U>,
    ) -> Arc<Mutex<Option<Arc<Coalescer<U>>>>>
    where
        T: DomainObject,
        F: TxFactory<T, U>,
        U: AutoCloseableTx + 'static,
    {
        Arc::clone(&coalescer.tx)
    }

    #[test]
    fn auto_closeable_tx_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn AutoCloseableTx>>();
        let _ = AtomicBool::new(false);
    }
}
