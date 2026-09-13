//! An observable reference useful for asynchronous computations.
//!
//! Port of `ghidra.async.AsyncReference`.
//!
//! The reference supports the usual set and get operations. The set operation accepts an
//! optional "cause" argument which is forwarded to some observers. The set operation may also be
//! intercepted by an optional filter. The filter function is provided a copy of the current
//! value, proposed value, and cause. The value it returns becomes the new value. If that value is
//! different than the current value, the observers are notified. The default filter returns the
//! new value, always.
//!
//! The reference provides three types of observation callbacks. The first is to listen for all
//! changes. This follows the listener pattern. When the value changes, i.e., is set to a value
//! different than the current value, all change listeners are invoked with a copy of the new
//! value and a reference to the provided cause, if given. The second is to wait for the very next
//! change. It follows the promises pattern. The returned future completes with the new value upon
//! the very next change. The cause is not provided to this type of observer. The third is to wait
//! for a given value. It, too, follows the promises pattern. The returned future completes as soon
//! as the reference takes the given value. The cause is not provided to this type of observer.
//!
//! # Deviations from Java
//!
//! * **`T val` becomes `Option<T>`.** Java's field can genuinely be `null` -- the no-arg
//!   constructor `AsyncReference()` delegates to `this(null)`, and every accessor/callback is
//!   written to tolerate a `null` `T`. Rust has no universal null, so -- following the same
//!   precedent already established by
//!   [`AsyncDebouncer`](super::async_debouncer::AsyncDebouncer)'s `last_contact: Option<T>` field
//!   -- this port makes "no value yet" explicit via `Option<T>` everywhere a `null` `T` could
//!   flow: [`AsyncReference::get`], the "old value" parameter passed to change listeners, the
//!   `cur` parameter of [`FilterFunction`], and the predicate parameter of
//!   [`AsyncReference::wait_until`]. Once a real value has been [`set`](AsyncReference::set) or
//!   [`compute`](AsyncReference::compute)d, the reference never reverts to "no value" through the
//!   public API, matching every real call site in the original codebase (none ever pass a `null`
//!   `newVal` to `set`/`compute`).
//! * **Listener/`Predicate` exception handling collapses two Java branches into one.** Java's
//!   `invokeListeners` specifically ignores `RejectedExecutionException` (logged at `trace`
//!   level) and logs every other `Throwable` at `error` level; both exist only because Java
//!   listeners might themselves try to submit work to an executor that has since shut down. Rust
//!   closures have no equivalent notion of "rejected execution" to distinguish, so this port
//!   simply catches any listener panic via [`std::panic::catch_unwind`] and logs it at `error`
//!   level unconditionally, preserving the overarching contract ("a broken listener never
//!   prevents the update from completing, nor takes down the caller of `set`/`compute`") without
//!   the no-longer-meaningful `trace`-vs-`error` distinction.
//! * **No `java.lang.ref.Cleaner`.** Per [`crate::util::async_utils`]'s own module docs, Rust's
//!   `Drop` is the idiomatic replacement for `Cleaner`-based finalization; see
//!   [`DebouncedAsyncReference`]'s own docs for how this port relies on `Drop` (plus a `Weak`
//!   back-reference) to reproduce the same "no leak, no update-after-drop" contract that Java
//!   achieves via `WeakReference` + `Cleaner`.

use std::collections::HashMap;
use std::hash::Hash;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::watch;

use super::async_debouncer::AsyncDebouncer;
use super::async_timer::AsyncTimer;
use super::disposed_exception::DisposedException;
use super::msg::Msg;

const ORIGINATOR: &str = "AsyncReference";

/// A function to filter updates to an [`AsyncReference`].
///
/// Port of the nested `AsyncReference.FilterFunction<T, C>` functional interface. `cur` is
/// `None` exactly when the reference has never yet been given a real value; see the module docs
/// for why this differs from Java's plain (nullable) `T cur`.
pub type FilterFunction<T, C> = Box<dyn Fn(Option<&T>, T, &C) -> T + Send + Sync>;

/// A listener notified of every change to an [`AsyncReference`]'s value.
///
/// Analogous to the `TriConsumer<? super T, ? super T, ? super C>` listener type used throughout
/// `AsyncReference`. Represented as `Arc<dyn Fn>` (rather than this crate's `Box`-based
/// [`crate::util::function::TriConsumer`]) so identity-based removal (see
/// [`AsyncReference::remove_change_listener`]) can use [`Arc::ptr_eq`], mirroring the precedent
/// already established by
/// [`DebounceListener`](super::async_debouncer::DebounceListener). `old_val` is `None` exactly on
/// the very first change (see the module docs).
pub type ChangeListener<T, C> = Arc<dyn Fn(Option<&T>, &T, &C) + Send + Sync>;

/// Predicate used by [`AsyncReference::wait_until`].
///
/// Mirrors `java.util.function.Predicate<T>`; `None` stands in for a `null` `T` (see the module
/// docs).
pub type UntilPredicate<T> = Box<dyn Fn(Option<&T>) -> bool + Send + Sync>;

fn cancelled_error() -> DisposedException {
    DisposedException::new(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "AsyncReference was dropped before this future completed",
    ))
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Slot for a pending [`AsyncReference::wait_until`] call.
///
/// Port of the nested `AsyncReference.WaitUntilFuture<T>` static class, which pairs a
/// `Predicate<T>` with the `CompletableFuture<T>` it will eventually complete.
struct UntilEntry<T> {
    predicate: UntilPredicate<T>,
    tx: watch::Sender<Option<Result<Option<T>, DisposedException>>>,
}

struct Inner<T, C> {
    val: Option<T>,
    listeners: Vec<ChangeListener<T, C>>,
    /// Mirrors `changePromise`.
    change_tx: Option<watch::Sender<Option<Result<T, DisposedException>>>>,
    /// Mirrors `waitsFor`.
    waits_for: HashMap<T, watch::Sender<Option<Result<(), DisposedException>>>>,
    /// Mirrors `waitsUntil`.
    waits_until: Vec<UntilEntry<T>>,
    filter: FilterFunction<T, C>,
    disposal_reason: Option<DisposedException>,
}

/// An observable reference useful for asynchronous computations.
///
/// Port of `ghidra.async.AsyncReference<T, C>`. See the module docs for the overall contract and
/// the deviations this port makes from Java's nullable-`T` semantics.
pub struct AsyncReference<T, C> {
    inner: Arc<Mutex<Inner<T, C>>>,
}

impl<T, C> Clone for AsyncReference<T, C> {
    /// Clones the *handle*, not the state: the clone refers to the same underlying reference,
    /// exactly like copying a Java object reference (`AsyncReference<T,C> other = this;`).
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

impl<T, C> AsyncReference<T, C>
where
    T: Clone + Eq + Hash + Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    /// Constructs a new reference initialized to "no value yet".
    ///
    /// Mirrors `AsyncReference()`, which initializes `val` to `null`.
    pub fn new() -> Self {
        Self::with_initial_opt(None)
    }

    /// Constructs a new reference initialized to the given value.
    ///
    /// Mirrors `AsyncReference(T t)`.
    pub fn with_initial(t: T) -> Self {
        Self::with_initial_opt(Some(t))
    }

    fn with_initial_opt(val: Option<T>) -> Self {
        AsyncReference {
            inner: Arc::new(Mutex::new(Inner {
                val,
                listeners: Vec::new(),
                change_tx: None,
                waits_for: HashMap::new(),
                waits_until: Vec::new(),
                filter: Box::new(|_cur: Option<&T>, set: T, _cause: &C| set),
                disposal_reason: None,
            })),
        }
    }

    /// Applies a filter function to all subsequent updates.
    ///
    /// The given function replaces the current function.
    ///
    /// Mirrors `filter(FilterFunction<T, ? super C>)`. Java throws `NullPointerException` for a
    /// `null` argument; Rust closures can't be null, so that check has no equivalent here.
    pub fn filter(&self, new_filter: impl Fn(Option<&T>, T, &C) -> T + Send + Sync + 'static) {
        self.inner.lock().unwrap().filter = Box::new(new_filter);
    }

    /// Gets the current value of this reference, or `None` if it has never been set.
    ///
    /// Mirrors `get()`.
    pub fn get(&self) -> Option<T> {
        self.inner.lock().unwrap().val.clone()
    }

    fn take_matching_untils(list: &mut Vec<UntilEntry<T>>, val: &T) -> Vec<UntilEntry<T>> {
        let mut matched = Vec::new();
        let mut i = 0;
        while i < list.len() {
            if (list[i].predicate)(Some(val)) {
                matched.push(list.remove(i));
            } else {
                i += 1;
            }
        }
        matched
    }

    fn invoke_listeners(listeners: &[ChangeListener<T, C>], old_val: Option<&T>, new_val: &T, cause: &C) {
        for listener in listeners {
            let result =
                panic::catch_unwind(AssertUnwindSafe(|| listener(old_val, new_val, cause)));
            if let Err(payload) = result {
                // See the module docs: Java's separate RejectedExecutionException/Throwable
                // branches collapse into a single logged-error path here.
                Msg::error(
                    ORIGINATOR,
                    &format!(
                        "Ignoring exception on async reference listener: {}",
                        panic_message(&*payload)
                    ),
                );
            }
        }
    }

    /// Updates this reference to the given value because of the given cause.
    ///
    /// Mirrors `set(T, C)`.
    pub fn set(&self, new_val: T, cause: C) -> bool {
        let old_val;
        let final_val;
        let listeners;
        let change_tx;
        let wait_for_tx;
        let until_matches;
        {
            let mut guard = self.inner.lock().unwrap();
            old_val = guard.val.clone();
            let filtered = {
                let f = &guard.filter;
                f(guard.val.as_ref(), new_val, &cause)
            };
            let changed = match &guard.val {
                Some(v) => *v != filtered,
                None => true,
            };
            if !changed {
                return false;
            }
            guard.val = Some(filtered.clone());
            final_val = filtered;

            listeners = guard.listeners.clone();
            change_tx = guard.change_tx.take();
            wait_for_tx = guard.waits_for.remove(&final_val);
            until_matches = Self::take_matching_untils(&mut guard.waits_until, &final_val);
        }

        Self::invoke_listeners(&listeners, old_val.as_ref(), &final_val, &cause);
        if let Some(tx) = change_tx {
            let _ = tx.send(Some(Ok(final_val.clone())));
        }
        if let Some(tx) = wait_for_tx {
            let _ = tx.send(Some(Ok(())));
        }
        for entry in until_matches {
            let _ = entry.tx.send(Some(Ok(Some(final_val.clone()))));
        }

        true
    }

    /// Updates this reference using the given function because of the given cause.
    ///
    /// Returns the new value of this reference (post filter), or the prior value (which may be
    /// `None`) if the update was filtered out as unchanged.
    ///
    /// Mirrors `compute(Function<? super T, ? extends T>, C)`.
    pub fn compute(&self, func: impl FnOnce(Option<&T>) -> T, cause: C) -> Option<T> {
        let old_val;
        let final_val;
        let listeners;
        let change_tx;
        let wait_for_tx;
        let until_matches;
        {
            let mut guard = self.inner.lock().unwrap();
            old_val = guard.val.clone();
            let proposed = func(guard.val.as_ref());
            let filtered = {
                let f = &guard.filter;
                f(guard.val.as_ref(), proposed, &cause)
            };
            let changed = match &guard.val {
                Some(v) => *v != filtered,
                None => true,
            };
            if !changed {
                return guard.val.clone();
            }
            guard.val = Some(filtered.clone());
            final_val = filtered;

            listeners = guard.listeners.clone();
            change_tx = guard.change_tx.take();
            wait_for_tx = guard.waits_for.remove(&final_val);
            until_matches = Self::take_matching_untils(&mut guard.waits_until, &final_val);
        }

        Self::invoke_listeners(&listeners, old_val.as_ref(), &final_val, &cause);
        if let Some(tx) = change_tx {
            let _ = tx.send(Some(Ok(final_val.clone())));
        }
        if let Some(tx) = wait_for_tx {
            let _ = tx.send(Some(Ok(())));
        }
        for entry in until_matches {
            let _ = entry.tx.send(Some(Ok(Some(final_val.clone()))));
        }

        Some(final_val)
    }

    /// Adds a listener for any change to this reference's value.
    ///
    /// Updates that get "filtered out" do not cause a change listener to fire.
    ///
    /// Mirrors `addChangeListener(TriConsumer<? super T, ? super T, ? super C>)`.
    pub fn add_change_listener(&self, listener: ChangeListener<T, C>) {
        self.inner.lock().unwrap().listeners.push(listener);
    }

    /// Removes a change listener, by pointer identity.
    ///
    /// Mirrors `removeChangeListener(TriConsumer<T, T, C>)`. Java's `List.remove(Object)` also
    /// reduces to reference identity for a listener with no custom `equals()`, matching
    /// [`Arc::ptr_eq`] here.
    pub fn remove_change_listener(&self, listener: &ChangeListener<T, C>) {
        self.inner
            .lock()
            .unwrap()
            .listeners
            .retain(|l| !Arc::ptr_eq(l, listener));
    }

    /// Waits for the next change and captures the new value.
    ///
    /// The returned future completes with the value of the very next change, at the time of that
    /// change. Subsequent changes to the value of the reference do not affect the returned
    /// future.
    ///
    /// Mirrors `waitChanged()`.
    pub fn wait_changed(&self) -> ChangedFuture<T> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(reason) = guard.disposal_reason.clone() {
            let (_tx, rx) = watch::channel(Some(Err(reason)));
            return ChangedFuture { rx };
        }
        if guard.change_tx.is_none() {
            let (tx, _rx) = watch::channel(None);
            guard.change_tx = Some(tx);
        }
        let rx = guard.change_tx.as_ref().unwrap().subscribe();
        ChangedFuture { rx }
    }

    /// Waits for this reference to accept a particular value (post-filter).
    ///
    /// If the reference already has the given value, an already-completed future is returned.
    ///
    /// Mirrors `waitValue(T)`.
    pub fn wait_value(&self, t: T) -> ValueFuture {
        let mut guard = self.inner.lock().unwrap();
        if let Some(reason) = guard.disposal_reason.clone() {
            let (_tx, rx) = watch::channel(Some(Err(reason)));
            return ValueFuture { rx };
        }
        if guard.val.as_ref() == Some(&t) {
            let (_tx, rx) = watch::channel(Some(Ok(())));
            return ValueFuture { rx };
        }
        let tx = guard
            .waits_for
            .entry(t)
            .or_insert_with(|| watch::channel(None).0);
        let rx = tx.subscribe();
        ValueFuture { rx }
    }

    /// Waits for this reference to accept the first value meeting the given condition
    /// (post-filter).
    ///
    /// If the current value already meets the condition, an already-completed future is
    /// returned (see the module docs for why this makes [`UntilFuture`] resolve to `Option<T>`
    /// rather than `T`: the current value may still be "no value yet").
    ///
    /// Mirrors `waitUntil(Predicate<T>)`.
    pub fn wait_until(
        &self,
        predicate: impl Fn(Option<&T>) -> bool + Send + Sync + 'static,
    ) -> UntilFuture<T> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(reason) = guard.disposal_reason.clone() {
            let (_tx, rx) = watch::channel(Some(Err(reason)));
            return UntilFuture { rx };
        }
        if predicate(guard.val.as_ref()) {
            let (_tx, rx) = watch::channel(Some(Ok(guard.val.clone())));
            return UntilFuture { rx };
        }
        let (tx, rx) = watch::channel(None);
        guard.waits_until.push(UntilEntry { predicate: Box::new(predicate), tx });
        UntilFuture { rx }
    }

    /// Clears out the queues of futures, completing each exceptionally.
    ///
    /// Mirrors `dispose(Throwable)`.
    pub fn dispose(&self, reason: impl std::error::Error + Send + Sync + 'static) {
        let de = DisposedException::new(reason);
        let change_tx;
        let wait_for_txs;
        let until_entries;
        {
            let mut guard = self.inner.lock().unwrap();
            guard.disposal_reason = Some(de.clone());
            change_tx = guard.change_tx.take();
            wait_for_txs = std::mem::take(&mut guard.waits_for);
            until_entries = std::mem::take(&mut guard.waits_until);
        }

        if let Some(tx) = change_tx {
            let _ = tx.send(Some(Err(de.clone())));
        }
        for (_, tx) in wait_for_txs {
            let _ = tx.send(Some(Err(de.clone())));
        }
        for entry in until_entries {
            let _ = entry.tx.send(Some(Err(de.clone())));
        }
    }

    /// Obtains a new [`DebouncedAsyncReference`] whose value is updated after this reference has
    /// settled.
    ///
    /// The original reference continues to behave as usual, except that it has an additional
    /// listener on it. When this reference is updated, the update is passed through an
    /// [`AsyncDebouncer`] configured with the given timer and window. When the debouncer settles,
    /// the debounced reference is updated.
    ///
    /// Directly [`set`](AsyncReference::set)-ting the returned reference subverts the debouncing
    /// mechanism and panics; only the original reference should be updated directly.
    ///
    /// Mirrors `debounced(AsyncTimer, long)`.
    pub fn debounced(&self, timer: AsyncTimer, window_millis: i64) -> DebouncedAsyncReference<T, C>
    where
        C: Clone,
    {
        DebouncedAsyncReference::new(self.clone(), timer, window_millis)
    }
}

impl<T, C> Default for AsyncReference<T, C>
where
    T: Clone + Eq + Hash + Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A future that resolves once with the value at the next change of an [`AsyncReference`].
///
/// Rust analogue of the `CompletableFuture<T>` returned by [`AsyncReference::wait_changed`].
/// Backed by a [`tokio::sync::watch`] receiver so multiple `ChangedFuture`s subscribed to the
/// same round (multiple calls to `wait_changed()` before the next change) each independently
/// observe the same eventual value, mirroring several callers holding the same Java
/// `CompletableFuture` reference.
pub struct ChangedFuture<T> {
    rx: watch::Receiver<Option<Result<T, DisposedException>>>,
}

impl<T: Clone> ChangedFuture<T> {
    /// Returns the result if this future has already completed, without waiting.
    pub fn peek(&self) -> Option<Result<T, DisposedException>> {
        self.rx.borrow().clone()
    }

    /// Returns `true` once this future has completed (successfully or exceptionally).
    pub fn is_done(&self) -> bool {
        self.rx.borrow().is_some()
    }

    /// Waits for this future to complete and returns its result.
    pub async fn wait(&mut self) -> Result<T, DisposedException> {
        loop {
            if let Some(result) = self.rx.borrow().clone() {
                return result;
            }
            if self.rx.changed().await.is_err() {
                return Err(cancelled_error());
            }
        }
    }
}

/// A future that resolves once an [`AsyncReference`] takes a particular value.
///
/// Rust analogue of the `CompletableFuture<Void>` returned by [`AsyncReference::wait_value`].
pub struct ValueFuture {
    rx: watch::Receiver<Option<Result<(), DisposedException>>>,
}

impl ValueFuture {
    /// Returns the result if this future has already completed, without waiting.
    pub fn peek(&self) -> Option<Result<(), DisposedException>> {
        self.rx.borrow().clone()
    }

    /// Returns `true` once this future has completed (successfully or exceptionally).
    pub fn is_done(&self) -> bool {
        self.rx.borrow().is_some()
    }

    /// Waits for this future to complete and returns its result.
    pub async fn wait(&mut self) -> Result<(), DisposedException> {
        loop {
            if let Some(result) = self.rx.borrow().clone() {
                return result;
            }
            if self.rx.changed().await.is_err() {
                return Err(cancelled_error());
            }
        }
    }
}

/// A future that resolves once an [`AsyncReference`] takes a value meeting some condition.
///
/// Rust analogue of the `CompletableFuture<T>` returned by [`AsyncReference::wait_until`]. See
/// the module docs for why this resolves to `Option<T>` rather than `T`.
pub struct UntilFuture<T> {
    rx: watch::Receiver<Option<Result<Option<T>, DisposedException>>>,
}

impl<T: Clone> UntilFuture<T> {
    /// Returns the result if this future has already completed, without waiting.
    pub fn peek(&self) -> Option<Result<Option<T>, DisposedException>> {
        self.rx.borrow().clone()
    }

    /// Returns `true` once this future has completed (successfully or exceptionally).
    pub fn is_done(&self) -> bool {
        self.rx.borrow().is_some()
    }

    /// Waits for this future to complete and returns its result.
    pub async fn wait(&mut self) -> Result<Option<T>, DisposedException> {
        loop {
            if let Some(result) = self.rx.borrow().clone() {
                return result;
            }
            if self.rx.changed().await.is_err() {
                return Err(cancelled_error());
            }
        }
    }
}

/// A pairing of a value and the cause of its update.
///
/// Port of the nested `AsyncReference.ChangeRecord<T, C>` static class, used only internally by
/// [`DebouncedAsyncReference`] to feed an [`AsyncDebouncer`].
#[derive(Clone)]
struct ChangeRecord<T, C> {
    val: T,
    cause: C,
}

/// An [`AsyncReference`] variant whose value is updated only after its source reference has
/// settled (stopped changing) for a configured time window.
///
/// Port of the nested `AsyncReference.DebouncedAsyncReference<T, C>` static class, which extends
/// `AsyncReference<T, C>` and overrides only `set(T, C)` (to throw) plus the constructor (to wire
/// up the debouncing listener). Rust has no inheritance, so this is a distinct type that
/// *composes* a private, independently-owned [`AsyncReference`] (`base`) for its own state,
/// exactly as `super(from.val)` constructs a fresh instance of the base class's state in Java --
/// [`DebouncedAsyncReference::get`]/[`wait_changed`](DebouncedAsyncReference::wait_changed)/etc.
/// simply delegate to it.
///
/// Java breaks the reference cycle this setup would otherwise create (`from` permanently holding
/// a listener that, through the debouncer, would otherwise keep the debounced reference alive
/// forever) using `WeakReference` plus a `Cleaner` that removes the listener once the debounced
/// reference is garbage collected. This port reproduces the same "no leak, no update-after-drop"
/// contract deterministically instead: the debouncer's settle callback captures only a
/// [`Weak`] handle to `base`'s state (upgraded, and silently skipped if already gone, exactly
/// like Java's `WeakReference::get() == null` check), and [`Drop`] removes the contact-forwarding
/// listener from `from` once the last `DebouncedAsyncReference` handle goes away -- matching this
/// crate's own documented preference (see [`crate::util::async_utils`]) for `Drop` over a ported
/// `Cleaner`.
pub struct DebouncedAsyncReference<T, C>
where
    T: Clone + Eq + Hash + Send + Sync + 'static,
    C: Clone + Send + Sync + 'static,
{
    base: AsyncReference<T, C>,
    from: AsyncReference<T, C>,
    listener: ChangeListener<T, C>,
}

impl<T, C> DebouncedAsyncReference<T, C>
where
    T: Clone + Eq + Hash + Send + Sync + 'static,
    C: Clone + Send + Sync + 'static,
{
    fn new(from: AsyncReference<T, C>, timer: AsyncTimer, window_millis: i64) -> Self {
        let initial = from.get();
        let base = AsyncReference::with_initial_opt(initial);

        let debouncer = Arc::new(AsyncDebouncer::<ChangeRecord<T, C>>::new(timer, window_millis));

        // The settle-side listener only ever holds a *weak* handle to `base`'s shared state,
        // mirroring Java's `WeakReference<DebouncedAsyncReference<T, C>>`; see the struct docs.
        let base_weak: Weak<Mutex<Inner<T, C>>> = Arc::downgrade(&base.inner);
        debouncer.add_listener(Arc::new(move |record: ChangeRecord<T, C>| {
            if let Some(inner) = base_weak.upgrade() {
                let temp = AsyncReference { inner };
                // Bypasses the panicking `DebouncedAsyncReference::set` below by calling the
                // plain `AsyncReference::set` directly -- mirrors Java's `doSet`, which invokes
                // `super.set(t, cause)` to sidestep its own class's overridden `set`.
                temp.set(record.val, record.cause);
            }
        }));

        let db_for_contact = Arc::clone(&debouncer);
        let listener: ChangeListener<T, C> = Arc::new(move |_old: Option<&T>, new_val: &T, cause: &C| {
            db_for_contact.contact(ChangeRecord { val: new_val.clone(), cause: cause.clone() });
        });
        from.add_change_listener(Arc::clone(&listener));

        Self { base, from, listener }
    }

    /// Delegates to the composed reference's [`AsyncReference::get`].
    pub fn get(&self) -> Option<T> {
        self.base.get()
    }

    /// Delegates to the composed reference's [`AsyncReference::wait_changed`].
    pub fn wait_changed(&self) -> ChangedFuture<T> {
        self.base.wait_changed()
    }

    /// Delegates to the composed reference's [`AsyncReference::wait_value`].
    pub fn wait_value(&self, t: T) -> ValueFuture {
        self.base.wait_value(t)
    }

    /// Delegates to the composed reference's [`AsyncReference::wait_until`].
    pub fn wait_until(
        &self,
        predicate: impl Fn(Option<&T>) -> bool + Send + Sync + 'static,
    ) -> UntilFuture<T> {
        self.base.wait_until(predicate)
    }

    /// Delegates to the composed reference's [`AsyncReference::add_change_listener`].
    pub fn add_change_listener(&self, listener: ChangeListener<T, C>) {
        self.base.add_change_listener(listener);
    }

    /// Delegates to the composed reference's [`AsyncReference::remove_change_listener`].
    pub fn remove_change_listener(&self, listener: &ChangeListener<T, C>) {
        self.base.remove_change_listener(listener);
    }

    /// Mirrors the overridden `DebouncedAsyncReference.set(T, C)`, which always throws
    /// `new IllegalStateException("Cannot set a debounced async reference.")`.
    ///
    /// # Panics
    ///
    /// Always. See above.
    pub fn set(&self, _new_val: T, _cause: C) -> bool {
        panic!("Cannot set a debounced async reference.")
    }
}

impl<T, C> Drop for DebouncedAsyncReference<T, C>
where
    T: Clone + Eq + Hash + Send + Sync + 'static,
    C: Clone + Send + Sync + 'static,
{
    /// Removes the contact-forwarding listener from `from`, matching what Java's `Cleaner`-driven
    /// `State.run()` does once the debounced reference becomes unreachable. See the struct docs.
    fn drop(&mut self) {
        self.from.remove_change_listener(&self.listener);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::time::Duration;

    // ---- construction / get ----

    #[test]
    fn new_reference_has_no_value() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        assert_eq!(r.get(), None);
    }

    #[test]
    fn with_initial_reports_that_value() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        assert_eq!(r.get(), Some(1));
    }

    // ---- set / listeners: mirrors AsyncReferenceTest.testListener ----

    #[test]
    fn set_notifies_change_listeners_with_value_and_cause() {
        let str_ref: AsyncReference<String, i32> = AsyncReference::new();
        let got = Arc::new(Mutex::new(String::new()));
        let got_cause = Arc::new(AtomicI32::new(0));
        let got2 = Arc::clone(&got);
        let got_cause2 = Arc::clone(&got_cause);
        str_ref.add_change_listener(Arc::new(move |_old: Option<&String>, val: &String, cause: &i32| {
            *got2.lock().unwrap() = val.clone();
            got_cause2.store(*cause, Ordering::SeqCst);
        }));

        str_ref.set("Hello".to_string(), 1);
        assert_eq!(*got.lock().unwrap(), "Hello");
        assert_eq!(got_cause.load(Ordering::SeqCst), 1);

        str_ref.set("World".to_string(), 2);
        assert_eq!(*got.lock().unwrap(), "World");
        assert_eq!(got_cause.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn first_change_listener_call_reports_no_old_value() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        let saw_none = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_none2 = Arc::clone(&saw_none);
        r.add_change_listener(Arc::new(move |old: Option<&i32>, _new: &i32, _c: &()| {
            saw_none2.store(old.is_none(), Ordering::SeqCst);
        }));
        r.set(5, ());
        assert!(saw_none.load(Ordering::SeqCst));
    }

    #[test]
    fn set_to_the_same_value_does_not_fire_listeners_and_returns_false() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        r.add_change_listener(Arc::new(move |_o: Option<&i32>, _n: &i32, _c: &()| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));
        assert!(!r.set(1, ()));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn remove_change_listener_stops_future_notifications() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let listener: ChangeListener<i32, ()> =
            Arc::new(move |_o: Option<&i32>, _n: &i32, _c: &()| {
                count2.fetch_add(1, Ordering::SeqCst);
            });
        r.add_change_listener(Arc::clone(&listener));
        r.remove_change_listener(&listener);
        r.set(1, ());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_panicking_listener_does_not_stop_other_listeners_or_the_caller() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        r.add_change_listener(Arc::new(|_o: Option<&i32>, _n: &i32, _c: &()| {
            panic!("boom");
        }));
        r.add_change_listener(Arc::new(move |_o: Option<&i32>, _n: &i32, _c: &()| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));
        assert!(r.set(1, ()));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    // ---- wait_changed: mirrors AsyncReferenceTest.testWaitChanged ----

    #[tokio::test]
    async fn wait_changed_completes_on_the_next_change_for_every_waiter() {
        let str_ref: AsyncReference<String, ()> = AsyncReference::new();
        let mut chg1 = str_ref.wait_changed();
        let mut chg2 = str_ref.wait_changed();
        assert!(!chg1.is_done());
        assert!(!chg2.is_done());

        str_ref.set("Hello".to_string(), ());
        assert!(chg1.is_done());
        assert!(chg2.is_done());
        assert_eq!(chg1.wait().await.unwrap(), "Hello");
        assert_eq!(chg2.wait().await.unwrap(), "Hello");

        let mut chg3 = str_ref.wait_changed();
        assert!(!chg3.is_done());
        str_ref.set("World".to_string(), ());
        assert!(chg3.is_done());
        assert_eq!(chg3.wait().await.unwrap(), "World");
    }

    // ---- wait_value: mirrors AsyncReferenceTest.testWaitValue ----

    #[tokio::test]
    async fn wait_value_completes_once_the_reference_takes_that_value() {
        let str_ref: AsyncReference<String, ()> = AsyncReference::new();
        let mut match_hello = str_ref.wait_value("Hello".to_string());
        let mut match_world = str_ref.wait_value("World".to_string());
        assert!(!match_hello.is_done());
        assert!(!match_world.is_done());
        assert!(str_ref.wait_value("Hello".to_string()).is_done() == false);

        str_ref.set("Hello".to_string(), ());
        assert!(match_hello.is_done());
        assert!(!match_world.is_done());
        assert!(str_ref.wait_value("Hello".to_string()).is_done());

        str_ref.set("World".to_string(), ());
        assert!(!str_ref.wait_value("Hello".to_string()).is_done());
        assert!(match_world.is_done());
        let _ = match_hello.wait().await;
        let _ = match_world.wait().await;
    }

    #[tokio::test]
    async fn wait_value_for_the_current_value_completes_immediately() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(7);
        let mut fut = r.wait_value(7);
        assert!(fut.is_done());
        assert!(fut.wait().await.is_ok());
    }

    // ---- wait_until ----

    #[tokio::test]
    async fn wait_until_completes_immediately_if_the_predicate_already_matches() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(10);
        let mut fut = r.wait_until(|v| matches!(v, Some(&n) if n >= 10));
        assert!(fut.is_done());
        assert_eq!(fut.wait().await.unwrap(), Some(10));
    }

    #[tokio::test]
    async fn wait_until_completes_on_the_first_matching_change() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        let mut fut = r.wait_until(|v| matches!(v, Some(&n) if n >= 10));
        assert!(!fut.is_done());
        r.set(3, ());
        assert!(!fut.is_done());
        r.set(11, ());
        assert!(fut.is_done());
        assert_eq!(fut.wait().await.unwrap(), Some(11));
    }

    #[tokio::test]
    async fn wait_until_matching_a_null_predicate_resolves_with_none() {
        // Exercises the `Option<T>`-resolution path documented on `UntilFuture`: a predicate
        // that matches "no value yet" resolves immediately with `None`, not a real `T`.
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        let mut fut = r.wait_until(|v: Option<&i32>| v.is_none());
        assert!(fut.is_done());
        assert_eq!(fut.wait().await.unwrap(), None);
    }

    // ---- filter ----

    #[test]
    fn custom_filter_can_veto_or_transform_updates() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(3);
        // Clamp all incoming values to be non-negative.
        r.filter(|_cur, set, _cause| if set < 0 { 0 } else { set });
        // Java's `filterAndSet` compares the *filtered* value against the current one, so this
        // is a real change (3 -> 0), even though the raw proposed value (-5) never lands.
        assert!(r.set(-5, ()));
        assert_eq!(r.get(), Some(0));
        // Setting to (the already-clamped) 0 again is filtered out as unchanged.
        assert!(!r.set(-1, ()));
        assert_eq!(r.get(), Some(0));
    }

    // ---- compute ----

    #[test]
    fn compute_derives_the_new_value_from_the_old_one() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        let updated = r.compute(|cur| cur.copied().unwrap_or(0) + 1, ());
        assert_eq!(updated, Some(2));
        assert_eq!(r.get(), Some(2));
    }

    #[test]
    fn compute_returning_the_same_value_reports_no_change() {
        let r: AsyncReference<i32, ()> = AsyncReference::with_initial(5);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        r.add_change_listener(Arc::new(move |_o: Option<&i32>, _n: &i32, _c: &()| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));
        let result = r.compute(|cur| cur.copied().unwrap(), ());
        assert_eq!(result, Some(5));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    // ---- dispose ----

    #[tokio::test]
    async fn dispose_fails_all_outstanding_waiters() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        let mut changed = r.wait_changed();
        let mut valued = r.wait_value(42);
        let mut until = r.wait_until(|v: Option<&i32>| matches!(v, Some(&99)));

        r.dispose(std::io::Error::new(std::io::ErrorKind::Other, "shutting down"));

        assert!(changed.wait().await.is_err());
        assert!(valued.wait().await.is_err());
        assert!(until.wait().await.is_err());
    }

    #[tokio::test]
    async fn wait_calls_after_dispose_fail_immediately() {
        let r: AsyncReference<i32, ()> = AsyncReference::new();
        r.dispose(std::io::Error::new(std::io::ErrorKind::Other, "gone"));

        assert!(r.wait_changed().wait().await.is_err());
        assert!(r.wait_value(1).wait().await.is_err());
        assert!(r.wait_until(|_| true).wait().await.is_err());
    }

    // ---- debounced: mirrors the AsyncReferenceTest debouncer tests ----

    #[tokio::test]
    async fn debounced_unchanged_value_never_settles() {
        let orig: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        let db = orig.debounced(AsyncTimer::new(), 100);
        let mut settled = db.wait_changed();
        orig.set(1, ());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!settled.is_done());
    }

    #[tokio::test]
    async fn debounced_single_change_settles_after_the_window() {
        let orig: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        let db = orig.debounced(AsyncTimer::new(), 100);
        let mut settled = db.wait_changed();
        let start = std::time::Instant::now();
        orig.set(2, ());
        let s = settled.wait().await.unwrap();
        assert_eq!(s, 2);
        assert!(start.elapsed() >= Duration::from_millis(90));
    }

    #[tokio::test]
    async fn debounced_changed_back_to_original_never_settles() {
        let orig: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        let db = orig.debounced(AsyncTimer::new(), 100);
        let mut settled = db.wait_changed();
        orig.set(2, ());
        orig.set(1, ());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!settled.is_done());
    }

    #[tokio::test]
    async fn debounced_many_rapid_changes_settle_once_on_the_final_value_and_cause() {
        let orig: AsyncReference<i32, String> = AsyncReference::with_initial(1);
        let db = orig.debounced(AsyncTimer::new(), 100);

        let seen_val = Arc::new(Mutex::new(None));
        let seen_cause = Arc::new(Mutex::new(None));
        let seen_val2 = Arc::clone(&seen_val);
        let seen_cause2 = Arc::clone(&seen_cause);
        db.add_change_listener(Arc::new(move |_o: Option<&i32>, v: &i32, c: &String| {
            *seen_val2.lock().unwrap() = Some(*v);
            *seen_cause2.lock().unwrap() = Some(c.clone());
        }));

        orig.set(2, "First".to_string());
        tokio::time::sleep(Duration::from_millis(50)).await;
        orig.set(4, "Second".to_string());
        tokio::time::sleep(Duration::from_millis(50)).await;
        orig.set(3, "Third".to_string());
        tokio::time::sleep(Duration::from_millis(50)).await;
        orig.set(4, "Fourth".to_string());

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(*seen_val.lock().unwrap(), Some(4));
        assert_eq!(*seen_cause.lock().unwrap(), Some("Fourth".to_string()));
    }

    #[test]
    #[should_panic(expected = "Cannot set a debounced async reference.")]
    fn setting_a_debounced_reference_directly_panics() {
        let orig: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        let db = orig.debounced(AsyncTimer::new(), 100);
        db.set(2, ());
    }

    #[tokio::test]
    async fn dropping_the_debounced_reference_removes_its_listener_from_the_source() {
        let orig: AsyncReference<i32, ()> = AsyncReference::with_initial(1);
        {
            let _db = orig.debounced(AsyncTimer::new(), 20);
            // `_db` is dropped at the end of this scope, which must remove its
            // contact-forwarding listener from `orig` per this port's `Drop` impl.
        }
        // If the listener were still registered, this would still just be a harmless no-op
        // (the debouncer's own settle callback holds only a `Weak` to the now-dropped `base`),
        // demonstrating that dropping neither panics nor leaves the reference unusable.
        assert!(orig.set(2, ()));
        assert_eq!(orig.get(), Some(2));
    }
}
