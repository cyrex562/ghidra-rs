//! A debouncer for asynchronous events.
//!
//! Port of `ghidra.async.AsyncDebouncer`.

use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::async_timer::AsyncTimer;

/// A listener notified with the debouncer's settled value.
///
/// Analogous to Java's `java.util.function.Consumer<T>`.
pub type DebounceListener<T> = Arc<dyn Fn(T) + Send + Sync>;

struct Inner<T> {
    listeners: Vec<DebounceListener<T>>,
    /// `Some` while a `settled()` promise is outstanding for the *next* settle event, mirroring
    /// `settledPromise`. Held as a `watch` sender so, unlike a one-shot channel, multiple
    /// concurrent [`SettledFuture`]s subscribed to the same round can all observe the result --
    /// see [`AsyncDebouncer::settled`].
    settled_tx: Option<watch::Sender<Option<T>>>,
    /// Mirrors `lastContact`. `None` before the first [`AsyncDebouncer::contact`] call; Java's
    /// `T lastContact` field starts `null` for the same reason.
    last_contact: Option<T>,
    /// Mirrors `alarm`: the in-flight delayed task that will fire [`AsyncDebouncer::do_settled`]
    /// once the timing window elapses without further contact.
    alarm: Option<JoinHandle<()>>,
}

/// A debouncer for asynchronous events.
///
/// A debouncer has an input "contact" event and produces an output "settled" event once
/// sufficient time has passed since the last contact event. The goal is to prevent the needless
/// frequent firing of asynchronous events if the next event is going to negate the current one.
/// The idea is that a series of events, each negating the previous, can be fired within relative
/// temporal proximity. Without a debouncer, event processing time may be wasted. By passing the
/// events through a debouncer configured with a time window that contains all the events, only
/// the final event in the cluster will be processed. The cost of doing this is a waiting period,
/// so event processing may be less responsive, but will also be less frantic.
///
/// Port of `ghidra.async.AsyncDebouncer<T>`.
///
/// Java's `T lastContact`/`CompletableFuture<T> settled()`/`stable()` can carry a `null` `T`
/// (before any [`contact`](Self::contact) call). This port makes that possibility explicit by
/// returning `Option<T>` from [`AsyncDebouncer::settled`] and [`AsyncDebouncer::stable`], rather
/// than requiring `T` itself to carry a sentinel "no value yet" state.
pub struct AsyncDebouncer<T: Clone + Send + Sync + 'static> {
    timer: AsyncTimer,
    window_millis: i64,
    inner: Arc<Mutex<Inner<T>>>,
}

impl<T: Clone + Send + Sync + 'static> AsyncDebouncer<T> {
    /// Constructs a new debouncer.
    ///
    /// Mirrors `AsyncDebouncer(AsyncTimer timer, long windowMillis)`.
    pub fn new(timer: AsyncTimer, window_millis: i64) -> Self {
        Self {
            timer,
            window_millis,
            inner: Arc::new(Mutex::new(Inner {
                listeners: Vec::new(),
                settled_tx: None,
                last_contact: None,
                alarm: None,
            })),
        }
    }

    /// Adds a listener for the settled event.
    ///
    /// Mirrors `addListener(Consumer<T>)`.
    pub fn add_listener(&self, listener: DebounceListener<T>) {
        self.inner.lock().unwrap().listeners.push(listener);
    }

    /// Removes a listener from the settled event, by pointer identity (Rust closures have no
    /// `equals()`; this mirrors Java's `List.remove(Object)`, which for a `Consumer<T>` without a
    /// custom `equals()` also reduces to reference identity).
    ///
    /// Mirrors `removeListener(Consumer<T>)`.
    pub fn remove_listener(&self, listener: &DebounceListener<T>) {
        self.inner
            .lock()
            .unwrap()
            .listeners
            .retain(|l| !Arc::ptr_eq(l, listener));
    }

    /// Runs the settled-event machinery: notifies listeners and fulfills any outstanding
    /// [`settled`](Self::settled) promise with the current `last_contact`.
    ///
    /// Mirrors `doSettled()`.
    fn do_settled(inner: &Arc<Mutex<Inner<T>>>) {
        let (listeners, tx, last_contact) = {
            let mut guard = inner.lock().unwrap();
            guard.alarm = None;
            let listeners = guard.listeners.clone();
            let tx = guard.settled_tx.take();
            let last_contact = guard.last_contact.clone();
            (listeners, tx, last_contact)
        };
        let value = last_contact.expect(
            "do_settled is only reachable after contact() has set last_contact at least once",
        );
        for listener in &listeners {
            listener(value.clone());
        }
        if let Some(tx) = tx {
            let _ = tx.send(Some(value));
        }
    }

    /// Sends a contact event.
    ///
    /// This sets or resets the timer for the event window. The settled event will fire with the
    /// given value after this waiting period, unless another contact event occurs first.
    ///
    /// Mirrors `contact(T)`. Java's `alarm.cancel(false)` prevents the *previous* window's
    /// `thenRun(this::doSettled)` continuation from ever firing (`CompletableFuture.cancel`
    /// force-completes it exceptionally, and an exceptional completion never satisfies a
    /// `thenRun`); [`JoinHandle::abort`] is the direct Tokio analogue.
    pub fn contact(&self, val: T) {
        // Mark the window *now*, before taking the lock, mirroring `timer.mark().after(...)`
        // being evaluated at the moment `contact()` is called.
        let after = self.timer.mark().after(self.window_millis);

        let mut guard = self.inner.lock().unwrap();
        guard.last_contact = Some(val);
        if let Some(old_alarm) = guard.alarm.take() {
            old_alarm.abort();
        }

        let inner = Arc::clone(&self.inner);
        let handle = tokio::spawn(async move {
            after.await;
            Self::do_settled(&inner);
        });
        guard.alarm = Some(handle);
    }

    /// Receives the next settled event.
    ///
    /// The returned future completes *after* all registered listeners have been invoked.
    ///
    /// Mirrors `settled()`.
    pub fn settled(&self) -> SettledFuture<T> {
        let mut guard = self.inner.lock().unwrap();
        if guard.settled_tx.is_none() {
            let (tx, _rx) = watch::channel(None);
            guard.settled_tx = Some(tx);
        }
        let rx = guard.settled_tx.as_ref().unwrap().subscribe();
        SettledFuture { rx }
    }

    /// Waits for the debouncer to be stable.
    ///
    /// If the debouncer has not received a contact event within the event window, it's
    /// considered stable, and this returns the value of the last received contact event (or
    /// `None` if there has never been one) immediately. Otherwise, this waits for the next
    /// settled event, as in [`AsyncDebouncer::settled`].
    ///
    /// Mirrors `stable()`.
    pub async fn stable(&self) -> Option<T> {
        let immediate = {
            let guard = self.inner.lock().unwrap();
            if guard.alarm.is_none() {
                Some(guard.last_contact.clone())
            } else {
                None
            }
        };
        match immediate {
            Some(last) => last,
            None => self.settled().wait().await,
        }
    }
}

/// A future that resolves once with the debouncer's next settled value.
///
/// Rust analogue of the `CompletableFuture<T>` returned by
/// [`AsyncDebouncer::settled`]/[`AsyncDebouncer::stable`]. Backed by a [`tokio::sync::watch`]
/// receiver so that multiple `SettledFuture`s subscribed to the same round can each independently
/// wait for (and observe) the same eventual value, mirroring several callers holding the same
/// Java `CompletableFuture` reference.
pub struct SettledFuture<T> {
    rx: watch::Receiver<Option<T>>,
}

impl<T: Clone> SettledFuture<T> {
    /// Waits for the settle event this future was created for.
    pub async fn wait(mut self) -> Option<T> {
        loop {
            let current = self.rx.borrow().clone();
            if current.is_some() {
                return current;
            }
            if self.rx.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// A debouncer variant that settles immediately on every contact, bypassing the timing window
/// entirely.
///
/// Port of the nested `AsyncDebouncer.Bypass<T>` static class, which extends `AsyncDebouncer<T>`
/// and overrides only `contact(T)`. Rust has no inheritance, so this struct composes an
/// [`AsyncDebouncer`] instead, reusing its `settled`/`stable`/`add_listener`/`remove_listener`
/// unchanged and reimplementing only the overridden `contact`.
pub struct Bypass<T: Clone + Send + Sync + 'static> {
    base: AsyncDebouncer<T>,
}

impl<T: Clone + Send + Sync + 'static> Bypass<T> {
    /// Mirrors `Bypass()`, which forwards to `super(null, 0)`. Java's `null` timer is never
    /// dereferenced, since `contact` is fully overridden to never schedule an alarm; this port
    /// simply supplies a real (but likewise never-used-for-scheduling) [`AsyncTimer`], since
    /// `AsyncTimer` carries no state to diverge from a shared instance anyway.
    pub fn new() -> Self {
        Self {
            base: AsyncDebouncer::new(AsyncTimer::new(), 0),
        }
    }

    /// Mirrors the overridden `Bypass.contact(T)`: settles immediately with `val`, never
    /// scheduling (or waiting on) an alarm.
    pub fn contact(&self, val: T) {
        {
            let mut guard = self.base.inner.lock().unwrap();
            guard.last_contact = Some(val);
            if let Some(old_alarm) = guard.alarm.take() {
                old_alarm.abort();
            }
        }
        AsyncDebouncer::<T>::do_settled(&self.base.inner);
    }

    /// Delegates to the composed [`AsyncDebouncer::add_listener`].
    pub fn add_listener(&self, listener: DebounceListener<T>) {
        self.base.add_listener(listener);
    }

    /// Delegates to the composed [`AsyncDebouncer::remove_listener`].
    pub fn remove_listener(&self, listener: &DebounceListener<T>) {
        self.base.remove_listener(listener);
    }

    /// Delegates to the composed [`AsyncDebouncer::settled`].
    pub fn settled(&self) -> SettledFuture<T> {
        self.base.settled()
    }

    /// Delegates to the composed [`AsyncDebouncer::stable`].
    pub async fn stable(&self) -> Option<T> {
        self.base.stable().await
    }

    /// Returns a reference to the underlying [`AsyncDebouncer`].
    pub fn base(&self) -> &AsyncDebouncer<T> {
        &self.base
    }
}

impl<T: Clone + Send + Sync + 'static> Default for Bypass<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn contact_then_settled_delivers_the_last_value_after_the_window() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 30);
        let settled = debouncer.settled();
        debouncer.contact(1);
        debouncer.contact(2);
        debouncer.contact(3);

        let result = settled.wait().await;
        assert_eq!(result, Some(3));
    }

    #[tokio::test]
    async fn rapid_contacts_within_the_window_only_settle_once() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 40);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        debouncer.add_listener(Arc::new(move |_v: i32| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));

        for i in 0..5 {
            debouncer.contact(i);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let result = debouncer.settled().wait().await;
        assert_eq!(result, Some(4));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn listeners_are_notified_with_the_settled_value() {
        let debouncer: AsyncDebouncer<&'static str> = AsyncDebouncer::new(AsyncTimer::new(), 20);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        debouncer.add_listener(Arc::new(move |v: &'static str| {
            seen2.lock().unwrap().push(v);
        }));

        debouncer.contact("hello");
        let _ = debouncer.settled().wait().await;

        assert_eq!(*seen.lock().unwrap(), vec!["hello"]);
    }

    #[tokio::test]
    async fn remove_listener_stops_future_notifications() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 15);
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let listener: DebounceListener<i32> = Arc::new(move |_v| {
            count2.fetch_add(1, Ordering::SeqCst);
        });
        debouncer.add_listener(listener.clone());
        debouncer.remove_listener(&listener);

        debouncer.contact(1);
        let _ = debouncer.settled().wait().await;

        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stable_returns_none_immediately_before_any_contact() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 1_000);
        let start = Instant::now();
        let result = debouncer.stable().await;
        assert_eq!(result, None);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn stable_returns_immediately_once_the_window_has_already_elapsed() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 10);
        debouncer.contact(7);
        // Let the alarm fire and clear itself before calling `stable()`.
        tokio::time::sleep(Duration::from_millis(40)).await;

        let start = Instant::now();
        let result = debouncer.stable().await;
        assert_eq!(result, Some(7));
        assert!(start.elapsed() < Duration::from_millis(20));
    }

    #[tokio::test]
    async fn stable_waits_for_settlement_while_the_window_is_open() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 30);
        debouncer.contact(9);

        let result = debouncer.stable().await;
        assert_eq!(result, Some(9));
    }

    #[tokio::test]
    async fn settled_called_multiple_times_before_firing_returns_the_same_round() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 30);
        let first = debouncer.settled();
        let second = debouncer.settled();
        debouncer.contact(11);

        assert_eq!(first.wait().await, Some(11));
        assert_eq!(second.wait().await, Some(11));
    }

    #[tokio::test]
    async fn settled_called_after_a_round_fires_starts_a_fresh_round() {
        let debouncer: AsyncDebouncer<i32> = AsyncDebouncer::new(AsyncTimer::new(), 15);
        debouncer.contact(1);
        assert_eq!(debouncer.settled().wait().await, Some(1));

        let next = debouncer.settled();
        debouncer.contact(2);
        assert_eq!(next.wait().await, Some(2));
    }

    #[tokio::test]
    async fn bypass_settles_immediately_without_waiting_for_a_window() {
        let bypass: Bypass<i32> = Bypass::new();
        let start = Instant::now();
        let settled = bypass.settled();
        bypass.contact(42);
        let result = settled.wait().await;
        assert_eq!(result, Some(42));
        assert!(start.elapsed() < Duration::from_millis(20));
    }

    #[tokio::test]
    async fn bypass_notifies_listeners_on_every_contact() {
        let bypass: Bypass<i32> = Bypass::new();
        let values = Arc::new(Mutex::new(Vec::new()));
        let values2 = Arc::clone(&values);
        bypass.add_listener(Arc::new(move |v: i32| {
            values2.lock().unwrap().push(v);
        }));

        bypass.contact(1);
        bypass.contact(2);
        bypass.contact(3);

        assert_eq!(*values.lock().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn bypass_stable_reflects_the_last_contact_immediately() {
        let bypass: Bypass<i32> = Bypass::new();
        bypass.contact(5);
        let result = bypass.stable().await;
        assert_eq!(result, Some(5));
    }
}
