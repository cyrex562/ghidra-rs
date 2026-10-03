//! A map of cached values computed upon the first request, asynchronously.
//!
//! Port of `ghidra.async.AsyncLazyMap`.
//!
//! Each key present in the cache behaves similarly to [`AsyncLazyValue`](super::AsyncLazyValue).
//! The cache starts empty. Whenever a key is requested, a computation for that key is started,
//! but a future is immediately returned. If the computation succeeds, the completed future is
//! cached indefinitely, and the result is recorded. Any subsequent requests for the same key
//! return the same future, even if the computation for that key has not yet completed. Thus, when
//! it completes, all requests for that key will be fulfilled by the result of the first request.
//! If the computation completes exceptionally, the key is optionally removed from the cache.
//! Thus, a subsequent request for a failed key may retry the computation.
//!
//! Values can also be provided "out of band." That is, they may be provided by an alternative
//! computation. This is accomplished using [`AsyncLazyMap::get_with`], [`AsyncLazyMap::put`] or
//! [`AsyncLazyMap::put_value`]. The last immediately provides a value and completes any
//! outstanding requests, even if there was an active computation for the key. The first claims
//! the key and promises to provide the value at a later time.
//!
//! At any point, a snapshot of the completed, cached values may be obtained.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use super::async_lazy_value::ArcError;

type BoxFuture<V> = Pin<Box<dyn Future<Output = Result<V, ArcError>> + Send + 'static>>;
type ComputeFn<K, V> = dyn Fn(K) -> BoxFuture<V> + Send + Sync;
type ForgetErrorsFn<K> = dyn Fn(&K, &ArcError) -> bool + Send + Sync;
type ForgetValuesFn<K, V> = dyn Fn(&K, &V) -> bool + Send + Sync;

/// A resolution slot for one key: a `watch` channel plus the sender kept around for identity
/// comparisons (see [`AsyncLazyMap::finish`]) and for late completion via
/// [`AsyncLazyMap::put_value`]/[`AsyncLazyMap::put`].
struct Slot<V> {
    tx: watch::Sender<Option<Result<V, ArcError>>>,
    rx: watch::Receiver<Option<Result<V, ArcError>>>,
}

impl<V> Clone for Slot<V> {
    fn clone(&self) -> Self {
        Slot {
            tx: self.tx.clone(),
            rx: self.rx.clone(),
        }
    }
}

fn cancelled_error() -> ArcError {
    Arc::new(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "computation was cancelled before completion",
    ))
}

/// A future tied to the key that produced it.
///
/// Port of the nested `AsyncLazyMap.KeyedFuture<K, V>`, a `CompletableFuture<V>` subclass that
/// additionally remembers its originating key. Java's version *is* a `CompletableFuture`, so
/// callers chain directly onto it. Rust has no equivalent "resolves once, `Clone`, multi-consumer
/// future" in the standard library, so this port is backed by a [`tokio::sync::watch`] channel
/// instead: every clone of a `KeyedFuture` observes the same eventual result, mirroring
/// "subsequent requests for the same key return the same future."
#[derive(Clone)]
pub struct KeyedFuture<K, V> {
    key: K,
    rx: watch::Receiver<Option<Result<V, ArcError>>>,
}

impl<K: Clone, V: Clone> KeyedFuture<K, V> {
    /// Mirrors `KeyedFuture.getKey()`.
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Returns the value if the future has already completed, without waiting.
    ///
    /// Analogous to checking `future.isDone()` then reading `future.getNow(null)` on the Java
    /// `KeyedFuture`.
    pub fn peek(&self) -> Option<Result<V, ArcError>> {
        self.rx.borrow().clone()
    }

    /// Returns `true` once the future has completed (successfully or not).
    pub fn is_done(&self) -> bool {
        self.rx.borrow().is_some()
    }

    /// Waits for the future to complete and returns its result.
    ///
    /// Mirrors awaiting the `CompletableFuture<V>` itself.
    pub async fn wait(&mut self) -> Result<V, ArcError> {
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

/// A promise handed back by [`AsyncLazyMap::put`], analogous to the `KeyedFuture<K, V>` that Java
/// returns from `put(K)` -- split into a separate consumer/producer pair, following the same
/// `AsyncLazyValue`/`Completer` precedent in this crate, since Rust's `KeyedFuture` (unlike
/// Java's, which literally *is* a `CompletableFuture`) is a read-only observer handle and cannot
/// also serve as the thing the caller completes.
pub struct KeyedCompleter<K, V> {
    key: K,
    tx: watch::Sender<Option<Result<V, ArcError>>>,
}

impl<K, V> KeyedCompleter<K, V> {
    /// Fulfills the promise with a successful value.
    pub fn complete(self, value: V) {
        let _ = self.tx.send(Some(Ok(value)));
    }

    /// Fulfills the promise with a failure.
    pub fn fail(self, error: ArcError) {
        let _ = self.tx.send(Some(Err(error)));
    }

    /// The key this completer was created for.
    pub fn key(&self) -> &K {
        &self.key
    }
}

struct Inner<K, V> {
    /// Every key ever requested/provided and not yet forgotten/removed, whether its computation
    /// is still pending or already resolved. Mirrors `futures`.
    futures: HashMap<K, Slot<V>>,
    /// Successfully completed (and not forgotten) values. Mirrors `map`.
    map: HashMap<K, V>,
    forget_errors: Arc<ForgetErrorsFn<K>>,
    forget_values: Arc<ForgetValuesFn<K, V>>,
}

/// A map of cached values computed upon the first request, asynchronously.
///
/// Port of `ghidra.async.AsyncLazyMap<K, V>`. See the module docs for the overall contract.
pub struct AsyncLazyMap<K: Eq + Hash + Clone + Send + Sync + 'static, V: Clone + Send + Sync + 'static>
{
    inner: Arc<Mutex<Inner<K, V>>>,
    function: Arc<ComputeFn<K, V>>,
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static, V: Clone + Send + Sync + 'static>
    AsyncLazyMap<K, V>
{
    /// Constructs a lazy map for the given function.
    ///
    /// Mirrors `AsyncLazyMap(Map<K, V> map, Function<K, CompletableFuture<V>> function)`. Java's
    /// constructor additionally takes the backing `Map<K, V>` the lazy map is to have "exclusive
    /// reference to"; this port always uses an internal `HashMap` instead, since safely sharing
    /// external ownership of that map is not achievable in Rust without the same synchronization
    /// this type already provides internally.
    ///
    /// By default, errors are always forgotten (retried on the next request) and successful
    /// values are always remembered, matching Java's default
    /// `forgetErrors = (k, t) -> true;`/`forgetValues = (k, v) -> false;`.
    pub fn new<F, Fut>(function: F) -> Self
    where
        F: Fn(K) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<V, ArcError>> + Send + 'static,
    {
        AsyncLazyMap {
            inner: Arc::new(Mutex::new(Inner {
                futures: HashMap::new(),
                map: HashMap::new(),
                forget_errors: Arc::new(|_k: &K, _e: &ArcError| true),
                forget_values: Arc::new(|_k: &K, _v: &V| false),
            })),
            function: Arc::new(move |k| Box::pin(function(k)) as BoxFuture<V>),
        }
    }

    /// Sets a predicate to determine which errors to forget (i.e., retry).
    ///
    /// A request resulting in an error that is remembered will not be retried until the cache is
    /// invalidated. For a forgotten error, the request is retried if re-requested later. This
    /// replaces the behavior of any previous error-testing predicate.
    ///
    /// Mirrors `forgetErrors(BiPredicate)`.
    pub fn forget_errors(
        &self,
        predicate: impl Fn(&K, &ArcError) -> bool + Send + Sync + 'static,
    ) -> &Self {
        self.inner.lock().unwrap().forget_errors = Arc::new(predicate);
        self
    }

    /// Sets a predicate to determine which errors to remember.
    ///
    /// Mirrors `rememberErrors(BiPredicate)`; see [`AsyncLazyMap::forget_errors`].
    pub fn remember_errors(
        &self,
        predicate: impl Fn(&K, &ArcError) -> bool + Send + Sync + 'static,
    ) -> &Self {
        self.forget_errors(move |k, e| !predicate(k, e))
    }

    /// Sets a predicate to determine which values to forget.
    ///
    /// The predicate is applied to a cached entry when its key is re-requested. If forgotten,
    /// the request will launch a fresh computation. The predicate is also applied at the time a
    /// computation completes. An entry that is forgotten still completes normally; however, it
    /// never enters the cache, thus a subsequent request for the same key will launch a fresh
    /// computation. This replaces the behavior of any previous value-testing predicate.
    ///
    /// Mirrors `forgetValues(BiPredicate)`.
    pub fn forget_values(
        &self,
        predicate: impl Fn(&K, &V) -> bool + Send + Sync + 'static,
    ) -> &Self {
        self.inner.lock().unwrap().forget_values = Arc::new(predicate);
        self
    }

    /// Sets a predicate to determine which values to remember.
    ///
    /// Mirrors `rememberValues(BiPredicate)`; see [`AsyncLazyMap::forget_values`].
    pub fn remember_values(
        &self,
        predicate: impl Fn(&K, &V) -> bool + Send + Sync + 'static,
    ) -> &Self {
        self.forget_values(move |k, v| !predicate(k, v))
    }

    /// Applies the forget-errors/forget-values decisions once a computation (however it was
    /// started) resolves, and publishes the result to every subscriber of `key`'s slot.
    ///
    /// Mirrors the shared logic Java attaches to every `KeyedFuture` in `putFuture(K,
    /// KeyedFuture<K, V>)`. Unlike Java's narrower guard (present only on the success path via
    /// `futures.get(key) != future`), this port applies the "is this slot still current"
    /// identity check uniformly to both the success and failure paths, as a deliberate,
    /// documented simplification: it is what keeps a `remove`/`forget`/`retain_keys`/`clear`
    /// call from having a stale in-flight computation resurrect an evicted (or since-replaced)
    /// entry, on *either* outcome.
    fn finish(
        inner: &Arc<Mutex<Inner<K, V>>>,
        key: K,
        result: Result<V, ArcError>,
        tx: watch::Sender<Option<Result<V, ArcError>>>,
    ) {
        {
            let mut guard = inner.lock().unwrap();
            let still_current = matches!(
                guard.futures.get(&key),
                Some(slot) if slot.tx.same_channel(&tx)
            );
            if still_current {
                match &result {
                    Ok(v) => {
                        if (guard.forget_values)(&key, v) {
                            guard.futures.remove(&key);
                        } else {
                            guard.map.insert(key.clone(), v.clone());
                        }
                    }
                    Err(e) => {
                        if (guard.forget_errors)(&key, e) {
                            guard.futures.remove(&key);
                        }
                    }
                }
            }
        }
        let _ = tx.send(Some(result));
    }

    /// Requests the value for a given key, using an alternative computation.
    ///
    /// If this is called before any other get or put, the given function is launched for the
    /// given key. A future is returned immediately. Subsequent gets or puts on the same key will
    /// return the same future without starting any new computation.
    ///
    /// Mirrors `get(K, Function<K, CompletableFuture<V>>)`.
    ///
    /// # Panics
    ///
    /// Faithfully reproduces a genuine Java quirk: `CompletableFuture.getNow(null)`, called on a
    /// future that completed *exceptionally*, does not return `null` -- it rethrows the
    /// completion exception. Since a *remembered* (non-forgotten) error is never removed from
    /// `futures`, Java's `get(key, ...)` on such a key does not quietly return the stale failed
    /// future: `future.getNow(null)` throws right out of the (synchronized) call. There is no
    /// unchecked-exception equivalent in Rust, so this port panics in that situation instead.
    /// This is unreachable with the default `forget_errors` predicate (which always forgets, so
    /// no error is ever remembered); it is only reachable after calling
    /// [`AsyncLazyMap::remember_errors`]/[`AsyncLazyMap::forget_errors`] with a predicate that
    /// sometimes returns `false`.
    pub fn get_with(
        &self,
        key: K,
        func: impl Fn(K) -> BoxFuture<V> + Send + Sync + 'static,
    ) -> KeyedFuture<K, V> {
        self.get_with_arc(key, Arc::new(func))
    }

    fn get_with_arc(&self, key: K, func: Arc<ComputeFn<K, V>>) -> KeyedFuture<K, V> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(slot) = guard.futures.get(&key) {
            let current = slot.rx.borrow().clone();
            match current {
                None => {
                    return KeyedFuture {
                        key,
                        rx: slot.rx.clone(),
                    };
                }
                Some(Ok(v)) => {
                    if !(guard.forget_values)(&key, &v) {
                        return KeyedFuture {
                            key,
                            rx: slot.rx.clone(),
                        };
                    }
                    // Forgotten: fall through to launch a fresh computation below.
                }
                Some(Err(e)) => {
                    // See the panic documentation on `get_with`.
                    panic!(
                        "AsyncLazyMap::get_with called for key with a remembered error (Java's \
                         CompletableFuture.getNow(null) rethrows here): {e}"
                    );
                }
            }
        }

        let (tx, rx) = watch::channel(None);
        guard.futures.insert(
            key.clone(),
            Slot {
                tx: tx.clone(),
                rx: rx.clone(),
            },
        );
        let dep = func(key.clone());
        drop(guard);

        let inner = Arc::clone(&self.inner);
        let spawn_key = key.clone();
        tokio::spawn(async move {
            let result = dep.await;
            Self::finish(&inner, spawn_key, result, tx);
        });

        KeyedFuture { key, rx }
    }

    /// Requests the value for a given key.
    ///
    /// If this is called before any other get or put, the computation given at construction is
    /// launched for the given key. A future is returned immediately. Subsequent calls gets or
    /// puts on the same key return the same future without starting any new computation.
    ///
    /// Mirrors `get(K)`. See [`AsyncLazyMap::get_with`] for the panic this can reproduce.
    pub fn get(&self, key: K) -> KeyedFuture<K, V> {
        let func = Arc::clone(&self.function);
        self.get_with_arc(key, func)
    }

    /// Immediately provides an out-of-band value for a given key.
    ///
    /// On occasion, the value for a key may become known outside the specified computation. This
    /// method circumvents the function given during construction by providing the value for a
    /// key. If there is an outstanding request for the key's value -- a rare occasion -- it is
    /// completed immediately with the provided value. Calling this method for a key that has
    /// already completed has no effect.
    ///
    /// Mirrors `put(K, V)`.
    pub fn put_value(&self, key: K, value: V) -> bool {
        let mut guard = self.inner.lock().unwrap();
        if let Some(slot) = guard.futures.get(&key) {
            if slot.rx.borrow().is_some() {
                // Already completed (successfully or not): mirrors
                // `CompletableFuture.complete(value)` being a no-op once already done.
                return false;
            }
            let tx = slot.tx.clone();
            drop(guard);
            Self::finish(&self.inner, key, Ok(value), tx);
            return true;
        }
        let (tx, rx) = watch::channel(Some(Ok(value.clone())));
        guard.futures.insert(key.clone(), Slot { tx, rx });
        guard.map.insert(key, value);
        true
    }

    /// Provides an out-of-band value for a given key, returning a promise the caller must
    /// fulfill or arrange to have fulfilled.
    ///
    /// If this is called before [`AsyncLazyMap::get`], the computation given at construction is
    /// ignored for the given key: the returned [`KeyedFuture`] only ever resolves via the
    /// returned [`KeyedCompleter`] (or a later call to [`AsyncLazyMap::put_value`]). Subsequent
    /// calls to either [`AsyncLazyMap::get`] or [`AsyncLazyMap::put`] on the same key return a
    /// [`KeyedFuture`] for this same slot without starting any computation.
    ///
    /// Under normal circumstances, the caller cannot determine whether it has "claimed" the
    /// computation for the key. If the usual computation is already running, the two are
    /// essentially in a race. As such, it is essential that alternative computations result in
    /// the same value for a given key as the usual computation -- the means of computation can
    /// differ, but the functions must not.
    ///
    /// Mirrors `put(K)`; see the module docs for why this returns a `(KeyedFuture,
    /// KeyedCompleter)` pair rather than the single dual-purpose object Java's `KeyedFuture`
    /// (itself a `CompletableFuture`) is able to be.
    pub fn put(&self, key: K) -> (KeyedFuture<K, V>, Option<KeyedCompleter<K, V>>) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(slot) = guard.futures.get(&key) {
            return (
                KeyedFuture {
                    key,
                    rx: slot.rx.clone(),
                },
                None,
            );
        }
        let (tx, rx) = watch::channel(None);
        guard.futures.insert(
            key.clone(),
            Slot {
                tx: tx.clone(),
                rx: rx.clone(),
            },
        );
        (
            KeyedFuture {
                key: key.clone(),
                rx,
            },
            Some(KeyedCompleter { key, tx }),
        )
    }

    /// Removes a key from the map, without canceling any pending computation.
    ///
    /// If the removed future has not yet completed, its value will never be added to the map of
    /// values (the pending computation, if any, still runs to completion in the background, but
    /// its result is discarded by [`AsyncLazyMap::finish`]'s identity check). Subsequent gets or
    /// puts to the invalidated key behave as if the key had never been requested.
    ///
    /// Mirrors `forget(K)`.
    pub fn forget(&self, key: &K) -> Option<KeyedFuture<K, V>> {
        let mut guard = self.inner.lock().unwrap();
        guard.map.remove(key);
        guard.futures.remove(key).map(|slot| KeyedFuture {
            key: key.clone(),
            rx: slot.rx,
        })
    }

    /// Removes a key from the map, canceling any pending computation.
    ///
    /// Mirrors `remove(K)`. "Canceling" mirrors `CompletableFuture.cancel(false)`: only the
    /// specific future handed out for this key so far is force-completed with a cancellation
    /// error (and only if it had not already completed); the real background computation, if
    /// still running when this is called, is not interrupted, and its eventual result is simply
    /// discarded by [`AsyncLazyMap::finish`]'s identity check (the key has been removed from
    /// `futures` by then).
    pub fn remove(&self, key: &K) -> Option<V> {
        let (slot, val) = {
            let mut guard = self.inner.lock().unwrap();
            let slot = guard.futures.remove(key);
            let val = guard.map.remove(key);
            (slot, val)
        };
        if let Some(slot) = slot {
            if slot.rx.borrow().is_none() {
                let _ = slot.tx.send(Some(Err(cancelled_error())));
            }
        }
        val
    }

    /// Returns a snapshot of the currently completed keys and values.
    ///
    /// Java returns a live `Collections.unmodifiableMap` view backed by the same map (itself
    /// documenting that "access to the view ought to be synchronized on this lazy map" for a
    /// consistent read); a point-in-time snapshot, taken under this map's own lock, achieves the
    /// same effect more simply in Rust.
    ///
    /// Mirrors `getCompletedMap()`.
    pub fn get_completed_map(&self) -> HashMap<K, V> {
        self.inner.lock().unwrap().map.clone()
    }

    /// Returns a snapshot of the keys which are requested but not completed.
    ///
    /// This should only be used for diagnostics.
    ///
    /// Mirrors `getPendingKeySet()`. Java collects into a `LinkedHashSet` for deterministic
    /// iteration order; nothing in the documented contract depends on that order, so this
    /// returns an (unordered) `HashSet`.
    pub fn get_pending_key_set(&self) -> HashSet<K> {
        let guard = self.inner.lock().unwrap();
        guard
            .futures
            .iter()
            .filter(|(_, slot)| slot.rx.borrow().is_none())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Clears the lazy map, including pending requests.
    ///
    /// Pending requests are cancelled (see [`AsyncLazyMap::remove`] for what "cancelled" means
    /// here).
    ///
    /// Mirrors `clear()`.
    pub fn clear(&self) {
        let slots: Vec<Slot<V>> = {
            let mut guard = self.inner.lock().unwrap();
            let slots = guard.futures.drain().map(|(_, v)| v).collect();
            guard.map.clear();
            slots
        };
        for slot in slots {
            if slot.rx.borrow().is_none() {
                let _ = slot.tx.send(Some(Err(cancelled_error())));
            }
        }
    }

    /// Retains only those entries whose keys appear in the given collection.
    ///
    /// All removed entries with pending computations are cancelled (see
    /// [`AsyncLazyMap::remove`]).
    ///
    /// Mirrors `retainKeys(Collection<K>)`.
    pub fn retain_keys(&self, keys: &HashSet<K>) {
        let removed: Vec<Slot<V>> = {
            let mut guard = self.inner.lock().unwrap();
            let mut removed = Vec::new();
            guard.futures.retain(|k, slot| {
                if keys.contains(k) {
                    true
                } else {
                    removed.push(slot.clone());
                    false
                }
            });
            guard.map.retain(|k, _| keys.contains(k));
            removed
        };
        for slot in removed {
            if slot.rx.borrow().is_none() {
                let _ = slot.tx.send(Some(Err(cancelled_error())));
            }
        }
    }

    /// Checks if a given key is in the map, pending or completed.
    ///
    /// Mirrors `containsKey(K)`.
    pub fn contains_key(&self, key: &K) -> bool {
        let guard = self.inner.lock().unwrap();
        guard.futures.contains_key(key) || guard.map.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn ok_after<V: Send + 'static>(value: V) -> impl Future<Output = Result<V, ArcError>> {
        async move { Ok(value) }
    }

    #[tokio::test]
    async fn get_computes_and_caches_the_value() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(move |k: i32| {
            cc.fetch_add(1, Ordering::SeqCst);
            ok_after(k * 2)
        });

        let mut f1 = map.get(21);
        assert_eq!(f1.wait().await.unwrap(), 42);
        let mut f2 = map.get(21);
        assert_eq!(f2.wait().await.unwrap(), 42);

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(map.get_completed_map().get(&21), Some(&42));
    }

    #[tokio::test]
    async fn concurrent_gets_for_the_same_key_share_one_computation() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let map: Arc<AsyncLazyMap<i32, i32>> = Arc::new(AsyncLazyMap::new(move |k: i32| {
            cc.fetch_add(1, Ordering::SeqCst);
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(k)
            }
        }));

        let m1 = Arc::clone(&map);
        let m2 = Arc::clone(&map);
        let h1 = tokio::spawn(async move { m1.get(5).wait().await });
        let h2 = tokio::spawn(async move { m2.get(5).wait().await });

        assert_eq!(h1.await.unwrap().unwrap(), 5);
        assert_eq!(h2.await.unwrap().unwrap(), 5);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn default_forgets_errors_so_a_failed_key_is_retried() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(move |_k: i32| {
            let n = cc.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "boom")) as ArcError)
                } else {
                    Ok(99)
                }
            }
        });

        assert!(map.get(1).wait().await.is_err());
        assert_eq!(map.get(1).wait().await.unwrap(), 99);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn default_remembers_successful_values_so_the_function_runs_once() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let map: AsyncLazyMap<i32, i32> =
            AsyncLazyMap::new(move |k: i32| {
                cc.fetch_add(1, Ordering::SeqCst);
                ok_after(k)
            });

        map.get(1).wait().await.unwrap();
        map.get(1).wait().await.unwrap();
        map.get(1).wait().await.unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn forget_values_predicate_causes_a_forgotten_success_to_be_recomputed() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(move |k: i32| {
            cc.fetch_add(1, Ordering::SeqCst);
            ok_after(k)
        });
        map.forget_values(|_k, _v| true); // always forget successes

        map.get(1).wait().await.unwrap();
        map.get(1).wait().await.unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        // Forgotten values never enter the completed map.
        assert!(map.get_completed_map().get(&1).is_none());
    }

    #[tokio::test]
    async fn remember_errors_keeps_a_remembered_error_and_get_panics_on_re_request() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|_k: i32| async move {
            Err(Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "boom")) as ArcError)
        });
        map.remember_errors(|_k, _e| true); // never forget: always remember

        assert!(map.get(1).wait().await.is_err());

        // Faithful reproduction of the Java `CompletableFuture.getNow(null)` rethrow quirk: a
        // second `get()` for a key with a *remembered* error panics instead of quietly handing
        // back the stale failed future.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| map.get(1)));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn put_value_provides_a_value_out_of_band() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|_k: i32| async move {
            panic!("function should not be invoked when put_value supplies the value directly")
        });

        let inserted = map.put_value(7, 100);
        assert!(inserted);
        assert_eq!(map.get(7).wait().await.unwrap(), 100);
        assert_eq!(map.get_completed_map().get(&7), Some(&100));
    }

    #[tokio::test]
    async fn put_value_on_an_already_completed_key_has_no_effect() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|k: i32| ok_after(k));
        map.get(1).wait().await.unwrap();

        let inserted = map.put_value(1, 999);
        assert!(!inserted);
        assert_eq!(map.get_completed_map().get(&1), Some(&1));
    }

    #[tokio::test]
    async fn put_value_completes_a_pending_get() {
        let map: Arc<AsyncLazyMap<i32, i32>> = Arc::new(AsyncLazyMap::new(|_k: i32| async move {
            // Never resolves on its own; only put_value should complete the pending future.
            std::future::pending::<()>().await;
            unreachable!()
        }));

        let m = Arc::clone(&map);
        let mut pending = map.get(3);
        let h = tokio::spawn(async move { pending.wait().await });
        tokio::task::yield_now().await;

        assert!(m.put_value(3, 55));
        assert_eq!(h.await.unwrap().unwrap(), 55);
    }

    #[tokio::test]
    async fn put_returns_a_promise_the_caller_must_fulfill() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|_k: i32| async move {
            panic!("function should not be invoked; put() claims the key itself")
        });

        let (mut future, completer) = map.put(9);
        let completer = completer.expect("first put() call for a fresh key returns a completer");
        completer.complete(123);

        assert_eq!(future.wait().await.unwrap(), 123);
    }

    #[tokio::test]
    async fn put_called_twice_shares_the_same_slot_and_only_the_first_gets_a_completer() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|_k: i32| async move {
            panic!("function should not be invoked")
        });

        let (mut f1, c1) = map.put(1);
        let (mut f2, c2) = map.put(1);
        assert!(c1.is_some());
        assert!(c2.is_none());

        c1.unwrap().complete(7);
        assert_eq!(f1.wait().await.unwrap(), 7);
        assert_eq!(f2.wait().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn forget_removes_a_completed_entry_and_forces_recomputation() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = Arc::clone(&call_count);
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(move |k: i32| {
            cc.fetch_add(1, Ordering::SeqCst);
            ok_after(k)
        });

        map.get(4).wait().await.unwrap();
        assert!(map.contains_key(&4));

        map.forget(&4);
        assert!(!map.contains_key(&4));

        map.get(4).wait().await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn remove_cancels_a_pending_computation_for_the_caller_that_already_holds_it() {
        let map: Arc<AsyncLazyMap<i32, i32>> = Arc::new(AsyncLazyMap::new(|_k: i32| async move {
            std::future::pending::<()>().await;
            unreachable!()
        }));

        let mut pending = map.get(2);
        assert!(map.remove(&2).is_none()); // never completed with a real value

        let result = pending.wait().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn remove_returns_the_completed_value_and_forgets_the_key() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|k: i32| ok_after(k * 10));
        map.get(3).wait().await.unwrap();

        let removed = map.remove(&3);
        assert_eq!(removed, Some(30));
        assert!(!map.contains_key(&3));
    }

    #[tokio::test]
    async fn clear_removes_everything_and_cancels_pending_computations() {
        let map: Arc<AsyncLazyMap<i32, i32>> = Arc::new(AsyncLazyMap::new(|k: i32| async move {
            if k == 1 {
                std::future::pending::<()>().await;
                unreachable!()
            }
            Ok(k)
        }));

        map.get(0).wait().await.unwrap();
        let mut pending = map.get(1);

        map.clear();

        assert!(!map.contains_key(&0));
        assert!(!map.contains_key(&1));
        assert!(pending.wait().await.is_err());
    }

    #[tokio::test]
    async fn retain_keys_drops_everything_else() {
        let map: AsyncLazyMap<i32, i32> = AsyncLazyMap::new(|k: i32| ok_after(k));
        map.get(1).wait().await.unwrap();
        map.get(2).wait().await.unwrap();
        map.get(3).wait().await.unwrap();

        let keep: HashSet<i32> = [2].into_iter().collect();
        map.retain_keys(&keep);

        assert!(!map.contains_key(&1));
        assert!(map.contains_key(&2));
        assert!(!map.contains_key(&3));
    }

    #[tokio::test]
    async fn contains_key_is_true_while_pending_and_after_completion() {
        let map: Arc<AsyncLazyMap<i32, i32>> = Arc::new(AsyncLazyMap::new(|k: i32| async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(k)
        }));

        let mut fut = map.get(8);
        assert!(map.contains_key(&8));
        fut.wait().await.unwrap();
        assert!(map.contains_key(&8));
    }

    #[tokio::test]
    async fn get_pending_key_set_only_includes_unresolved_keys() {
        let map: Arc<AsyncLazyMap<i32, i32>> = Arc::new(AsyncLazyMap::new(|k: i32| async move {
            if k == 1 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Ok(k)
        }));

        map.get(0).wait().await.unwrap();
        let _still_pending = map.get(1);
        tokio::task::yield_now().await;

        let pending = map.get_pending_key_set();
        assert!(pending.contains(&1));
        assert!(!pending.contains(&0));
    }

    #[tokio::test]
    async fn keyed_future_key_and_peek_reflect_state() {
        let map: AsyncLazyMap<&'static str, i32> = AsyncLazyMap::new(|_k| ok_after(1));
        let mut fut = map.get("alpha");
        assert_eq!(*fut.key(), "alpha");
        assert!(fut.peek().is_none());
        assert!(!fut.is_done());

        fut.wait().await.unwrap();
        assert!(fut.is_done());
        assert_eq!(fut.peek().unwrap().unwrap(), 1);
    }
}
