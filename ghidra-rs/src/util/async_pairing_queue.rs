use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::oneshot;

/// Pairs producers (givers) with consumers (takers) in FIFO order.
///
/// When a giver arrives before any taker is waiting, it is queued until a taker
/// appears. When a taker arrives before any giver is ready, it blocks until a
/// giver provides a value. The pairing is always one-to-one: each giver's value
/// is delivered to exactly one taker.
///
/// Port of `ghidra.async.AsyncPairingQueue`.
pub struct AsyncPairingQueue<T: Send + 'static> {
    inner: Mutex<PairingQueueInner<T>>,
}

struct PairingQueueInner<T: Send + 'static> {
    givers: VecDeque<oneshot::Receiver<T>>,
    takers: VecDeque<oneshot::Sender<T>>,
}

impl<T: Send + 'static> AsyncPairingQueue<T> {
    /// Creates a new empty `AsyncPairingQueue`.
    pub fn new() -> Self {
        AsyncPairingQueue {
            inner: Mutex::new(PairingQueueInner {
                givers: VecDeque::new(),
                takers: VecDeque::new(),
            }),
        }
    }

    /// Queues `giver` as a pending producer.
    ///
    /// If a taker is already waiting, the two are paired immediately and the
    /// giver's value is forwarded to the taker asynchronously. Otherwise `giver`
    /// is held until a taker calls [`take`][Self::take].
    ///
    /// Analogous to Java's `give(CompletableFuture<? extends T>)`.
    ///
    /// # Panics
    /// Panics if called outside a Tokio runtime (only when pairing occurs).
    pub fn give(&self, giver: oneshot::Receiver<T>) {
        let taker = {
            let mut inner = self.inner.lock().unwrap();
            match inner.takers.pop_front() {
                Some(t) => t,
                None => {
                    inner.givers.push_back(giver);
                    return;
                }
            }
        };
        Self::pair(giver, taker);
    }

    /// Creates a producer slot and returns its sender handle.
    ///
    /// The caller fills the slot by calling [`send`][oneshot::Sender::send] on the
    /// returned sender. If a taker is already waiting the pairing happens
    /// immediately; otherwise the slot is queued until a taker arrives.
    ///
    /// Analogous to Java's `give()` which returns a `CompletableFuture<T>` that
    /// the caller completes.
    ///
    /// # Panics
    /// Panics if called outside a Tokio runtime (only when pairing occurs).
    pub fn give_slot(&self) -> oneshot::Sender<T> {
        let (tx, rx) = oneshot::channel();
        self.give(rx);
        tx
    }

    /// Registers a taker and returns a receiver that resolves to the next available value.
    ///
    /// If a giver is already queued, the two are paired immediately and the
    /// returned receiver will resolve once the giver's sender fires. Otherwise the
    /// taker is held until a giver calls [`give`][Self::give] or
    /// [`give_slot`][Self::give_slot].
    ///
    /// Analogous to Java's `take()`.
    ///
    /// # Panics
    /// Panics if called outside a Tokio runtime (only when pairing occurs).
    pub fn take(&self) -> oneshot::Receiver<T> {
        let (tx, rx) = oneshot::channel();
        let giver = {
            let mut inner = self.inner.lock().unwrap();
            match inner.givers.pop_front() {
                Some(g) => g,
                None => {
                    inner.takers.push_back(tx);
                    return rx;
                }
            }
        };
        Self::pair(giver, tx);
        rx
    }

    /// Returns `true` if both the giver and taker queues are empty.
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.givers.is_empty() && inner.takers.is_empty()
    }

    fn pair(giver: oneshot::Receiver<T>, taker: oneshot::Sender<T>) {
        tokio::spawn(async move {
            if let Ok(val) = giver.await {
                let _ = taker.send(val);
            }
            // If giver's sender was dropped, taker is dropped here too,
            // propagating the error to the taker's receiver (analogous to
            // completeExceptionally in Java).
        });
    }
}

impl<T: Send + 'static> Default for AsyncPairingQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn take_before_give_receives_value() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::new();
        let rx = queue.take();
        assert!(!queue.is_empty());

        let tx = queue.give_slot();
        assert!(queue.is_empty());

        tx.send(42).unwrap();
        assert_eq!(rx.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn give_before_take_delivers_value() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::new();
        let tx = queue.give_slot();
        assert!(!queue.is_empty());

        tx.send(99).unwrap();

        let rx = queue.take();
        assert!(queue.is_empty());
        assert_eq!(rx.await.unwrap(), 99);
    }

    #[tokio::test]
    async fn give_receiver_directly() {
        let queue: AsyncPairingQueue<u64> = AsyncPairingQueue::new();
        let (giver_tx, giver_rx) = oneshot::channel::<u64>();
        let taker_rx = queue.take();

        queue.give(giver_rx);
        giver_tx.send(7).unwrap();
        assert_eq!(taker_rx.await.unwrap(), 7);
    }

    #[tokio::test]
    async fn multiple_pairs_fifo_order() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::new();
        let rx1 = queue.take();
        let rx2 = queue.take();
        let rx3 = queue.take();

        let tx1 = queue.give_slot();
        let tx2 = queue.give_slot();
        let tx3 = queue.give_slot();

        tx1.send(1).unwrap();
        tx2.send(2).unwrap();
        tx3.send(3).unwrap();

        assert_eq!(rx1.await.unwrap(), 1);
        assert_eq!(rx2.await.unwrap(), 2);
        assert_eq!(rx3.await.unwrap(), 3);
    }

    #[tokio::test]
    async fn is_empty_reflects_state() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::new();
        assert!(queue.is_empty());

        let rx = queue.take();
        assert!(!queue.is_empty());

        let tx = queue.give_slot();
        assert!(queue.is_empty());

        tx.send(0).unwrap();
        let _ = rx.await;
    }

    #[tokio::test]
    async fn dropped_giver_sender_errors_taker() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::new();
        let rx = queue.take();
        let tx = queue.give_slot();
        drop(tx);
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn dropped_giver_receiver_errors_taker() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::new();
        let (giver_tx, giver_rx) = oneshot::channel::<i32>();
        let taker_rx = queue.take();
        queue.give(giver_rx);
        drop(giver_tx);
        assert!(taker_rx.await.is_err());
    }

    #[tokio::test]
    async fn concurrent_givers_and_takers() {
        let queue = Arc::new(AsyncPairingQueue::<i32>::new());
        let mut taker_handles = Vec::new();
        let mut giver_handles = Vec::new();

        for _ in 0..5 {
            let q = Arc::clone(&queue);
            taker_handles.push(tokio::spawn(async move { q.take().await }));
        }
        for i in 0..5i32 {
            let q = Arc::clone(&queue);
            giver_handles.push(tokio::spawn(async move {
                let tx = q.give_slot();
                tx.send(i).unwrap();
            }));
        }

        for h in giver_handles {
            h.await.unwrap();
        }
        let mut values: Vec<i32> = Vec::new();
        for h in taker_handles {
            values.push(h.await.unwrap().unwrap());
        }
        values.sort();
        assert_eq!(values, vec![0, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn default_creates_empty_queue() {
        let queue: AsyncPairingQueue<i32> = AsyncPairingQueue::default();
        assert!(queue.is_empty());
    }
}
