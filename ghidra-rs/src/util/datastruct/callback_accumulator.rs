use std::sync::atomic::{AtomicUsize, Ordering};
use std::marker::PhantomData;

use super::Accumulator;

/// An implementation of [`Accumulator`] that allows clients to easily process items as
/// they arrive.
pub struct CallbackAccumulator<T, F: Fn(&T)> {
    counter: AtomicUsize,
    consumer: F,
    _phantom: PhantomData<T>,
}

impl<T, F: Fn(&T)> CallbackAccumulator<T, F> {
    /// Creates a new `CallbackAccumulator` with the given consumer function.
    ///
    /// # Arguments
    ///
    /// * `consumer` - A closure that will be called each time an item is added
    pub fn new(consumer: F) -> Self {
        Self {
            counter: AtomicUsize::new(0),
            consumer,
            _phantom: PhantomData,
        }
    }
}

impl<T, F: Fn(&T)> Accumulator<T> for CallbackAccumulator<T, F> {
    fn add(&mut self, item: T) {
        (self.consumer)(&item);
        self.counter.fetch_add(1, Ordering::SeqCst);
    }

    fn get_progress(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn add_calls_consumer_and_increments_counter() {
        let items = Arc::new(Mutex::new(Vec::new()));
        let items_clone = Arc::clone(&items);

        let consumer = move |item: &i32| {
            items_clone.lock().unwrap().push(*item);
        };

        let mut acc = CallbackAccumulator::new(consumer);

        assert_eq!(acc.get_progress(), 0);
        acc.add(42);
        assert_eq!(acc.get_progress(), 1);
        assert_eq!(items.lock().unwrap().as_slice(), &[42]);
    }

    #[test]
    fn add_all_calls_consumer_for_each_item() {
        let items = Arc::new(Mutex::new(Vec::new()));
        let items_clone = Arc::clone(&items);

        let consumer = move |item: &i32| {
            items_clone.lock().unwrap().push(*item);
        };

        let mut acc = CallbackAccumulator::new(consumer);
        acc.add_all(vec![1, 2, 3]);

        assert_eq!(acc.get_progress(), 3);
        assert_eq!(items.lock().unwrap().as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn progress_starts_at_zero() {
        let consumer = |_: &i32| {};

        let acc = CallbackAccumulator::new(consumer);
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn multiple_add_calls_increment_progress() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);

        let consumer = move |_: &i32| {
            *counter_clone.lock().unwrap() += 1;
        };

        let mut acc = CallbackAccumulator::new(consumer);

        for i in 0..10 {
            acc.add(i);
        }

        assert_eq!(acc.get_progress(), 10);
        assert_eq!(*counter.lock().unwrap(), 10);
    }

    #[test]
    fn consumer_receives_correct_values() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);

        let consumer = move |item: &String| {
            received_clone.lock().unwrap().push(item.clone());
        };

        let mut acc = CallbackAccumulator::new(consumer);

        acc.add("hello".to_string());
        acc.add("world".to_string());

        assert_eq!(acc.get_progress(), 2);
        assert_eq!(
            received.lock().unwrap().as_slice(),
            &["hello".to_string(), "world".to_string()]
        );
    }

    #[test]
    fn empty_add_all_leaves_progress_unchanged() {
        let consumer = |_: &i32| {};
        let mut acc = CallbackAccumulator::new(consumer);
        acc.add_all(std::iter::empty());
        assert_eq!(acc.get_progress(), 0);
    }
}
