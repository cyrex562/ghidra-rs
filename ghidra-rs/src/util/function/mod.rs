/// A generic functional interface that is more semantically sound than a bare `Fn`.
///
/// Port of `utility.function.Callback`.
pub type Callback = Box<dyn Fn() + Send + Sync>;

/// Returns a no-op callback.
///
/// Useful to avoid using `None` or null.
pub fn dummy_callback() -> Callback {
    Box::new(|| {})
}

/// Returns the given callback if it is `Some`, otherwise returns a dummy callback.
///
/// Useful to avoid using `None` or null.
///
/// Port of `Callback.dummyIfNull`.
pub fn dummy_if_none(c: Option<Callback>) -> Callback {
    c.unwrap_or_else(dummy_callback)
}

/// A generic functional interface that can throw an exception.
///
/// This is the Rust equivalent of Java's `ExceptionalCallback<E>`. It represents a
/// callback that takes no arguments and can either succeed (returning `Ok(())`) or fail
/// by returning an error of type `E`.
///
/// Port of `utility.function.ExceptionalCallback`.
pub type ExceptionalCallback<E> = Box<dyn Fn() -> Result<(), E> + Send + Sync>;
pub type ExceptionalConsumer<T, E> = Box<dyn Fn(T) -> Result<(), E> + Send + Sync>;
pub type ExceptionalFunction<T, R, E> = Box<dyn Fn(T) -> Result<R, E> + Send + Sync>;
pub type ExceptionalSupplier<R, E> = Box<dyn Fn() -> Result<R, E> + Send + Sync>;

/// A consumer that accepts three arguments. Patterned after `BiConsumer`.
pub type TriConsumer<T, U, V> = Box<dyn Fn(T, U, V) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn dummy_callback_is_noop() {
        let callback = dummy_callback();
        callback();
    }

    #[test]
    fn dummy_if_none_with_none_returns_dummy() {
        let callback = dummy_if_none(None);
        callback();
    }

    #[test]
    fn dummy_if_none_with_some_returns_callback() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);
        let callback = Box::new(move || {
            *called_clone.lock().unwrap() = true;
        });

        let result = dummy_if_none(Some(callback));
        result();

        assert!(*called.lock().unwrap());
    }

    #[test]
    fn tri_consumer_receives_all_three_args() {
        let log: Arc<Mutex<Vec<(i32, i32, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let consumer: TriConsumer<i32, i32, i32> =
            Box::new(move |a, b, c| log2.lock().unwrap().push((a, b, c)));
        consumer(1, 2, 3);
        consumer(10, 20, 30);
        assert_eq!(*log.lock().unwrap(), vec![(1, 2, 3), (10, 20, 30)]);
    }

    #[test]
    fn tri_consumer_with_mixed_types() {
        let log: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let log2 = Arc::clone(&log);
        let consumer: TriConsumer<&str, u32, bool> =
            Box::new(move |s, n, b| *log2.lock().unwrap() = format!("{s}{n}{b}"));
        consumer("hello", 42, true);
        assert_eq!(*log.lock().unwrap(), "hello42true");
    }

    #[test]
    fn exceptional_callback_succeeds() {
        let callback: ExceptionalCallback<String> = Box::new(|| Ok(()));
        assert!(callback().is_ok());
    }

    #[test]
    fn exceptional_callback_returns_error() {
        let callback: ExceptionalCallback<String> = Box::new(|| Err("error".to_string()));
        let result = callback();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "error");
    }

    #[test]
    fn exceptional_callback_with_closure_state() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);
        let callback: ExceptionalCallback<()> = Box::new(move || {
            *counter_clone.lock().unwrap() += 1;
            Ok(())
        });

        callback().unwrap();
        callback().unwrap();
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[test]
    fn exceptional_callback_propagates_different_error_types() {
        #[derive(Debug, PartialEq)]
        struct CustomError(i32);

        let callback: ExceptionalCallback<CustomError> =
            Box::new(|| Err(CustomError(42)));
        let result = callback();
        assert_eq!(result, Err(CustomError(42)));
    }

    #[test]
    fn exceptional_callback_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        let callback: ExceptionalCallback<String> = Box::new(|| Ok(()));
        assert_send_sync::<ExceptionalCallback<String>>();
        drop(callback);
    }
}
