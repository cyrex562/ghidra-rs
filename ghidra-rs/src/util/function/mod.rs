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

    #[test]
    fn exceptional_consumer_accepts_value_and_succeeds() {
        let log: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let consumer: ExceptionalConsumer<i32, String> = Box::new(move |value| {
            log_clone.lock().unwrap().push(value);
            Ok(())
        });

        assert!(consumer(42).is_ok());
        assert_eq!(*log.lock().unwrap(), vec![42]);
    }

    #[test]
    fn exceptional_consumer_returns_error() {
        let consumer: ExceptionalConsumer<i32, String> =
            Box::new(|_| Err("error occurred".to_string()));
        let result = consumer(42);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "error occurred");
    }

    #[test]
    fn exceptional_consumer_with_multiple_invocations() {
        let log: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let consumer: ExceptionalConsumer<i32, String> = Box::new(move |value| {
            log_clone.lock().unwrap().push(value);
            Ok(())
        });

        assert!(consumer(1).is_ok());
        assert!(consumer(2).is_ok());
        assert!(consumer(3).is_ok());
        assert_eq!(*log.lock().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn exceptional_consumer_with_different_types() {
        let log: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let log_clone = Arc::clone(&log);
        let consumer: ExceptionalConsumer<&str, ()> = Box::new(move |value| {
            log_clone.lock().unwrap().push_str(value);
            Ok(())
        });

        assert!(consumer("hello").is_ok());
        assert!(consumer(" world").is_ok());
        assert_eq!(*log.lock().unwrap(), "hello world");
    }

    #[test]
    fn exceptional_consumer_can_fail_conditionally() {
        let consumer: ExceptionalConsumer<i32, String> = Box::new(|value| {
            if value < 0 {
                Err("negative value".to_string())
            } else {
                Ok(())
            }
        });

        assert!(consumer(42).is_ok());
        let result = consumer(-1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "negative value");
    }

    #[test]
    fn exceptional_consumer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        let consumer: ExceptionalConsumer<i32, String> = Box::new(|_| Ok(()));
        assert_send_sync::<ExceptionalConsumer<i32, String>>();
        drop(consumer);
    }

    #[test]
    fn exceptional_function_transforms_input_to_output() {
        let func: ExceptionalFunction<i32, String, String> =
            Box::new(|x| Ok(format!("value: {}", x)));
        let result = func(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "value: 42");
    }

    #[test]
    fn exceptional_function_returns_error() {
        let func: ExceptionalFunction<i32, String, String> =
            Box::new(|_| Err("computation failed".to_string()));
        let result = func(42);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "computation failed");
    }

    #[test]
    fn exceptional_function_with_multiple_invocations() {
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let func: ExceptionalFunction<i32, i32, String> = Box::new(move |x| {
            *call_count_clone.lock().unwrap() += 1;
            Ok(x * 2)
        });

        assert_eq!(func(5).unwrap(), 10);
        assert_eq!(func(10).unwrap(), 20);
        assert_eq!(*call_count.lock().unwrap(), 2);
    }

    #[test]
    fn exceptional_function_with_different_types() {
        let func: ExceptionalFunction<&str, usize, ()> =
            Box::new(|s| Ok(s.len()));
        assert_eq!(func("hello").unwrap(), 5);
        assert_eq!(func("world").unwrap(), 5);
        assert_eq!(func("x").unwrap(), 1);
    }

    #[test]
    fn exceptional_function_can_fail_conditionally() {
        let func: ExceptionalFunction<i32, i32, String> = Box::new(|x| {
            if x < 0 {
                Err("negative input".to_string())
            } else {
                Ok(x * 2)
            }
        });

        assert_eq!(func(5).unwrap(), 10);
        let result = func(-1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "negative input");
    }

    #[test]
    fn exceptional_function_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        let func: ExceptionalFunction<i32, String, String> = Box::new(|x| Ok(x.to_string()));
        assert_send_sync::<ExceptionalFunction<i32, String, String>>();
        drop(func);
    }

    #[test]
    fn exceptional_function_with_complex_error_type() {
        #[derive(Debug, PartialEq)]
        struct CustomError {
            code: i32,
            msg: String,
        }

        let func: ExceptionalFunction<i32, String, CustomError> = Box::new(|x| {
            if x >= 0 {
                Ok(format!("processed: {}", x))
            } else {
                Err(CustomError {
                    code: -1,
                    msg: "negative".to_string(),
                })
            }
        });

        assert_eq!(func(42).unwrap(), "processed: 42");
        let err = func(-1).unwrap_err();
        assert_eq!(err.code, -1);
        assert_eq!(err.msg, "negative");
    }

    #[test]
    fn exceptional_supplier_succeeds_and_returns_value() {
        let supplier: ExceptionalSupplier<i32, String> = Box::new(|| Ok(42));
        let result = supplier();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn exceptional_supplier_returns_error() {
        let supplier: ExceptionalSupplier<i32, String> =
            Box::new(|| Err("supply failed".to_string()));
        let result = supplier();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "supply failed");
    }

    #[test]
    fn exceptional_supplier_with_string_type() {
        let supplier: ExceptionalSupplier<String, ()> =
            Box::new(|| Ok("hello world".to_string()));
        let result = supplier();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello world");
    }

    #[test]
    fn exceptional_supplier_with_multiple_calls() {
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let supplier: ExceptionalSupplier<i32, String> = Box::new(move || {
            let mut count = call_count_clone.lock().unwrap();
            *count += 1;
            Ok(*count)
        });

        assert_eq!(supplier().unwrap(), 1);
        assert_eq!(supplier().unwrap(), 2);
        assert_eq!(supplier().unwrap(), 3);
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[test]
    fn exceptional_supplier_can_fail_conditionally() {
        let invocation_count = Arc::new(Mutex::new(0));
        let invocation_count_clone = Arc::clone(&invocation_count);
        let supplier: ExceptionalSupplier<i32, String> = Box::new(move || {
            let mut count = invocation_count_clone.lock().unwrap();
            *count += 1;
            if *count < 3 {
                Ok(*count)
            } else {
                Err("limit reached".to_string())
            }
        });

        assert_eq!(supplier().unwrap(), 1);
        assert_eq!(supplier().unwrap(), 2);
        let result = supplier();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "limit reached");
    }

    #[test]
    fn exceptional_supplier_with_different_types() {
        let supplier: ExceptionalSupplier<Vec<i32>, ()> =
            Box::new(|| Ok(vec![1, 2, 3]));
        let result = supplier();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn exceptional_supplier_with_complex_error_type() {
        #[derive(Debug, PartialEq)]
        struct SupplyError {
            reason: String,
        }

        let supplier: ExceptionalSupplier<String, SupplyError> = Box::new(|| {
            Err(SupplyError {
                reason: "resource unavailable".to_string(),
            })
        });

        let result = supplier();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.reason, "resource unavailable");
    }

    #[test]
    fn exceptional_supplier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        let supplier: ExceptionalSupplier<i32, String> = Box::new(|| Ok(42));
        assert_send_sync::<ExceptionalSupplier<i32, String>>();
        drop(supplier);
    }

    #[test]
    fn exceptional_supplier_returns_different_values_on_successive_calls() {
        let state = Arc::new(Mutex::new(vec![10, 20, 30, 40]));
        let state_clone = Arc::clone(&state);
        let supplier: ExceptionalSupplier<i32, String> = Box::new(move || {
            let mut items = state_clone.lock().unwrap();
            if items.is_empty() {
                Err("no more items".to_string())
            } else {
                Ok(items.remove(0))
            }
        });

        assert_eq!(supplier().unwrap(), 10);
        assert_eq!(supplier().unwrap(), 20);
        assert_eq!(supplier().unwrap(), 30);
        assert_eq!(supplier().unwrap(), 40);
        let result = supplier();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "no more items");
    }
}
