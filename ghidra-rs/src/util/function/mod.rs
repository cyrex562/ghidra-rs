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

/// A consumer function that accepts a single value and returns nothing.
pub type Consumer<T> = Box<dyn Fn(T) + Send + Sync>;

/// A consumer function that accepts two values and returns nothing.
pub type BiConsumer<T, U> = Box<dyn Fn(T, U) + Send + Sync>;

/// A function that transforms an input value into an output value. The result may be
/// absent, mirroring Java's ability to return `null` from a `Function<T, R>`.
pub type Function<T, R> = Box<dyn Fn(T) -> Option<R> + Send + Sync>;

/// A function that supplies a value with no input. The result may be absent, mirroring
/// Java's ability to return `null` from a `Supplier<T>`.
pub type Supplier<T> = Box<dyn Fn() -> Option<T> + Send + Sync>;

/// A function that takes no arguments and returns nothing.
pub type Runnable = Box<dyn Fn() + Send + Sync>;

/// A predicate function that tests a single value.
pub type Predicate<T> = Box<dyn Fn(&T) -> bool + Send + Sync>;

/// A predicate function that tests two values.
pub type BiPredicate<T, U> = Box<dyn Fn(&T, &U) -> bool + Send + Sync>;

/// Creates a dummy consumer that ignores its argument.
///
/// Port of `utility.function.Dummy.consumer`.
pub fn dummy_consumer<T>() -> Consumer<T> {
    Box::new(|_| {})
}

/// Creates a dummy consumer that ignores its argument and never fails.
///
/// Port of `utility.function.Dummy.exceptionalConsumer`.
pub fn dummy_exceptional_consumer<T, E>() -> ExceptionalConsumer<T, E> {
    Box::new(|_| Ok(()))
}

/// Creates a dummy consumer that ignores both of its arguments.
///
/// Port of `utility.function.Dummy.biConsumer`.
pub fn dummy_bi_consumer<T, U>() -> BiConsumer<T, U> {
    Box::new(|_, _| {})
}

/// Creates a dummy function that always returns an absent result.
///
/// Port of `utility.function.Dummy.function`.
pub fn dummy_function<T, R>() -> Function<T, R> {
    Box::new(|_| None)
}

/// Creates a dummy supplier that always returns an absent result.
///
/// Port of `utility.function.Dummy.supplier`.
pub fn dummy_supplier<T>() -> Supplier<T> {
    Box::new(|| None)
}

/// Creates a dummy runnable that does nothing.
///
/// Port of `utility.function.Dummy.runnable`.
pub fn dummy_runnable() -> Runnable {
    Box::new(|| {})
}

/// Creates a dummy predicate that always returns `true`.
///
/// Port of `utility.function.Dummy.predicate`.
pub fn dummy_predicate<T>() -> Predicate<T> {
    Box::new(|_| true)
}

/// Creates a dummy predicate that always returns `true`.
///
/// Port of `utility.function.Dummy.biPredicate`.
pub fn dummy_bi_predicate<T, U>() -> BiPredicate<T, U> {
    Box::new(|_, _| true)
}

/// Returns the given consumer if it is `Some`, otherwise a [`dummy_consumer`]. Useful to
/// avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(Consumer)`.
pub fn consumer_if_none<T>(c: Option<Consumer<T>>) -> Consumer<T> {
    c.unwrap_or_else(dummy_consumer)
}

/// Returns the given consumer if it is `Some`, otherwise a [`dummy_bi_consumer`]. Useful
/// to avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(BiConsumer)`.
pub fn bi_consumer_if_none<T, U>(c: Option<BiConsumer<T, U>>) -> BiConsumer<T, U> {
    c.unwrap_or_else(dummy_bi_consumer)
}

/// Returns the given function if it is `Some`, otherwise a [`dummy_function`]. Useful to
/// avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(Function)`.
pub fn function_if_none<T, R>(f: Option<Function<T, R>>) -> Function<T, R> {
    f.unwrap_or_else(dummy_function)
}

/// Returns the given supplier if it is `Some`, otherwise a [`dummy_supplier`]. Useful to
/// avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(Supplier)`.
pub fn supplier_if_none<T>(s: Option<Supplier<T>>) -> Supplier<T> {
    s.unwrap_or_else(dummy_supplier)
}

/// Returns the given runnable if it is `Some`, otherwise a [`dummy_runnable`]. Useful to
/// avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(Runnable)`.
pub fn runnable_if_none(r: Option<Runnable>) -> Runnable {
    r.unwrap_or_else(dummy_runnable)
}

/// Returns the given predicate if it is `Some`, otherwise a [`dummy_predicate`] (which
/// always returns `true`). Useful to avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(Predicate)`.
pub fn predicate_if_none<T>(p: Option<Predicate<T>>) -> Predicate<T> {
    p.unwrap_or_else(dummy_predicate)
}

/// Returns the given predicate if it is `Some`, otherwise a [`dummy_bi_predicate`] (which
/// always returns `true`). Useful to avoid using `None`.
///
/// Port of `utility.function.Dummy.ifNull(BiPredicate)`.
pub fn bi_predicate_if_none<T, U>(p: Option<BiPredicate<T, U>>) -> BiPredicate<T, U> {
    p.unwrap_or_else(dummy_bi_predicate)
}

/// A consumer that can request termination of the supplier once some condition is reached.
///
/// Port of `utility.function.TerminatingConsumer<T>`.
pub trait TerminatingConsumer<T>: Send + Sync {
    fn accept(&self, item: T);

    fn termination_requested(&self) -> bool {
        false
    }
}

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

    #[test]
    fn terminating_consumer_default_termination_is_false() {
        struct LoggingConsumer {
            items: Mutex<Vec<i32>>,
        }

        impl TerminatingConsumer<i32> for LoggingConsumer {
            fn accept(&self, item: i32) {
                self.items.lock().unwrap().push(item);
            }
        }

        let consumer = LoggingConsumer {
            items: Mutex::new(Vec::new()),
        };
        consumer.accept(42);
        assert!(!consumer.termination_requested());
        assert_eq!(*consumer.items.lock().unwrap(), vec![42]);
    }

    #[test]
    fn terminating_consumer_custom_termination_logic() {
        struct CountingConsumer {
            count: Mutex<i32>,
            limit: i32,
        }

        impl TerminatingConsumer<i32> for CountingConsumer {
            fn accept(&self, _item: i32) {
                *self.count.lock().unwrap() += 1;
            }

            fn termination_requested(&self) -> bool {
                *self.count.lock().unwrap() >= self.limit
            }
        }

        let consumer = CountingConsumer {
            count: Mutex::new(0),
            limit: 3,
        };

        assert!(!consumer.termination_requested());
        consumer.accept(1);
        assert!(!consumer.termination_requested());
        consumer.accept(2);
        assert!(!consumer.termination_requested());
        consumer.accept(3);
        assert!(consumer.termination_requested());
    }

    #[test]
    fn terminating_consumer_as_trait_object() {
        struct StringConsumer {
            values: Mutex<Vec<String>>,
        }

        impl TerminatingConsumer<String> for StringConsumer {
            fn accept(&self, item: String) {
                self.values.lock().unwrap().push(item);
            }
        }

        let consumer: Box<dyn TerminatingConsumer<String>> = Box::new(StringConsumer {
            values: Mutex::new(Vec::new()),
        });

        consumer.accept("hello".to_string());
        consumer.accept("world".to_string());
        assert!(!consumer.termination_requested());
    }

    #[test]
    fn terminating_consumer_with_arc() {
        struct SharedConsumer {
            items: Arc<Mutex<Vec<i32>>>,
        }

        impl TerminatingConsumer<i32> for SharedConsumer {
            fn accept(&self, item: i32) {
                self.items.lock().unwrap().push(item);
            }
        }

        let items = Arc::new(Mutex::new(Vec::new()));
        let consumer = SharedConsumer {
            items: Arc::clone(&items),
        };

        consumer.accept(1);
        consumer.accept(2);
        consumer.accept(3);

        assert_eq!(*items.lock().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn terminating_consumer_termination_can_change_state() {
        struct StatefulConsumer {
            count: Mutex<i32>,
        }

        impl TerminatingConsumer<()> for StatefulConsumer {
            fn accept(&self, _item: ()) {
                *self.count.lock().unwrap() += 1;
            }

            fn termination_requested(&self) -> bool {
                *self.count.lock().unwrap() > 5
            }
        }

        let consumer = StatefulConsumer {
            count: Mutex::new(0),
        };

        for i in 1..=10 {
            consumer.accept(());
            if consumer.termination_requested() {
                assert!(i > 5);
                break;
            }
        }

        assert_eq!(*consumer.count.lock().unwrap(), 6);
    }

    #[test]
    fn dummy_consumer_is_noop() {
        let consumer = dummy_consumer::<i32>();
        consumer(42);
    }

    #[test]
    fn dummy_exceptional_consumer_is_noop_and_never_fails() {
        let consumer = dummy_exceptional_consumer::<i32, String>();
        assert!(consumer(42).is_ok());
    }

    #[test]
    fn dummy_bi_consumer_is_noop() {
        let consumer = dummy_bi_consumer::<i32, i32>();
        consumer(1, 2);
    }

    #[test]
    fn dummy_function_returns_none() {
        let function = dummy_function::<i32, String>();
        assert_eq!(function(42), None);
    }

    #[test]
    fn dummy_supplier_returns_none() {
        let supplier = dummy_supplier::<String>();
        assert_eq!(supplier(), None);
    }

    #[test]
    fn dummy_runnable_is_noop() {
        let runnable = dummy_runnable();
        runnable();
    }

    #[test]
    fn dummy_predicate_always_true() {
        let predicate = dummy_predicate::<i32>();
        assert!(predicate(&1));
        assert!(predicate(&-1));
    }

    #[test]
    fn dummy_bi_predicate_always_true() {
        let predicate = dummy_bi_predicate::<i32, i32>();
        assert!(predicate(&1, &2));
    }

    #[test]
    fn consumer_if_none_with_none_returns_dummy() {
        let consumer = consumer_if_none::<i32>(None);
        consumer(1);
    }

    #[test]
    fn consumer_if_none_with_some_returns_given() {
        let log: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let given: Consumer<i32> = Box::new(move |v| log_clone.lock().unwrap().push(v));

        let consumer = consumer_if_none(Some(given));
        consumer(7);

        assert_eq!(*log.lock().unwrap(), vec![7]);
    }

    #[test]
    fn bi_consumer_if_none_with_none_returns_dummy() {
        let consumer = bi_consumer_if_none::<i32, i32>(None);
        consumer(1, 2);
    }

    #[test]
    fn function_if_none_with_none_returns_dummy() {
        let function = function_if_none::<i32, String>(None);
        assert_eq!(function(1), None);
    }

    #[test]
    fn function_if_none_with_some_returns_given() {
        let given: Function<i32, i32> = Box::new(|v| Some(v * 2));
        let function = function_if_none(Some(given));
        assert_eq!(function(21), Some(42));
    }

    #[test]
    fn supplier_if_none_with_none_returns_dummy() {
        let supplier = supplier_if_none::<i32>(None);
        assert_eq!(supplier(), None);
    }

    #[test]
    fn supplier_if_none_with_some_returns_given() {
        let given: Supplier<i32> = Box::new(|| Some(42));
        let supplier = supplier_if_none(Some(given));
        assert_eq!(supplier(), Some(42));
    }

    #[test]
    fn runnable_if_none_with_none_returns_dummy() {
        let runnable = runnable_if_none(None);
        runnable();
    }

    #[test]
    fn runnable_if_none_with_some_returns_given() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);
        let given: Runnable = Box::new(move || *called_clone.lock().unwrap() = true);

        let runnable = runnable_if_none(Some(given));
        runnable();

        assert!(*called.lock().unwrap());
    }

    #[test]
    fn predicate_if_none_with_none_returns_dummy() {
        let predicate = predicate_if_none::<i32>(None);
        assert!(predicate(&1));
    }

    #[test]
    fn predicate_if_none_with_some_returns_given() {
        let given: Predicate<i32> = Box::new(|v| *v > 0);
        let predicate = predicate_if_none(Some(given));
        assert!(predicate(&1));
        assert!(!predicate(&-1));
    }

    #[test]
    fn bi_predicate_if_none_with_none_returns_dummy() {
        let predicate = bi_predicate_if_none::<i32, i32>(None);
        assert!(predicate(&1, &2));
    }

    #[test]
    fn bi_predicate_if_none_with_some_returns_given() {
        let given: BiPredicate<i32, i32> = Box::new(|a, b| a == b);
        let predicate = bi_predicate_if_none(Some(given));
        assert!(predicate(&1, &1));
        assert!(!predicate(&1, &2));
    }
}
