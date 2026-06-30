pub type Callback = Box<dyn Fn() + Send + Sync>;

pub fn dummy_callback() -> Callback {
    Box::new(|| {})
}

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
}
