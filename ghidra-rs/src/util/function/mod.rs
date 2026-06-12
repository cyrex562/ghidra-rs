pub type Callback = Box<dyn Fn() + Send + Sync>;

pub fn dummy_callback() -> Callback {
    Box::new(|| {})
}

pub type ExceptionalCallback<E> = Box<dyn Fn() -> Result<(), E> + Send + Sync>;
pub type ExceptionalConsumer<T, E> = Box<dyn Fn(T) -> Result<(), E> + Send + Sync>;
pub type ExceptionalFunction<T, R, E> = Box<dyn Fn(T) -> Result<R, E> + Send + Sync>;
pub type ExceptionalSupplier<R, E> = Box<dyn Fn() -> Result<R, E> + Send + Sync>;
