use std::any::Any;
use std::marker::PhantomData;

/// Functional trait to read a structure field's value.
///
/// This is the Rust equivalent of the Java `FieldReadFunction<T>` `@FunctionalInterface`
/// from `ghidra.app.util.bin.format.golang.structmapping`.
///
/// In Java the interface declares a single method:
/// ```java
/// Object get(FieldContext<T> context) throws IOException;
/// ```
/// In Rust the context type is expressed as an associated type so that the trait compiles
/// independently of `FieldContext<T>`, which is ported separately.  When `FieldContext<T>`
/// is available, concrete implementations set `type Context = FieldContext<T>`.
///
/// Closure-based implementations can use [`FnFieldReader`] to satisfy this trait without
/// writing a named struct.
pub trait FieldReadFunction<T> {
    /// Context passed to the read function (typically `FieldContext<T>` once ported).
    type Context;

    /// Deserializes and returns this field's value.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or deserializing the field value fails.
    fn get(&self, context: Self::Context) -> anyhow::Result<Box<dyn Any>>;
}

/// Newtype that adapts any compatible [`Fn`] closure into a [`FieldReadFunction`].
///
/// This mirrors the Java `@FunctionalInterface` idiom — callers wrap a closure in
/// `FnFieldReader::new(|ctx| ...)` instead of defining a dedicated struct.
pub struct FnFieldReader<T, C, F>
where
    F: Fn(C) -> anyhow::Result<Box<dyn Any>>,
{
    func: F,
    _marker: PhantomData<fn(T, C)>,
}

impl<T, C, F> FnFieldReader<T, C, F>
where
    F: Fn(C) -> anyhow::Result<Box<dyn Any>>,
{
    /// Wraps `func` as a [`FieldReadFunction`].
    pub fn new(func: F) -> Self {
        Self { func, _marker: PhantomData }
    }
}

impl<T, C, F> FieldReadFunction<T> for FnFieldReader<T, C, F>
where
    F: Fn(C) -> anyhow::Result<Box<dyn Any>>,
{
    type Context = C;

    fn get(&self, context: C) -> anyhow::Result<Box<dyn Any>> {
        (self.func)(context)
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldReadFunction, FnFieldReader};
    use std::any::Any;

    struct TestContext {
        value: i64,
    }

    struct MyStruct;

    struct ConstantReader(i64);

    impl FieldReadFunction<MyStruct> for ConstantReader {
        type Context = TestContext;

        fn get(&self, _context: TestContext) -> anyhow::Result<Box<dyn Any>> {
            Ok(Box::new(self.0))
        }
    }

    #[test]
    fn named_impl_returns_constant() {
        let reader = ConstantReader(42);
        let result = reader.get(TestContext { value: 0 }).unwrap();
        assert_eq!(*result.downcast_ref::<i64>().unwrap(), 42);
    }

    #[test]
    fn named_impl_error_propagates() {
        struct FailingReader;
        impl FieldReadFunction<MyStruct> for FailingReader {
            type Context = TestContext;
            fn get(&self, _context: TestContext) -> anyhow::Result<Box<dyn Any>> {
                anyhow::bail!("field read failed")
            }
        }
        let err = FailingReader.get(TestContext { value: 0 }).unwrap_err();
        assert!(err.to_string().contains("field read failed"));
    }

    #[test]
    fn fn_field_reader_reads_from_context() {
        let reader = FnFieldReader::<MyStruct, _, _>::new(|ctx: TestContext| {
            Ok(Box::new(ctx.value) as Box<dyn Any>)
        });
        let result = reader.get(TestContext { value: 99 }).unwrap();
        assert_eq!(*result.downcast_ref::<i64>().unwrap(), 99);
    }

    #[test]
    fn fn_field_reader_captures_external_state() {
        let multiplier = 3i64;
        let reader = FnFieldReader::<MyStruct, _, _>::new(move |ctx: TestContext| {
            Ok(Box::new(ctx.value * multiplier) as Box<dyn Any>)
        });
        let result = reader.get(TestContext { value: 7 }).unwrap();
        assert_eq!(*result.downcast_ref::<i64>().unwrap(), 21);
    }

    #[test]
    fn fn_field_reader_error_propagates() {
        let reader = FnFieldReader::<MyStruct, _, _>::new(|_ctx: TestContext| {
            anyhow::bail!("read error")
        });
        let err = reader.get(TestContext { value: 0 }).unwrap_err();
        assert!(err.to_string().contains("read error"));
    }
}
