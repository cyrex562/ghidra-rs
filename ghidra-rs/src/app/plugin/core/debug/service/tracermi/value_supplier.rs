//! Port of `ghidra.app.plugin.core.debug.service.tracermi.ValueSupplier`.
//!
//! A supplier that uses a `ValueDecoder` to produce objects from trace wire data.

use std::any::Any;
use crate::app::plugin::core::debug::service::tracermi::ValueDecoder;
use crate::program::model::address::AddressOverflowException;

/// Supplies values by decoding them through a `ValueDecoder`.
///
/// Corresponds to `ghidra.app.plugin.core.debug.service.tracermi.ValueSupplier`.
pub trait ValueSupplier {
    /// Get an object from the decoder.
    ///
    /// Corresponds to `ValueSupplier.get(ValueDecoder)`.
    ///
    /// # Errors
    /// Returns an `AddressOverflowException` if the underlying decoder operation
    /// encounters an overflow condition.
    fn get(&self, decoder: &dyn ValueDecoder) -> Result<Box<dyn Any>, AddressOverflowException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::service::tracermi::DefaultValueDecoder;

    /// Mock implementation for testing.
    struct TestValueSupplier {
        value: i32,
    }

    impl ValueSupplier for TestValueSupplier {
        fn get(&self, _decoder: &dyn ValueDecoder) -> Result<Box<dyn Any>, AddressOverflowException> {
            Ok(Box::new(self.value))
        }
    }

    #[test]
    fn test_value_supplier_get_returns_boxed_value() {
        let supplier = TestValueSupplier { value: 42 };
        let result = supplier.get(&DefaultValueDecoder);
        assert!(result.is_ok());
        let obj = result.unwrap();
        assert_eq!(*obj.downcast::<i32>().unwrap(), 42);
    }

    #[test]
    fn test_value_supplier_get_with_decoder() {
        let supplier = TestValueSupplier { value: 100 };
        let decoder = DefaultValueDecoder;
        let result = supplier.get(&decoder);
        assert!(result.is_ok());
        let obj = result.unwrap();
        assert_eq!(*obj.downcast::<i32>().unwrap(), 100);
    }
}
