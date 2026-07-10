use crate::program::model::mem::MemoryAccessException;
use crate::program::seam_stubs::MemBuffer;

/// Port of `ghidra.app.plugin.processors.generic.ExpressionValue`.
///
/// A trait for evaluating expressions based on a memory buffer at a given offset.
/// This is used by generic processors to handle operand expressions and constraints.
pub trait ExpressionValue {
    /// Returns the value of this expression as a long (i64).
    ///
    /// # Arguments
    /// * `buf` - The memory buffer providing access to memory contents
    /// * `offset` - The offset within the buffer where the value should be read
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if the memory cannot be accessed at the given offset.
    fn long_value(
        &self,
        buf: &dyn MemBuffer,
        offset: i32,
    ) -> Result<i64, MemoryAccessException>;

    /// Returns the length of this expression value in bytes.
    ///
    /// # Arguments
    /// * `buf` - The memory buffer providing access to memory contents
    /// * `offset` - The offset within the buffer where the length should be calculated from
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if the memory cannot be accessed at the given offset.
    fn length(&self, buf: &dyn MemBuffer, offset: i32) -> Result<i32, MemoryAccessException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of MemBuffer for testing.
    struct TestMemBuffer {
        data: Vec<u8>,
        big_endian: bool,
    }

    impl TestMemBuffer {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                big_endian: false,
            }
        }

        fn with_endian(data: Vec<u8>, big_endian: bool) -> Self {
            Self { data, big_endian }
        }
    }

    impl MemBuffer for TestMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            let space = crate::program::model::address::AddressSpace::new(
                "ram",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                0,
            );
            crate::program::model::address::Address::new(space, 0)
        }

        fn is_initialized_memory(&self) -> bool {
            true
        }

        fn is_at_initialized_memory_address(&self) -> bool {
            true
        }
    }

    /// Simple implementation of ExpressionValue for testing.
    struct SimpleExpression {
        value: i64,
        len: i32,
    }

    impl SimpleExpression {
        fn new(value: i64, len: i32) -> Self {
            Self { value, len }
        }
    }

    impl ExpressionValue for SimpleExpression {
        fn long_value(
            &self,
            _buf: &dyn MemBuffer,
            _offset: i32,
        ) -> Result<i64, MemoryAccessException> {
            Ok(self.value)
        }

        fn length(&self, _buf: &dyn MemBuffer, _offset: i32) -> Result<i32, MemoryAccessException> {
            Ok(self.len)
        }
    }

    #[test]
    fn expression_value_trait_is_object_safe() {
        let expr: Box<dyn ExpressionValue> = Box::new(SimpleExpression::new(42, 8));
        let buf = TestMemBuffer::new(vec![0, 0, 0, 0, 0, 0, 0, 42]);
        assert_eq!(expr.long_value(&buf, 0).unwrap(), 42);
        assert_eq!(expr.length(&buf, 0).unwrap(), 8);
    }

    #[test]
    fn simple_expression_returns_stored_value() {
        let expr = SimpleExpression::new(0x123456, 4);
        let buf = TestMemBuffer::new(vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(expr.long_value(&buf, 0).unwrap(), 0x123456);
    }

    #[test]
    fn simple_expression_returns_stored_length() {
        let expr = SimpleExpression::new(100, 2);
        let buf = TestMemBuffer::new(vec![100, 0]);
        assert_eq!(expr.length(&buf, 0).unwrap(), 2);
    }

    #[test]
    fn long_value_with_different_offsets() {
        let expr = SimpleExpression::new(999, 8);
        let buf = TestMemBuffer::new(vec![0; 16]);
        assert_eq!(expr.long_value(&buf, 0).unwrap(), 999);
        assert_eq!(expr.long_value(&buf, 8).unwrap(), 999);
    }

    #[test]
    fn length_with_zero_length() {
        let expr = SimpleExpression::new(0, 0);
        let buf = TestMemBuffer::new(vec![]);
        assert_eq!(expr.length(&buf, 0).unwrap(), 0);
    }

    #[test]
    fn large_long_value() {
        let large_val = i64::MAX;
        let expr = SimpleExpression::new(large_val, 8);
        let buf = TestMemBuffer::new(vec![0xff; 8]);
        assert_eq!(expr.long_value(&buf, 0).unwrap(), large_val);
    }

    #[test]
    fn multiple_expressions_in_collection() {
        let exprs: Vec<Box<dyn ExpressionValue>> = vec![
            Box::new(SimpleExpression::new(1, 1)),
            Box::new(SimpleExpression::new(2, 2)),
            Box::new(SimpleExpression::new(3, 3)),
        ];
        let buf = TestMemBuffer::new(vec![1, 2, 3]);
        assert_eq!(exprs[0].long_value(&buf, 0).unwrap(), 1);
        assert_eq!(exprs[1].long_value(&buf, 1).unwrap(), 2);
        assert_eq!(exprs[2].long_value(&buf, 2).unwrap(), 3);
    }
}
