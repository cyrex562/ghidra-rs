use crate::program::model::mem::MemoryAccessException;
use crate::program::seam_stubs::MemBuffer;

use super::expression_value::ExpressionValue;

/// Port of `ghidra.app.plugin.processors.generic.Constant`.
///
/// A constant value implementation of the ExpressionValue trait.
/// This represents a fixed constant value that is independent of memory contents.
pub struct Constant {
    val: i64,
}

impl Constant {
    /// Creates a new Constant with the specified value.
    pub fn new(val: i64) -> Self {
        Self { val }
    }
}

impl ExpressionValue for Constant {
    fn long_value(
        &self,
        _buf: &dyn MemBuffer,
        _offset: i32,
    ) -> Result<i64, MemoryAccessException> {
        Ok(self.val)
    }

    fn length(&self, _buf: &dyn MemBuffer, _offset: i32) -> Result<i32, MemoryAccessException> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::seam_stubs::MemBuffer;

    struct TestMemBuffer;

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

    #[test]
    fn constant_returns_stored_value() {
        let c = Constant::new(42);
        let buf = TestMemBuffer;
        assert_eq!(c.long_value(&buf, 0).unwrap(), 42);
    }

    #[test]
    fn constant_length_is_zero() {
        let c = Constant::new(42);
        let buf = TestMemBuffer;
        assert_eq!(c.length(&buf, 0).unwrap(), 0);
    }

    #[test]
    fn constant_with_negative_value() {
        let c = Constant::new(-1);
        let buf = TestMemBuffer;
        assert_eq!(c.long_value(&buf, 0).unwrap(), -1);
    }

    #[test]
    fn constant_with_max_i64_value() {
        let c = Constant::new(i64::MAX);
        let buf = TestMemBuffer;
        assert_eq!(c.long_value(&buf, 0).unwrap(), i64::MAX);
    }

    #[test]
    fn constant_with_min_i64_value() {
        let c = Constant::new(i64::MIN);
        let buf = TestMemBuffer;
        assert_eq!(c.long_value(&buf, 0).unwrap(), i64::MIN);
    }

    #[test]
    fn constant_ignores_buffer_and_offset() {
        let c = Constant::new(100);
        let buf = TestMemBuffer;
        assert_eq!(c.long_value(&buf, 0).unwrap(), 100);
        assert_eq!(c.long_value(&buf, 100).unwrap(), 100);
        assert_eq!(c.long_value(&buf, -5).unwrap(), 100);
    }

    #[test]
    fn constant_length_ignores_buffer_and_offset() {
        let c = Constant::new(42);
        let buf = TestMemBuffer;
        assert_eq!(c.length(&buf, 0).unwrap(), 0);
        assert_eq!(c.length(&buf, 10).unwrap(), 0);
        assert_eq!(c.length(&buf, -10).unwrap(), 0);
    }

    #[test]
    fn constant_as_expression_value_trait_object() {
        let c: Box<dyn ExpressionValue> = Box::new(Constant::new(256));
        let buf = TestMemBuffer;
        assert_eq!(c.long_value(&buf, 0).unwrap(), 256);
        assert_eq!(c.length(&buf, 0).unwrap(), 0);
    }

    #[test]
    fn multiple_constants_with_different_values() {
        let constants = vec![
            Constant::new(1),
            Constant::new(10),
            Constant::new(100),
            Constant::new(1000),
        ];
        let buf = TestMemBuffer;
        assert_eq!(constants[0].long_value(&buf, 0).unwrap(), 1);
        assert_eq!(constants[1].long_value(&buf, 0).unwrap(), 10);
        assert_eq!(constants[2].long_value(&buf, 0).unwrap(), 100);
        assert_eq!(constants[3].long_value(&buf, 0).unwrap(), 1000);
    }
}
