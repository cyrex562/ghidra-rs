use crate::program::model::mem::MemoryAccessException;
use crate::program::seam_stubs::MemBuffer;

use super::expression_value::ExpressionValue;

/// Port of `ghidra.app.plugin.processors.generic.Label`.
///
/// A label value implementation of the ExpressionValue trait.
/// This represents the address of something in the memory, used as a label
/// in generic processors to handle address expressions and constraints.
pub struct Label;

impl Label {
    /// Creates a new Label.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Label {
    fn default() -> Self {
        Self::new()
    }
}

impl ExpressionValue for Label {
    fn long_value(
        &self,
        buf: &dyn MemBuffer,
        offset: i32,
    ) -> Result<i64, MemoryAccessException> {
        let addr = buf.get_address();
        Ok(addr.offset() + offset as i64)
    }

    fn length(&self, _buf: &dyn MemBuffer, _offset: i32) -> Result<i32, MemoryAccessException> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of MemBuffer for testing.
    struct TestMemBuffer {
        addr_offset: i64,
    }

    impl TestMemBuffer {
        fn new(addr_offset: i64) -> Self {
            Self { addr_offset }
        }
    }

    impl MemBuffer for TestMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            use crate::program::model::address::{AddressSpace, AddressSpaceType};

            let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
            crate::program::model::address::Address::new(space, self.addr_offset)
        }

        fn is_initialized_memory(&self) -> bool {
            true
        }

        fn is_at_initialized_memory_address(&self) -> bool {
            true
        }
    }

    #[test]
    fn label_long_value_returns_address_offset_plus_arg() {
        let label = Label::new();
        let buf = TestMemBuffer::new(1000);
        assert_eq!(label.long_value(&buf, 0).unwrap(), 1000);
        assert_eq!(label.long_value(&buf, 10).unwrap(), 1010);
        assert_eq!(label.long_value(&buf, -5).unwrap(), 995);
    }

    #[test]
    fn label_long_value_with_zero_address_offset() {
        let label = Label::new();
        let buf = TestMemBuffer::new(0);
        assert_eq!(label.long_value(&buf, 0).unwrap(), 0);
        assert_eq!(label.long_value(&buf, 42).unwrap(), 42);
    }

    #[test]
    fn label_long_value_with_negative_offset_argument() {
        let label = Label::new();
        let buf = TestMemBuffer::new(100);
        assert_eq!(label.long_value(&buf, -50).unwrap(), 50);
    }

    #[test]
    fn label_length_is_always_zero() {
        let label = Label::new();
        let buf = TestMemBuffer::new(1000);
        assert_eq!(label.length(&buf, 0).unwrap(), 0);
        assert_eq!(label.length(&buf, 100).unwrap(), 0);
        assert_eq!(label.length(&buf, -100).unwrap(), 0);
    }

    #[test]
    fn label_as_expression_value_trait_object() {
        let label: Box<dyn ExpressionValue> = Box::new(Label::new());
        let buf = TestMemBuffer::new(5000);
        assert_eq!(label.long_value(&buf, 0).unwrap(), 5000);
        assert_eq!(label.long_value(&buf, 20).unwrap(), 5020);
        assert_eq!(label.length(&buf, 0).unwrap(), 0);
    }

    #[test]
    fn label_default_creates_valid_label() {
        let label = Label::default();
        let buf = TestMemBuffer::new(42);
        assert_eq!(label.long_value(&buf, 0).unwrap(), 42);
    }

    #[test]
    fn label_with_large_address_offset() {
        let label = Label::new();
        let buf = TestMemBuffer::new(i64::MAX - 100);
        assert_eq!(label.long_value(&buf, 50).unwrap(), i64::MAX - 50);
    }

    #[test]
    fn label_with_small_address_offset() {
        let label = Label::new();
        let buf = TestMemBuffer::new(i64::MIN + 100);
        assert_eq!(label.long_value(&buf, -50).unwrap(), i64::MIN + 50);
    }
}
