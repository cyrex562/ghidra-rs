use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::lang::sleigh::walker::MemBuffer;

/// A memory buffer that supports repositioning to different addresses.
///
/// This trait extends [`MemBuffer`] to allow changing the buffer's base address.
/// Implementations must maintain consistency between the position and the underlying memory content.
pub trait MutableMemBuffer: MemBuffer {
    /// Advance the address pointer by the given displacement.
    ///
    /// # Arguments
    /// * `displacement` - The amount to adjust the pointer by (can be positive or negative)
    ///
    /// # Errors
    /// Returns [`AddressOverflowException`] if the displacement would cause the buffer position to overflow
    /// (e.g., advancing beyond the address space bounds).
    fn advance(&mut self, displacement: i32) -> Result<(), AddressOverflowException>;

    /// Set the base address to which offset 0 points.
    ///
    /// # Arguments
    /// * `addr` - The new base address for this buffer
    fn set_position(&mut self, addr: Address);

    /// Create a cloned copy of this MutableMemBuffer.
    fn clone_mutable(&self) -> Box<dyn MutableMemBuffer>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct MockMutableMemBuffer {
        address: Address,
        data: Vec<u8>,
        big_endian: bool,
    }

    impl MockMutableMemBuffer {
        fn new(space: Arc<AddressSpace>, offset: i64, data: Vec<u8>) -> Self {
            Self {
                address: Address::new(space, offset),
                data,
                big_endian: true,
            }
        }

        fn with_little_endian(mut self) -> Self {
            self.big_endian = false;
            self
        }
    }

    impl MemBuffer for MockMutableMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            let idx = offset as usize;
            self.data
                .get(idx)
                .copied()
                .ok_or_else(|| crate::program::model::mem::MemoryAccessException::new("Offset out of bounds"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            if start >= self.data.len() {
                return 0;
            }
            let available = self.data.len() - start;
            let to_copy = buf.len().min(available);
            buf[..to_copy].copy_from_slice(&self.data[start..start + to_copy]);
            to_copy
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    impl MutableMemBuffer for MockMutableMemBuffer {
        fn advance(&mut self, displacement: i32) -> Result<(), AddressOverflowException> {
            let new_addr = self.address.add(displacement as i64)?;
            self.address = new_addr;
            Ok(())
        }

        fn set_position(&mut self, addr: Address) {
            self.address = addr;
        }

        fn clone_mutable(&self) -> Box<dyn MutableMemBuffer> {
            Box::new(MockMutableMemBuffer {
                address: self.address.clone(),
                data: self.data.clone(),
                big_endian: self.big_endian,
            })
        }
    }

    #[test]
    fn advance_with_positive_displacement() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut buf = MockMutableMemBuffer::new(space.clone(), 0x1000, vec![1, 2, 3, 4, 5]);

        assert_eq!(buf.get_address().offset(), 0x1000);
        buf.advance(0x10).unwrap();
        assert_eq!(buf.get_address().offset(), 0x1010);
    }

    #[test]
    fn advance_with_negative_displacement() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut buf = MockMutableMemBuffer::new(space.clone(), 0x2000, vec![1, 2, 3, 4, 5]);

        assert_eq!(buf.get_address().offset(), 0x2000);
        buf.advance(-0x100).unwrap();
        assert_eq!(buf.get_address().offset(), 0x1f00);
    }

    #[test]
    fn advance_overflow_returns_error() {
        let space = AddressSpace::new("RAM", 8, 1, AddressSpaceType::Ram, 1);
        let max_addr = space.max_address();
        let mut buf = MockMutableMemBuffer::new(space.clone(), max_addr.offset(), vec![1, 2, 3]);

        let result = buf.advance(1);
        assert!(result.is_err());
        assert_eq!(buf.get_address().offset(), max_addr.offset());
    }

    #[test]
    fn set_position() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut buf = MockMutableMemBuffer::new(space.clone(), 0x1000, vec![1, 2, 3, 4, 5]);
        let new_addr = Address::new(space.clone(), 0x5000);

        buf.set_position(new_addr.clone());
        assert_eq!(buf.get_address(), new_addr);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut original = MockMutableMemBuffer::new(space.clone(), 0x1000, vec![1, 2, 3, 4, 5]);

        let mut cloned = original.clone_mutable();
        assert_eq!(cloned.get_address().offset(), original.get_address().offset());

        // Modify the clone and verify original is unchanged
        cloned.advance(0x100).unwrap();
        assert_eq!(original.get_address().offset(), 0x1000);
        assert_eq!(cloned.get_address().offset(), 0x1100);
    }

    #[test]
    fn advance_zero_displacement_is_noop() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut buf = MockMutableMemBuffer::new(space.clone(), 0x1000, vec![1, 2, 3, 4, 5]);

        buf.advance(0).unwrap();
        assert_eq!(buf.get_address().offset(), 0x1000);
    }
}
