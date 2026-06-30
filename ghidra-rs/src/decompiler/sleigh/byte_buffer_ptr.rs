use std::rc::Rc;

/// A pointer into a shared byte buffer, supporting offset arithmetic.
///
/// Models `ghidra.pcodeCPort.sleigh.ByteBufferPtr`: a pair of a shared byte array and an
/// integer index, where `add` creates a new pointer into the same underlying buffer.
#[derive(Clone, Debug)]
pub struct ByteBufferPtr {
    buffer: Rc<Vec<u8>>,
    index: usize,
}

impl ByteBufferPtr {
    /// Creates a new `ByteBufferPtr` owning `buffer` with the given starting `index`.
    pub fn new(buffer: Vec<u8>, index: usize) -> Self {
        Self { buffer: Rc::new(buffer), index }
    }

    fn from_shared(buffer: Rc<Vec<u8>>, index: usize) -> Self {
        Self { buffer, index }
    }

    /// Returns a new `ByteBufferPtr` into the same buffer at `self.index + offset`.
    pub fn add(&self, offset: usize) -> Self {
        Self::from_shared(Rc::clone(&self.buffer), self.index + offset)
    }

    /// Returns the byte at `buffer[self.index + i]`, sign-extended to `i32`
    /// to match Java's `byte`-to-`int` widening.
    pub fn get(&self, i: usize) -> i32 {
        self.buffer[self.index + i] as i8 as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_at_index_zero() {
        let ptr = ByteBufferPtr::new(vec![10, 20, 30], 0);
        assert_eq!(ptr.get(0), 10);
        assert_eq!(ptr.get(1), 20);
        assert_eq!(ptr.get(2), 30);
    }

    #[test]
    fn get_with_nonzero_base_index() {
        let ptr = ByteBufferPtr::new(vec![0, 0, 42, 7], 2);
        assert_eq!(ptr.get(0), 42);
        assert_eq!(ptr.get(1), 7);
    }

    #[test]
    fn add_shifts_index() {
        let ptr = ByteBufferPtr::new(vec![1, 2, 3, 4], 0);
        let ptr2 = ptr.add(2);
        assert_eq!(ptr2.get(0), 3);
        assert_eq!(ptr2.get(1), 4);
    }

    #[test]
    fn add_shares_buffer() {
        let ptr = ByteBufferPtr::new(vec![10, 20, 30], 0);
        let ptr2 = ptr.add(1);
        assert!(Rc::ptr_eq(&ptr.buffer, &ptr2.buffer));
    }

    #[test]
    fn get_sign_extends_negative_bytes() {
        let ptr = ByteBufferPtr::new(vec![0xFF, 0x80], 0);
        assert_eq!(ptr.get(0), -1);
        assert_eq!(ptr.get(1), -128);
    }

    #[test]
    fn original_unaffected_after_add() {
        let ptr = ByteBufferPtr::new(vec![5, 6, 7], 0);
        let _ptr2 = ptr.add(1);
        assert_eq!(ptr.get(0), 5);
    }

    #[test]
    fn chained_add() {
        let ptr = ByteBufferPtr::new(vec![1, 2, 3, 4, 5], 0);
        let ptr2 = ptr.add(1).add(2);
        assert_eq!(ptr2.get(0), 4);
    }
}
