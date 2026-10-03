use super::buffer::{Buffer, DataBuffer};

/// Data buffer used internally for field encoding.
///
/// Port of `db.BinaryDataBuffer`, a package-private `class BinaryDataBuffer extends
/// db.buffers.DataBuffer` whose *entire* purpose in Java is visibility plumbing: `DataBuffer`'s
/// constructors and `getData()` accessor are `protected` (so only reachable from
/// `db.buffers`-package code or a subclass), and `BinaryDataBuffer` exists solely so callers
/// elsewhere in the `db` package (e.g. `BinaryCodedField`, `IndexField`) can construct a
/// `DataBuffer` and read back its raw storage array.
///
/// This port's [`DataBuffer`] (in [`super::buffer`]) already merges `db.Buffer` +
/// `db.buffers.DataBuffer` into one type with a fully `pub` constructor and `pub fn get_data`
/// accessor, so none of that visibility work-around is needed here: `BinaryDataBuffer` is
/// ported as a thin composing wrapper (per this crate's composition-over-inheritance
/// convention) purely to preserve the distinct type name and constructor shapes for call sites
/// that are ported expecting them, delegating every [`Buffer`] method to the inner
/// [`DataBuffer`].
pub struct BinaryDataBuffer {
    inner: DataBuffer,
}

impl BinaryDataBuffer {
    /// Construct a data buffer of `size` zero-initialized bytes. Mirrors
    /// `BinaryDataBuffer(int size)`.
    pub fn new(size: usize) -> Self {
        Self { inner: DataBuffer::new(0, size) }
    }

    /// Construct a data buffer wrapping the given storage array. Mirrors
    /// `BinaryDataBuffer(byte[] data)`.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self { inner: DataBuffer::from_data(0, data) }
    }

    /// Get the byte storage array associated with this buffer. Mirrors the overridden
    /// (package-visibility-only) `BinaryDataBuffer.getData()`.
    pub fn get_data(&self) -> &[u8] {
        self.inner.get_data()
    }
}

impl Buffer for BinaryDataBuffer {
    fn get_id(&self) -> i32 {
        self.inner.get_id()
    }

    fn length(&self) -> usize {
        self.inner.length()
    }

    fn get(&self, offset: usize, bytes: &mut [u8]) {
        self.inner.get(offset, bytes)
    }

    fn get_byte(&self, offset: usize) -> u8 {
        self.inner.get_byte(offset)
    }

    fn get_short(&self, offset: usize) -> i16 {
        self.inner.get_short(offset)
    }

    fn get_int(&self, offset: usize) -> i32 {
        self.inner.get_int(offset)
    }

    fn get_long(&self, offset: usize) -> i64 {
        self.inner.get_long(offset)
    }

    fn put(&mut self, offset: usize, bytes: &[u8]) -> isize {
        self.inner.put(offset, bytes)
    }

    fn put_byte(&mut self, offset: usize, b: u8) -> isize {
        self.inner.put_byte(offset, b)
    }

    fn put_short(&mut self, offset: usize, v: i16) -> isize {
        self.inner.put_short(offset, v)
    }

    fn put_int(&mut self, offset: usize, v: i32) -> isize {
        self.inner.put_int(offset, v)
    }

    fn put_long(&mut self, offset: usize, v: i64) -> isize {
        self.inner.put_long(offset, v)
    }

    fn move_data(&mut self, from: usize, to: usize, len: usize) {
        self.inner.move_data(from, to, len)
    }

    fn copy_data(&mut self, to_offset: usize, from_buf: &dyn Buffer, from_offset: usize, len: usize) {
        self.inner.copy_data(to_offset, from_buf, from_offset, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_zero_initialized_with_id_zero() {
        let buf = BinaryDataBuffer::new(4);
        assert_eq!(buf.get_id(), 0);
        assert_eq!(buf.length(), 4);
        assert_eq!(buf.get_data(), &[0u8, 0, 0, 0]);
    }

    #[test]
    fn test_from_data_wraps_given_array() {
        let buf = BinaryDataBuffer::from_data(vec![1, 2, 3]);
        assert_eq!(buf.get_data(), &[1u8, 2, 3]);
        assert_eq!(buf.length(), 3);
    }

    #[test]
    fn test_put_and_get_data_reflects_mutation() {
        let mut buf = BinaryDataBuffer::new(4);
        buf.put_int(0, 0x01020304);
        assert_eq!(buf.get_data(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buf.get_int(0), 0x01020304);
    }

    #[test]
    fn test_buffer_trait_object_usable() {
        let mut buf: Box<dyn Buffer> = Box::new(BinaryDataBuffer::new(2));
        buf.put_byte(0, 0xAB);
        assert_eq!(buf.get_byte(0), 0xAB);
    }
}
