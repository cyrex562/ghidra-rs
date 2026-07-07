/// A byte-backed buffer that stores `i32` values as big-endian 4-byte sequences.
///
/// Mirrors `ghidra.util.TestBuffer` from the Ghidra Java source.
pub struct TestBuffer {
    data: Vec<u8>,
}

impl TestBuffer {
    /// Creates a new `TestBuffer` that can hold `size` integer values.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size * 4],
        }
    }

    /// Stores `value` at logical index `index` using big-endian byte order.
    pub fn put(&mut self, index: usize, value: i32) {
        let i = index * 4;
        self.data[i] = (value >> 24) as u8;
        self.data[i + 1] = (value >> 16) as u8;
        self.data[i + 2] = (value >> 8) as u8;
        self.data[i + 3] = value as u8;
    }

    /// Retrieves the integer stored at logical index `index`.
    pub fn get(&self, index: usize) -> i32 {
        let i = index * 4;
        let a = (self.data[i] as i32) << 24;
        let b = ((self.data[i + 1] as i32) << 16) & 0x00ff_0000;
        let c = ((self.data[i + 2] as i32) << 8) & 0x0000_ff00;
        let d = (self.data[i + 3] as i32) & 0x0000_00ff;
        a | b | c | d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_and_get_zero() {
        let mut buf = TestBuffer::new(4);
        buf.put(0, 0);
        assert_eq!(buf.get(0), 0);
    }

    #[test]
    fn test_put_and_get_positive() {
        let mut buf = TestBuffer::new(4);
        buf.put(1, 12345678);
        assert_eq!(buf.get(1), 12345678);
    }

    #[test]
    fn test_put_and_get_negative() {
        let mut buf = TestBuffer::new(4);
        buf.put(0, -1);
        assert_eq!(buf.get(0), -1);
    }

    #[test]
    fn test_put_and_get_min_i32() {
        let mut buf = TestBuffer::new(4);
        buf.put(0, i32::MIN);
        assert_eq!(buf.get(0), i32::MIN);
    }

    #[test]
    fn test_put_and_get_max_i32() {
        let mut buf = TestBuffer::new(4);
        buf.put(0, i32::MAX);
        assert_eq!(buf.get(0), i32::MAX);
    }

    #[test]
    fn test_multiple_entries_independent() {
        let size = 10;
        let mut buf = TestBuffer::new(size);
        for i in 0..size {
            buf.put(i, i as i32);
        }
        for i in 0..size {
            assert_eq!(buf.get(i), i as i32);
        }
    }

    #[test]
    fn test_big_endian_byte_layout() {
        let mut buf = TestBuffer::new(1);
        // 0x01020304 in big-endian is bytes [0x01, 0x02, 0x03, 0x04]
        buf.put(0, 0x01020304);
        assert_eq!(buf.data[0], 0x01);
        assert_eq!(buf.data[1], 0x02);
        assert_eq!(buf.data[2], 0x03);
        assert_eq!(buf.data[3], 0x04);
    }

    #[test]
    fn test_overwrite() {
        let mut buf = TestBuffer::new(2);
        buf.put(0, 42);
        buf.put(0, 99);
        assert_eq!(buf.get(0), 99);
    }
}
