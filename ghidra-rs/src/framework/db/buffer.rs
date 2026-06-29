/// General purpose storage buffer interface providing various data access methods.
pub trait Buffer {
    /// Get the buffer ID for this buffer.
    fn get_id(&self) -> i32;

    /// Get the length of the buffer in bytes.
    fn length(&self) -> usize;

    /// Read `bytes.len()` bytes starting at `offset` into `bytes`.
    fn get(&self, offset: usize, bytes: &mut [u8]);

    /// Read `length` bytes starting at `offset` into `data[data_offset..]`.
    fn get_into(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) {
        self.get(offset, &mut data[data_offset..data_offset + length]);
    }

    /// Read `length` bytes starting at `offset` and return them as a new `Vec<u8>`.
    fn get_bytes(&self, offset: usize, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        self.get(offset, &mut bytes);
        bytes
    }

    /// Get the 8-bit byte value at `offset`.
    fn get_byte(&self, offset: usize) -> u8;

    /// Get the 16-bit big-endian short value at `offset`.
    fn get_short(&self, offset: usize) -> i16;

    /// Get the 32-bit big-endian integer value at `offset`.
    fn get_int(&self, offset: usize) -> i32;

    /// Get the 64-bit big-endian long value at `offset`.
    fn get_long(&self, offset: usize) -> i64;

    /// Write all of `bytes` into the buffer at `offset`.
    ///
    /// Returns the next available offset, or -1 if the buffer is full.
    fn put(&mut self, offset: usize, bytes: &[u8]) -> isize;

    /// Write `data[data_offset..data_offset + length]` into the buffer at `offset`.
    ///
    /// Returns the next available offset, or -1 if the buffer is full.
    fn put_from(&mut self, offset: usize, data: &[u8], data_offset: usize, length: usize) -> isize {
        self.put(offset, &data[data_offset..data_offset + length])
    }

    /// Put the 8-bit byte value into the buffer at `offset`.
    ///
    /// Returns the next available offset, or -1 if the buffer is full.
    fn put_byte(&mut self, offset: usize, b: u8) -> isize;

    /// Put the 16-bit big-endian short value into the buffer at `offset`.
    ///
    /// Returns the next available offset, or -1 if the buffer is full.
    fn put_short(&mut self, offset: usize, v: i16) -> isize;

    /// Put the 32-bit big-endian integer value into the buffer at `offset`.
    ///
    /// Returns the next available offset, or -1 if the buffer is full.
    fn put_int(&mut self, offset: usize, v: i32) -> isize;

    /// Put the 64-bit big-endian long value into the buffer at `offset`.
    ///
    /// Returns the next available offset, or -1 if the buffer is full.
    fn put_long(&mut self, offset: usize, v: i64) -> isize;

    fn move_data(&mut self, from: usize, to: usize, len: usize);
    fn copy_data(
        &mut self,
        to_offset: usize,
        from_buf: &dyn Buffer,
        from_offset: usize,
        len: usize,
    );
}

pub struct DataBuffer {
    id: i32,
    data: Vec<u8>,
}

impl DataBuffer {
    pub fn new(id: i32, size: usize) -> Self {
        Self {
            id,
            data: vec![0; size],
        }
    }

    pub fn from_data(id: i32, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn get_data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Buffer for DataBuffer {
    fn get_id(&self) -> i32 {
        self.id
    }

    fn length(&self) -> usize {
        self.data.len()
    }

    fn get(&self, offset: usize, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.data[offset..offset + bytes.len()]);
    }

    fn get_byte(&self, offset: usize) -> u8 {
        self.data[offset]
    }

    fn get_short(&self, offset: usize) -> i16 {
        i16::from_be_bytes([self.data[offset], self.data[offset + 1]])
    }

    fn get_int(&self, offset: usize) -> i32 {
        i32::from_be_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    fn get_long(&self, offset: usize) -> i64 {
        i64::from_be_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
            self.data[offset + 4],
            self.data[offset + 5],
            self.data[offset + 6],
            self.data[offset + 7],
        ])
    }

    fn put(&mut self, offset: usize, bytes: &[u8]) -> isize {
        if offset + bytes.len() > self.data.len() {
            return -1;
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        (offset + bytes.len()) as isize
    }

    fn put_byte(&mut self, offset: usize, b: u8) -> isize {
        if offset + 1 > self.data.len() {
            return -1;
        }
        self.data[offset] = b;
        (offset + 1) as isize
    }

    fn put_short(&mut self, offset: usize, v: i16) -> isize {
        self.put(offset, &v.to_be_bytes())
    }

    fn put_int(&mut self, offset: usize, v: i32) -> isize {
        self.put(offset, &v.to_be_bytes())
    }

    fn put_long(&mut self, offset: usize, v: i64) -> isize {
        self.put(offset, &v.to_be_bytes())
    }

    fn move_data(&mut self, from: usize, to: usize, len: usize) {
        self.data.copy_within(from..from + len, to);
    }

    fn copy_data(
        &mut self,
        to_offset: usize,
        from_buf: &dyn Buffer,
        from_offset: usize,
        len: usize,
    ) {
        let mut temp = vec![0u8; len];
        from_buf.get(from_offset, &mut temp);
        self.data[to_offset..to_offset + len].copy_from_slice(&temp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(size: usize) -> DataBuffer {
        DataBuffer::new(1, size)
    }

    #[test]
    fn test_get_id_and_length() {
        let buf = DataBuffer::new(42, 64);
        assert_eq!(buf.get_id(), 42);
        assert_eq!(buf.length(), 64);
    }

    #[test]
    fn test_put_get_byte() {
        let mut buf = make_buf(8);
        assert_eq!(buf.put_byte(0, 0xAB), 1);
        assert_eq!(buf.get_byte(0), 0xAB);
    }

    #[test]
    fn test_put_get_short_big_endian() {
        let mut buf = make_buf(8);
        assert_eq!(buf.put_short(0, 0x1234_i16), 2);
        assert_eq!(buf.get_short(0), 0x1234_i16);
        assert_eq!(buf.get_byte(0), 0x12);
        assert_eq!(buf.get_byte(1), 0x34);
    }

    #[test]
    fn test_put_get_int_big_endian() {
        let mut buf = make_buf(8);
        assert_eq!(buf.put_int(0, 0x12345678_i32), 4);
        assert_eq!(buf.get_int(0), 0x12345678_i32);
        assert_eq!(buf.get_byte(0), 0x12);
        assert_eq!(buf.get_byte(3), 0x78);
    }

    #[test]
    fn test_put_get_long_big_endian() {
        let mut buf = make_buf(16);
        let v: i64 = 0x0102030405060708;
        assert_eq!(buf.put_long(0, v), 8);
        assert_eq!(buf.get_long(0), v);
        assert_eq!(buf.get_byte(0), 0x01);
        assert_eq!(buf.get_byte(7), 0x08);
    }

    #[test]
    fn test_put_get_bytes() {
        let mut buf = make_buf(16);
        let data = [1u8, 2, 3, 4, 5];
        assert_eq!(buf.put(2, &data), 7);
        let mut out = [0u8; 5];
        buf.get(2, &mut out);
        assert_eq!(out, data);
    }

    #[test]
    fn test_get_bytes_returns_vec() {
        let mut buf = make_buf(16);
        buf.put(4, &[0xAAu8, 0xBB, 0xCC]);
        let v = buf.get_bytes(4, 3);
        assert_eq!(v, vec![0xAAu8, 0xBB, 0xCC]);
    }

    #[test]
    fn test_get_into_with_offset() {
        let mut buf = make_buf(16);
        buf.put(0, &[10u8, 20, 30, 40]);
        let mut dest = [0u8; 8];
        buf.get_into(1, &mut dest, 3, 2);
        // dest[3] == 20, dest[4] == 30, rest untouched
        assert_eq!(dest[3], 20);
        assert_eq!(dest[4], 30);
        assert_eq!(dest[0], 0);
        assert_eq!(dest[5], 0);
    }

    #[test]
    fn test_put_from_with_offset() {
        let mut buf = make_buf(16);
        let src = [0u8, 1, 2, 3, 4, 5];
        // Write src[2..4] (i.e. [2, 3]) into buf at offset 5
        let next = buf.put_from(5, &src, 2, 2);
        assert_eq!(next, 7);
        assert_eq!(buf.get_byte(5), 2);
        assert_eq!(buf.get_byte(6), 3);
    }

    #[test]
    fn test_put_returns_minus_one_when_full() {
        let mut buf = make_buf(4);
        assert_eq!(buf.put(3, &[1u8, 2]), -1);
    }

    #[test]
    fn test_put_byte_returns_minus_one_at_boundary() {
        let mut buf = make_buf(4);
        assert_eq!(buf.put_byte(4, 0xFF), -1);
    }

    #[test]
    fn test_from_data_constructor() {
        let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let buf = DataBuffer::from_data(7, data.clone());
        assert_eq!(buf.get_id(), 7);
        assert_eq!(buf.get_data(), data.as_slice());
        assert_eq!(buf.length(), 4);
    }

    #[test]
    fn test_move_data() {
        let mut buf = DataBuffer::from_data(1, vec![1u8, 2, 3, 4, 5, 6]);
        buf.move_data(0, 2, 3); // copy [1,2,3] to offset 2
        assert_eq!(buf.get_byte(2), 1);
        assert_eq!(buf.get_byte(3), 2);
        assert_eq!(buf.get_byte(4), 3);
    }

    #[test]
    fn test_copy_data_between_buffers() {
        let src = DataBuffer::from_data(1, vec![0xAAu8, 0xBB, 0xCC, 0xDD]);
        let mut dst = make_buf(8);
        dst.copy_data(2, &src, 1, 2); // copy src[1..3] ([BB, CC]) to dst at 2
        assert_eq!(dst.get_byte(2), 0xBB);
        assert_eq!(dst.get_byte(3), 0xCC);
    }
}
