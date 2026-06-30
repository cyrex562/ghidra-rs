use std::io::{self, Write};

/// A dynamically growing byte buffer for collecting a stream of bytes with support
/// for in-place editing and bulk output.
pub struct PackedBytes {
    data: Vec<u8>,
    len: usize,
}

impl PackedBytes {
    /// Creates a new `PackedBytes` with initial backing storage of `start_len` bytes.
    pub fn new(start_len: usize) -> Self {
        Self {
            data: vec![0u8; start_len],
            len: 0,
        }
    }

    /// Returns the number of bytes accumulated so far.
    pub fn size(&self) -> usize {
        self.len
    }

    /// Returns the byte at `pos` in the accumulated stream.
    pub fn get_byte(&self, pos: usize) -> u8 {
        self.data[pos]
    }

    /// Overwrites the byte at `pos` with `val`.
    pub fn insert_byte(&mut self, pos: usize, val: u8) {
        self.data[pos] = val;
    }

    /// Returns the index of the first byte equal to `val` at or after `start`,
    /// or `None` if no such byte exists within the accumulated stream.
    pub fn find(&self, start: usize, val: u8) -> Option<usize> {
        self.data[start..self.len]
            .iter()
            .position(|&b| b == val)
            .map(|p| p + start)
    }

    /// Writes the accumulated byte stream to `writer`.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.data[..self.len])
    }

    fn ensure_capacity(&mut self, needed: usize) {
        if needed > self.data.len() {
            let new_cap = self.data.len().saturating_mul(2).max(needed);
            self.data.resize(new_cap, 0);
        }
    }
}

impl Write for PackedBytes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let new_len = self.len + buf.len();
        self.ensure_capacity(new_len);
        self.data[self.len..new_len].copy_from_slice(buf);
        self.len = new_len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_new_is_empty() {
        let pb = PackedBytes::new(16);
        assert_eq!(pb.size(), 0);
    }

    #[test]
    fn test_write_single_byte_and_size() {
        let mut pb = PackedBytes::new(16);
        pb.write_all(&[0x42]).unwrap();
        assert_eq!(pb.size(), 1);
        assert_eq!(pb.get_byte(0), 0x42);
    }

    #[test]
    fn test_write_slice() {
        let mut pb = PackedBytes::new(8);
        pb.write_all(&[1, 2, 3, 4]).unwrap();
        assert_eq!(pb.size(), 4);
        assert_eq!(pb.get_byte(0), 1);
        assert_eq!(pb.get_byte(3), 4);
    }

    #[test]
    fn test_insert_byte_overwrites() {
        let mut pb = PackedBytes::new(8);
        pb.write_all(&[0xAA, 0xBB, 0xCC]).unwrap();
        pb.insert_byte(1, 0xFF);
        assert_eq!(pb.get_byte(1), 0xFF);
        assert_eq!(pb.get_byte(0), 0xAA);
        assert_eq!(pb.get_byte(2), 0xCC);
    }

    #[test]
    fn test_find_present() {
        let mut pb = PackedBytes::new(8);
        pb.write_all(&[0x10, 0x20, 0x30, 0x20, 0x40]).unwrap();
        assert_eq!(pb.find(0, 0x20), Some(1));
        assert_eq!(pb.find(2, 0x20), Some(3));
    }

    #[test]
    fn test_find_absent() {
        let mut pb = PackedBytes::new(8);
        pb.write_all(&[1, 2, 3]).unwrap();
        assert_eq!(pb.find(0, 0xFF), None);
    }

    #[test]
    fn test_find_past_end_returns_none() {
        let mut pb = PackedBytes::new(8);
        pb.write_all(&[0x01]).unwrap();
        assert_eq!(pb.find(1, 0x01), None);
    }

    #[test]
    fn test_write_to() {
        let mut pb = PackedBytes::new(8);
        pb.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let mut out = Vec::new();
        pb.write_to(&mut out).unwrap();
        assert_eq!(out, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_growth_beyond_initial_capacity() {
        let mut pb = PackedBytes::new(2);
        for i in 0u8..16 {
            pb.write_all(&[i]).unwrap();
        }
        assert_eq!(pb.size(), 16);
        for i in 0u8..16 {
            assert_eq!(pb.get_byte(i as usize), i);
        }
    }

    #[test]
    fn test_growth_from_zero_capacity() {
        let mut pb = PackedBytes::new(0);
        pb.write_all(&[0xAB, 0xCD]).unwrap();
        assert_eq!(pb.size(), 2);
        assert_eq!(pb.get_byte(0), 0xAB);
        assert_eq!(pb.get_byte(1), 0xCD);
    }

    #[test]
    fn test_write_to_empty_produces_empty_output() {
        let pb = PackedBytes::new(8);
        let mut out = Vec::new();
        pb.write_to(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
