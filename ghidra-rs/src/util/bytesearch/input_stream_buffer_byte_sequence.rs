use std::io::{self, Read};

use super::byte_sequence::ByteSequence;

/// A [`ByteSequence`] that buffers bytes read from a [`Read`] source.
pub struct InputStreamBufferByteSequence {
    bytes: Vec<u8>,
    valid_data_length: usize,
}

impl InputStreamBufferByteSequence {
    /// Creates a new buffer with the given fixed capacity.
    pub fn new(buffer_size: usize) -> Self {
        Self { bytes: vec![0u8; buffer_size], valid_data_length: 0 }
    }

    /// Loads up to `amount` bytes from `reader` into this buffer.
    ///
    /// `amount` must not exceed the buffer capacity. A single `read` call is issued; the
    /// actual number of bytes transferred (which may be less than `amount`) is recorded as
    /// the valid data length. On EOF, the valid data length becomes 0.
    ///
    /// # Errors
    ///
    /// Returns an error if `amount` exceeds the buffer capacity, or if `reader` returns an
    /// I/O error.
    pub fn load<R: Read>(&mut self, reader: &mut R, amount: usize) -> io::Result<()> {
        if amount > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Attempted to read greater that buffer size!",
            ));
        }
        let num_read = reader.read(&mut self.bytes[..amount])?;
        self.valid_data_length = num_read;
        Ok(())
    }
}

impl ByteSequence for InputStreamBufferByteSequence {
    fn len(&self) -> usize {
        self.valid_data_length
    }

    fn get_byte(&self, index: usize) -> u8 {
        self.bytes[index]
    }

    fn get_bytes(&self, start: usize, length: usize) -> Vec<u8> {
        if start + length > self.valid_data_length {
            panic!("index out of bounds");
        }
        self.bytes[start..start + length].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn new_starts_with_zero_len() {
        let seq = InputStreamBufferByteSequence::new(16);
        assert_eq!(seq.len(), 0);
        assert!(seq.is_empty());
    }

    #[test]
    fn load_fills_valid_data_length() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![0x01, 0x02, 0x03, 0x04]);
        seq.load(&mut reader, 4).unwrap();
        assert_eq!(seq.len(), 4);
    }

    #[test]
    fn load_partial_amount() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        seq.load(&mut reader, 2).unwrap();
        assert_eq!(seq.len(), 2);
        assert_eq!(seq.get_byte(0), 0xAA);
        assert_eq!(seq.get_byte(1), 0xBB);
    }

    #[test]
    fn load_amount_exceeds_buffer_returns_error() {
        let mut seq = InputStreamBufferByteSequence::new(4);
        let mut reader = Cursor::new(vec![0u8; 8]);
        let result = seq.load(&mut reader, 5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn load_eof_sets_len_to_zero() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![] as Vec<u8>);
        seq.load(&mut reader, 4).unwrap();
        assert_eq!(seq.len(), 0);
        assert!(seq.is_empty());
    }

    #[test]
    fn get_byte_returns_correct_value() {
        let mut seq = InputStreamBufferByteSequence::new(4);
        let mut reader = Cursor::new(vec![0x10, 0x20, 0x30, 0x40]);
        seq.load(&mut reader, 4).unwrap();
        assert_eq!(seq.get_byte(0), 0x10);
        assert_eq!(seq.get_byte(3), 0x40);
    }

    #[test]
    fn has_available_bytes_within_valid_range() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![1u8, 2, 3, 4]);
        seq.load(&mut reader, 4).unwrap();
        assert!(seq.has_available_bytes(0, 4));
        assert!(seq.has_available_bytes(1, 3));
        assert!(seq.has_available_bytes(4, 0));
    }

    #[test]
    fn has_available_bytes_out_of_valid_range() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![1u8, 2, 3, 4]);
        seq.load(&mut reader, 4).unwrap();
        assert!(!seq.has_available_bytes(0, 5));
        assert!(!seq.has_available_bytes(4, 1));
    }

    #[test]
    fn get_bytes_returns_correct_slice() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        seq.load(&mut reader, 4).unwrap();
        assert_eq!(seq.get_bytes(1, 2), vec![0xAD, 0xBE]);
    }

    #[test]
    #[should_panic]
    fn get_bytes_panics_when_out_of_bounds() {
        let mut seq = InputStreamBufferByteSequence::new(8);
        let mut reader = Cursor::new(vec![1u8, 2, 3]);
        seq.load(&mut reader, 3).unwrap();
        let _ = seq.get_bytes(2, 2);
    }

    #[test]
    fn load_overwrites_previous_data() {
        let mut seq = InputStreamBufferByteSequence::new(4);
        let mut r1 = Cursor::new(vec![0xAA, 0xBB]);
        seq.load(&mut r1, 2).unwrap();
        assert_eq!(seq.len(), 2);
        let mut r2 = Cursor::new(vec![0x11, 0x22, 0x33]);
        seq.load(&mut r2, 3).unwrap();
        assert_eq!(seq.len(), 3);
        assert_eq!(seq.get_byte(0), 0x11);
    }
}
