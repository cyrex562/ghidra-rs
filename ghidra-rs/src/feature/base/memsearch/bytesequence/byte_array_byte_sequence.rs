use crate::util::bytesearch::{ByteSequence, ExtendedByteSequence};

/// A byte sequence implementation that wraps a fixed byte array.
pub struct ByteArrayByteSequence {
    bytes: Vec<u8>,
}

impl ByteArrayByteSequence {
    /// Creates a new byte sequence from the given byte slice.
    pub fn new(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec() }
    }

    /// Creates a new byte sequence from a string's UTF-8 encoded bytes.
    pub fn from_string(data: &str) -> Self {
        Self { bytes: data.as_bytes().to_vec() }
    }
}

impl ByteSequence for ByteArrayByteSequence {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn get_byte(&self, index: usize) -> u8 {
        self.bytes[index]
    }

    fn get_bytes(&self, index: usize, size: usize) -> Vec<u8> {
        if index + size > self.bytes.len() {
            panic!("index out of bounds");
        }
        self.bytes[index..index + size].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_from_bytes() {
        let data = &[0x01, 0x02, 0x03];
        let seq = ByteArrayByteSequence::new(data);
        assert_eq!(seq.len(), 3);
    }

    #[test]
    fn new_empty() {
        let seq = ByteArrayByteSequence::new(&[]);
        assert_eq!(seq.len(), 0);
        assert!(seq.is_empty());
    }

    #[test]
    fn get_byte_returns_correct_value() {
        let data = &[0xAA, 0xBB, 0xCC];
        let seq = ByteArrayByteSequence::new(data);
        assert_eq!(seq.get_byte(0), 0xAA);
        assert_eq!(seq.get_byte(1), 0xBB);
        assert_eq!(seq.get_byte(2), 0xCC);
    }

    #[test]
    fn from_string_creates_sequence_from_utf8() {
        let seq = ByteArrayByteSequence::from_string("hello");
        assert_eq!(seq.len(), 5);
        assert_eq!(seq.get_byte(0), b'h');
        assert_eq!(seq.get_byte(1), b'e');
        assert_eq!(seq.get_byte(2), b'l');
        assert_eq!(seq.get_byte(3), b'l');
        assert_eq!(seq.get_byte(4), b'o');
    }

    #[test]
    fn get_bytes_returns_correct_range() {
        let data = &[0x10, 0x20, 0x30, 0x40, 0x50];
        let seq = ByteArrayByteSequence::new(data);
        assert_eq!(seq.get_bytes(1, 3), vec![0x20, 0x30, 0x40]);
    }

    #[test]
    fn get_bytes_full_range() {
        let data = &[0xDE, 0xAD, 0xBE, 0xEF];
        let seq = ByteArrayByteSequence::new(data);
        assert_eq!(seq.get_bytes(0, 4), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn get_bytes_empty_range() {
        let data = &[0x01, 0x02];
        let seq = ByteArrayByteSequence::new(data);
        assert_eq!(seq.get_bytes(1, 0), Vec::<u8>::new());
    }

    #[test]
    fn has_available_bytes_within_bounds() {
        let data = &[0x01, 0x02, 0x03, 0x04];
        let seq = ByteArrayByteSequence::new(data);
        assert!(seq.has_available_bytes(0, 4));
        assert!(seq.has_available_bytes(1, 3));
        assert!(seq.has_available_bytes(2, 2));
        assert!(seq.has_available_bytes(4, 0));
    }

    #[test]
    fn has_available_bytes_out_of_bounds() {
        let data = &[0x01, 0x02, 0x03];
        let seq = ByteArrayByteSequence::new(data);
        assert!(!seq.has_available_bytes(0, 4));
        assert!(!seq.has_available_bytes(3, 1));
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn get_bytes_negative_index_panics() {
        let data = &[0x01, 0x02, 0x03];
        let seq = ByteArrayByteSequence::new(data);
        seq.get_bytes(0, 4);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn get_bytes_overflow_panics() {
        let data = &[0x01, 0x02, 0x03];
        let seq = ByteArrayByteSequence::new(data);
        seq.get_bytes(2, 2);
    }

    fn make_pre() -> ByteArrayByteSequence {
        ByteArrayByteSequence::new(&[0, 1, 2, 3])
    }

    fn make_main() -> ByteArrayByteSequence {
        ByteArrayByteSequence::new(&[0, 1, 2, 3])
    }

    fn make_extra() -> ByteArrayByteSequence {
        ByteArrayByteSequence::new(&[4, 5])
    }

    fn make_extended() -> ExtendedByteSequence {
        ExtendedByteSequence::new(Box::new(make_main()), Some(Box::new(make_pre())), Some(Box::new(make_extra())), 100)
    }

    #[test]
    fn simple_byte_sequence() {
        let main = make_main();
        assert_eq!(main.len(), 4);
        assert_eq!(main.get_byte(0), 0);
        assert_eq!(main.get_byte(1), 1);
        assert_eq!(main.get_byte(2), 2);
        assert_eq!(main.get_byte(3), 3);
    }

    #[test]
    #[should_panic]
    fn simple_byte_sequence_get_byte_out_of_bounds_panics() {
        let main = make_main();
        main.get_byte(4);
    }

    #[test]
    fn simple_get_available_bytes() {
        let main = make_main();

        assert!(main.has_available_bytes(0, 1));
        assert!(main.has_available_bytes(0, 2));
        assert!(main.has_available_bytes(0, 3));
        assert!(main.has_available_bytes(0, 4));
        assert!(!main.has_available_bytes(0, 5));

        assert!(main.has_available_bytes(1, 1));
        assert!(main.has_available_bytes(1, 2));
        assert!(main.has_available_bytes(1, 3));
        assert!(!main.has_available_bytes(1, 4));
        assert!(!main.has_available_bytes(1, 5));

        assert!(main.has_available_bytes(2, 1));
        assert!(main.has_available_bytes(2, 2));
        assert!(!main.has_available_bytes(2, 3));
        assert!(!main.has_available_bytes(2, 4));

        assert!(main.has_available_bytes(3, 1));
        assert!(!main.has_available_bytes(3, 2));
        assert!(!main.has_available_bytes(3, 3));

        assert!(!main.has_available_bytes(4, 1));
        assert!(!main.has_available_bytes(4, 2));
    }

    #[test]
    fn extended_byte_sequence() {
        let extended = make_extended();
        assert_eq!(extended.len(), 4);
        assert_eq!(extended.get_byte(0), 0);
        assert_eq!(extended.get_byte(1), 1);
        assert_eq!(extended.get_byte(2), 2);
        assert_eq!(extended.get_byte(3), 3);
        assert_eq!(extended.get_byte(4), 4);
        assert_eq!(extended.get_byte(5), 5);
    }

    #[test]
    #[should_panic]
    fn extended_byte_sequence_get_byte_out_of_bounds_panics() {
        let extended = make_extended();
        extended.get_byte(6);
    }

    #[test]
    fn extended_get_available_bytes() {
        let extended = make_extended();

        assert!(extended.has_available_bytes(0, 1));
        assert!(extended.has_available_bytes(0, 2));
        assert!(extended.has_available_bytes(0, 3));
        assert!(extended.has_available_bytes(0, 4));
        assert!(extended.has_available_bytes(0, 5));
        assert!(extended.has_available_bytes(0, 6));
        assert!(!extended.has_available_bytes(0, 7));

        assert!(extended.has_available_bytes(1, 1));
        assert!(extended.has_available_bytes(1, 2));
        assert!(extended.has_available_bytes(1, 3));
        assert!(extended.has_available_bytes(1, 4));
        assert!(extended.has_available_bytes(1, 5));
        assert!(!extended.has_available_bytes(1, 6));
        assert!(!extended.has_available_bytes(1, 7));

        assert!(extended.has_available_bytes(2, 1));
        assert!(extended.has_available_bytes(2, 2));
        assert!(extended.has_available_bytes(2, 3));
        assert!(extended.has_available_bytes(2, 4));
        assert!(!extended.has_available_bytes(2, 5));
        assert!(!extended.has_available_bytes(2, 6));

        assert!(extended.has_available_bytes(3, 1));
        assert!(extended.has_available_bytes(3, 2));
        assert!(extended.has_available_bytes(3, 3));
        assert!(!extended.has_available_bytes(3, 4));
        assert!(!extended.has_available_bytes(3, 5));

        assert!(extended.has_available_bytes(4, 1));
        assert!(extended.has_available_bytes(4, 2));
        assert!(!extended.has_available_bytes(4, 3));
        assert!(!extended.has_available_bytes(4, 4));

        assert!(extended.has_available_bytes(5, 1));
        assert!(!extended.has_available_bytes(5, 2));
        assert!(!extended.has_available_bytes(5, 3));

        assert!(!extended.has_available_bytes(6, 1));
    }
}
