/// A trait for accessing bytes from a byte source.
pub trait ByteSequence {
    /// Returns the length of available bytes.
    fn len(&self) -> usize;

    /// Returns the byte at the given index.
    ///
    /// The index must be between 0 and the sequence length.
    fn get_byte(&self, index: usize) -> u8;

    /// Returns `true` if bytes are available for the given range `[index, index + length)`.
    fn has_available_bytes(&self, index: usize, length: usize) -> bool {
        index.checked_add(length).map_or(false, |end| end <= self.len())
    }

    /// Returns a `Vec<u8>` containing bytes from the range `[start, start + length)`.
    fn get_bytes(&self, start: usize, length: usize) -> Vec<u8> {
        (start..start + length).map(|i| self.get_byte(i)).collect()
    }

    /// Returns `true` if the sequence contains no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::ByteSequence;

    struct SliceSequence<'a>(&'a [u8]);

    impl<'a> ByteSequence for SliceSequence<'a> {
        fn len(&self) -> usize {
            self.0.len()
        }

        fn get_byte(&self, index: usize) -> u8 {
            self.0[index]
        }
    }

    #[test]
    fn len_returns_slice_length() {
        let s = SliceSequence(&[0x01, 0x02, 0x03]);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn get_byte_returns_correct_value() {
        let s = SliceSequence(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(s.get_byte(0), 0xAA);
        assert_eq!(s.get_byte(1), 0xBB);
        assert_eq!(s.get_byte(2), 0xCC);
    }

    #[test]
    fn has_available_bytes_within_bounds() {
        let s = SliceSequence(&[0x01, 0x02, 0x03, 0x04]);
        assert!(s.has_available_bytes(0, 4));
        assert!(s.has_available_bytes(1, 3));
        assert!(s.has_available_bytes(2, 2));
        assert!(s.has_available_bytes(4, 0));
    }

    #[test]
    fn has_available_bytes_out_of_bounds() {
        let s = SliceSequence(&[0x01, 0x02, 0x03]);
        assert!(!s.has_available_bytes(0, 4));
        assert!(!s.has_available_bytes(3, 1));
    }

    #[test]
    fn has_available_bytes_overflow_safe() {
        let s = SliceSequence(&[0x00]);
        assert!(!s.has_available_bytes(usize::MAX, 2));
    }

    #[test]
    fn get_bytes_returns_correct_range() {
        let s = SliceSequence(&[0x10, 0x20, 0x30, 0x40, 0x50]);
        assert_eq!(s.get_bytes(1, 3), vec![0x20, 0x30, 0x40]);
    }

    #[test]
    fn get_bytes_full_range() {
        let data = &[0xDE, 0xAD, 0xBE, 0xEF];
        let s = SliceSequence(data);
        assert_eq!(s.get_bytes(0, 4), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn get_bytes_empty_range() {
        let s = SliceSequence(&[0x01, 0x02]);
        assert_eq!(s.get_bytes(1, 0), Vec::<u8>::new());
    }

    #[test]
    fn is_empty_true_for_empty_sequence() {
        let s = SliceSequence(&[]);
        assert!(s.is_empty());
    }

    #[test]
    fn is_empty_false_for_nonempty_sequence() {
        let s = SliceSequence(&[0x01]);
        assert!(!s.is_empty());
    }
}
