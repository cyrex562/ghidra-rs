use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_set::LengthStringSet;

/// Stores a length/string/ordinal triplet.
///
/// Extends `LengthStringSet` by adding an ordinal (short integer) that is read
/// only if the length field is non-zero.
///
/// Mirrors `LengthStringOrdinalSet` from the original Ghidra Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthStringOrdinalSet {
    length_string_set: LengthStringSet,
    ordinal: Option<i16>,
}

impl LengthStringOrdinalSet {
    /// Constructs a new length/string/ordinal set by reading from the given binary reader.
    ///
    /// Reads the length/string pair from the parent `LengthStringSet`, then if the
    /// length is non-zero, reads a 2-byte signed integer for the ordinal value.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let length_string_set = LengthStringSet::new(reader)?;

        let ordinal = if length_string_set.length() == 0 {
            None
        } else {
            Some(reader.read_next_short()?)
        };

        Ok(LengthStringOrdinalSet {
            length_string_set,
            ordinal,
        })
    }

    /// Returns the ordinal value if the length was non-zero.
    pub fn ordinal(&self) -> Option<i16> {
        self.ordinal
    }

    /// Returns a reference to the underlying `LengthStringSet`.
    pub fn length_string_set(&self) -> &LengthStringSet {
        &self.length_string_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_zero_length_no_ordinal() {
        let mut r = BinaryReader::from_bytes(vec![0], true);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 0);
        assert_eq!(s.length_string_set().name(), None);
        assert_eq!(s.ordinal(), None);
    }

    #[test]
    fn reads_nonzero_length_with_ordinal() {
        let mut data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        data.extend_from_slice(&42i16.to_le_bytes());
        let mut r = BinaryReader::from_bytes(data, true);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 5);
        assert_eq!(s.length_string_set().name(), Some("hello"));
        assert_eq!(s.ordinal(), Some(42));
    }

    #[test]
    fn reads_single_char_with_ordinal() {
        let mut data = vec![1, b'x'];
        data.extend_from_slice(&100i16.to_le_bytes());
        let mut r = BinaryReader::from_bytes(data, true);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 1);
        assert_eq!(s.length_string_set().name(), Some("x"));
        assert_eq!(s.ordinal(), Some(100));
    }

    #[test]
    fn reads_negative_ordinal() {
        let mut data = vec![2, b'a', b'b'];
        data.extend_from_slice(&(-5i16).to_le_bytes());
        let mut r = BinaryReader::from_bytes(data, true);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 2);
        assert_eq!(s.length_string_set().name(), Some("ab"));
        assert_eq!(s.ordinal(), Some(-5));
    }

    #[test]
    fn updates_reader_position_with_ordinal() {
        let mut data = vec![3, b'a', b'b', b'c'];
        data.extend_from_slice(&99i16.to_le_bytes());
        data.push(255);
        let mut r = BinaryReader::from_bytes(data, true);
        let _ = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 6);
    }

    #[test]
    fn zero_length_no_ordinal_read() {
        let mut data = vec![0];
        data.extend_from_slice(&42i16.to_le_bytes());
        let mut r = BinaryReader::from_bytes(data, true);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.ordinal(), None);
        assert_eq!(r.get_pointer_index(), 1);
    }

    #[test]
    fn clone_equality() {
        let mut data = vec![4, b't', b'e', b's', b't'];
        data.extend_from_slice(&200i16.to_le_bytes());
        let data_clone = data.clone();
        let mut r = BinaryReader::from_bytes(data, true);
        let s1 = LengthStringOrdinalSet::new(&mut r).unwrap();

        let mut r2 = BinaryReader::from_bytes(data_clone, true);
        let s2 = LengthStringOrdinalSet::new(&mut r2).unwrap();

        assert_eq!(s1, s2);
    }

    #[test]
    fn zero_length_vs_nonzero_inequality() {
        let mut r1 = BinaryReader::from_bytes(vec![0], true);
        let s1 = LengthStringOrdinalSet::new(&mut r1).unwrap();

        let mut data2 = vec![1, b'x'];
        data2.extend_from_slice(&42i16.to_le_bytes());
        let mut r2 = BinaryReader::from_bytes(data2, true);
        let s2 = LengthStringOrdinalSet::new(&mut r2).unwrap();

        assert_ne!(s1, s2);
    }

    #[test]
    fn same_string_different_ordinal_inequality() {
        let mut data1 = vec![3, b'f', b'o', b'o'];
        data1.extend_from_slice(&10i16.to_le_bytes());
        let mut r1 = BinaryReader::from_bytes(data1, true);
        let s1 = LengthStringOrdinalSet::new(&mut r1).unwrap();

        let mut data2 = vec![3, b'f', b'o', b'o'];
        data2.extend_from_slice(&20i16.to_le_bytes());
        let mut r2 = BinaryReader::from_bytes(data2, true);
        let s2 = LengthStringOrdinalSet::new(&mut r2).unwrap();

        assert_ne!(s1, s2);
    }
}
