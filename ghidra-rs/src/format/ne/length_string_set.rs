use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Stores a length/string pair where the string is not null-terminated
/// and the length field determines the string length.
///
/// Mirrors `LengthStringSet` from the original Ghidra Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthStringSet {
    index: u64,
    length: u8,
    name: Option<String>,
}

impl LengthStringSet {
    /// Constructs a new length/string set by reading from the given binary reader.
    ///
    /// Reads a single byte for the length, then if the length is non-zero,
    /// reads that many ASCII bytes for the name (not null-terminated).
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let index = reader.get_pointer_index();
        let length = reader.read_next_byte()?;

        let name = if length == 0 {
            None
        } else {
            let s = reader.read_next_ascii_string_fixed(length as usize)?;
            Some(s)
        };

        Ok(LengthStringSet {
            index,
            length,
            name,
        })
    }

    /// Returns the byte index of this string, relative to the beginning of the file.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns the length of the string.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Returns the string, or `None` if the length was zero.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_zero_length_string() {
        let mut r = BinaryReader::from_bytes(vec![0], true);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 0);
        assert_eq!(s.length(), 0);
        assert_eq!(s.name(), None);
    }

    #[test]
    fn reads_nonempty_string() {
        let data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let mut r = BinaryReader::from_bytes(data, true);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 0);
        assert_eq!(s.length(), 5);
        assert_eq!(s.name(), Some("hello"));
    }

    #[test]
    fn reads_single_char_string() {
        let data = vec![1, b'x'];
        let mut r = BinaryReader::from_bytes(data, true);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 0);
        assert_eq!(s.length(), 1);
        assert_eq!(s.name(), Some("x"));
    }

    #[test]
    fn updates_reader_position() {
        let data = vec![3, b'a', b'b', b'c', 99];
        let mut r = BinaryReader::from_bytes(data, true);
        let _ = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn tracks_index_at_different_position() {
        let data = vec![0, 0, 0, 2, b'h', b'i'];
        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(3);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 3);
        assert_eq!(s.length(), 2);
        assert_eq!(s.name(), Some("hi"));
    }

    #[test]
    fn clone_equality() {
        let data = vec![4, b't', b'e', b's', b't'];
        let mut r = BinaryReader::from_bytes(data.clone(), true);
        let s1 = LengthStringSet::new(&mut r).unwrap();

        let mut r2 = BinaryReader::from_bytes(data, true);
        let s2 = LengthStringSet::new(&mut r2).unwrap();

        assert_eq!(s1, s2);
    }

    #[test]
    fn zero_length_vs_nonzero_inequality() {
        let mut r1 = BinaryReader::from_bytes(vec![0], true);
        let s1 = LengthStringSet::new(&mut r1).unwrap();

        let data2 = vec![1, b'x'];
        let mut r2 = BinaryReader::from_bytes(data2, true);
        let s2 = LengthStringSet::new(&mut r2).unwrap();

        assert_ne!(s1, s2);
    }
}
