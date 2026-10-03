use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_set::LengthStringSet;

/// Stores a resource name in a new-executable (NE) format file.
///
/// A resource name consists of a length-prefixed string and an index marking
/// its position in the file.
///
/// Mirrors `ResourceName` from the original Ghidra Java source.
#[derive(Debug, Clone)]
pub struct ResourceName {
    lns: LengthStringSet,
    index: u64,
}

impl ResourceName {
    /// Constructs a new resource name by reading from the given binary reader.
    ///
    /// Captures the current pointer index before reading the length-string pair,
    /// then reads and stores the length and name data.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let index = reader.get_pointer_index();
        let lns = LengthStringSet::new(reader)?;

        Ok(ResourceName { lns, index })
    }

    /// Returns the length of the resource name.
    pub fn length(&self) -> u8 {
        self.lns.length()
    }

    /// Returns the name string, or an empty string if no name was present.
    pub fn name(&self) -> String {
        self.lns.name().unwrap_or("").to_string()
    }

    /// Returns the byte index of this resource name, relative to the beginning of the file.
    pub fn index(&self) -> u64 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn constructs_with_zero_length_name() {
        let mut r = BinaryReader::from_bytes(vec![0], true);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 0);
        assert_eq!(rn.length(), 0);
        assert_eq!(rn.name(), "");
    }

    #[test]
    fn constructs_with_nonempty_name() {
        let data = vec![5, b'a', b'l', b'i', b'a', b's'];
        let mut r = BinaryReader::from_bytes(data, true);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 0);
        assert_eq!(rn.length(), 5);
        assert_eq!(rn.name(), "alias");
    }

    #[test]
    fn constructs_with_single_char_name() {
        let data = vec![1, b'x'];
        let mut r = BinaryReader::from_bytes(data, true);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 0);
        assert_eq!(rn.length(), 1);
        assert_eq!(rn.name(), "x");
    }

    #[test]
    fn preserves_index_from_reader_position() {
        let data = vec![0, 0, 0, 3, b'r', b'e', b's'];
        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(3);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 3);
        assert_eq!(rn.length(), 3);
        assert_eq!(rn.name(), "res");
    }

    #[test]
    fn updates_reader_position_after_construction() {
        let data = vec![2, b'n', b'a', 99];
        let mut r = BinaryReader::from_bytes(data, true);
        let _ = ResourceName::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 3);
    }

    #[test]
    fn cloning_preserves_data() {
        let data = vec![4, b't', b'e', b's', b't'];
        let mut r = BinaryReader::from_bytes(data, true);
        let rn1 = ResourceName::new(&mut r).unwrap();
        let rn2 = rn1.clone();

        assert_eq!(rn1.index(), rn2.index());
        assert_eq!(rn1.length(), rn2.length());
        assert_eq!(rn1.name(), rn2.name());
    }
}
