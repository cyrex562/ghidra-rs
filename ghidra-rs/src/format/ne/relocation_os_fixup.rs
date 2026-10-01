use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// A relocation entry for an operating system fixup.
///
/// Mirrors `RelocationOSFixup` from the original Ghidra Java source.
/// Stores a fixup type and padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationOSFixup {
    fixup_type: i16,
    zeropad: i16,
}

impl RelocationOSFixup {
    /// Constructs a new relocation OS fixup by reading from the given binary reader.
    ///
    /// Reads two i16 values: the fixup type and a padding value.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let fixup_type = reader.read_next_short()?;
        let zeropad = reader.read_next_short()?;

        Ok(RelocationOSFixup {
            fixup_type,
            zeropad,
        })
    }

    /// Returns the fixup type.
    pub fn fixup_type(&self) -> i16 {
        self.fixup_type
    }

    /// Returns the padding value.
    pub fn pad(&self) -> i16 {
        self.zeropad
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_simple_fixup() {
        let mut data = Vec::new();
        data.extend_from_slice(&(5i16).to_le_bytes());
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 5);
        assert_eq!(rel.pad(), 0);
    }

    #[test]
    fn reads_zero_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0i16).to_le_bytes());
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 0);
        assert_eq!(rel.pad(), 0);
    }

    #[test]
    fn reads_negative_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i16).to_le_bytes());
        data.extend_from_slice(&(-100i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), -1);
        assert_eq!(rel.pad(), -100);
    }

    #[test]
    fn reads_large_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&(32767i16).to_le_bytes());
        data.extend_from_slice(&(32767i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 32767);
        assert_eq!(rel.pad(), 32767);
    }

    #[test]
    fn updates_reader_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&(10i16).to_le_bytes());
        data.extend_from_slice(&(20i16).to_le_bytes());
        data.push(99);

        let mut r = BinaryReader::from_bytes(data, true);
        let _ = RelocationOSFixup::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_at_different_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&(7i16).to_le_bytes());
        data.extend_from_slice(&(77i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(3);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 7);
        assert_eq!(rel.pad(), 77);
    }

    #[test]
    fn copy_semantics() {
        let mut data = Vec::new();
        data.extend_from_slice(&(3i16).to_le_bytes());
        data.extend_from_slice(&(9i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data.clone(), true);
        let rel1 = RelocationOSFixup::new(&mut r).unwrap();
        let rel2 = rel1;

        assert_eq!(rel1, rel2);
        assert_eq!(rel1.fixup_type(), rel2.fixup_type());
        assert_eq!(rel1.pad(), rel2.pad());
    }

    #[test]
    fn equality_between_different_constructions() {
        let mut data1 = Vec::new();
        data1.extend_from_slice(&(15i16).to_le_bytes());
        data1.extend_from_slice(&(20i16).to_le_bytes());

        let mut r1 = BinaryReader::from_bytes(data1, true);
        let rel1 = RelocationOSFixup::new(&mut r1).unwrap();

        let mut data2 = Vec::new();
        data2.extend_from_slice(&(15i16).to_le_bytes());
        data2.extend_from_slice(&(20i16).to_le_bytes());

        let mut r2 = BinaryReader::from_bytes(data2, true);
        let rel2 = RelocationOSFixup::new(&mut r2).unwrap();

        assert_eq!(rel1, rel2);
    }
}
