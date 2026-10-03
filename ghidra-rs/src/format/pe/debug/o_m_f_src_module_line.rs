use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) Source Module Line data structure.
///
/// Mirrors the `OMFSrcModuleLine` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// short seg            - segment index.
/// short cPair          - Count or number of source line pairs to follow.
/// int [] offsets       - offset within the code segment of the start of the line.
/// short [] linenumbers - line numbers that are in the source file that cause code
///                         to be emitted to the code segment.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSrcModuleLine {
    seg: i16,
    c_pair: i16,
    offsets: Vec<i32>,
    linenumbers: Vec<i16>,
}

impl OmfSrcModuleLine {
    /// Creates a new `OmfSrcModuleLine` by reading from the given binary reader at
    /// the specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &BinaryReader, ptr: u64) -> io::Result<Self> {
        let mut index = ptr;

        let seg = reader.read_short(index)?;
        index += 2;
        let c_pair = reader.read_short(index)?;
        index += 2;

        let pair_count = c_pair as u16 as usize;

        let mut offsets = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            offsets.push(reader.read_int(index)?);
            index += 4;
        }

        let mut linenumbers = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            linenumbers.push(reader.read_short(index)?);
            index += 2;
        }

        Ok(OmfSrcModuleLine {
            seg,
            c_pair,
            offsets,
            linenumbers,
        })
    }

    /// Returns the count or number of source line pairs to follow.
    pub fn pair_count(&self) -> i16 {
        self.c_pair
    }

    /// Returns the line numbers that are in the source file that cause code to be
    /// emitted to the code segment.
    pub fn linenumbers(&self) -> &[i16] {
        &self.linenumbers
    }

    /// Returns the offset within the code segment of the start of the line.
    pub fn offsets(&self) -> &[i32] {
        &self.offsets
    }

    /// Returns the segment index.
    pub fn segment_index(&self) -> i16 {
        self.seg
    }

    /// Returns the on-disk byte count of this structure.
    pub fn byte_count(&self) -> i32 {
        let pair_count = self.c_pair as i32;
        2 + 2 + 4 * pair_count + 2 * pair_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn read_structure_with_no_pairs() {
        let data = vec![
            0x07, 0x00, // seg = 7
            0x00, 0x00, // cPair = 0
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let line = OmfSrcModuleLine::new(&reader, 0).expect("failed to read");

        assert_eq!(line.segment_index(), 7);
        assert_eq!(line.pair_count(), 0);
        assert!(line.offsets().is_empty());
        assert!(line.linenumbers().is_empty());
        assert_eq!(line.byte_count(), 4);
    }

    #[test]
    fn read_structure_with_pairs_little_endian() {
        let data = vec![
            0x01, 0x00, // seg = 1
            0x02, 0x00, // cPair = 2
            0x10, 0x00, 0x00, 0x00, // offsets[0] = 0x10
            0x20, 0x00, 0x00, 0x00, // offsets[1] = 0x20
            0x64, 0x00, // linenumbers[0] = 100
            0xC8, 0x00, // linenumbers[1] = 200
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let line = OmfSrcModuleLine::new(&reader, 0).expect("failed to read");

        assert_eq!(line.segment_index(), 1);
        assert_eq!(line.pair_count(), 2);
        assert_eq!(line.offsets(), &[0x10, 0x20]);
        assert_eq!(line.linenumbers(), &[100, 200]);
        assert_eq!(line.byte_count(), 4 + 4 * 2 + 2 * 2);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x01, // seg = 1
            0x00, 0x01, // cPair = 1
            0x00, 0x00, 0x00, 0x30, // offsets[0] = 0x30
            0x00, 0x09, // linenumbers[0] = 9
        ];

        let reader = BinaryReader::from_bytes(data, false);
        let line = OmfSrcModuleLine::new(&reader, 0).expect("failed to read");

        assert_eq!(line.segment_index(), 1);
        assert_eq!(line.pair_count(), 1);
        assert_eq!(line.offsets(), &[0x30]);
        assert_eq!(line.linenumbers(), &[9]);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let mut data = vec![0xFF; 4];
        data.extend_from_slice(&[
            0x05, 0x00, // seg = 5
            0x01, 0x00, // cPair = 1
            0x0A, 0x00, 0x00, 0x00, // offsets[0] = 10
            0x0B, 0x00, // linenumbers[0] = 11
        ]);

        let reader = BinaryReader::from_bytes(data, true);
        let line = OmfSrcModuleLine::new(&reader, 4).expect("failed to read");

        assert_eq!(line.segment_index(), 5);
        assert_eq!(line.offsets(), &[10]);
        assert_eq!(line.linenumbers(), &[11]);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x01, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B, 0x00,
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let line1 = OmfSrcModuleLine::new(&reader, 0).expect("failed to read");
        let line2 = line1.clone();

        assert_eq!(line1, line2);
    }
}
