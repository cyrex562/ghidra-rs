use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::SegmentRelocation;
use std::io;

/// data segment type.
const FLAG_DATA: i16 = 0x0001;
/// loaded has allocated memory.
const FLAG_ALLOC: i16 = 0x0002;
/// segment is loaded.
const FLAG_LOADED: i16 = 0x0004;
/// segment not fixed.
const FLAG_MOVEABLE: i16 = 0x0010;
/// pure (shareable) or impure (unshareable).
const FLAG_PURE: i16 = 0x0020;
/// preload or load-on-call.
const FLAG_PRELOAD: i16 = 0x0040;
/// if code, segment is execute-only.
const FLAG_EXE_ONLY: i16 = 0x0080;
/// if data, segment is read-only.
const FLAG_READ_ONLY: i16 = 0x0080;
/// segment has relocation records.
const FLAG_RELOC_INFO: i16 = 0x0100;
/// segment is discardable.
const FLAG_DISCARD: i16 = 0x1000;
/// segment is 32 bit.
const FLAG_32BIT: i16 = 0x2000;

/// Represents a new-executable (NE) format segment.
///
/// Mirrors `Segment` from the original Ghidra Java source.
pub struct Segment {
    segment_id: i32,
    /// byte offset to content, relative to BOF (zero means no file data)
    offset: i16,
    /// length of segment in file (zero means 64k)
    length: i16,
    /// flags
    flagword: i16,
    /// minimum size in memory to allocate (zero means 64k)
    min_alloc_size: i16,
    /// the aligned offset value
    offset_align: i32,
    /// relocation records
    relocations: Vec<SegmentRelocation>,
}

impl Segment {
    /// Constructs a new NE segment by reading its header and (if present) its relocation
    /// records from `reader`.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(
        reader: &mut dyn BinaryReader,
        segment_alignment: i16,
        segment_id: i32,
    ) -> io::Result<Self> {
        let offset = reader.read_next_short()?;
        let length = reader.read_next_short()?;
        let flagword = reader.read_next_short()?;
        let min_alloc_size = reader.read_next_short()?;

        let offset_align =
            ((offset as u16 as u32).wrapping_mul(segment_alignment as u16 as u32)) as i32;

        let mut relocations = Vec::new();
        if flagword & FLAG_RELOC_INFO != 0 {
            let reloc_pos = offset_align.wrapping_add(length as u16 as i32);

            let old_index = reader.get_pointer_index();
            reader.set_pointer_index(reloc_pos as i64 as u64);

            let n_relocations = reader.read_next_short()?;

            for _ in 0..n_relocations.max(0) {
                relocations.push(SegmentRelocation::new(reader, segment_id)?);
            }
            reader.set_pointer_index(old_index);
        }

        Ok(Segment {
            segment_id,
            offset,
            length,
            flagword,
            min_alloc_size,
            offset_align,
            relocations,
        })
    }

    /// Returns segment ID.
    pub fn get_segment_id(&self) -> i32 {
        self.segment_id
    }

    /// Returns true if the segment should operate in 32 bit mode.
    pub fn is_32bit(&self) -> bool {
        self.flagword & FLAG_32BIT != 0
    }

    /// Returns true if this is a code segment.
    pub fn is_code(&self) -> bool {
        !self.is_data()
    }

    /// Returns true if this is a data segment.
    pub fn is_data(&self) -> bool {
        self.flagword & FLAG_DATA != 0
    }

    /// Returns true if this segment has relocations.
    pub fn has_relocation(&self) -> bool {
        self.flagword & FLAG_RELOC_INFO != 0
    }

    /// Returns true if this segment is loader allocated.
    pub fn is_loader_allocated(&self) -> bool {
        self.flagword & FLAG_ALLOC != 0
    }

    /// Returns true if this segment is loaded.
    pub fn is_loaded(&self) -> bool {
        self.flagword & FLAG_LOADED != 0
    }

    /// Returns true if this segment is moveable.
    pub fn is_moveable(&self) -> bool {
        self.flagword & FLAG_MOVEABLE != 0
    }

    /// Returns true if this segment is preloaded.
    pub fn is_preload(&self) -> bool {
        self.flagword & FLAG_PRELOAD != 0
    }

    /// Returns true if this segment is pure.
    pub fn is_pure(&self) -> bool {
        self.flagword & FLAG_PURE != 0
    }

    /// Returns true if this segment is read-only.
    pub fn is_read_only(&self) -> bool {
        self.is_data() && self.flagword & FLAG_READ_ONLY != 0
    }

    /// Returns true if this segment is execute-only.
    pub fn is_execute_only(&self) -> bool {
        self.is_code() && self.flagword & FLAG_EXE_ONLY != 0
    }

    /// Returns true if this segment is discardable.
    pub fn is_discardable(&self) -> bool {
        self.flagword & FLAG_DISCARD != 0
    }

    /// Returns the flag word of this segment.
    pub fn get_flagword(&self) -> i16 {
        self.flagword
    }

    /// Returns the length of this segment.
    pub fn get_length(&self) -> i16 {
        self.length
    }

    /// Returns the minimum allocation size of this segment.
    pub fn get_min_alloc_size(&self) -> i16 {
        self.min_alloc_size
    }

    /// Returns the offset to the contents of this segment.
    /// NOTE: This value needs to be shift aligned.
    pub fn get_offset(&self) -> i16 {
        self.offset
    }

    /// Returns the actual (shifted) offset to the contents.
    pub fn get_offset_shift_aligned(&self) -> i32 {
        self.offset_align
    }

    /// Returns the relocations defined for this segment.
    pub fn get_relocations(&self) -> &[SegmentRelocation] {
        &self.relocations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn reads_header_without_relocations() {
        let mut data = Vec::new();
        data.extend_from_slice(&2i16.to_le_bytes()); // offset
        data.extend_from_slice(&0x1000i16.to_le_bytes()); // length
        data.extend_from_slice(&FLAG_DATA.to_le_bytes()); // flagword (data, no relocations)
        data.extend_from_slice(&0x2000i16.to_le_bytes()); // min alloc size

        let mut reader = MockReader::new(data);
        let segment = Segment::new(&mut reader, 9, 3).unwrap();

        assert_eq!(segment.get_segment_id(), 3);
        assert_eq!(segment.get_offset(), 2);
        assert_eq!(segment.get_length(), 0x1000);
        assert_eq!(segment.get_min_alloc_size(), 0x2000);
        // offsetAlign = unsigned(offset) * unsigned(segmentAlignment) = 2 * 9
        assert_eq!(segment.get_offset_shift_aligned(), 2 * 9);
        assert!(segment.is_data());
        assert!(!segment.is_code());
        assert!(!segment.has_relocation());
        assert_eq!(segment.get_relocations().len(), 0);
    }

    #[test]
    fn reads_code_segment_flags() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i16.to_le_bytes()); // offset
        data.extend_from_slice(&0i16.to_le_bytes()); // length
        let flagword = FLAG_MOVEABLE | FLAG_EXE_ONLY | FLAG_32BIT;
        data.extend_from_slice(&flagword.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes()); // min alloc size

        let mut reader = MockReader::new(data);
        let segment = Segment::new(&mut reader, 4, 1).unwrap();

        assert!(segment.is_code());
        assert!(!segment.is_data());
        assert!(segment.is_moveable());
        assert!(segment.is_execute_only());
        assert!(segment.is_32bit());
        assert!(!segment.is_read_only());
    }

    #[test]
    fn reads_relocations_when_present() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i16.to_le_bytes()); // offset (0 -> offsetAlign 0)
        data.extend_from_slice(&8i16.to_le_bytes()); // length
        data.extend_from_slice(&FLAG_RELOC_INFO.to_le_bytes()); // flagword
        data.extend_from_slice(&0i16.to_le_bytes()); // min alloc size
                                                       // pad up to offsetAlign(0) + length(8) = 8, where relocation table begins
        data.extend_from_slice(&[0u8; 0]);
        while data.len() < 8 {
            data.push(0);
        }
        data.extend_from_slice(&1i16.to_le_bytes()); // nRelocations
                                                       // one SegmentRelocation record: type, flagbyte, offset, targetSegment, targetOffset
        data.push(0x05); // type
        data.push(0x00); // flagbyte
        data.extend_from_slice(&0x10i16.to_le_bytes()); // offset
        data.extend_from_slice(&0x02i16.to_le_bytes()); // target segment
        data.extend_from_slice(&0x20i16.to_le_bytes()); // target offset

        let mut reader = MockReader::new(data);
        let segment = Segment::new(&mut reader, 1, 7).unwrap();

        assert!(segment.has_relocation());
        assert_eq!(segment.get_relocations().len(), 1);
        assert_eq!(segment.get_relocations()[0].get_offset(), 0x10);
    }

    #[test]
    fn restores_reader_position_after_relocations() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i16.to_le_bytes()); // offset
        data.extend_from_slice(&8i16.to_le_bytes()); // length
        data.extend_from_slice(&FLAG_RELOC_INFO.to_le_bytes()); // flagword
        data.extend_from_slice(&0i16.to_le_bytes()); // min alloc size
        while data.len() < 8 {
            data.push(0);
        }
        data.extend_from_slice(&0i16.to_le_bytes()); // nRelocations = 0

        let mut reader = MockReader::new(data);
        Segment::new(&mut reader, 1, 0).unwrap();
        // header is 8 bytes; reader should be left right after the header, not after the
        // relocation table it jumped to.
        assert_eq!(reader.get_pointer_index(), 8);
    }
}
