use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Represents a new-executable (NE) segment relocation.
///
/// Mirrors `SegmentRelocation` from the original Ghidra Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRelocation {
    segment: i32,
    r#type: i8,
    flagbyte: i8,
    offset: i16,
    target_segment: i16,
    target_offset: i16,
}

impl SegmentRelocation {
    /// The number of `long` values expected by [`Self::from_values`].
    pub const VALUES_SIZE: usize = 5;

    /// Moveable relocation.
    pub const MOVEABLE: i16 = 0xff;
    /// A mask indicating that the low-order nibble is the type.
    pub const TYPE_MASK: i8 = 0x0f;
    /// Low byte at the specified address.
    pub const TYPE_LO_BYTE: i8 = 0x00;
    /// 16-bit selector.
    pub const TYPE_SEGMENT: i8 = 0x02;
    /// 32-bit pointer.
    pub const TYPE_FAR_ADDR: i8 = 0x03;
    /// 16-bit pointer.
    pub const TYPE_OFFSET: i8 = 0x05;
    /// 48-bit pointer.
    pub const TYPE_FAR_ADDR_48: i8 = 0x0c;
    /// 32-bit offset.
    pub const TYPE_OFFSET_32: i8 = 0x0d;

    /// The names of the available relocations.
    ///
    /// Quirk preserved from the original Java array literal: this list is *not* index-aligned
    /// with [`Self::TYPE_LENGTHS`] (or with the `TYPE_*` constant values) at every position.
    /// `TYPE_LENGTHS[TYPE_FAR_ADDR_48]` (index 12) correctly holds the byte length for
    /// [`Self::TYPE_FAR_ADDR_48`], but `TYPE_STRINGS[12]` is the placeholder `"???12"` --
    /// `"48-bit Pointer"` instead sits one slot earlier, at index 11, which does not correspond
    /// to any defined `TYPE_*` constant. See
    /// `type_strings_is_off_by_one_at_far_addr_48` for a dedicated regression test.
    pub const TYPE_STRINGS: [&'static str; 14] = [
        "Low Byte",
        "???1",
        "16-bit Segment Selector",
        "32-bit Pointer",
        "???4",
        "16-bit Pointer",
        "???6",
        "???7",
        "???8",
        "???9",
        "???10",
        "48-bit Pointer",
        "???12",
        "32-bit Offset",
    ];

    /// The number of bytes required to perform relocation.
    pub const TYPE_LENGTHS: [i32; 14] = [
        1, // TYPE_LO_BYTE
        0, 2, // TYPE_SEGMENT
        4, // TYPE_FAR_ADDR
        0, 2, // TYPE_OFFSET
        0, 0, 0, 0, 0, 0, 6, // TYPE_FAR_ADDR_48
        4, // TYPE_OFFSET_32
    ];

    /// A mask indicating that the low-order two-bits is the type.
    pub const FLAG_TARGET_MASK: i8 = 0x03;
    /// Internal reference relocation.
    pub const FLAG_INTERNAL_REF: i8 = 0x00;
    /// Import ordinal relocation.
    pub const FLAG_IMPORT_ORDINAL: i8 = 0x01;
    /// Import name relocation.
    pub const FLAG_IMPORT_NAME: i8 = 0x02;
    /// Operating system fixup relocation.
    pub const FLAG_OS_FIXUP: i8 = 0x03;
    /// Additive relocation.
    pub const FLAG_ADDITIVE: i8 = 0x04;

    /// Constructs a new segment relocation.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader, segment: i32) -> io::Result<Self> {
        let r#type = reader.read_next_byte()? as i8;
        let flagbyte = reader.read_next_byte()? as i8;
        let offset = reader.read_next_short()?;
        let target_segment = reader.read_next_short()?;
        let target_offset = reader.read_next_short()?;

        Ok(SegmentRelocation {
            segment,
            r#type,
            flagbyte,
            offset,
            target_segment,
            target_offset,
        })
    }

    /// Constructs a segment relocation directly from its raw field values.
    ///
    /// `values` must contain exactly [`Self::VALUES_SIZE`] elements, in the order `[segment,
    /// flagbyte, offset, targetSegment, targetOffset]` -- the same order returned by
    /// [`Self::get_values`].
    ///
    /// # Panics
    /// Panics if `values.len() != Self::VALUES_SIZE`, mirroring the Java
    /// `IllegalArgumentException("Expected 5 values")`.
    pub fn from_values(r#type: i8, values: &[i64]) -> Self {
        assert_eq!(
            values.len(),
            Self::VALUES_SIZE,
            "Expected {} values",
            Self::VALUES_SIZE
        );

        SegmentRelocation {
            segment: values[0] as i32,
            r#type,
            flagbyte: values[1] as i8,
            offset: values[2] as i16,
            target_segment: values[3] as i16,
            target_offset: values[4] as i16,
        }
    }

    /// Returns true if this relocation is an internal reference.
    pub fn is_internal_ref(&self) -> bool {
        (self.flagbyte & Self::FLAG_TARGET_MASK) == Self::FLAG_INTERNAL_REF
    }

    /// Returns true if this relocation is an import by ordinal.
    pub fn is_import_ordinal(&self) -> bool {
        (self.flagbyte & Self::FLAG_TARGET_MASK) == Self::FLAG_IMPORT_ORDINAL
    }

    /// Returns true if this relocation is an import by name.
    pub fn is_import_name(&self) -> bool {
        (self.flagbyte & Self::FLAG_TARGET_MASK) == Self::FLAG_IMPORT_NAME
    }

    /// Returns true if this relocation is an operating system fixup.
    pub fn is_op_sys_fixup(&self) -> bool {
        (self.flagbyte & Self::FLAG_TARGET_MASK) == Self::FLAG_OS_FIXUP
    }

    /// Returns true if this relocation is additive. If this bit is set, then add relocation to
    /// existing value. Otherwise overwrite the existing value.
    pub fn is_additive(&self) -> bool {
        (self.flagbyte & Self::FLAG_ADDITIVE) != 0
    }

    /// Returns the relocation type.
    pub fn get_type(&self) -> i8 {
        self.r#type
    }

    /// Returns the relocation flags.
    pub fn get_flag_byte(&self) -> i8 {
        self.flagbyte
    }

    /// Returns the segment this relocation belongs to.
    pub fn get_segment(&self) -> i32 {
        self.segment
    }

    /// Returns the relocation offset.
    pub fn get_offset(&self) -> i16 {
        self.offset
    }

    /// Returns the relocation target segment.
    pub fn get_target_segment(&self) -> i16 {
        self.target_segment
    }

    /// Returns the relocation target offset.
    pub fn get_target_offset(&self) -> i16 {
        self.target_offset
    }

    /// Returns values required to reconstruct this object, in the order `[segment, flagbyte,
    /// offset, targetSegment, targetOffset]`.
    pub fn get_values(&self) -> [i64; Self::VALUES_SIZE] {
        [
            self.segment as i64,
            self.flagbyte as i64,
            self.offset as i64,
            self.target_segment as i64,
            self.target_offset as i64,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::GByteStore;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
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
        provider: Rc<RefCell<dyn GByteStore>>,
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
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
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
    fn reads_from_binary_reader() {
        let data = vec![
            0x05, // type = TYPE_OFFSET
            0x00, // flagbyte = FLAG_INTERNAL_REF
            0x10, 0x00, // offset = 0x0010
            0x02, 0x00, // targetSegment = 2
            0x20, 0x00, // targetOffset = 0x0020
        ];
        let mut reader = MockReader::new(data);

        let reloc = SegmentRelocation::new(&mut reader, 7).unwrap();

        assert_eq!(reloc.get_segment(), 7);
        assert_eq!(reloc.get_type(), SegmentRelocation::TYPE_OFFSET);
        assert_eq!(reloc.get_flag_byte(), 0);
        assert_eq!(reloc.get_offset(), 0x0010);
        assert_eq!(reloc.get_target_segment(), 2);
        assert_eq!(reloc.get_target_offset(), 0x0020);
        assert!(reloc.is_internal_ref());
        assert!(!reloc.is_import_ordinal());
        assert!(!reloc.is_additive());
        assert_eq!(reader.get_pointer_index(), 8);
    }

    #[test]
    fn flag_target_classification() {
        let mut reader = MockReader::new(vec![0x03, 0x01, 0, 0, 0, 0, 0, 0]);
        let import_ordinal = SegmentRelocation::new(&mut reader, 0).unwrap();
        assert!(import_ordinal.is_import_ordinal());
        assert!(!import_ordinal.is_internal_ref());
        assert!(!import_ordinal.is_import_name());
        assert!(!import_ordinal.is_op_sys_fixup());

        let mut reader = MockReader::new(vec![0x03, 0x02, 0, 0, 0, 0, 0, 0]);
        let import_name = SegmentRelocation::new(&mut reader, 0).unwrap();
        assert!(import_name.is_import_name());

        let mut reader = MockReader::new(vec![0x03, 0x03, 0, 0, 0, 0, 0, 0]);
        let os_fixup = SegmentRelocation::new(&mut reader, 0).unwrap();
        assert!(os_fixup.is_op_sys_fixup());

        let mut reader = MockReader::new(vec![0x03, 0x04, 0, 0, 0, 0, 0, 0]);
        let additive = SegmentRelocation::new(&mut reader, 0).unwrap();
        // FLAG_ADDITIVE(0x04) is a separate bit from FLAG_TARGET_MASK(0x03), so the low two
        // bits are still FLAG_INTERNAL_REF here.
        assert!(additive.is_internal_ref());
        assert!(additive.is_additive());
    }

    #[test]
    fn round_trips_through_get_values_and_from_values() {
        let data = vec![
            0x0d, // type = TYPE_OFFSET_32
            0x05, // flagbyte
            0x11, 0x22, // offset
            0x33, 0x44, // targetSegment
            0x55, 0x66, // targetOffset
        ];
        let mut reader = MockReader::new(data);
        let original = SegmentRelocation::new(&mut reader, 42).unwrap();

        let values = original.get_values();
        assert_eq!(values.len(), SegmentRelocation::VALUES_SIZE);

        let reconstructed = SegmentRelocation::from_values(original.get_type(), &values);

        assert_eq!(reconstructed, original);
    }

    #[test]
    #[should_panic(expected = "Expected 5 values")]
    fn from_values_panics_on_wrong_length() {
        let _ = SegmentRelocation::from_values(SegmentRelocation::TYPE_LO_BYTE, &[1, 2, 3]);
    }

    #[test]
    fn type_strings_is_off_by_one_at_far_addr_48() {
        // Genuine quirk in the original Java `TYPE_STRINGS` array literal: "48-bit Pointer" sits
        // at index 11, not at index 12 (== TYPE_FAR_ADDR_48), so looking it up by the type
        // constant yields the unrelated placeholder "???12" instead.
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_FAR_ADDR_48 as usize],
            "???12"
        );
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_FAR_ADDR_48 as usize - 1],
            "48-bit Pointer"
        );
    }

    #[test]
    fn type_strings_and_lengths_tables_are_indexable_by_known_types() {
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_LO_BYTE as usize],
            "Low Byte"
        );
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_SEGMENT as usize],
            "16-bit Segment Selector"
        );
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_FAR_ADDR as usize],
            "32-bit Pointer"
        );
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_OFFSET as usize],
            "16-bit Pointer"
        );
        // NOTE: `TYPE_STRINGS[TYPE_FAR_ADDR_48]` is *not* "48-bit Pointer" -- see the dedicated
        // `type_strings_is_off_by_one_at_far_addr_48` quirk test below.
        assert_eq!(
            SegmentRelocation::TYPE_STRINGS[SegmentRelocation::TYPE_OFFSET_32 as usize],
            "32-bit Offset"
        );

        assert_eq!(
            SegmentRelocation::TYPE_LENGTHS[SegmentRelocation::TYPE_LO_BYTE as usize],
            1
        );
        assert_eq!(
            SegmentRelocation::TYPE_LENGTHS[SegmentRelocation::TYPE_SEGMENT as usize],
            2
        );
        assert_eq!(
            SegmentRelocation::TYPE_LENGTHS[SegmentRelocation::TYPE_FAR_ADDR as usize],
            4
        );
        assert_eq!(
            SegmentRelocation::TYPE_LENGTHS[SegmentRelocation::TYPE_OFFSET as usize],
            2
        );
        assert_eq!(
            SegmentRelocation::TYPE_LENGTHS[SegmentRelocation::TYPE_FAR_ADDR_48 as usize],
            6
        );
        assert_eq!(
            SegmentRelocation::TYPE_LENGTHS[SegmentRelocation::TYPE_OFFSET_32 as usize],
            4
        );
    }
}
