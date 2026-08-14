//! Port of `ghidra.app.util.bin.format.pef.LoaderRelocationHeader`.
//!
//! See Apple's PEFBinaryFormat.h:
//! ```text
//! struct PEFLoaderRelocationHeader {
//!     UInt16   sectionIndex;     // Index of the section to be fixed up.
//!     UInt16   reservedA;        // Reserved, must be zero.
//!     UInt32   relocCount;       // Number of 16 bit relocation chunks.
//!     UInt32   firstRelocOffset; // Offset of first relocation instruction.
//! };
//!
//! typedef UInt16 PEFRelocChunk;
//! ```
//!
//! Java's constructor takes a `LoaderInfoHeader` back-reference to locate the start of this
//! section's relocation instructions, and constructs each relocation via `RelocationFactory`.
//! Neither `LoaderInfoHeader` nor `RelocationFactory` are ported yet -- `LoaderInfoHeader` in
//! particular owns a `getRelocations()` that returns a list of this very type, the cycle edge
//! that put this type up for porting now -- so both are held as
//! [`seam_stubs::LoaderInfoHeader`](crate::format::seam_stubs::LoaderInfoHeader) /
//! [`seam_stubs::RelocationFactory`](crate::format::seam_stubs::RelocationFactory) placeholders.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::{LoaderInfoHeader, RelocationFactory, StructConverterUtilDataType};
use crate::program::model::data::data_type::DataType;
use crate::program::model::reloc::relocation::Relocation;

/// Describes the relocations to be applied to one section of a PEF container.
///
/// Port of `ghidra.app.util.bin.format.pef.LoaderRelocationHeader`.
pub struct LoaderRelocationHeader {
    section_index: i16,
    reserved_a: i16,
    reloc_count: i32,
    first_reloc_offset: i32,
    relocations: Vec<Relocation>,
}

impl LoaderRelocationHeader {
    /// Reads a [`LoaderRelocationHeader`] and its relocation stream from `reader`.
    ///
    /// Port of `LoaderRelocationHeader(BinaryReader, LoaderInfoHeader)`.
    pub fn new(reader: &mut dyn BinaryReader, loader: &dyn LoaderInfoHeader) -> io::Result<Self> {
        let section_index = reader.read_next_short()?;
        let reserved_a = reader.read_next_short()?;
        let reloc_count = reader.read_next_int()?;
        let first_reloc_offset = reader.read_next_int()?;

        let old_index = reader.get_pointer_index();
        let index_to_relocations = (loader.get_section().get_container_offset()
            + loader.get_reloc_instr_offset()) as u64;
        reader.set_pointer_index(index_to_relocations);
        let end_index = index_to_relocations + (reloc_count as u64) * 2;

        let mut relocations = Vec::new();
        let read_result: io::Result<()> = (|| {
            while reader.get_pointer_index() < end_index {
                relocations.push(RelocationFactory::get_relocation(reader));
            }
            Ok(())
        })();
        reader.set_pointer_index(old_index);
        read_result?;

        Ok(LoaderRelocationHeader {
            section_index,
            reserved_a,
            reloc_count,
            first_reloc_offset,
            relocations,
        })
    }

    /// The sectionIndex field (2 bytes) designates the section number to which this relocation
    /// header refers.
    ///
    /// Port of `LoaderRelocationHeader.getSectionIndex()`.
    pub fn section_index(&self) -> i16 {
        self.section_index
    }

    /// Reserved, must be set to zero (0).
    ///
    /// Port of `LoaderRelocationHeader.getReservedA()`.
    pub fn reserved_a(&self) -> i16 {
        self.reserved_a
    }

    /// The relocCount field (4 bytes) indicates the number of 16-bit relocation blocks for this
    /// section.
    ///
    /// Port of `LoaderRelocationHeader.getRelocCount()`.
    pub fn reloc_count(&self) -> i32 {
        self.reloc_count
    }

    /// The firstRelocOffset field (4 bytes) indicates the byte offset from the start of the
    /// relocations area to the first relocation instruction for this section.
    ///
    /// Port of `LoaderRelocationHeader.getFirstRelocOffset()`.
    pub fn first_reloc_offset(&self) -> i32 {
        self.first_reloc_offset
    }

    /// Port of `LoaderRelocationHeader.getRelocations()`.
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }
}

impl StructConverter for LoaderRelocationHeader {
    /// Port of `LoaderRelocationHeader.toDataType()`, which delegates to
    /// `StructConverterUtil.toDataType(getClass())`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        // 2 (sectionIndex) + 2 (reservedA) + 4 (relocCount) + 4 (firstRelocOffset).
        Ok(Box::new(StructConverterUtilDataType::to_data_type(
            "LoaderRelocationHeader",
            12,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::SectionHeader;

    /// Minimal in-memory [`BinaryReader`] sufficient for this module's tests: it never needs
    /// anything beyond sequential 16/32-bit big-endian reads and pointer-index manipulation.
    struct MockReader {
        bytes: Vec<u8>,
        pos: u64,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            MockReader { bytes, pos: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn get_pointer_index(&self) -> u64 {
            self.pos
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.pos;
            self.pos = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            false
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>
        {
            unimplemented!("not needed by LoaderRelocationHeader tests")
        }
        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderRelocationHeader tests")
        }
        fn clone_reader(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderRelocationHeader tests")
        }
        fn as_big_endian(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderRelocationHeader tests")
        }
        fn as_little_endian(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderRelocationHeader tests")
        }
    }

    struct MockSectionHeader {
        container_offset: i32,
    }

    impl SectionHeader for MockSectionHeader {
        fn get_container_offset(&self) -> i32 {
            self.container_offset
        }
    }

    struct MockLoaderInfoHeader {
        container_offset: i32,
        reloc_instr_offset: i32,
    }

    impl LoaderInfoHeader for MockLoaderInfoHeader {
        fn get_section(&self) -> Box<dyn SectionHeader> {
            Box::new(MockSectionHeader { container_offset: self.container_offset })
        }
        fn get_reloc_instr_offset(&self) -> i32 {
            self.reloc_instr_offset
        }
    }

    #[test]
    fn parses_header_fields_with_zero_reloc_count() {
        // sectionIndex=3, reservedA=0, relocCount=0, firstRelocOffset=0x10.
        let bytes = vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
        let mut reader = MockReader::new(bytes);
        let loader = MockLoaderInfoHeader { container_offset: 0, reloc_instr_offset: 0 };

        let header = LoaderRelocationHeader::new(&mut reader, &loader).unwrap();

        assert_eq!(header.section_index(), 3);
        assert_eq!(header.reserved_a(), 0);
        assert_eq!(header.reloc_count(), 0);
        assert_eq!(header.first_reloc_offset(), 0x10);
        assert!(header.relocations().is_empty());
    }

    #[test]
    fn restores_pointer_index_after_reading_relocations() {
        let bytes = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = MockReader::new(bytes);
        let loader = MockLoaderInfoHeader { container_offset: 0, reloc_instr_offset: 0 };

        LoaderRelocationHeader::new(&mut reader, &loader).unwrap();

        // The constructor reads 12 bytes of fixed header fields, then must restore the pointer
        // to just past them (matching Java's `finally { reader.setPointerIndex(oldIndex); }`).
        assert_eq!(reader.get_pointer_index(), 12);
    }

    #[test]
    fn to_data_type_reports_fixed_header_length() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = MockReader::new(bytes);
        let loader = MockLoaderInfoHeader { container_offset: 0, reloc_instr_offset: 0 };
        let header = LoaderRelocationHeader::new(&mut reader, &loader).unwrap();

        let dt = header.to_data_type().unwrap();
        assert_eq!(dt.get_length(), 12);
        assert_eq!(dt.get_name(), "LoaderRelocationHeader");
    }
}
