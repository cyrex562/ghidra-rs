//! Port of `ghidra.app.util.bin.format.elf.ElfCompressedSectionHeader`.
//!
//! Header at the beginning of an ELF compressed section. See
//! <https://docs.oracle.com/cd/E53394_01/html/E54813/section_compression.html>.
//!
//! ```text
//! typedef struct {
//!      Elf32_Word      ch_type;
//!      Elf32_Word      ch_size;
//!      Elf32_Word      ch_addralign;
//! } Elf32_Chdr;
//!
//! typedef struct {
//!      Elf64_Word      ch_type;
//!      Elf64_Word      ch_reserved;
//!      Elf64_Xword     ch_size;
//!      Elf64_Xword     ch_addralign;
//! } Elf64_Chdr;
//! ```

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::ElfHeader;

/// Compression algorithm identifier for the zlib algorithm.
pub const ELFCOMPRESS_ZLIB: i32 = 1;

const SIZEOF_HEADER_32: i32 = 12; // sizeof(word)*3 fields
const SIZEOF_HEADER_64: i32 = 24; // sizeof(word)*2 fields + sizeof(xword)*2 fields

/// Header at the beginning of an ELF compressed section (`Elf32_Chdr` / `Elf64_Chdr`).
pub struct ElfCompressedSectionHeader {
    /// Compression algorithm, see [`ELFCOMPRESS_ZLIB`].
    ch_type: i32,
    /// Size, in bytes, of the uncompressed data.
    ch_size: i64,
    /// Alignment of the uncompressed data (`sh_addralign`).
    ch_addralign: i64,
    /// Size of this header struct, used to skip the header when re-reading.
    header_size: i32,
}

impl ElfCompressedSectionHeader {
    /// Reads an `Elf(32|64)_Chdr` from the current position in the supplied reader.
    ///
    /// # Arguments
    /// * `reader` - stream to read from
    /// * `elf` - `ElfHeader` that defines the format of the binary
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during parse.
    pub fn read(reader: &mut impl BinaryReader, elf: &impl ElfHeader) -> io::Result<Self> {
        if elf.is32_bit() {
            Self::read32(reader)
        } else {
            Self::read64(reader)
        }
    }

    /// The compression type, see [`ELFCOMPRESS_ZLIB`].
    pub fn get_ch_type(&self) -> i32 {
        self.ch_type
    }

    /// The uncompressed size.
    pub fn get_ch_size(&self) -> i64 {
        self.ch_size
    }

    /// The address alignment value.
    ///
    /// See `ElfSectionHeader::get_address_alignment`.
    pub fn get_ch_addralign(&self) -> i64 {
        self.ch_addralign
    }

    /// The size of this header struct.
    pub fn get_header_size(&self) -> i32 {
        self.header_size
    }

    fn read32(reader: &mut impl BinaryReader) -> io::Result<Self> {
        let ch_type = reader.read_next_int()?;
        let ch_size = reader.read_next_unsigned_int()? as i64;
        let ch_addralign = reader.read_next_unsigned_int()? as i64;

        Ok(ElfCompressedSectionHeader {
            ch_type,
            ch_size,
            ch_addralign,
            header_size: SIZEOF_HEADER_32,
        })
    }

    fn read64(reader: &mut impl BinaryReader) -> io::Result<Self> {
        let ch_type = reader.read_next_int()?;
        let _unused_reserved = reader.read_next_unsigned_int()?;
        let ch_size = reader.read_next_long()?;
        let ch_addralign = reader.read_next_long()?;

        Ok(ElfCompressedSectionHeader {
            ch_type,
            ch_size,
            ch_addralign,
            header_size: SIZEOF_HEADER_64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct MockHeader {
        is32: bool,
    }

    impl ElfHeader for MockHeader {
        fn is32_bit(&self) -> bool {
            self.is32
        }

        fn is_relocatable(&self) -> bool {
            false
        }

        fn get_sections(
            &self,
        ) -> Vec<Box<dyn crate::format::seam_stubs::ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockReader {
        bytes: Vec<u8>,
        pos: RefCell<u64>,
        little_endian: RefCell<bool>,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            MockReader {
                bytes,
                pos: RefCell::new(0),
                little_endian: RefCell::new(true),
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }

        fn get_pointer_index(&self) -> u64 {
            *self.pos.borrow()
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            *self.pos.borrow_mut() = index;
            index
        }

        fn is_little_endian(&self) -> bool {
            *self.little_endian.borrow()
        }

        fn set_little_endian(&mut self, is_little_endian: bool) {
            *self.little_endian.borrow_mut() = is_little_endian;
        }

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

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            unimplemented!("not needed for this test")
        }

        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed for this test")
        }

        fn clone_reader(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed for this test")
        }
    }

    #[test]
    fn read_32bit_header_matches_java_layout() {
        // ch_type = 1 (ELFCOMPRESS_ZLIB), ch_size = 0x100, ch_addralign = 8, little-endian.
        let mut reader = MockReader::new(vec![
            0x01, 0x00, 0x00, 0x00, // ch_type
            0x00, 0x01, 0x00, 0x00, // ch_size
            0x08, 0x00, 0x00, 0x00, // ch_addralign
        ]);
        let header = MockHeader { is32: true };

        let chdr = ElfCompressedSectionHeader::read(&mut reader, &header).unwrap();

        assert_eq!(chdr.get_ch_type(), ELFCOMPRESS_ZLIB);
        assert_eq!(chdr.get_ch_size(), 0x100);
        assert_eq!(chdr.get_ch_addralign(), 8);
        assert_eq!(chdr.get_header_size(), 12);
        assert_eq!(reader.get_pointer_index(), 12);
    }

    #[test]
    fn read_64bit_header_skips_reserved_field() {
        // ch_type = 1, ch_reserved (skipped) = 0xDEADBEEF, ch_size = 0x200, ch_addralign = 16.
        let mut reader = MockReader::new(vec![
            0x01, 0x00, 0x00, 0x00, // ch_type
            0xEF, 0xBE, 0xAD, 0xDE, // ch_reserved (unused)
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ch_size
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ch_addralign
        ]);
        let header = MockHeader { is32: false };

        let chdr = ElfCompressedSectionHeader::read(&mut reader, &header).unwrap();

        assert_eq!(chdr.get_ch_type(), ELFCOMPRESS_ZLIB);
        assert_eq!(chdr.get_ch_size(), 0x200);
        assert_eq!(chdr.get_ch_addralign(), 16);
        assert_eq!(chdr.get_header_size(), 24);
        assert_eq!(reader.get_pointer_index(), 24);
    }
}
