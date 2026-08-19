//! Port of `ghidra.app.util.bin.format.elf.ElfDynamic`.
//!
//! Represents an `Elf32_Dyn`/`Elf64_Dyn` entry:
//!
//! ```text
//! typedef  int32_t  Elf32_Sword;
//! typedef uint32_t  Elf32_Word;
//! typedef uint32_t  Elf32_Addr;
//!
//!  typedef struct {
//!      Elf32_Sword     d_tag;
//!      union {
//!          Elf32_Word  d_val;
//!          Elf32_Addr  d_ptr;
//!      } d_un;
//!  } Elf32_Dyn;
//!
//! typedef   int64_t  Elf64_Sxword;
//! typedef  uint64_t  Elf64_Xword;
//! typedef  uint64_t  Elf64_Addr;
//!
//! typedef struct {
//!     Elf64_Sxword    d_tag;     //Dynamic entry type
//!     union {
//!         Elf64_Xword d_val;     //Integer value
//!         Elf64_Addr  d_ptr;     //Address value
//!     } d_un;
//! } Elf64_Dyn;
//! ```
//!
//! `elf` is stored as `Arc<dyn ElfHeader>`, matching the storage convention already used for a
//! retained `ElfHeader` back-reference elsewhere in this crate (e.g.
//! [`ElfRelocationContextBase`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase)),
//! since [`ElfHeader`] is still an unported seam.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::{ElfDynamicType, ElfHeader};
use crate::util::string_utilities::StringUtilities;

/// A single ELF dynamic table entry (`Elf32_Dyn`/`Elf64_Dyn`).
#[derive(Clone)]
pub struct ElfDynamic {
    elf: Arc<dyn ElfHeader>,

    d_tag: i32,
    d_val: u64,
}

impl ElfDynamic {
    /// Read an ELF dynamic table entry at the reader's current position.
    ///
    /// The reader is not retained; its position moves to the next entry.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during parse.
    pub fn parse(reader: &mut impl BinaryReader, elf: Arc<dyn ElfHeader>) -> io::Result<Self> {
        let (d_tag, d_val) = if elf.is32_bit() {
            let d_tag = reader.read_next_int()?;
            let d_val = reader.read_next_unsigned_int()?;
            (d_tag, d_val)
        } else {
            let d_tag = reader.read_next_long()? as i32;
            let d_val = reader.read_next_long()? as u64;
            (d_tag, d_val)
        };

        Ok(ElfDynamic { elf, d_tag, d_val })
    }

    /// Construct a new ELF dynamic with the specified tag and value.
    pub fn new(tag: i32, value: u64, elf: Arc<dyn ElfHeader>) -> Self {
        ElfDynamic { elf, d_tag: tag, d_val: value }
    }

    /// Construct a new ELF dynamic with the specified (enum) tag and value.
    pub fn with_type(tag: &dyn ElfDynamicType, value: u64, elf: Arc<dyn ElfHeader>) -> Self {
        Self::new(tag.value(), value, elf)
    }

    /// The value that controls the interpretation of `d_val`/`d_ptr`.
    pub fn get_tag(&self) -> i32 {
        self.d_tag
    }

    /// The enum value that controls the interpretation of `d_val`/`d_ptr`, or `None` if unknown.
    pub fn get_tag_type(&self) -> Option<Box<dyn ElfDynamicType>> {
        self.elf.get_dynamic_type(self.d_tag)
    }

    /// The object whose integer values represent various interpretations.
    ///
    /// For example, if `d_tag == DT_SYMTAB`, then `d_val` holds the address of the symbol table.
    /// But if `d_tag == DT_SYMENT`, then `d_val` holds the size of each symbol entry.
    pub fn get_value(&self) -> u64 {
        self.d_val
    }

    /// A convenience method for getting a string representing the `d_tag` value.
    ///
    /// For example, if `d_tag == DT_SYMTAB`, this returns `"DT_SYMTAB"`.
    pub fn get_tag_as_string(&self) -> String {
        match self.get_tag_type() {
            Some(tag_type) => tag_type.name(),
            None => format!("DT_0x{}", format!("{:x}", self.d_tag as u32).pad('0', 8)),
        }
    }

    /// The size in bytes of this object.
    pub fn sizeof(&self) -> i32 {
        if self.elf.is32_bit() { 8 } else { 16 }
    }
}

impl std::fmt::Display for ElfDynamic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_tag_as_string())
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
        fn get_dynamic_type(&self, type_: i32) -> Option<Box<dyn ElfDynamicType>> {
            if type_ == 6 {
                Some(Box::new(MockDynamicType { value: 6, name: "DT_SYMTAB".to_string() }))
            } else {
                None
            }
        }
    }

    struct MockDynamicType {
        value: i32,
        name: String,
    }

    impl ElfDynamicType for MockDynamicType {
        fn value(&self) -> i32 {
            self.value
        }
        fn name(&self) -> String {
            self.name.clone()
        }
    }

    /// `Elf32_Dyn`: d_tag, d_val.
    fn dyn32(tag: i32, val: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&tag.to_le_bytes());
        data.extend_from_slice(&val.to_le_bytes());
        data
    }

    /// `Elf64_Dyn`: d_tag, d_val.
    fn dyn64(tag: i64, val: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&tag.to_le_bytes());
        data.extend_from_slice(&val.to_le_bytes());
        data
    }

    #[test]
    fn parses_elf32_entry_field_order() {
        let mut reader = MockReader::new(dyn32(6, 0x8048_400));
        let header: Arc<dyn ElfHeader> = Arc::new(MockHeader { is32: true });
        let dynamic = ElfDynamic::parse(&mut reader, header).unwrap();

        assert_eq!(dynamic.get_tag(), 6);
        assert_eq!(dynamic.get_value(), 0x8048_400);
        assert_eq!(dynamic.sizeof(), 8);
        // 8 bytes consumed: 4 + 4
        assert_eq!(reader.get_pointer_index(), 8);
    }

    #[test]
    fn parses_elf64_entry_field_order() {
        let mut reader = MockReader::new(dyn64(7, 0xdead_beef));
        let header: Arc<dyn ElfHeader> = Arc::new(MockHeader { is32: false });
        let dynamic = ElfDynamic::parse(&mut reader, header).unwrap();

        assert_eq!(dynamic.get_tag(), 7);
        assert_eq!(dynamic.get_value(), 0xdead_beef);
        assert_eq!(dynamic.sizeof(), 16);
        // 16 bytes consumed: 8 + 8
        assert_eq!(reader.get_pointer_index(), 16);
    }

    #[test]
    fn tag_as_string_uses_known_type_name() {
        let header: Arc<dyn ElfHeader> = Arc::new(MockHeader { is32: true });
        let dynamic = ElfDynamic::new(6, 0, header);

        assert_eq!(dynamic.get_tag_as_string(), "DT_SYMTAB");
        assert_eq!(dynamic.to_string(), "DT_SYMTAB");
    }

    #[test]
    fn tag_as_string_falls_back_to_hex_for_unknown_tag() {
        let header: Arc<dyn ElfHeader> = Arc::new(MockHeader { is32: true });
        let dynamic = ElfDynamic::new(0x7fff_fffd, 0, header);

        // Integer.toHexString(0x7ffffffd) == "7ffffffd", zero-padded to 8 chars (already 8).
        assert_eq!(dynamic.get_tag_as_string(), "DT_0x7ffffffd");
        assert!(dynamic.get_tag_type().is_none());
    }

    #[test]
    fn tag_as_string_pads_short_hex_values() {
        let header: Arc<dyn ElfHeader> = Arc::new(MockHeader { is32: true });
        let dynamic = ElfDynamic::new(0x2a, 0, header);

        assert_eq!(dynamic.get_tag_as_string(), "DT_0x0000002a");
    }

    #[test]
    fn with_type_uses_the_enum_tag_value() {
        let header: Arc<dyn ElfHeader> = Arc::new(MockHeader { is32: true });
        let tag_type = MockDynamicType { value: 6, name: "DT_SYMTAB".to_string() };
        let dynamic = ElfDynamic::with_type(&tag_type, 0x1000, header);

        assert_eq!(dynamic.get_tag(), 6);
        assert_eq!(dynamic.get_value(), 0x1000);
    }
}
