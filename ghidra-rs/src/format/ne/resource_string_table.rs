use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::length_string_set::LengthStringSet;
use crate::format::seam_stubs::Resource;
use std::io;

/// Stores new-executable (NE) resource string tables.
///
/// Strings are not stored as individual resources; rather, strings are grouped together into a
/// string table, which is then stored as a resource.
///
/// Mirrors `ResourceStringTable` from the original Ghidra Java source. Java models this as
/// `ResourceStringTable extends Resource`; this port instead composes a `base: Resource` field,
/// consistent with this crate's "composition over inheritance" convention.
///
/// The Java constructor takes a back-reference to the owning `ResourceTable` (`rt`), which
/// `Resource`'s own constructor forwards on to resolve the alignment shift count for
/// `getFileOffsetShifted`/`getFileLengthShifted`. That value is already known by the time any
/// `Resource` is constructed, so -- consistent with [`Resource`]'s (still a seam stub) and
/// [`ResourceType`](crate::format::ne::resource_type::ResourceType)'s established convention --
/// this port takes the alignment shift count directly instead, avoiding an ownership cycle with
/// `ResourceTable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStringTable {
    base: Resource,
    strings: Vec<LengthStringSet>,
}

impl ResourceStringTable {
    /// Constructs a new resource string table.
    ///
    /// # Arguments
    /// * `reader` - the binary reader
    /// * `alignment_shift_count` - the owning resource table's alignment shift count (see
    ///   [`Resource::get_file_offset_shifted`]/[`Resource::get_file_length_shifted`])
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader, alignment_shift_count: i16) -> io::Result<Self> {
        let base = Resource::new(reader, alignment_shift_count)?;

        // Mirrors `Resource.getBytes()`: `reader.readByteArray(getFileOffsetShifted(),
        // getFileLengthShifted())`.
        let bytes = reader.read_byte_array(
            base.get_file_offset_shifted() as u64,
            base.get_file_length_shifted() as usize,
        )?;

        let mut strings = Vec::new();
        let mut i: usize = 0;
        while i < bytes.len() {
            if bytes[i] != 0 {
                let old_index = reader.get_pointer_index();
                reader.set_pointer_index(base.get_file_offset_shifted() as u64 + i as u64);
                let lss = LengthStringSet::new(reader)?;
                if lss.length() == 0 {
                    break;
                }
                let lss_len = lss.length();
                strings.push(lss);
                i += lss_len as usize + 1;
                reader.set_pointer_index(old_index);
            } else {
                i += 1;
            }
        }

        Ok(ResourceStringTable { base, strings })
    }

    /// Returns the base `Resource` this string table was read as.
    pub fn base(&self) -> &Resource {
        &self.base
    }

    /// Returns the strings defined in this resource string table.
    pub fn get_strings(&self) -> &[LengthStringSet] {
        &self.strings
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

    /// Builds a buffer with a 12-byte `Resource` header (offset, length, flagword, resourceID,
    /// handle, usage) at the front, followed by the raw resource content at `content_offset`
    /// (unshifted; alignment shift count is 0 in these tests, so shifted == unshifted).
    fn build_resource(content_offset: u16, content: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&content_offset.to_le_bytes()); // fileOffset
        data.extend_from_slice(&(content.len() as u16).to_le_bytes()); // fileLength
        data.extend_from_slice(&0u16.to_le_bytes()); // flagword
        data.extend_from_slice(&0u16.to_le_bytes()); // resourceID
        data.extend_from_slice(&0u16.to_le_bytes()); // handle
        data.extend_from_slice(&0u16.to_le_bytes()); // usage
        while (data.len() as u16) < content_offset {
            data.push(0xCC); // filler between the header and the content
        }
        data.extend_from_slice(content);
        data
    }

    #[test]
    fn reads_multiple_strings_separated_by_padding() {
        // Two length-prefixed strings "hi" and "bye", separated by a zero-length padding byte.
        let mut content = Vec::new();
        content.push(2);
        content.extend_from_slice(b"hi");
        content.push(0); // padding byte (skipped, since not a valid LengthStringSet start)
        content.push(3);
        content.extend_from_slice(b"bye");

        let data = build_resource(12, &content);
        let mut reader = MockReader::new(data);

        let table = ResourceStringTable::new(&mut reader, 0).unwrap();

        let strings = table.get_strings();
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].name(), Some("hi"));
        assert_eq!(strings[1].name(), Some("bye"));
    }

    #[test]
    fn empty_content_yields_no_strings() {
        let data = build_resource(12, &[]);
        let mut reader = MockReader::new(data);

        let table = ResourceStringTable::new(&mut reader, 0).unwrap();

        assert!(table.get_strings().is_empty());
    }

    #[test]
    fn single_string_fills_entire_content() {
        let content = vec![3, b'a', b'b', b'c'];
        let data = build_resource(12, &content);
        let mut reader = MockReader::new(data);

        let table = ResourceStringTable::new(&mut reader, 0).unwrap();

        assert_eq!(table.get_strings().len(), 1);
        assert_eq!(table.get_strings()[0].name(), Some("abc"));
    }

    #[test]
    fn restores_reader_position_after_construction() {
        let content = vec![2, b'h', b'i'];
        let data = build_resource(12, &content);
        let mut reader = MockReader::new(data);

        let _ = ResourceStringTable::new(&mut reader, 0).unwrap();

        // Resource's own constructor reads 6 shorts (12 bytes) sequentially via readNextShort,
        // so the reader is left positioned right after the Resource header; the string-scanning
        // loop restores the pointer after each LengthStringSet it reads.
        assert_eq!(reader.get_pointer_index(), 12);
    }

    #[test]
    fn applies_alignment_shift_to_offset_and_length() {
        // fileOffset/fileLength are stored pre-shift; with a shift count of 2 an on-disk value
        // of 3 resolves to byte offset 12.
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes()); // fileOffset (shifted: 3 << 2 == 12)
        data.extend_from_slice(&1u16.to_le_bytes()); // fileLength (shifted: 1 << 2 == 4)
        data.extend_from_slice(&0u16.to_le_bytes()); // flagword
        data.extend_from_slice(&0u16.to_le_bytes()); // resourceID
        data.extend_from_slice(&0u16.to_le_bytes()); // handle
        data.extend_from_slice(&0u16.to_le_bytes()); // usage
        // content lives at byte offset 12, and (fileLength << shift) == 4 bytes are read, of
        // which only the first 2 form a valid LengthStringSet ("x").
        data.extend_from_slice(&[1, b'x', 0, 0]);

        let mut reader = MockReader::new(data);
        let table = ResourceStringTable::new(&mut reader, 2).unwrap();

        assert_eq!(table.base().get_file_offset_shifted(), 12);
        assert_eq!(table.base().get_file_length_shifted(), 4);
        assert_eq!(table.get_strings().len(), 1);
        assert_eq!(table.get_strings()[0].name(), Some("x"));
    }
}
