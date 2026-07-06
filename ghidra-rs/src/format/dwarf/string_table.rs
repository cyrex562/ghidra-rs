use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::util::datastruct::abstract_weak_value_map::AbstractWeakValueMap;
use crate::util::datastruct::weak_value_hash_map::WeakValueHashMap;

/// Character encoding used to decode strings read from a [`StringTable`].
///
/// Stands in for `java.nio.charset.Charset`, covering the encodings DWARF string sections
/// actually use: single-byte, null-terminated text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringTableCharset {
    /// US-ASCII: each byte maps directly to one character.
    Ascii,
    /// UTF-8.
    Utf8,
}

impl StringTableCharset {
    fn decode(self, bytes: &[u8]) -> String {
        match self {
            StringTableCharset::Ascii => bytes.iter().map(|&b| b as char).collect(),
            StringTableCharset::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        }
    }
}

/// Represents a DWARF string table, backed by a memory section like `.debug_str`.
///
/// Strings are read from the section the first time requested, and then cached in a weak
/// lookup table.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.StringTable`.
pub struct StringTable {
    reader: Option<Box<dyn BinaryReader>>,
    cache: WeakValueHashMap<u64, String>,
    charset: StringTableCharset,
}

impl StringTable {
    /// Creates a `StringTable` instance, if the supplied reader is `Some`.
    pub fn of(
        reader: Option<Box<dyn BinaryReader>>,
        charset: StringTableCharset,
    ) -> Option<StringTable> {
        reader.map(|reader| StringTable::new(reader, charset))
    }

    /// Creates a `StringTable` backed by `.debug_str` or `.debug_line_str`.
    pub fn new(reader: Box<dyn BinaryReader>, charset: StringTableCharset) -> StringTable {
        StringTable {
            reader: Some(reader),
            cache: WeakValueHashMap::new(),
            charset,
        }
    }

    /// Returns true if the specified offset is a valid offset for this string table.
    pub fn is_valid(&self, offset: u64) -> bool {
        self.reader
            .as_ref()
            .is_some_and(|reader| reader.is_valid_index(offset))
    }

    /// Releases the reader and clears the string cache.
    pub fn clear(&mut self) {
        self.reader = None;
        self.cache.clear();
    }

    /// Returns the string found at `offset`, or an error if the offset is out of bounds.
    pub fn get_string_at_offset(&mut self, offset: u64) -> io::Result<String> {
        if !self.is_valid(offset) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid offset requested {offset} [{offset:#x}]"),
            ));
        }

        if let Some(cached) = self.cache.get(&offset) {
            return Ok((*cached).clone());
        }

        let bytes = self
            .reader
            .as_ref()
            .expect("is_valid confirmed reader is present")
            .read_until_null_term(offset, 1)?;
        let s = self.charset.decode(&bytes);
        self.cache.put(offset, Arc::new(s.clone()));
        Ok(s)
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

    /// Minimal [`BinaryReader`] impl backed by an in-memory [`VecProvider`], used only by
    /// these tests.
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

    fn table_with(data: Vec<u8>, charset: StringTableCharset) -> StringTable {
        StringTable::new(Box::new(MockReader::new(data)), charset)
    }

    #[test]
    fn of_returns_none_for_none_reader() {
        assert!(StringTable::of(None, StringTableCharset::Utf8).is_none());
    }

    #[test]
    fn of_returns_some_for_some_reader() {
        let reader: Box<dyn BinaryReader> = Box::new(MockReader::new(vec![0]));
        assert!(StringTable::of(Some(reader), StringTableCharset::Utf8).is_some());
    }

    #[test]
    fn reads_utf8_string_at_offset() {
        let mut data = b"hello".to_vec();
        data.push(0);
        let mut table = table_with(data, StringTableCharset::Utf8);
        assert_eq!(table.get_string_at_offset(0).unwrap(), "hello");
    }

    #[test]
    fn reads_ascii_string_at_offset() {
        let mut data = b"world".to_vec();
        data.push(0);
        let mut table = table_with(data, StringTableCharset::Ascii);
        assert_eq!(table.get_string_at_offset(0).unwrap(), "world");
    }

    #[test]
    fn reads_string_at_nonzero_offset() {
        let mut data = b"abc\0".to_vec();
        data.extend_from_slice(b"xyz\0");
        let mut table = table_with(data, StringTableCharset::Utf8);
        assert_eq!(table.get_string_at_offset(0).unwrap(), "abc");
        assert_eq!(table.get_string_at_offset(4).unwrap(), "xyz");
    }

    #[test]
    fn caches_repeated_lookups() {
        let mut data = b"cached".to_vec();
        data.push(0);
        let mut table = table_with(data, StringTableCharset::Utf8);
        let first = table.get_string_at_offset(0).unwrap();
        let second = table.get_string_at_offset(0).unwrap();
        assert_eq!(first, "cached");
        assert_eq!(second, "cached");
    }

    #[test]
    fn invalid_offset_is_an_error() {
        let mut table = table_with(vec![0x61, 0x00], StringTableCharset::Utf8);
        let err = table.get_string_at_offset(100).unwrap_err();
        assert!(err.to_string().contains("Invalid offset requested 100"));
    }

    #[test]
    fn is_valid_reflects_reader_bounds() {
        let table = table_with(vec![0x61, 0x00], StringTableCharset::Utf8);
        assert!(table.is_valid(0));
        assert!(table.is_valid(1));
        assert!(!table.is_valid(5));
    }

    #[test]
    fn clear_drops_reader_and_cache() {
        let mut data = b"gone".to_vec();
        data.push(0);
        let mut table = table_with(data, StringTableCharset::Utf8);
        table.get_string_at_offset(0).unwrap();
        table.clear();
        assert!(!table.is_valid(0));
        assert!(table.get_string_at_offset(0).is_err());
    }
}
