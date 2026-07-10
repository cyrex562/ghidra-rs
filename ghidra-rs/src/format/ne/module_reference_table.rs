use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::imported_name_table::ImportedNameTable;
use crate::format::ne::length_string_set::LengthStringSet;
use std::io;

/// Represents the module reference table in a new-executable (NE) format file.
///
/// The module reference table stores references to imported modules (DLLs).
/// Each entry contains an offset into the imported name table that identifies the module.
///
/// Mirrors `ModuleReferenceTable` from the original Ghidra Java source.
pub struct ModuleReferenceTable {
    offsets: Vec<i16>,
    names: Vec<LengthStringSet>,
}

impl ModuleReferenceTable {
    /// Constructs a new module reference table.
    ///
    /// # Arguments
    /// * `reader` - The binary reader used to read from the underlying data
    /// * `index` - The absolute file offset where the table begins
    /// * `count` - The number of module references in the table
    /// * `imported_name_table` - The imported name table used to resolve module names
    ///
    /// # Errors
    /// Returns an error if there is an IO-related error reading from the reader.
    pub fn new(
        mut reader: Box<dyn BinaryReader>,
        index: u64,
        count: i16,
        imported_name_table: &ImportedNameTable,
    ) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut offsets = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let offset = reader.read_next_short()?;
            offsets.push(offset);
        }

        let mut names = Vec::new();
        for &offset in &offsets {
            let lss = imported_name_table.get_name_at(offset)?;
            if lss.length() == 0 {
                break;
            }
            names.push(lss);
        }

        reader.set_pointer_index(old_index);

        Ok(ModuleReferenceTable { offsets, names })
    }

    /// Returns the array of module names.
    pub fn names(&self) -> &[LengthStringSet] {
        &self.names
    }

    /// Returns the array of offsets into the imported name table.
    pub fn offsets(&self) -> &[i16] {
        &self.offsets
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
        current_index: Rc<RefCell<u64>>,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: Rc::new(RefCell::new(0)),
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
            *self.current_index.borrow()
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = *self.current_index.borrow();
            *self.current_index.borrow_mut() = index;
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
                current_index: Rc::new(RefCell::new(new_index)),
            })
        }
    }

    #[test]
    fn creates_table_with_no_modules() {
        let data = vec![];
        let reader = Box::new(MockReader::new(data));
        let import_table = ImportedNameTable::new(Box::new(MockReader::new(vec![])), 0);

        let table = ModuleReferenceTable::new(reader, 0, 0, &import_table).unwrap();
        assert_eq!(table.offsets().len(), 0);
        assert_eq!(table.names().len(), 0);
    }

    #[test]
    fn reads_offsets_correctly() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0i16, 4, 8, 12].iter().flat_map(|&x| x.to_le_bytes()).collect::<Vec<_>>());
        data.extend_from_slice(&[0u8; 20]);

        let reader = Box::new(MockReader::new(data.clone()));
        // Imported name table shares the same buffer; names begin right after the
        // 8-byte offset table. Offset 0 lands on a zero-length entry, so the name
        // loop terminates immediately, leaving only the offsets to verify.
        let import_table = ImportedNameTable::new(Box::new(MockReader::new(data)), 8);

        let table = ModuleReferenceTable::new(reader, 0, 4, &import_table).unwrap();
        assert_eq!(table.offsets(), &[0, 4, 8, 12]);
    }

    #[test]
    fn stops_at_zero_length_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0i16, 4].iter().flat_map(|&x| x.to_le_bytes()).collect::<Vec<_>>());

        data.push(3);
        data.extend_from_slice(b"mod");

        data.push(0);

        let reader = Box::new(MockReader::new(data.clone()));
        let import_table = ImportedNameTable::new(Box::new(MockReader::new(data)), 4);

        let table = ModuleReferenceTable::new(reader, 0, 2, &import_table).unwrap();
        assert_eq!(table.offsets(), &[0, 4]);
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].name(), Some("mod"));
    }

    #[test]
    fn restores_reader_index() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0i16].iter().flat_map(|&x| x.to_le_bytes()).collect::<Vec<_>>());
        data.push(2);
        data.extend_from_slice(b"ab");

        let mut reader = Box::new(MockReader::new(data.clone()));
        reader.set_pointer_index(100);
        let index_handle = Rc::clone(&reader.current_index);

        let import_table = ImportedNameTable::new(Box::new(MockReader::new(data)), 0);
        let _ = ModuleReferenceTable::new(reader, 0, 1, &import_table).unwrap();

        let ptr = *index_handle.borrow();
        assert_eq!(ptr, 100);
    }

    #[test]
    fn handles_table_at_different_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 50]);

        data.extend_from_slice(&[0i16].iter().flat_map(|&x| x.to_le_bytes()).collect::<Vec<_>>());
        data.push(4);
        data.extend_from_slice(b"test");

        let reader = Box::new(MockReader::new(data.clone()));
        // Names begin right after the 2-byte offset table at index 52; offset 0
        // therefore resolves against import-table base 52.
        let import_table = ImportedNameTable::new(Box::new(MockReader::new(data)), 52);

        let table = ModuleReferenceTable::new(reader, 50, 1, &import_table).unwrap();
        assert_eq!(table.offsets(), &[0]);
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].name(), Some("test"));
    }

    #[test]
    fn empty_names_when_first_is_zero() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0i16].iter().flat_map(|&x| x.to_le_bytes()).collect::<Vec<_>>());
        data.push(0);

        let reader = Box::new(MockReader::new(data.clone()));
        let import_table = ImportedNameTable::new(Box::new(MockReader::new(data)), 0);

        let table = ModuleReferenceTable::new(reader, 0, 1, &import_table).unwrap();
        assert_eq!(table.offsets(), &[0]);
        assert_eq!(table.names().len(), 0);
    }

    #[test]
    fn multiple_modules() {
        let mut data = Vec::new();
        // Names are packed after the 6-byte offset table (base 6): "dll" at rel 0,
        // "sys" at rel 4, "so" at rel 8.
        data.extend_from_slice(&[0i16, 4, 8].iter().flat_map(|&x| x.to_le_bytes()).collect::<Vec<_>>());

        data.push(3);
        data.extend_from_slice(b"dll");

        data.push(3);
        data.extend_from_slice(b"sys");

        data.push(2);
        data.extend_from_slice(b"so");

        let reader = Box::new(MockReader::new(data.clone()));
        let import_table = ImportedNameTable::new(Box::new(MockReader::new(data)), 6);

        let table = ModuleReferenceTable::new(reader, 0, 3, &import_table).unwrap();
        assert_eq!(table.offsets(), &[0, 4, 8]);
        assert_eq!(table.names().len(), 3);
        assert_eq!(table.names()[0].name(), Some("dll"));
        assert_eq!(table.names()[1].name(), Some("sys"));
        assert_eq!(table.names()[2].name(), Some("so"));
    }
}
