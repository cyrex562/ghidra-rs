use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::seam_stubs::{
    DWARFCompilationUnit, DWARFFormContext, DWARFLine, DWARFLineContentType, DWARFLineContentTypeDef,
    DWARFStringAttribute, FSUtilities,
};

/// `DWARFFile` is used to store file or directory entries in the `DWARFLine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFFile {
    name: String,
    directory_index: i32,
    modification_time: i64,
    length: i64,
    md5: Option<Vec<u8>>,
}

impl DWARFFile {
    /// Mirrors the Java `DWARFFile(String)` convenience constructor.
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_details(name, -1, 0, 0, None)
    }

    /// Creates a new DWARF file entry with the given parameters, mirroring the Java
    /// `DWARFFile(String, int, long, long, byte[])` constructor.
    pub fn with_details(
        name: impl Into<String>,
        directory_index: i32,
        modification_time: i64,
        length: i64,
        md5: Option<Vec<u8>>,
    ) -> Self {
        DWARFFile { name: name.into(), directory_index, modification_time, length, md5 }
    }

    /// Reads a DWARFFile entry from a DWARF v2-v4 line program header. Returns `Ok(None)` if the
    /// end-of-list marker (an empty name) was found.
    ///
    /// The real `BinaryReader.readNextString(Charset, int)` looks up the compilation unit's
    /// program charset to decode the name; that charset plumbing isn't ported yet, so this reads
    /// the name as UTF-8, which covers the overwhelmingly common ASCII/UTF-8 case.
    pub fn read_v4(
        reader: &mut dyn BinaryReader,
        _cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<Option<DWARFFile>> {
        let name = reader.read_next_utf8_string()?;
        if name.is_empty() {
            // empty name == end-of-list of files
            return Ok(None);
        }

        let directory_index = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;
        let modification_time = LEB128Info::unsigned(reader)?.as_long();
        let length = LEB128Info::unsigned(reader)?.as_long();

        Ok(Some(DWARFFile::with_details(name, directory_index, modification_time, length, None)))
    }

    /// Reads a DWARFFile entry from a DWARF v5 line program header, using `defs` to describe how
    /// each field is serialized.
    pub fn read_v5(
        reader: &mut dyn BinaryReader,
        defs: &[DWARFLineContentTypeDef],
        dwarf_int_size: i32,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<DWARFFile> {
        let mut name: Option<String> = None;
        let mut directory_index: i32 = -1;
        let mut modification_time: i64 = 0;
        let mut length: i64 = 0;
        let mut md5: Option<Vec<u8>> = None;

        for def in defs {
            let mut context =
                DWARFFormContext { reader: &mut *reader, comp_unit: cu, def, dwarf_int_size };
            let val = def.get_attribute_form().read_value(&mut context)?;

            match def.get_attribute_id() {
                DWARFLineContentType::DwLnctPath => {
                    name = val
                        .as_any()
                        .downcast_ref::<DWARFStringAttribute>()
                        .map(|strval| strval.get_value(cu));
                }
                DWARFLineContentType::DwLnctDirectoryIndex => {
                    directory_index = match val
                        .as_any()
                        .downcast_ref::<crate::format::seam_stubs::DWARFNumericAttribute>()
                    {
                        Some(numval) => numval.get_unsigned_int_exact()?,
                        None => -1,
                    };
                }
                DWARFLineContentType::DwLnctTimestamp => {
                    modification_time = val
                        .as_any()
                        .downcast_ref::<crate::format::seam_stubs::DWARFNumericAttribute>()
                        .map(|numval| numval.get_value())
                        .unwrap_or(0);
                }
                DWARFLineContentType::DwLnctSize => {
                    length = val
                        .as_any()
                        .downcast_ref::<crate::format::seam_stubs::DWARFNumericAttribute>()
                        .map(|numval| numval.get_unsigned_value())
                        .unwrap_or(0);
                }
                DWARFLineContentType::DwLnctMd5 => {
                    md5 = val
                        .as_any()
                        .downcast_ref::<crate::format::seam_stubs::DWARFBlobAttribute>()
                        .map(|blobval| blobval.get_bytes().to_vec());
                }
                _ => {
                    // skip any DW_LNCT_??? values that we don't care about
                }
            }
        }

        let name = name
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No name value for DWARFLine file"))?;
        Ok(DWARFFile::with_details(name, directory_index, modification_time, length, md5))
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the full path of this file, joining its parent directory's name (looked up via
    /// `parent_line`) with this file's own name.
    pub fn get_path_name(&self, parent_line: &DWARFLine) -> String {
        let dir = if self.directory_index >= 0 {
            match parent_line.get_dir(self.directory_index) {
                Ok(dir_file) => dir_file.get_name().to_string(),
                Err(_) => return self.name.clone(),
            }
        } else {
            String::new()
        };

        FSUtilities::append_path(&[&dir, &self.name])
    }

    /// Returns a copy of this `DWARFFile` with its name replaced by `new_name`.
    pub fn with_name(&self, new_name: impl Into<String>) -> DWARFFile {
        DWARFFile::with_details(new_name, self.directory_index, self.modification_time, self.length, self.md5.clone())
    }

    pub fn get_directory_index(&self) -> i32 {
        self.directory_index
    }

    pub fn get_modification_time(&self) -> i64 {
        self.modification_time
    }

    pub fn get_md5(&self) -> Option<&[u8]> {
        self.md5.as_deref()
    }
}

impl fmt::Display for DWARFFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Filename: {}, Length: 0x{:x}, Time: 0x{:x}, DirIndex: {}",
            self.name, self.length, self.modification_time, self.directory_index
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::{DWARFBlobAttribute, DWARFForm, DWARFNumericAttribute};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0.get(index as usize).copied().ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    /// Minimal `BinaryReader` implementation backed by an in-memory byte vector, for testing.
    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader { provider: Rc::new(RefCell::new(VecProvider(bytes))), index: 0, little_endian: true }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
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
            Box::new(TestReader { provider: Rc::clone(&self.provider), index: new_index, little_endian: self.little_endian })
        }
    }

    struct MockCompilationUnit;
    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            4
        }
    }

    struct StringForm(String);
    impl DWARFForm for StringForm {
        fn is_class(&self, _class: &dyn std::any::Any) -> bool {
            false
        }
        fn read_value(
            &self,
            _context: &mut DWARFFormContext,
        ) -> io::Result<Box<dyn crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue>> {
            Ok(Box::new(DWARFStringAttribute::new(self.0.clone())))
        }
    }

    struct NumericForm(i64);
    impl DWARFForm for NumericForm {
        fn is_class(&self, _class: &dyn std::any::Any) -> bool {
            false
        }
        fn read_value(
            &self,
            _context: &mut DWARFFormContext,
        ) -> io::Result<Box<dyn crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue>> {
            Ok(Box::new(DWARFNumericAttribute::new(self.0)))
        }
    }

    struct BlobForm(Vec<u8>);
    impl DWARFForm for BlobForm {
        fn is_class(&self, _class: &dyn std::any::Any) -> bool {
            false
        }
        fn read_value(
            &self,
            _context: &mut DWARFFormContext,
        ) -> io::Result<Box<dyn crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue>> {
            Ok(Box::new(DWARFBlobAttribute::new(self.0.clone())))
        }
    }

    /// Encodes `name`, then unsigned LEB128 `directory_index`, `modification_time`, `length`,
    /// matching the DWARF v4 line-table file-entry layout that `readV4` parses in the original
    /// Ghidra source.
    fn encode_v4_entry(name: &str, directory_index: i64, modification_time: i64, length: i64) -> Vec<u8> {
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(crate::program::model::data::leb128::Leb128::encode(directory_index, false));
        bytes.extend(crate::program::model::data::leb128::Leb128::encode(modification_time, false));
        bytes.extend(crate::program::model::data::leb128::Leb128::encode(length, false));
        bytes
    }

    #[test]
    fn read_v4_parses_a_file_entry() {
        let mut reader = TestReader::new(encode_v4_entry("main.c", 2, 0x1234, 0x5678));
        let cu = MockCompilationUnit;

        let file = DWARFFile::read_v4(&mut reader, &cu).unwrap().unwrap();

        assert_eq!(file.get_name(), "main.c");
        assert_eq!(file.get_directory_index(), 2);
        assert_eq!(file.get_modification_time(), 0x1234);
        assert_eq!(file.length, 0x5678);
        assert_eq!(file.get_md5(), None);
    }

    #[test]
    fn read_v4_returns_none_for_end_of_list_marker() {
        // An empty (null-terminated) name signals end-of-list.
        let mut reader = TestReader::new(vec![0]);
        let cu = MockCompilationUnit;

        assert!(DWARFFile::read_v4(&mut reader, &cu).unwrap().is_none());
    }

    #[test]
    fn read_v5_extracts_fields_by_content_type() {
        let defs = vec![
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctPath,
                attribute_form: Box::new(StringForm("foo.c".to_string())),
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctDirectoryIndex,
                attribute_form: Box::new(NumericForm(3)),
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctTimestamp,
                attribute_form: Box::new(NumericForm(0xdead)),
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctSize,
                attribute_form: Box::new(NumericForm(42)),
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctMd5,
                attribute_form: Box::new(BlobForm(vec![0xAA, 0xBB, 0xCC])),
            },
        ];
        let mut reader = TestReader::new(vec![]);
        let cu = MockCompilationUnit;

        let file = DWARFFile::read_v5(&mut reader, &defs, 4, &cu).unwrap();

        assert_eq!(file.get_name(), "foo.c");
        assert_eq!(file.get_directory_index(), 3);
        assert_eq!(file.get_modification_time(), 0xdead);
        assert_eq!(file.length, 42);
        assert_eq!(file.get_md5(), Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn read_v5_errors_when_no_path_def_present() {
        let defs = vec![DWARFLineContentTypeDef {
            attribute_id: DWARFLineContentType::DwLnctDirectoryIndex,
            attribute_form: Box::new(NumericForm(1)),
        }];
        let mut reader = TestReader::new(vec![]);
        let cu = MockCompilationUnit;

        assert!(DWARFFile::read_v5(&mut reader, &defs, 4, &cu).is_err());
    }

    #[test]
    fn get_path_name_joins_directory_and_name() {
        let parent_line = DWARFLine { dirs: vec![DWARFFile::new("src")] };
        let file = DWARFFile::with_details("main.c", 0, 0, 0, None);

        assert_eq!(file.get_path_name(&parent_line), "src/main.c");
    }

    #[test]
    fn get_path_name_falls_back_to_name_when_directory_index_invalid() {
        let parent_line = DWARFLine { dirs: vec![] };
        let file = DWARFFile::with_details("main.c", 5, 0, 0, None);

        assert_eq!(file.get_path_name(&parent_line), "main.c");
    }

    #[test]
    fn get_path_name_uses_bare_name_when_no_directory() {
        let parent_line = DWARFLine { dirs: vec![] };
        let file = DWARFFile::new("main.c");

        assert_eq!(file.get_path_name(&parent_line), "main.c");
    }

    #[test]
    fn with_name_replaces_name_but_keeps_other_fields() {
        let file = DWARFFile::with_details("a.c", 1, 2, 3, Some(vec![1, 2, 3]));
        let renamed = file.with_name("b.c");

        assert_eq!(renamed.get_name(), "b.c");
        assert_eq!(renamed.get_directory_index(), 1);
        assert_eq!(renamed.get_modification_time(), 2);
        assert_eq!(renamed.get_md5(), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let file = DWARFFile::with_details("main.c", 4, 0x1234, 0x5678, None);
        assert_eq!(format!("{file}"), "Filename: main.c, Length: 0x5678, Time: 0x1234, DirIndex: 4");
    }
}
