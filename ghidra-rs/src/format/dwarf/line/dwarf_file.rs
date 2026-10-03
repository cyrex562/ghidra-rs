use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_form_context::DWARFFormContext;
use crate::format::dwarf::line::dwarf_line::DWARFLine;
use crate::format::seam_stubs::{
    DWARFCompilationUnit, DWARFLineContentType, DWARFLineContentTypeDef, DWARFStringAttribute,
    FSUtilities,
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
        reader: &mut BinaryReader,
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
        reader: &mut BinaryReader,
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
    use crate::format::dwarf::attribs::dwarf_form::DWARFForm;

    struct MockCompilationUnit;
    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            4
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
        let mut reader = BinaryReader::from_bytes(encode_v4_entry("main.c", 2, 0x1234, 0x5678), true);
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
        let mut reader = BinaryReader::from_bytes(vec![0], true);
        let cu = MockCompilationUnit;

        assert!(DWARFFile::read_v4(&mut reader, &cu).unwrap().is_none());
    }

    #[test]
    fn read_v5_extracts_fields_by_content_type() {
        use crate::program::model::data::leb128::Leb128;

        let defs = vec![
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctPath,
                attribute_form: DWARFForm::DwFormString,
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctDirectoryIndex,
                attribute_form: DWARFForm::DwFormUdata,
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctTimestamp,
                attribute_form: DWARFForm::DwFormUdata,
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctSize,
                attribute_form: DWARFForm::DwFormData4,
            },
            DWARFLineContentTypeDef {
                attribute_id: DWARFLineContentType::DwLnctMd5,
                attribute_form: DWARFForm::DwFormData16,
            },
        ];

        let md5 = (0u8..16).collect::<Vec<u8>>();
        let mut bytes = b"foo.c\0".to_vec();
        bytes.extend(Leb128::encode(3, false));
        bytes.extend(Leb128::encode(0xdead, false));
        bytes.extend(42u32.to_le_bytes());
        bytes.extend(&md5);

        let mut reader = BinaryReader::from_bytes(bytes, true);
        let cu = MockCompilationUnit;

        let file = DWARFFile::read_v5(&mut reader, &defs, 4, &cu).unwrap();

        assert_eq!(file.get_name(), "foo.c");
        assert_eq!(file.get_directory_index(), 3);
        assert_eq!(file.get_modification_time(), 0xdead);
        assert_eq!(file.length, 42);
        assert_eq!(file.get_md5(), Some(&md5[..]));
    }

    #[test]
    fn read_v5_errors_when_no_path_def_present() {
        let defs = vec![DWARFLineContentTypeDef {
            attribute_id: DWARFLineContentType::DwLnctDirectoryIndex,
            attribute_form: DWARFForm::DwFormUdata,
        }];
        let mut reader = BinaryReader::from_bytes(vec![0x01], true);
        let cu = MockCompilationUnit;

        assert!(DWARFFile::read_v5(&mut reader, &defs, 4, &cu).is_err());
    }

    #[test]
    fn get_path_name_joins_directory_and_name() {
        let parent_line = DWARFLine::with_directories(vec![DWARFFile::new("src")]);
        let file = DWARFFile::with_details("main.c", 0, 0, 0, None);

        assert_eq!(file.get_path_name(&parent_line), "src/main.c");
    }

    #[test]
    fn get_path_name_falls_back_to_name_when_directory_index_invalid() {
        let parent_line = DWARFLine::empty();
        let file = DWARFFile::with_details("main.c", 5, 0, 0, None);

        assert_eq!(file.get_path_name(&parent_line), "main.c");
    }

    #[test]
    fn get_path_name_uses_bare_name_when_no_directory() {
        let parent_line = DWARFLine::empty();
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
