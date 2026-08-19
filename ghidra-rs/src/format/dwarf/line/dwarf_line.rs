use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::dwarf::dwarf_length_value::DWARFLengthValue;
use crate::format::dwarf::line::dwarf_file::DWARFFile;
use crate::format::seam_stubs::{
    DWARFCompilationUnit, DWARFLineContentTypeDef, DWARFLineProgramExecutor, FSUtilities,
};

/// A structure read from `.debug_line`, contains indexed source filenames as well as a mapping
/// between addresses and source filename and linenumbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFLine {
    start_offset: u64,

    /// Offset in the section of the end of this header. (exclusive)
    end_offset: u64,

    /// Length in bytes of this header.
    length: i64,

    /// Size of integers, 4=int32 or 8=int64.
    int_size: i32,

    /// Version number, as read from the header.
    dwarf_version: i32,

    minimum_instruction_length: i32,
    maximum_operations_per_instruction: i32,
    default_is_stmt: bool,
    line_base: i32,
    line_range: i32,
    opcode_base: i32,
    standard_opcode_length: Vec<i32>,
    directories: Vec<DWARFFile>,
    files: Vec<DWARFFile>,
    address_size: i32,
    segment_selector_size: i32,

    /// Offset where the line number program opcodes start.
    opcodes_start: u64,
}

/// The path and MD5 hash of one source file listed in a line table, mirroring the Java
/// `DWARFLine.SourceFileInfo` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileInfo {
    pub file_path: String,
    pub md5: Option<Vec<u8>>,
}

/// One row of the line-number matrix: the address, its source file and line number, mirroring the
/// Java `DWARFLine.SourceFileAddr` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileAddr {
    pub address: u64,
    pub file_name: String,
    pub md5: Option<Vec<u8>>,
    pub line_num: u32,
    pub is_end_sequence: bool,
}

impl DWARFLine {
    /// Returns a dummy `DWARFLine` instance that contains no information.
    pub fn empty() -> DWARFLine {
        DWARFLine {
            start_offset: 0,
            end_offset: 0,
            length: 0,
            int_size: 0,
            dwarf_version: 0,
            minimum_instruction_length: 0,
            maximum_operations_per_instruction: 0,
            default_is_stmt: false,
            line_base: 0,
            line_range: 0,
            opcode_base: 0,
            standard_opcode_length: Vec::new(),
            directories: Vec::new(),
            files: Vec::new(),
            address_size: 0,
            segment_selector_size: 0,
            opcodes_start: 0,
        }
    }

    /// Creates a line table that only knows about the given include directories. Used to exercise
    /// [`DWARFFile::get_path_name`] without having to synthesize a whole `.debug_line` header.
    pub(crate) fn with_directories(directories: Vec<DWARFFile>) -> DWARFLine {
        DWARFLine { directories, ..DWARFLine::empty() }
    }

    /// Creates a line table that only knows about the given source files, indexed the way
    /// `dwarf_version` dictates (1-based before DWARF5, 0-based from DWARF5 on). Used to exercise
    /// [`Self::get_file`] callers without having to synthesize a whole `.debug_line` header.
    pub(crate) fn with_files(dwarf_version: i32, files: Vec<DWARFFile>) -> DWARFLine {
        DWARFLine { dwarf_version, files, ..DWARFLine::empty() }
    }

    /// Reads a line table header (and its directory / file tables) from the stream.
    pub fn read(
        reader: &mut dyn BinaryReader,
        default_int_size: i32,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<DWARFLine> {
        // probe for the DWARFLine version number
        // length : dwarf_length
        // version : 2 bytes
        let mut result = DWARFLine::empty();
        result.start_offset = reader.get_pointer_index();
        let length_info = DWARFLengthValue::read(reader, default_int_size)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                DWARFException::with_message(format!(
                    "Invalid DWARFLine length at 0x{:x}",
                    result.start_offset
                )),
            )
        })?;

        result.length = length_info.length();
        result.int_size = length_info.int_size();
        result.end_offset = reader.get_pointer_index() + length_info.length() as u64;

        result.dwarf_version = reader.read_next_unsigned_short()? as i32;
        if result.dwarf_version < 5 {
            DWARFLine::read_v4(&mut result, reader, cu)?;
        } else {
            DWARFLine::read_v5(&mut result, reader, cu)?;
        }
        Ok(result)
    }

    fn read_v4(
        result: &mut DWARFLine,
        reader: &mut dyn BinaryReader,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<()> {
        // length : dwarf_length (already)
        // version : 2 bytes (already)
        // header_len : dwarf_intsize
        // min_instr_len : 1 byte
        // ....
        let header_length = reader.read_next_unsigned_value(result.int_size as usize)?;
        result.opcodes_start = reader.get_pointer_index() + header_length;

        result.minimum_instruction_length = reader.read_next_unsigned_byte()? as i32;

        result.maximum_operations_per_instruction = if result.dwarf_version >= 4 {
            // Maximum operations per instruction only exists in DWARF version 4 or higher
            reader.read_next_unsigned_byte()? as i32
        } else {
            1
        };
        result.default_is_stmt = reader.read_next_unsigned_byte()? != 0;
        result.line_base = reader.read_next_byte()? as i8 as i32;
        result.line_range = reader.read_next_unsigned_byte()? as i32;
        result.opcode_base = reader.read_next_unsigned_byte()? as i32;
        result.read_standard_opcode_lengths(reader)?;

        // Add the cu's compDir as element 0 of the dir table
        let default_comp_dir = Self::default_comp_dir(cu);
        result.directories.push(DWARFFile::new(default_comp_dir.clone()));

        // Read all include directories, which are only a list of names in v4.
        //
        // The Java code decodes these with the program's charset; that charset plumbing isn't
        // ported yet, so (as in `DWARFFile::read_v4`) the names are read as UTF-8.
        let mut dir_name = reader.read_next_utf8_string()?;
        while !dir_name.is_empty() {
            let dir = Self::fixup_dir(DWARFFile::new(dir_name), &default_comp_dir);
            result.directories.push(dir);
            dir_name = reader.read_next_utf8_string()?;
        }

        // Read all files, ending when null (hit empty filename)
        while let Some(file) = DWARFFile::read_v4(reader, cu)? {
            result.files.push(file);
        }

        Ok(())
    }

    fn read_v5(
        result: &mut DWARFLine,
        reader: &mut dyn BinaryReader,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<()> {
        // length : dwarf_length (already)
        // version : 2 bytes (already)
        // address_size : 1 byte
        // segment_selector_size : 1 byte
        // header_len : dwarf_intsize
        // min_instr_len : 1 byte
        // ...
        result.address_size = reader.read_next_unsigned_byte()? as i32;
        result.segment_selector_size = reader.read_next_unsigned_byte()? as i32;

        let header_length = reader.read_next_unsigned_value(result.int_size as usize)?;
        result.opcodes_start = reader.get_pointer_index() + header_length;

        result.minimum_instruction_length = reader.read_next_unsigned_byte()? as i32;
        result.maximum_operations_per_instruction = reader.read_next_unsigned_byte()? as i32;
        result.default_is_stmt = reader.read_next_unsigned_byte()? != 0;
        result.line_base = reader.read_next_byte()? as i8 as i32;
        result.line_range = reader.read_next_unsigned_byte()? as i32;
        result.opcode_base = reader.read_next_unsigned_byte()? as i32;
        result.read_standard_opcode_lengths(reader)?;

        let directory_entry_format_count = reader.read_next_unsigned_byte()?;
        let mut dir_format_defs: Vec<DWARFLineContentTypeDef> = Vec::new();
        for _ in 0..directory_entry_format_count {
            dir_format_defs.push(DWARFLineContentTypeDef::read(reader)?);
        }

        let default_comp_dir = Self::default_comp_dir(cu);

        // read the directories, which are defined the same way files are
        let directories_count = LEB128Info::unsigned(reader)?.as_u_int32()?;
        for _ in 0..directories_count {
            let dir = DWARFFile::read_v5(reader, &dir_format_defs, result.int_size, cu)?;
            result.directories.push(Self::fixup_dir(dir, &default_comp_dir));
        }

        let filename_entry_format_count = reader.read_next_unsigned_byte()?;
        let mut file_format_defs: Vec<DWARFLineContentTypeDef> = Vec::new();
        for _ in 0..filename_entry_format_count {
            file_format_defs.push(DWARFLineContentTypeDef::read(reader)?);
        }

        let file_names_count = LEB128Info::unsigned(reader)?.as_u_int32()?;
        for _ in 0..file_names_count {
            result.files.push(DWARFFile::read_v5(reader, &file_format_defs, result.int_size, cu)?);
        }

        Ok(())
    }

    /// Reads the `opcode_base - 1` standard opcode operand counts. Element 0 is never used by the
    /// line program and is set to 1, as in the Java code.
    fn read_standard_opcode_lengths(&mut self, reader: &mut dyn BinaryReader) -> io::Result<()> {
        self.standard_opcode_length = vec![0; self.opcode_base.max(0) as usize];
        if let Some(first) = self.standard_opcode_length.first_mut() {
            *first = 1; /* Should never be used */
        }
        for i in 1..self.standard_opcode_length.len() {
            self.standard_opcode_length[i] = reader.read_next_unsigned_byte()? as i32;
        }
        Ok(())
    }

    /// The compilation unit's compile directory, normalized to `""` when absent or blank.
    fn default_comp_dir(cu: &dyn DWARFCompilationUnit) -> String {
        match cu.get_compile_directory() {
            Some(dir) if !dir.trim().is_empty() => dir,
            _ => String::new(),
        }
    }

    /// Fixes relative dir names using the compile directory string from the CU.
    fn fixup_dir(dir: DWARFFile, default_comp_dir: &str) -> DWARFFile {
        if !default_comp_dir.is_empty() {
            if dir.get_name() == "." {
                return dir.with_name(default_comp_dir);
            } else if !Self::is_absolute_path(dir.get_name()) {
                return dir.with_name(FSUtilities::append_path(&[default_comp_dir, dir.get_name()]));
            }
        }
        dir
    }

    fn is_absolute_path(s: &str) -> bool {
        let bytes = s.as_bytes();
        s.starts_with('/')
            || s.starts_with('\\')
            || (bytes.len() > 3 && bytes[1] == b':' && (bytes[2] == b'/' || bytes[2] == b'\\'))
    }

    pub fn get_start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn get_end_offset(&self) -> u64 {
        self.end_offset
    }

    /// Creates an executor positioned at this header's line number program.
    ///
    /// Java dereferences the compilation unit's `.debug_line` reader unconditionally; here a
    /// missing reader (or compilation unit program) is reported as an error instead.
    pub fn get_line_program_executor(
        &self,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<DWARFLineProgramExecutor> {
        let debug_line_reader = cu
            .get_die_container()
            .and_then(|die_container| die_container.get_debug_line_reader())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No .debug_line reader available for line program",
                )
            })?;
        let program = cu.get_program().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "No DWARFProgram for compilation unit")
        })?;

        Ok(DWARFLineProgramExecutor::new(
            debug_line_reader.clone_at(self.opcodes_start),
            self.end_offset,
            cu.get_pointer_size(),
            self.opcode_base,
            self.line_base,
            self.line_range,
            self.minimum_instruction_length,
            self.default_is_stmt,
            program.is_addr0_tombstone(),
        ))
    }

    /// Executes the line number program and returns one entry per row of the line-number matrix.
    ///
    /// Returns an empty list when the compilation unit has no `.debug_line` reader.
    pub fn get_all_source_file_addr_info(
        &self,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<Vec<SourceFileAddr>> {
        let has_debug_line_reader = cu
            .get_die_container()
            .is_some_and(|die_container| die_container.get_debug_line_reader().is_some());
        if !has_debug_line_reader {
            return Ok(Vec::new());
        }

        let import_summary = cu.get_program().map(|program| program.get_import_summary());

        let mut lpe = self.get_line_program_executor(cu)?;
        let rows = lpe.all_rows();
        lpe.close();

        let mut results = Vec::new();
        for row in rows? {
            if row.tombstone {
                // skips elements that were based on tombstoned/dead code that wasn't included
                // in final binary
                if let Some(summary) = import_summary {
                    summary.increment_tombstoned_source_line_entry_skipped_count();
                }
                continue;
            }
            match self.get_file(row.file as i32) {
                Ok(file) => results.push(SourceFileAddr {
                    address: row.address,
                    file_name: file.get_path_name(self),
                    md5: file.get_md5().map(<[u8]>::to_vec),
                    line_num: row.line,
                    is_end_sequence: row.is_end_sequence,
                }),
                Err(_) => {
                    if let Some(summary) = import_summary {
                        summary.increment_bad_source_file_count();
                    }
                }
            }
        }

        Ok(results)
    }

    pub fn get_all_source_file_infos(&self) -> Vec<SourceFileInfo> {
        // TODO: last_mod info not included yet
        self.files
            .iter()
            .map(|df| SourceFileInfo {
                file_path: df.get_path_name(self),
                md5: df.get_md5().map(<[u8]>::to_vec),
            })
            .collect()
    }

    pub fn get_dir(&self, index: i32) -> io::Result<&DWARFFile> {
        if index >= 0 {
            if let Some(dir) = self.directories.get(index as usize) {
                return Ok(dir);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid dir index {} for line table at 0x{:x}: ",
                index, self.start_offset
            ),
        ))
    }

    /// Get a file given a file index, where the index may not be zero based depending on the
    /// dwarf version.
    pub fn get_file(&self, index: i32) -> io::Result<&DWARFFile> {
        if self.dwarf_version < 5 {
            if index > 0 {
                // Retrieve the file by index (index starts at 1)
                if let Some(file) = self.files.get(index as usize - 1) {
                    return Ok(file);
                }
            }
        } else if index >= 0 {
            if let Some(file) = self.files.get(index as usize) {
                return Ok(file);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid file index {} for line table at 0x{:x}: ",
                index, self.start_offset
            ),
        ))
    }
}

impl fmt::Display for DWARFLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Line Entry Include Directories: [")?;
        for dir in &self.directories {
            write!(f, "{dir}, ")?;
        }
        f.write_str("] File Names: [")?;
        for file in &self.files {
            write!(f, "{file}, ")?;
        }
        f.write_str("]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::{DIEContainer, DWARFImportSummary, DWARFProgram};
    use crate::program::model::data::leb128::Leb128;
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
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
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
            TestReader {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
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
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    struct MockProgram {
        summary: DWARFImportSummary,
    }

    impl DWARFProgram for MockProgram {
        fn is_addr0_tombstone(&self) -> bool {
            true
        }
        fn get_import_summary(&self) -> &DWARFImportSummary {
            &self.summary
        }
    }

    struct MockDIEContainer {
        debug_line_bytes: Option<Vec<u8>>,
    }

    impl DIEContainer for MockDIEContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            self.debug_line_bytes
                .as_ref()
                .map(|bytes| Box::new(TestReader::new(bytes.clone())) as Box<dyn BinaryReader>)
        }
    }

    struct MockCompilationUnit {
        version: i16,
        comp_dir: Option<String>,
        program: Option<MockProgram>,
        die_container: Option<MockDIEContainer>,
    }

    impl MockCompilationUnit {
        fn new(version: i16, comp_dir: Option<&str>) -> Self {
            MockCompilationUnit {
                version,
                comp_dir: comp_dir.map(str::to_string),
                program: None,
                die_container: None,
            }
        }

        fn with_debug_line(mut self, debug_line_bytes: Option<Vec<u8>>) -> Self {
            self.program = Some(MockProgram { summary: DWARFImportSummary::new() });
            self.die_container = Some(MockDIEContainer { debug_line_bytes });
            self
        }
    }

    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            self.version
        }
        fn get_compile_directory(&self) -> Option<String> {
            self.comp_dir.clone()
        }
        fn get_pointer_size(&self) -> i8 {
            8
        }
        fn get_program(&self) -> Option<&dyn DWARFProgram> {
            self.program.as_ref().map(|p| p as &dyn DWARFProgram)
        }
        fn get_die_container(&self) -> Option<&dyn DIEContainer> {
            self.die_container.as_ref().map(|c| c as &dyn DIEContainer)
        }
    }

    /// Builds a DWARF v2/v3/v4 `.debug_line` header, with the given include directory names and
    /// v4-style file entries, laid out exactly as `DWARFLine.readV4` expects it.
    fn encode_v4_header(version: u16, dirs: &[&str], files: &[&str]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.push(1); // minimum_instruction_length
        if version >= 4 {
            body.push(1); // maximum_operations_per_instruction
        }
        body.push(1); // default_is_stmt
        body.push(0xfb); // line_base, -5 as a signed byte
        body.push(14); // line_range
        body.push(13); // opcode_base
        // opcode_base - 1 standard opcode operand counts, as emitted by gcc/clang
        body.extend([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
        for dir in dirs {
            body.extend(dir.as_bytes());
            body.push(0);
        }
        body.push(0); // end of include_directories
        for file in files {
            body.extend(file.as_bytes());
            body.push(0);
            body.extend(Leb128::encode(1, false)); // directory index
            body.extend(Leb128::encode(0, false)); // modification time
            body.extend(Leb128::encode(0, false)); // length
        }
        body.push(0); // end of file_names

        // unit_length counts everything after itself; header_length everything after itself up to
        // the start of the opcodes (i.e. the whole of `body`).
        let mut header: Vec<u8> = Vec::new();
        header.extend((version).to_le_bytes());
        header.extend((body.len() as u32).to_le_bytes());
        header.extend(&body);

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend((header.len() as u32).to_le_bytes());
        bytes.extend(&header);
        bytes
    }

    #[test]
    fn empty_line_table_has_no_files_or_dirs() {
        let line = DWARFLine::empty();

        assert_eq!(line.get_start_offset(), 0);
        assert_eq!(line.get_end_offset(), 0);
        assert!(line.get_all_source_file_infos().is_empty());
        assert!(line.get_dir(0).is_err());
        assert!(line.get_file(1).is_err());
    }

    #[test]
    fn read_v4_parses_header_dirs_and_files() {
        let bytes = encode_v4_header(4, &["/usr/include"], &["main.c", "util.c"]);
        let total_len = bytes.len() as u64;
        let mut reader = TestReader::new(bytes);
        let cu = MockCompilationUnit::new(4, Some("/home/user/proj"));

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();

        assert_eq!(line.get_start_offset(), 0);
        // unit_length is 4 bytes, and covers everything after itself.
        assert_eq!(line.get_end_offset(), total_len);
        assert_eq!(line.length, total_len as i64 - 4);
        assert_eq!(line.int_size, 4);
        assert_eq!(line.dwarf_version, 4);
        assert_eq!(line.minimum_instruction_length, 1);
        assert_eq!(line.maximum_operations_per_instruction, 1);
        assert!(line.default_is_stmt);
        assert_eq!(line.line_base, -5);
        assert_eq!(line.line_range, 14);
        assert_eq!(line.opcode_base, 13);
        assert_eq!(
            line.standard_opcode_length,
            vec![1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
        );
        // The opcodes start where the header ends, since this header has no line program bytes.
        assert_eq!(line.opcodes_start, total_len);

        // dir 0 is always the CU's compile directory, and the absolute include dir is left alone.
        assert_eq!(line.get_dir(0).unwrap().get_name(), "/home/user/proj");
        assert_eq!(line.get_dir(1).unwrap().get_name(), "/usr/include");
        assert!(line.get_dir(2).is_err());

        // v4 file indexes are 1-based.
        assert!(line.get_file(0).is_err());
        assert_eq!(line.get_file(1).unwrap().get_name(), "main.c");
        assert_eq!(line.get_file(2).unwrap().get_name(), "util.c");
        assert!(line.get_file(3).is_err());
    }

    #[test]
    fn read_v2_has_no_max_ops_per_instruction_field() {
        let bytes = encode_v4_header(2, &[], &["a.c"]);
        let mut reader = TestReader::new(bytes);
        let cu = MockCompilationUnit::new(2, None);

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();

        assert_eq!(line.dwarf_version, 2);
        // Not read from the stream for versions < 4; defaulted to 1.
        assert_eq!(line.maximum_operations_per_instruction, 1);
        assert_eq!(line.get_file(1).unwrap().get_name(), "a.c");
    }

    #[test]
    fn read_v4_makes_relative_include_dirs_absolute() {
        let bytes = encode_v4_header(4, &["include", ".", "/abs/dir", "d:\\win\\dir"], &[]);
        let mut reader = TestReader::new(bytes);
        let cu = MockCompilationUnit::new(4, Some("/home/user/proj"));

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();

        assert_eq!(line.get_dir(1).unwrap().get_name(), "/home/user/proj/include");
        assert_eq!(line.get_dir(2).unwrap().get_name(), "/home/user/proj");
        assert_eq!(line.get_dir(3).unwrap().get_name(), "/abs/dir");
        assert_eq!(line.get_dir(4).unwrap().get_name(), "d:\\win\\dir");
    }

    #[test]
    fn read_v4_leaves_relative_dirs_alone_without_a_compile_directory() {
        let bytes = encode_v4_header(4, &["include", "."], &[]);
        let mut reader = TestReader::new(bytes);
        // A blank compile directory is treated the same as a missing one.
        let cu = MockCompilationUnit::new(4, Some("   "));

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();

        assert_eq!(line.get_dir(0).unwrap().get_name(), "");
        assert_eq!(line.get_dir(1).unwrap().get_name(), "include");
        assert_eq!(line.get_dir(2).unwrap().get_name(), ".");
    }

    #[test]
    fn read_v5_parses_header_with_empty_dir_and_file_tables() {
        // v5 layout: unit_length, version, address_size, segment_selector_size, header_length, ...
        let mut body: Vec<u8> = Vec::new();
        body.push(1); // minimum_instruction_length
        body.push(1); // maximum_operations_per_instruction
        body.push(0); // default_is_stmt
        body.push(0xfb); // line_base, -5
        body.push(14); // line_range
        body.push(2); // opcode_base
        body.push(0); // standard_opcode_length[1]
        body.push(1); // directory_entry_format_count
        body.extend(Leb128::encode(0x1, false)); // DW_LNCT_path
        body.extend(Leb128::encode(0x08, false)); // DW_FORM_string
        body.extend(Leb128::encode(0, false)); // directories_count
        body.push(1); // file_name_entry_format_count
        body.extend(Leb128::encode(0x1, false)); // DW_LNCT_path
        body.extend(Leb128::encode(0x08, false)); // DW_FORM_string
        body.extend(Leb128::encode(0, false)); // file_names_count

        let mut header: Vec<u8> = Vec::new();
        header.extend(5u16.to_le_bytes()); // version
        header.push(8); // address_size
        header.push(0); // segment_selector_size
        header.extend((body.len() as u32).to_le_bytes()); // header_length
        header.extend(&body);

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend((header.len() as u32).to_le_bytes());
        bytes.extend(&header);
        let total_len = bytes.len() as u64;

        let mut reader = TestReader::new(bytes);
        let cu = MockCompilationUnit::new(5, Some("/proj"));

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();

        assert_eq!(line.dwarf_version, 5);
        assert_eq!(line.address_size, 8);
        assert_eq!(line.segment_selector_size, 0);
        assert_eq!(line.line_base, -5);
        assert_eq!(line.opcode_base, 2);
        assert_eq!(line.standard_opcode_length, vec![1, 0]);
        assert!(!line.default_is_stmt);
        assert_eq!(line.get_end_offset(), total_len);
        assert_eq!(line.opcodes_start, total_len);
        // v5 dir tables don't get the CU's comp dir prepended, and this one is empty.
        assert!(line.get_dir(0).is_err());
        // v5 file indexes are 0-based.
        assert!(line.get_file(0).is_err());
    }

    #[test]
    fn read_rejects_a_zero_length_unit() {
        let mut reader = TestReader::new(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let cu = MockCompilationUnit::new(4, None);

        assert!(DWARFLine::read(&mut reader, 4, &cu).is_err());
    }

    #[test]
    fn get_all_source_file_infos_joins_dir_and_file_names() {
        let bytes = encode_v4_header(4, &["/usr/include"], &["main.c", "util.c"]);
        let mut reader = TestReader::new(bytes);
        let cu = MockCompilationUnit::new(4, Some("/home/user/proj"));

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();
        let infos = line.get_all_source_file_infos();

        // Both files were encoded with directory index 1, i.e. "/usr/include".
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].file_path, "/usr/include/main.c");
        assert_eq!(infos[0].md5, None);
        assert_eq!(infos[1].file_path, "/usr/include/util.c");
    }

    #[test]
    fn get_all_source_file_addr_info_is_empty_without_a_debug_line_reader() {
        let cu = MockCompilationUnit::new(4, None).with_debug_line(None);
        let line = DWARFLine::empty();

        assert!(line.get_all_source_file_addr_info(&cu).unwrap().is_empty());
    }

    #[test]
    fn line_program_executor_gets_the_header_values() {
        let bytes = encode_v4_header(4, &[], &["main.c"]);
        let mut reader = TestReader::new(bytes.clone());
        let cu = MockCompilationUnit::new(4, None).with_debug_line(Some(bytes));

        let line = DWARFLine::read(&mut reader, 4, &cu).unwrap();
        let lpe = line.get_line_program_executor(&cu).unwrap();

        assert_eq!(lpe.reader.get_pointer_index(), line.opcodes_start);
        assert_eq!(lpe.end_offset, line.get_end_offset());
        assert_eq!(lpe.pointer_size, 8);
        assert_eq!(lpe.opcode_base, 13);
        assert_eq!(lpe.line_base, -5);
        assert_eq!(lpe.line_range, 14);
        assert_eq!(lpe.minimum_instruction_length, 1);
        assert!(lpe.default_is_stmt);
        assert!(lpe.is_addr0_tombstone);
    }

    #[test]
    fn display_lists_directories_and_files() {
        let line = DWARFLine::with_directories(vec![DWARFFile::new("/proj")]);

        assert_eq!(
            line.to_string(),
            "Line Entry Include Directories: \
             [Filename: /proj, Length: 0x0, Time: 0x0, DirIndex: -1, ] File Names: []"
        );
    }
}
