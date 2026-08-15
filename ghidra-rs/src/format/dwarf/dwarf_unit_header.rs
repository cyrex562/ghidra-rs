use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::dwarf::dwarf_length_value::DWARFLengthValue;
use crate::format::dwarf::dwarf_unit_type::DWARFUnitType;
use crate::format::seam_stubs::{self, DIEContainer, DWARFCompilationUnit, DWARFProgram};

/// The base set of fields shared by every DWARF unit header.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.DWARFUnitHeader`. In Java this is the base class of
/// a single-subclass hierarchy (`DWARFCompilationUnit` is its only subclass). Rust has no class
/// inheritance, so the future `DWARFCompilationUnit` port embeds this struct as a field rather
/// than extending it.
#[derive(Clone)]
pub struct DWARFUnitHeader {
    /// Reference to the owning [`DWARFProgram`].
    dprog: Arc<dyn DWARFProgram>,
    die_container: Arc<dyn DIEContainer>,
    /// Offset in the section of this header.
    start_offset: u64,
    /// Offset in the section of the end of this header (exclusive).
    end_offset: u64,
    /// Size of integers, 4 = int32 or 8 = int64.
    int_size: i32,
    /// Version number as read from the header. Note: some header types use version numbers that
    /// do not match the general DWARF version.
    dwarf_version: i16,
    /// Sequential number of this unit.
    unit_number: i32,
}

impl DWARFUnitHeader {
    pub(crate) fn new(
        die_container: Arc<dyn DIEContainer>,
        start_offset: u64,
        end_offset: u64,
        int_size: i32,
        dwarf_version: i16,
        unit_number: i32,
    ) -> Self {
        let dprog = die_container
            .get_program()
            .expect("DIEContainer.getProgram() must not return None");
        DWARFUnitHeader {
            dprog,
            die_container,
            start_offset,
            end_offset,
            int_size,
            dwarf_version,
            unit_number,
        }
    }

    /// Reads the initial fields found in a unit header.
    ///
    /// Mirrors `DWARFUnitHeader.read(DIEContainer, BinaryReader, int)`. Returns `Ok(None)` if at
    /// the end-of-list.
    pub fn read(
        die_container: Arc<dyn DIEContainer>,
        reader: &mut dyn BinaryReader,
        unit_number: i32,
    ) -> io::Result<Option<Box<dyn DWARFCompilationUnit>>> {
        // unit_length : dwarf_length
        // version : 2 bytes
        // unit type : 1 byte [ version >= 5 ]

        let dprog = die_container
            .get_program()
            .expect("DIEContainer.getProgram() must not return None");
        let start_offset = reader.get_pointer_index();
        let length_info = match DWARFLengthValue::read(reader, dprog.get_default_int_size())? {
            Some(length_info) => length_info,
            None => return Ok(None),
        };

        let end_offset = reader.get_pointer_index() + length_info.length() as u64;
        let version = reader.read_next_short()?;
        if version < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                DWARFException::with_message(format!("Unsupported DWARF version [{version}]")),
            ));
        }

        let partial = DWARFUnitHeader::new(
            Arc::clone(&die_container),
            start_offset,
            end_offset,
            length_info.int_size(),
            version,
            unit_number,
        );

        if (2..=4).contains(&version) {
            return seam_stubs::dwarf_compilation_unit_read_v4(partial, reader).map(Some);
        }

        let unit_type = reader.read_next_unsigned_byte()? as u8;
        if unit_type == DWARFUnitType::Compile as u8 {
            return seam_stubs::dwarf_compilation_unit_read_v5(partial, reader).map(Some);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            DWARFException::with_message(format!(
                "Unsupported unitType {unit_type}, {}",
                describe_unit_type(unit_type)
            )),
        ))
    }

    /// Mirrors `DWARFUnitHeader.getProgram()`.
    pub fn get_program(&self) -> &dyn DWARFProgram {
        self.dprog.as_ref()
    }

    /// Mirrors `DWARFUnitHeader.getDIEContainer()`.
    pub fn get_die_container(&self) -> &dyn DIEContainer {
        self.die_container.as_ref()
    }

    /// Mirrors `DWARFUnitHeader.getDWARFVersion()`.
    pub fn get_dwarf_version(&self) -> i16 {
        self.dwarf_version
    }

    /// Returns the byte offset to the start of this unit.
    pub fn get_start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Returns the byte offset to the end of this unit.
    pub fn get_end_offset(&self) -> u64 {
        self.end_offset
    }

    /// Returns either 4 (for DWARF_32) or 8 (for DWARF_64) depending on the current unit format.
    pub fn get_int_size(&self) -> i32 {
        self.int_size
    }

    /// Returns the ordinal number of this unit.
    pub fn get_unit_number(&self) -> i32 {
        self.unit_number
    }
}

/// Mirrors `DWARFUtil.toString(DWARFUnitType.class, unitType)`, used only to build the
/// "Unsupported unitType" error message.
fn describe_unit_type(unit_type: u8) -> String {
    match unit_type {
        x if x == DWARFUnitType::Compile as u8 => "DW_UT_compile".to_string(),
        x if x == DWARFUnitType::Type as u8 => "DW_UT_type".to_string(),
        x if x == DWARFUnitType::Partial as u8 => "DW_UT_partial".to_string(),
        x if x == DWARFUnitType::Skeleton as u8 => "DW_UT_skeleton".to_string(),
        x if x == DWARFUnitType::SplitCompile as u8 => "DW_UT_split_compile".to_string(),
        x if x == DWARFUnitType::SplitType as u8 => "DW_UT_split_type".to_string(),
        other => format!("0x{other:02x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
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
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
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

    struct MockProgram;

    impl DWARFProgram for MockProgram {
        fn is_addr0_tombstone(&self) -> bool {
            false
        }
        fn get_import_summary(&self) -> &seam_stubs::DWARFImportSummary {
            unimplemented!()
        }
    }

    struct MockDIEContainer {
        program: Arc<dyn DWARFProgram>,
    }

    impl MockDIEContainer {
        fn new() -> Self {
            MockDIEContainer {
                program: Arc::new(MockProgram),
            }
        }
    }

    impl DIEContainer for MockDIEContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            None
        }
        fn get_program(&self) -> Option<Arc<dyn DWARFProgram>> {
            Some(Arc::clone(&self.program))
        }
    }

    fn build_v4_header_bytes(version: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_le_bytes());
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // rest of the unit, not parsed by this type
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes()); // dwarf length
        bytes.extend_from_slice(&body);
        bytes
    }

    fn build_v5_header_bytes(unit_type: u8) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes()); // version
        body.push(unit_type);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // rest of the unit, not parsed by this type
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes()); // dwarf length
        bytes.extend_from_slice(&body);
        bytes
    }

    /// `Result::unwrap_err` requires the `Ok` type to implement `Debug`, which
    /// `Option<Box<dyn DWARFCompilationUnit>>` doesn't. This does the same job without that bound.
    fn expect_err<T>(result: io::Result<T>) -> io::Error {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn read_returns_none_at_end_of_list() {
        let mut reader = TestReader::new(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let container: Arc<dyn DIEContainer> = Arc::new(MockDIEContainer::new());
        let result = DWARFUnitHeader::read(container, &mut reader, 0).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_rejects_versions_below_2() {
        let bytes = build_v4_header_bytes(1);
        let mut reader = TestReader::new(bytes);
        let container: Arc<dyn DIEContainer> = Arc::new(MockDIEContainer::new());
        let err = expect_err(DWARFUnitHeader::read(container, &mut reader, 0));
        assert!(err.to_string().contains("Unsupported DWARF version [1]"));
    }

    #[test]
    fn read_dispatches_v2_through_v4_to_the_unported_compilation_unit_reader() {
        // DWARFCompilationUnit hasn't been ported yet, so the forward-cycle stub always errors;
        // what matters here is that read() actually reached that dispatch point instead of
        // erroring earlier on version validation.
        for version in [2u16, 3, 4] {
            let bytes = build_v4_header_bytes(version);
            let mut reader = TestReader::new(bytes);
            let container: Arc<dyn DIEContainer> = Arc::new(MockDIEContainer::new());
            let err = expect_err(DWARFUnitHeader::read(container, &mut reader, 0));
            assert!(err.to_string().contains("DWARFCompilationUnit.readV4"));
        }
    }

    #[test]
    fn read_dispatches_v5_compile_unit_to_the_unported_compilation_unit_reader() {
        let bytes = build_v5_header_bytes(DWARFUnitType::Compile as u8);
        let mut reader = TestReader::new(bytes);
        let container: Arc<dyn DIEContainer> = Arc::new(MockDIEContainer::new());
        let err = expect_err(DWARFUnitHeader::read(container, &mut reader, 0));
        assert!(err.to_string().contains("DWARFCompilationUnit.readV5"));
    }

    #[test]
    fn read_rejects_unsupported_v5_unit_types() {
        for unit_type in [
            DWARFUnitType::Type as u8,
            DWARFUnitType::Partial as u8,
            DWARFUnitType::Skeleton as u8,
            DWARFUnitType::SplitCompile as u8,
            DWARFUnitType::SplitType as u8,
        ] {
            let bytes = build_v5_header_bytes(unit_type);
            let mut reader = TestReader::new(bytes);
            let container: Arc<dyn DIEContainer> = Arc::new(MockDIEContainer::new());
            let err = expect_err(DWARFUnitHeader::read(container, &mut reader, 0));
            assert!(err.to_string().contains("Unsupported unitType"));
        }
    }

    #[test]
    fn getters_return_constructed_values() {
        let container: Arc<dyn DIEContainer> = Arc::new(MockDIEContainer::new());
        let header = DWARFUnitHeader::new(container, 0, 8, 4, 4, 7);

        assert_eq!(header.get_start_offset(), 0);
        assert_eq!(header.get_end_offset(), 8);
        assert_eq!(header.get_int_size(), 4);
        assert_eq!(header.get_dwarf_version(), 4);
        assert_eq!(header.get_unit_number(), 7);
        assert!(!header.get_program().is_addr0_tombstone());
    }
}
