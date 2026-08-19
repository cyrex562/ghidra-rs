//! Port of `ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader`.
//!
//! # Departures from the Java class
//!
//! * `DWARFCompilationUnit` and `DIEContainer` aren't ported yet, so `cu` is stored as
//!   `Arc<dyn DWARFCompilationUnit>` (see [`crate::format::seam_stubs`]) and [`Self::get_entries`]
//!   goes through [`DIEContainer::get_macro_entries`](crate::format::seam_stubs::DIEContainer::get_macro_entries).
//! * An opcode's operand form code that no [`DWARFForm`] recognizes is reported as an error while
//!   reading the per-unit opcode table, rather than deferred to the `NullPointerException` Java
//!   would raise later when it tries to read a value through the resulting null form.
//! * The `EMTPY` singleton (an anonymous subclass overriding `getEntries()` to always return an
//!   empty list, to avoid dereferencing its null `cu`) becomes [`Self::empty`], a header with
//!   `cu: None`; [`Self::get_entries`] checks for that directly instead of relying on
//!   virtual dispatch.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::line::dwarf_line::DWARFLine;
use crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntry;
use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
use crate::format::seam_stubs::{DWARFCompilationUnit, DWARFMacroOpcode};

const OFFSET_SIZE_FLAG_MASK: i32 = 0x1;
const DEBUG_LINE_OFFSET_FLAG_MASK: i32 = 0x2;
const OPCODE_OPERANDS_TABLE_FLAG_MASK: i32 = 0x4;

/// Represents a DWARF Macro Header.
#[derive(Clone)]
pub struct DWARFMacroHeader {
    start_offset: u64,
    version: i32,
    flags: i32,
    debug_line_offset: i64,
    int_size: i32,
    entries_start_offset: u64,
    opcode_map: HashMap<i32, Vec<DWARFForm>>,
    cu: Option<Arc<dyn DWARFCompilationUnit>>,
    line: Option<DWARFLine>,
}

impl DWARFMacroHeader {
    /// Mirrors the public `DWARFMacroHeader(long, int, int, long, int, long,
    /// DWARFCompilationUnit, DWARFLine, Map)` constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        start_offset: u64,
        version: i32,
        flags: i32,
        debug_line_offset: i64,
        int_size: i32,
        entries_start_offset: u64,
        cu: Option<Arc<dyn DWARFCompilationUnit>>,
        line: Option<DWARFLine>,
        opcode_map: HashMap<i32, Vec<DWARFForm>>,
    ) -> Self {
        DWARFMacroHeader {
            start_offset,
            version,
            flags,
            debug_line_offset,
            int_size,
            entries_start_offset,
            opcode_map,
            cu,
            line,
        }
    }

    /// Mirrors the `DWARFMacroHeader.EMTPY` singleton: a header with no compilation unit and an
    /// empty line table, whose [`Self::get_entries`] always returns an empty list.
    pub fn empty() -> DWARFMacroHeader {
        DWARFMacroHeader {
            start_offset: 0,
            version: 0,
            flags: 0,
            debug_line_offset: 0,
            int_size: 0,
            entries_start_offset: 0,
            opcode_map: HashMap::new(),
            cu: None,
            line: Some(DWARFLine::empty()),
        }
    }

    /// Reads a `DWARFMacroHeader` from a stream. Mirrors `DWARFMacroHeader.readV5(BinaryReader,
    /// DWARFCompilationUnit)`.
    pub fn read_v5(reader: &mut dyn BinaryReader, cu: Arc<dyn DWARFCompilationUnit>) -> io::Result<DWARFMacroHeader> {
        let start_offset = reader.get_pointer_index();
        let version = reader.read_next_unsigned_short()? as i32;
        if version != 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported DWARF Macro version: {version}"),
            ));
        }

        let flags = reader.read_next_unsigned_byte()? as i32;
        let int_size = if flags & OFFSET_SIZE_FLAG_MASK == OFFSET_SIZE_FLAG_MASK { 8 } else { 4 };

        let mut line = None;
        let mut debug_line_offset: i64 = -1;
        if flags & DEBUG_LINE_OFFSET_FLAG_MASK != 0 {
            debug_line_offset = reader.read_next_unsigned_value(int_size as usize)? as i64;
            let container = cu.get_die_container().expect(
                "DWARFCompilationUnit.getDIEContainer: cu has no DIE container (mirrors a Java \
                 NullPointerException)",
            );
            line = Some(container.get_line(debug_line_offset as u64, cu.as_ref(), false)?);
        }

        let mut opcode_map = DWARFMacroOpcode::default_opcode_operand_map();
        if flags & OPCODE_OPERANDS_TABLE_FLAG_MASK != 0 {
            Self::read_macro_opcode_table(reader, &mut opcode_map)?;
        }

        let entries_start_offset = reader.get_pointer_index();
        Ok(DWARFMacroHeader {
            start_offset,
            version,
            flags,
            debug_line_offset,
            int_size,
            entries_start_offset,
            opcode_map,
            cu: Some(cu),
            line,
        })
    }

    /// Mirrors the private `DWARFMacroHeader.readMacroOpcodeTable(BinaryReader, Map)`.
    ///
    /// TODO: needs testing with actual data emitted from toolchain (matches a Java comment).
    fn read_macro_opcode_table(reader: &mut dyn BinaryReader, opcode_map: &mut HashMap<i32, Vec<DWARFForm>>) -> io::Result<()> {
        let num_opcodes = reader.read_next_unsigned_byte()?;
        for _ in 0..num_opcodes {
            let opcode = reader.read_next_unsigned_byte()? as i32;
            let num_operands = LEB128Info::unsigned(reader)?.as_u_int32()?;
            let mut operand_forms = Vec::with_capacity(num_operands as usize);
            for _ in 0..num_operands {
                let form_code = reader.read_next_unsigned_byte()? as i32;
                let form = DWARFForm::of(form_code).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown DWARF Form in macro opcode table: {form_code:#x}"),
                    )
                })?;
                operand_forms.push(form);
            }
            opcode_map.insert(opcode, operand_forms);
        }
        Ok(())
    }

    /// Reads consecutive macro info entries until the end-of-list marker. Mirrors
    /// `DWARFMacroHeader.readMacroEntries(BinaryReader, DWARFMacroHeader)`.
    pub fn read_macro_entries(
        reader: &mut dyn BinaryReader,
        macro_header: Arc<DWARFMacroHeader>,
    ) -> io::Result<Vec<Box<dyn DWARFMacroInfoEntry>>> {
        use crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntryBase;

        let mut results = Vec::new();
        while let Some(entry) = DWARFMacroInfoEntryBase::read(reader, Arc::clone(&macro_header))? {
            results.push(entry);
        }
        Ok(results)
    }

    /// Mirrors `DWARFMacroHeader.getLine()`.
    pub fn get_line(&self) -> Option<&DWARFLine> {
        self.line.as_ref()
    }

    /// Mirrors `DWARFMacroHeader.getDebug_line_offset()`.
    pub fn get_debug_line_offset(&self) -> i64 {
        self.debug_line_offset
    }

    /// Mirrors `DWARFMacroHeader.getIntSize()`.
    pub fn get_int_size(&self) -> i32 {
        self.int_size
    }

    /// Mirrors `DWARFMacroHeader.getEntriesStartOffset()`.
    pub fn get_entries_start_offset(&self) -> u64 {
        self.entries_start_offset
    }

    /// Mirrors `DWARFMacroHeader.getEntries()`. Delegates to the owning compilation unit's DIE
    /// container, or returns an empty list for a header with no compilation unit (mirrors the
    /// `EMTPY` singleton's overridden `getEntries()`).
    pub fn get_entries(&self) -> io::Result<Vec<Box<dyn DWARFMacroInfoEntry>>> {
        let Some(cu) = &self.cu else {
            return Ok(Vec::new());
        };
        let container = cu.get_die_container().expect(
            "DWARFCompilationUnit.getDIEContainer: cu has no DIE container (mirrors a Java \
             NullPointerException)",
        );
        container.get_macro_entries(Arc::new(self.clone()))
    }

    /// Mirrors `DWARFMacroHeader.getCompilationUnit()`.
    ///
    /// # Panics
    /// Panics if this header has no compilation unit, mirroring the Java `NullPointerException`
    /// callers would hit dereferencing the `EMTPY` singleton's null `cu` field.
    pub fn get_compilation_unit(&self) -> Arc<dyn DWARFCompilationUnit> {
        self.cu.clone().expect(
            "DWARFMacroHeader.getCompilationUnit: cu is null (mirrors a Java NullPointerException \
             on the EMTPY singleton)",
        )
    }

    /// Mirrors `DWARFMacroHeader.getOpcodeMap()`.
    pub fn get_opcode_map(&self) -> HashMap<i32, Vec<DWARFForm>> {
        self.opcode_map.clone()
    }

    /// Mirrors `DWARFMacroHeader.toString()`.
    pub fn to_string(&self) -> String {
        format!(
            "DWARFMacroHeader: startOffset=0x{:x}, debug_line_offset=0x{:x}, intSize={}",
            self.start_offset, self.debug_line_offset, self.int_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::DIEContainer;
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

    struct MockDIEContainer;

    impl DIEContainer for MockDIEContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            None
        }

        fn get_line(&self, offset: u64, _cu: &dyn DWARFCompilationUnit, _read_if_missing: bool) -> io::Result<DWARFLine> {
            assert_eq!(offset, 0x20);
            Ok(DWARFLine::empty())
        }
    }

    struct MockCompilationUnit {
        die_container: MockDIEContainer,
    }

    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
        fn get_die_container(&self) -> Option<&dyn DIEContainer> {
            Some(&self.die_container)
        }
    }

    #[test]
    fn read_v5_reads_debug_line_offset_when_flagged() {
        // version=5 (LE u16), flags=0x2 (debug line offset present, 4-byte offsets), then a
        // 4-byte little-endian offset (0x20), mirroring a real `.debug_macro` unit header.
        let mut reader = TestReader::new(vec![0x05, 0x00, 0x02, 0x20, 0x00, 0x00, 0x00]);
        let cu: Arc<dyn DWARFCompilationUnit> = Arc::new(MockCompilationUnit { die_container: MockDIEContainer });

        let header = DWARFMacroHeader::read_v5(&mut reader, cu).unwrap();

        assert_eq!(header.get_debug_line_offset(), 0x20);
        assert_eq!(header.get_int_size(), 4);
        assert!(header.get_line().is_some());
        assert_eq!(header.get_entries_start_offset(), 7);
        assert_eq!(
            header.to_string(),
            "DWARFMacroHeader: startOffset=0x0, debug_line_offset=0x20, intSize=4"
        );
    }

    #[test]
    fn read_v5_rejects_unsupported_version() {
        let mut reader = TestReader::new(vec![0x04, 0x00]);
        let cu: Arc<dyn DWARFCompilationUnit> = Arc::new(MockCompilationUnit { die_container: MockDIEContainer });

        let err = match DWARFMacroHeader::read_v5(&mut reader, cu) {
            Err(err) => err,
            Ok(_) => panic!("expected an error for an unsupported version"),
        };
        assert!(err.to_string().contains("Unsupported DWARF Macro version: 4"));
    }

    #[test]
    fn empty_header_returns_no_entries_without_dereferencing_a_null_cu() {
        // Mirrors `DWARFMacroHeader.EMTPY.getEntries()`, whose override sidesteps its null `cu`.
        let header = DWARFMacroHeader::empty();
        assert_eq!(header.get_entries().unwrap().len(), 0);
    }

    #[test]
    fn default_opcode_operand_map_covers_every_known_opcode() {
        // readV5's default table (no per-unit override) recognizes every `DW_MACRO_*` opcode,
        // e.g. DW_MACRO_end_file (0x4) with zero operands.
        let mut reader = TestReader::new(vec![0x05, 0x00, 0x00]);
        let cu: Arc<dyn DWARFCompilationUnit> = Arc::new(MockCompilationUnit { die_container: MockDIEContainer });
        let header = DWARFMacroHeader::read_v5(&mut reader, cu).unwrap();

        let opcode_map = header.get_opcode_map();
        assert_eq!(opcode_map.get(&0x4).unwrap().len(), 0);
        assert_eq!(opcode_map.get(&0x1).unwrap().len(), 2);
    }
}
