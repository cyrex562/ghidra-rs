use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
use crate::format::dwarf::dwarf_location_list_entry::DWARFLocationListEntry;
use crate::format::dwarf::dwarf_range::DWARFRange;
use crate::format::dwarf::expression::dwarf_expression::DWARFExpression;
use crate::format::seam_stubs::{DWARFCompilationUnit, DWARFLocation};

/// A collection of [`DWARFLocation`] elements, each of which represents the location of an item
/// that is only valid for a certain range of program-counter locations.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.DWARFLocationList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFLocationList {
    list: Vec<DWARFLocation>,
}

impl DWARFLocationList {
    /// Mirrors `DWARFLocationList.EMPTY`.
    pub const EMPTY: DWARFLocationList = DWARFLocationList { list: Vec::new() };

    pub fn new(list: Vec<DWARFLocation>) -> Self {
        DWARFLocationList { list }
    }

    /// Creates a simple location list containing a single wildcarded range and the specified
    /// expression bytes.
    ///
    /// Mirrors `DWARFLocationList.withWildcardRange(byte[])`.
    pub fn with_wildcard_range(expr: Vec<u8>) -> Self {
        DWARFLocationList::new(vec![DWARFLocation::wildcard(expr)])
    }

    /// Reads a v4 [`DWARFLocationList`] from the `.debug_loc` section.
    ///
    /// `reader` must be positioned at the start of a `.debug_loc` location list; `cu` is the
    /// compilation unit that refers to the location list.
    ///
    /// Mirrors `DWARFLocationList.readV4(BinaryReader, DWARFCompilationUnit)`.
    pub fn read_v4(
        reader: &mut dyn BinaryReader,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<DWARFLocationList> {
        let mut results = Vec::new();

        let pointer_size = cu.get_pointer_size();
        let mut base_address = cu.get_pc_range().from();
        let max_addr_val: u64 = if pointer_size == 4 { 0xFFFF_FFFF } else { u64::MAX };

        while reader.has_next() {
            // Read the beginning and ending addresses
            let beginning = reader.read_next_unsigned_value(pointer_size as usize)?;
            let ending = reader.read_next_unsigned_value(pointer_size as usize)?; // dwarf end addrs are exclusive

            // End of the list
            if beginning == 0 && ending == 0 {
                break;
            }

            // Check to see if this is a base address entry
            if beginning == max_addr_val {
                base_address = ending;
                continue;
            }

            let size = reader.read_next_unsigned_short()? as usize;
            let expr = reader.read_next_byte_array(size)?;

            if beginning == ending {
                // skip adding empty ranges because Ghidra can't use them
                continue;
            }

            let range =
                DWARFRange::new(base_address.wrapping_add(beginning), base_address.wrapping_add(ending));
            results.push(DWARFLocation::new(range, expr));
        }
        Ok(DWARFLocationList::new(results))
    }

    /// Reads a v5 [`DWARFLocationList`] from the `.debug_loclists` stream.
    ///
    /// `reader` must be positioned at the start of a `.debug_loclists` location list; `cu` is the
    /// compilation unit that refers to the location list.
    ///
    /// Mirrors `DWARFLocationList.readV5(BinaryReader, DWARFCompilationUnit)`.
    pub fn read_v5(
        reader: &mut dyn BinaryReader,
        cu: &dyn DWARFCompilationUnit,
    ) -> io::Result<DWARFLocationList> {
        let mut base_addr = cu.get_pc_range().from();
        let die_container = cu.get_die_container().expect(
            "DWARFCompilationUnit.getDIEContainer: cu has no DIE container (mirrors a Java \
             NullPointerException)",
        );

        let mut list = Vec::new();
        while reader.has_next() {
            let lle_id = reader.read_next_unsigned_byte()?;
            if lle_id as u32 == DWARFLocationListEntry::EndOfList.value() {
                break;
            }
            let entry = DWARFLocationListEntry::find(lle_id as u64).map_err(|id| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported DWARF Location List Entry type: {id}"),
                )
            })?;

            match entry {
                DWARFLocationListEntry::EndOfList => unreachable!("handled above"),
                DWARFLocationListEntry::BaseAddressx => {
                    let addr_index = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    base_addr =
                        die_container.get_address(DWARFForm::DwFormAddrx, addr_index as i64, cu)? as u64;
                }
                DWARFLocationListEntry::StartxEndx => {
                    let start_addr_index = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let end_addr_index = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let expr = Self::uleb128_sized_byte_array(reader)?;
                    let start = die_container.get_address(
                        DWARFForm::DwFormAddrx,
                        start_addr_index as i64,
                        cu,
                    )? as u64;
                    let end = die_container.get_address(
                        DWARFForm::DwFormAddrx,
                        end_addr_index as i64,
                        cu,
                    )? as u64;
                    list.push(DWARFLocation::from_bounds(start, end, expr));
                }
                DWARFLocationListEntry::StartxLength => {
                    let start_addr_index = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let len = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let expr = Self::uleb128_sized_byte_array(reader)?;
                    let start = die_container.get_address(
                        DWARFForm::DwFormAddrx,
                        start_addr_index as i64,
                        cu,
                    )? as u64;
                    list.push(DWARFLocation::from_bounds(start, start + len as u64, expr));
                }
                DWARFLocationListEntry::OffsetPair => {
                    let start_ofs = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let end_ofs = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let expr = Self::uleb128_sized_byte_array(reader)?;
                    list.push(DWARFLocation::from_bounds(
                        base_addr + start_ofs as u64,
                        base_addr + end_ofs as u64,
                        expr,
                    ));
                }
                DWARFLocationListEntry::DefaultLocation => {
                    let expr = Self::uleb128_sized_byte_array(reader)?;
                    list.push(DWARFLocation::new(DWARFRange::EMPTY, expr));
                }
                DWARFLocationListEntry::BaseAddress => {
                    base_addr = reader.read_next_unsigned_value(cu.get_pointer_size() as usize)?;
                }
                DWARFLocationListEntry::StartEnd => {
                    let start_addr = reader.read_next_unsigned_value(cu.get_pointer_size() as usize)?;
                    let end_addr = reader.read_next_unsigned_value(cu.get_pointer_size() as usize)?;
                    let expr = Self::uleb128_sized_byte_array(reader)?;
                    list.push(DWARFLocation::from_bounds(start_addr, end_addr, expr));
                }
                DWARFLocationListEntry::StartLength => {
                    let start_addr = reader.read_next_unsigned_value(cu.get_pointer_size() as usize)?;
                    let len = LEB128Info::unsigned(reader)?.as_u_int32()?;
                    let expr = Self::uleb128_sized_byte_array(reader)?;
                    list.push(DWARFLocation::from_bounds(start_addr, start_addr + len as u64, expr));
                }
            }
        }
        Ok(DWARFLocationList::new(list))
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Gets the location that corresponds to the specified PC location.
    ///
    /// Mirrors `DWARFLocationList.getLocationContaining(long)`.
    pub fn get_location_containing(&self, pc: u64) -> Option<&DWARFLocation> {
        self.list.iter().find(|loc| loc.contains(pc))
    }

    /// Mirrors `DWARFLocationList.getFirstLocation()`.
    pub fn get_first_location(&self) -> Option<&DWARFLocation> {
        self.list.first()
    }

    /// Reader func that reads a uleb128-length prefixed byte array.
    ///
    /// Mirrors `DWARFLocationList.uleb128SizedByteArray(BinaryReader)`.
    fn uleb128_sized_byte_array(reader: &mut dyn BinaryReader) -> io::Result<Vec<u8>> {
        let len = LEB128Info::unsigned(reader)?.as_u_int32()?;
        if len > DWARFExpression::MAX_SANE_EXPR as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid DWARF exprloc size: {len}"),
            ));
        }
        reader.read_next_byte_array(len as usize)
    }
}

impl fmt::Display for DWARFLocationList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DWARFLocationList: [")?;
        for (i, loc) in self.list.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{loc}")?;
        }
        write!(f, "]")
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

        fn get_address(
            &self,
            _form: DWARFForm,
            value: i64,
            _cu: &dyn DWARFCompilationUnit,
        ) -> io::Result<i64> {
            // test fixture: address-table index N resolves to 0x1000 + N*0x10
            Ok(0x1000 + value * 0x10)
        }
    }

    struct MockCompilationUnit {
        pointer_size: i8,
        pc_range: DWARFRange,
        die_container: MockDIEContainer,
    }

    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
        fn get_pointer_size(&self) -> i8 {
            self.pointer_size
        }
        fn get_pc_range(&self) -> DWARFRange {
            self.pc_range
        }
        fn get_die_container(&self) -> Option<&dyn DIEContainer> {
            Some(&self.die_container)
        }
    }

    fn cu(pointer_size: i8, pc_range_from: u64) -> MockCompilationUnit {
        MockCompilationUnit {
            pointer_size,
            pc_range: DWARFRange::new(pc_range_from, pc_range_from + 1),
            die_container: MockDIEContainer,
        }
    }

    #[test]
    fn empty_constant_is_empty() {
        assert!(DWARFLocationList::EMPTY.is_empty());
        assert_eq!(DWARFLocationList::EMPTY.get_first_location(), None);
    }

    #[test]
    fn with_wildcard_range_contains_any_pc() {
        let list = DWARFLocationList::with_wildcard_range(vec![0x03]);
        assert!(!list.is_empty());
        let loc = list.get_first_location().unwrap();
        assert!(loc.is_wildcard());
        assert!(loc.contains(0));
        assert!(loc.contains(u64::MAX));
        assert_eq!(loc.get_expr(), &[0x03]);
    }

    /// A v4 location list: one real range [0x10,0x20) with a 2-byte expr, then the end-of-list
    /// terminator (beginning == ending == 0). Pointer size 8, so each address field is 8 bytes.
    #[test]
    fn read_v4_reads_single_range() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x10u64.to_le_bytes());
        bytes.extend_from_slice(&0x20u64.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes()); // expr length
        bytes.extend_from_slice(&[0x91, 0x00]); // expr bytes
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let mut reader = TestReader::new(bytes);
        let cu = cu(8, 0);
        let list = DWARFLocationList::read_v4(&mut reader, &cu).unwrap();

        assert!(!list.is_empty());
        let loc = list.get_first_location().unwrap();
        assert!(!loc.is_wildcard());
        assert_eq!(loc.get_range(), Some(DWARFRange::new(0x10, 0x20)));
        assert_eq!(loc.get_expr(), &[0x91, 0x00]);
        assert!(loc.contains(0x15));
        assert!(!loc.contains(0x25));
    }

    /// A v4 location list skips zero-length (beginning == ending) ranges, per
    /// `DWARFLocationList.readV4`'s "skip adding empty ranges" comment.
    #[test]
    fn read_v4_skips_empty_ranges() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x10u64.to_le_bytes());
        bytes.extend_from_slice(&0x10u64.to_le_bytes()); // beginning == ending: skipped
        bytes.extend_from_slice(&0u16.to_le_bytes()); // zero-length expr
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let mut reader = TestReader::new(bytes);
        let cu = cu(8, 0);
        let list = DWARFLocationList::read_v4(&mut reader, &cu).unwrap();
        assert!(list.is_empty());
    }

    /// A v5 `DW_LLE_offset_pair` entry: base address (from the CU's PC range) plus a start/end
    /// offset pair, encoded as ULEB128, followed by a ULEB128-length-prefixed expr.
    #[test]
    fn read_v5_reads_offset_pair() {
        let mut bytes = Vec::new();
        bytes.push(DWARFLocationListEntry::OffsetPair.value() as u8);
        bytes.push(0x10); // start offset (ULEB128, fits in one byte)
        bytes.push(0x20); // end offset
        bytes.push(0x01); // expr length
        bytes.push(0x9c); // expr bytes (DW_OP_call_frame_cfa)
        bytes.push(DWARFLocationListEntry::EndOfList.value() as u8);

        let mut reader = TestReader::new(bytes);
        let cu = cu(8, 0x1000);
        let list = DWARFLocationList::read_v5(&mut reader, &cu).unwrap();

        assert!(!list.is_empty());
        let loc = list.get_first_location().unwrap();
        assert_eq!(loc.get_range(), Some(DWARFRange::new(0x1010, 0x1020)));
        assert_eq!(loc.get_expr(), &[0x9c]);
    }

    /// A v5 `DW_LLE_startx_length` entry resolves its start address through the compilation
    /// unit's `DIEContainer` (mocked here to map index N to 0x1000 + N*0x10).
    #[test]
    fn read_v5_reads_startx_length_via_die_container() {
        let mut bytes = Vec::new();
        bytes.push(DWARFLocationListEntry::StartxLength.value() as u8);
        bytes.push(0x02); // address-table index (ULEB128)
        bytes.push(0x08); // length (ULEB128)
        bytes.push(0x01); // expr length
        bytes.push(0x50); // expr bytes
        bytes.push(DWARFLocationListEntry::EndOfList.value() as u8);

        let mut reader = TestReader::new(bytes);
        let cu = cu(8, 0);
        let list = DWARFLocationList::read_v5(&mut reader, &cu).unwrap();

        let loc = list.get_first_location().unwrap();
        // index 2 -> 0x1000 + 2*0x10 == 0x1020
        assert_eq!(loc.get_range(), Some(DWARFRange::new(0x1020, 0x1028)));
    }

    /// A v5 `DW_LLE_default_location` entry (no address range, valid whenever nothing else
    /// matches) produces a non-wildcard location with `DWARFRange::EMPTY`, matching Java's
    /// `new DWARFLocation(DWARFRange.EMPTY, expr)`.
    #[test]
    fn read_v5_default_location_uses_empty_range() {
        let mut bytes = Vec::new();
        bytes.push(DWARFLocationListEntry::DefaultLocation.value() as u8);
        bytes.push(0x01); // expr length
        bytes.push(0x9f); // expr bytes
        bytes.push(DWARFLocationListEntry::EndOfList.value() as u8);

        let mut reader = TestReader::new(bytes);
        let cu = cu(8, 0);
        let list = DWARFLocationList::read_v5(&mut reader, &cu).unwrap();

        let loc = list.get_first_location().unwrap();
        assert!(!loc.is_wildcard());
        assert_eq!(loc.get_range(), Some(DWARFRange::EMPTY));
    }

    #[test]
    fn read_v5_rejects_unsupported_entry_type() {
        let bytes = vec![0xff];
        let mut reader = TestReader::new(bytes);
        let cu = cu(8, 0);
        let err = DWARFLocationList::read_v5(&mut reader, &cu).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Unsupported DWARF Location List Entry type"));
    }

    #[test]
    fn get_location_containing_finds_matching_range() {
        let list = DWARFLocationList::new(vec![
            DWARFLocation::from_bounds(0x10, 0x20, vec![1]),
            DWARFLocation::from_bounds(0x20, 0x30, vec![2]),
        ]);
        assert_eq!(list.get_location_containing(0x25).unwrap().get_expr(), &[2]);
        assert!(list.get_location_containing(0x35).is_none());
    }

    #[test]
    fn display_matches_java_format() {
        let list = DWARFLocationList::new(vec![DWARFLocation::from_bounds(0x10, 0x20, vec![1])]);
        assert_eq!(
            list.to_string(),
            "DWARFLocationList: [DWARFLocation: range: [10,20), expr: [1]]"
        );
    }
}
