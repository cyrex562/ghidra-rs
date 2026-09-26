//! Port of `ghidra.app.util.bin.format.pe.resource.ResourceDirectory`.
//!
//! ```text
//! typedef struct _IMAGE_RESOURCE_DIRECTORY {
//!     DWORD   Characteristics;
//!     DWORD   TimeDateStamp;
//!     WORD    MajorVersion;
//!     WORD    MinorVersion;
//!     WORD    NumberOfNamedEntries;
//!     WORD    NumberOfIdEntries;
//! };
//! ```

use std::collections::HashSet;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::{NTHeader, ResourceDirectoryEntry};
use crate::program::model::data::data_type::DataType;
use crate::util::msg::Msg;

/// Port of `ResourceDirectory.NAME`.
pub const NAME: &str = "IMAGE_RESOURCE_DIRECTORY";

/// Port of `ResourceDirectory.SIZEOF`.
pub const SIZEOF: i32 = 16;

/// Mirrors `ResourceDataDirectory.IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY` (value `8`), duplicated
/// here because `ResourceDataDirectory` itself is not yet ported (see
/// [`ResourceDirectoryEntry`](crate::format::seam_stubs::ResourceDirectoryEntry)'s doc comment for
/// the wider mutual-recursion cycle `ResourceDirectory` cuts). Fold this into the real constant
/// once `ResourceDataDirectory` lands.
const IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY: i64 = 8;

/// Port of `ghidra.app.util.bin.format.pe.resource.ResourceDirectory`.
///
/// Ownership note: Java threads duplicate-directory detection through the static mutable field
/// `ResourceDataDirectory.directoryMap`, reset per top-level parse by that (unported) class's
/// constructor before it recurses into the root `ResourceDirectory`. This port takes that set as
/// an explicit `&mut HashSet<u64>` parameter instead of hidden global state -- callers that parse
/// a full resource tree should create one empty set per top-level parse, exactly as
/// `ResourceDataDirectory`'s constructor does in Java, and thread it through.
pub struct ResourceDirectory {
    characteristics: i32,
    time_data_stamp: i32,
    major_version: i16,
    minor_version: i16,
    number_of_named_entries: i16,
    number_of_id_entries: i16,
    entries: Vec<ResourceDirectoryEntry>,
}

impl ResourceDirectory {
    /// Port of `ResourceDirectory(BinaryReader, int, int, boolean, NTHeader)`.
    ///
    /// Java's constructor is defensive rather than exceptional: on any structural problem
    /// (invalid pointer, duplicate directory, too many entries, an invalid entry) it logs via
    /// `Msg.error` and returns early, leaving the object partially populated instead of throwing.
    /// This port mirrors that exactly -- it only returns `Err` for a genuine I/O failure from
    /// `reader`, never for the "this directory is malformed" case, which yields a
    /// `ResourceDirectory` with fewer (possibly zero) entries instead.
    pub fn new(
        reader: &dyn BinaryReader,
        mut index: u64,
        resource_base: u64,
        is_first_level: bool,
        nt_header: &dyn NTHeader,
        directory_map: &mut HashSet<u64>,
    ) -> io::Result<Self> {
        let mut dir = ResourceDirectory {
            characteristics: 0,
            time_data_stamp: 0,
            major_version: 0,
            minor_version: 0,
            number_of_named_entries: 0,
            number_of_id_entries: 0,
            entries: Vec::new(),
        };

        if !nt_header.check_pointer(index as i64) {
            Msg::error("ResourceDirectory", &format!("Invalid file index {index:x}"));
            return Ok(dir);
        }
        if directory_map.contains(&index) {
            Msg::error("ResourceDirectory", &format!("Duplicate ResourceDirectory at {index} ignored."));
            return Ok(dir);
        }
        directory_map.insert(index);

        dir.characteristics = reader.read_int(index)?;
        index += 4;
        dir.time_data_stamp = reader.read_int(index)?;
        index += 4;
        dir.major_version = reader.read_short(index)?;
        index += 2;
        dir.minor_version = reader.read_short(index)?;
        index += 2;
        dir.number_of_named_entries = reader.read_short(index)?;
        index += 2;
        dir.number_of_id_entries = reader.read_short(index)?;
        index += 2;

        let total_entries = dir.number_of_named_entries as i64 + dir.number_of_id_entries as i64;
        let rva = index as i64 + total_entries * IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY;
        let len = reader.length()? as i64;
        if !nt_header.check_rva(rva) || !(0..=len).contains(&rva) {
            Msg::error(
                "ResourceDirectory",
                &format!("Too many resource entries {total_entries:x}"),
            );
            dir.number_of_named_entries = 0;
            dir.number_of_id_entries = 0;
        }

        for _ in 0..dir.number_of_named_entries {
            if !nt_header.check_pointer(index as i64) {
                Msg::error("ResourceDirectory", &format!("Invalid file index {index:x}"));
                return Ok(dir);
            }
            let entry =
                ResourceDirectoryEntry::new(reader, index, resource_base, true, is_first_level, nt_header)?;
            if !entry.is_valid() {
                return Ok(dir);
            }
            dir.entries.push(entry);
            index += IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY as u64;
        }
        for _ in 0..dir.number_of_id_entries {
            if !nt_header.check_pointer(index as i64) {
                Msg::error("ResourceDirectory", &format!("Invalid file index {index:x}"));
                return Ok(dir);
            }
            let entry = ResourceDirectoryEntry::new(
                reader,
                index,
                resource_base,
                false,
                is_first_level,
                nt_header,
            )?;
            if !entry.is_valid() {
                return Ok(dir);
            }
            dir.entries.push(entry);
            index += IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY as u64;
        }

        Ok(dir)
    }

    /// Port of `ResourceDirectory.getEntries()`, which returns a defensive copy in Java.
    pub fn get_entries(&self) -> Vec<ResourceDirectoryEntry> {
        self.entries.clone()
    }

    /// Port of `ResourceDirectory.getCharacteristics()`.
    ///
    /// Theoretically this field could hold flags for the resource, but appears to always be 0.
    pub fn get_characteristics(&self) -> i32 {
        self.characteristics
    }

    /// Port of `ResourceDirectory.getTimeDataStamp()`.
    pub fn get_time_data_stamp(&self) -> i32 {
        self.time_data_stamp
    }

    /// Port of `ResourceDirectory.getNumberOfNamedEntries()`.
    pub fn get_number_of_named_entries(&self) -> i16 {
        self.number_of_named_entries
    }

    /// Port of `ResourceDirectory.getNumberOfIdEntries()`.
    pub fn get_number_of_id_entries(&self) -> i16 {
        self.number_of_id_entries
    }

    /// Port of `ResourceDirectory.getMajorVersion()`.
    ///
    /// Theoretically this field would hold a version number for the resource; appears to always
    /// be set to 0.
    pub fn get_major_version(&self) -> i16 {
        self.major_version
    }

    /// Port of `ResourceDirectory.getMinorVersion()`.
    pub fn get_minor_version(&self) -> i16 {
        self.minor_version
    }
}

impl StructConverter for ResourceDirectory {
    /// Port of `ResourceDirectory.toDataType()`.
    ///
    /// Java builds a `StructureDataType` of two `DWORD` and four `WORD` fields. Those builtin
    /// singleton datatypes (`ghidra.program.model.data.DWordDataType`/`WordDataType`) are not yet
    /// ported to a concrete, usable instance -- `StructConverter`'s own doc comment notes the same
    /// gap for its `DWORD`/`WORD` constants. Rather than fabricate placeholder field types, this
    /// reports the gap; replace with the real `StructureDataTypeImpl` construction once
    /// `DWordDataType`/`WordDataType` land.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "ResourceDirectory::to_data_type needs DWordDataType/WordDataType, not yet ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A tiny in-memory `BinaryReader` over a fixed byte buffer, little-endian, matching the
    /// on-disk layout `ResourceDirectory` reads.
    struct BufReader {
        bytes: Vec<u8>,
        pointer: RefCell<u64>,
        little_endian: RefCell<bool>,
    }

    impl BufReader {
        fn new(bytes: Vec<u8>) -> Self {
            BufReader { bytes, pointer: RefCell::new(0), little_endian: RefCell::new(true) }
        }
    }

    impl BinaryReader for BufReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn get_pointer_index(&self) -> u64 {
            *self.pointer.borrow()
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            *self.pointer.borrow_mut() = index;
            index
        }
        fn is_little_endian(&self) -> bool {
            *self.little_endian.borrow()
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            *self.little_endian.borrow_mut() = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::GByteStore>> {
            unimplemented!("not needed by ResourceDirectory tests")
        }
        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by ResourceDirectory tests")
        }
    }

    fn le_u16_bytes(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn le_u32_bytes(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// An `NTHeader` stand-in that accepts every pointer/RVA, mirroring an unrelocated,
    /// unbounded-image test fixture.
    struct PermissiveNtHeader;
    impl NTHeader for PermissiveNtHeader {
        fn get_name(&self) -> String {
            "NT Header".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> &crate::format::pe::file_header::FileHeader {
            unimplemented!()
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
            unimplemented!()
        }
        fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, _rva: i64) -> bool {
            true
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    /// Builds the 16-byte `IMAGE_RESOURCE_DIRECTORY` header followed by `named + id`
    /// `IMAGE_RESOURCE_DIRECTORY_ENTRY` records (8 bytes each: a name/ID DWORD, then an
    /// offset-to-data DWORD whose top bit is clear, i.e. "data", not "directory").
    fn directory_bytes(
        characteristics: u32,
        time_date_stamp: u32,
        major: u16,
        minor: u16,
        named: u16,
        ids: u16,
        entry_name_or_ids: &[u32],
        entry_offsets: &[u32],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&le_u32_bytes(characteristics));
        out.extend_from_slice(&le_u32_bytes(time_date_stamp));
        out.extend_from_slice(&le_u16_bytes(major));
        out.extend_from_slice(&le_u16_bytes(minor));
        out.extend_from_slice(&le_u16_bytes(named));
        out.extend_from_slice(&le_u16_bytes(ids));
        for i in 0..(named as usize + ids as usize) {
            out.extend_from_slice(&le_u32_bytes(entry_name_or_ids[i]));
            out.extend_from_slice(&le_u32_bytes(entry_offsets[i]));
        }
        out
    }

    #[test]
    fn parses_header_fields_and_entries_like_java_constructor() {
        // Two ID entries (ids 5 and 7), both pointing at plain data (top bit clear).
        let bytes = directory_bytes(0, 0xDEADBEEF, 0, 0, 0, 2, &[5, 7], &[0x100, 0x200]);
        let reader = BufReader::new(bytes);
        let nt = PermissiveNtHeader;
        let mut seen = HashSet::new();

        let dir = ResourceDirectory::new(&reader, 0, 0, true, &nt, &mut seen).unwrap();

        assert_eq!(dir.get_characteristics(), 0);
        assert_eq!(dir.get_time_data_stamp(), 0xDEADBEEFu32 as i32);
        assert_eq!(dir.get_major_version(), 0);
        assert_eq!(dir.get_minor_version(), 0);
        assert_eq!(dir.get_number_of_named_entries(), 0);
        assert_eq!(dir.get_number_of_id_entries(), 2);

        let entries = dir.get_entries();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.is_valid()));
    }

    #[test]
    fn duplicate_directory_index_is_ignored_like_java() {
        let bytes = directory_bytes(0, 0, 0, 0, 0, 0, &[], &[]);
        let reader = BufReader::new(bytes);
        let nt = PermissiveNtHeader;
        let mut seen = HashSet::new();
        seen.insert(0u64);

        // Java: `ResourceDataDirectory.directoryMap.contains(index)` -> Msg.error + early return,
        // leaving all fields at their default (0) and no entries.
        let dir = ResourceDirectory::new(&reader, 0, 0, true, &nt, &mut seen).unwrap();
        assert_eq!(dir.get_number_of_id_entries(), 0);
        assert!(dir.get_entries().is_empty());
    }

    #[test]
    fn invalid_pointer_yields_empty_directory_without_error() {
        struct RejectAllNtHeader;
        impl NTHeader for RejectAllNtHeader {
            fn get_name(&self) -> String {
                "NT Header".to_string()
            }
            fn is_rva_resoltion_section_aligned(&self) -> bool {
                true
            }
            fn get_file_header(&self) -> &crate::format::pe::file_header::FileHeader {
                unimplemented!()
            }
            fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
                unimplemented!()
            }
            fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
                unimplemented!()
            }
            fn rva_to_pointer(&self, rva: i32) -> i32 {
                rva
            }
            fn rva_to_pointer_long(&self, rva: i64) -> i64 {
                rva
            }
            fn check_pointer(&self, _ptr: i64) -> bool {
                false
            }
            fn check_rva(&self, _rva: i64) -> bool {
                false
            }
            fn va_to_pointer(&self, va: i32) -> i32 {
                va
            }
        }

        let bytes = directory_bytes(0, 0, 0, 0, 0, 0, &[], &[]);
        let reader = BufReader::new(bytes);
        let nt = RejectAllNtHeader;
        let mut seen = HashSet::new();

        let dir = ResourceDirectory::new(&reader, 0, 0, true, &nt, &mut seen).unwrap();
        assert_eq!(dir.get_characteristics(), 0);
        assert!(dir.get_entries().is_empty());
        // The invalid-pointer index must never be marked "seen" -- Java returns before touching
        // `directoryMap` when `checkPointer` fails.
        assert!(seen.is_empty());
    }

    #[test]
    fn to_data_type_reports_missing_dword_word_singletons() {
        let bytes = directory_bytes(0, 0, 0, 0, 0, 0, &[], &[]);
        let reader = BufReader::new(bytes);
        let nt = PermissiveNtHeader;
        let mut seen = HashSet::new();
        let dir = ResourceDirectory::new(&reader, 0, 0, true, &nt, &mut seen).unwrap();

        assert!(dir.to_data_type().is_err());
    }
}
