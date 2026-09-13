use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::resource_string_table::ResourceStringTable;
use crate::format::seam_stubs::Resource;

/// One entry of a [`ResourceType`]'s resource list.
///
/// Mirrors the Java constructor's polymorphic dispatch: `ResourceType`'s Java constructor stores
/// a `Resource[]`, but pushes either a plain `Resource` or, for `RT_STRING`-typed entries, a
/// `ResourceStringTable` (`ResourceStringTable extends Resource`). Rust has no class hierarchy,
/// so -- consistent with this crate's "composition over inheritance" convention -- the two shapes
/// are represented explicitly as enum variants rather than upcast to a common base type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceTypeEntry {
    /// A generic resource record.
    Resource(Resource),
    /// An `RT_STRING`-typed resource: a table of strings rather than a single opaque blob.
    StringTable(ResourceStringTable),
}

impl ResourceTypeEntry {
    /// Returns the common `Resource` header fields, regardless of which variant this is.
    /// Mirrors reading the inherited `Resource` fields/methods off of a `ResourceStringTable`
    /// instance in Java.
    pub fn resource(&self) -> &Resource {
        match self {
            ResourceTypeEntry::Resource(r) => r,
            ResourceTypeEntry::StringTable(st) => st.base(),
        }
    }

    /// Returns the [`ResourceStringTable`], if this entry is `RT_STRING`-typed.
    pub fn as_string_table(&self) -> Option<&ResourceStringTable> {
        match self {
            ResourceTypeEntry::StringTable(st) => Some(st),
            ResourceTypeEntry::Resource(_) => None,
        }
    }
}

/// An implementation of the TTYPEINFO structure.
///
/// Mirrors `ResourceType` from the original Ghidra Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceType {
    type_id: i16,
    count: i16,
    reserved: i32,
    resources: Vec<ResourceTypeEntry>,
}

impl ResourceType {
    // 0x00 is not defined...?
    /// Constant indicating cursor resource type.
    pub const RT_CURSOR: i16 = 0x01;
    /// Constant indicating bitmap resource type.
    pub const RT_BITMAP: i16 = 0x02;
    /// Constant indicating icon resource type.
    pub const RT_ICON: i16 = 0x03;
    /// Constant indicating menu resource type.
    pub const RT_MENU: i16 = 0x04;
    /// Constant indicating dialog resource type.
    pub const RT_DIALOG: i16 = 0x05;
    /// Constant indicating string resource type.
    pub const RT_STRING: i16 = 0x06;
    /// Constant indicating font directory resource type.
    pub const RT_FONTDIR: i16 = 0x07;
    /// Constant indicating font resource type.
    pub const RT_FONT: i16 = 0x08;
    /// Constant indicating an accelerator resource type.
    pub const RT_ACCELERATOR: i16 = 0x09;
    /// Constant indicating RC data resource type.
    pub const RT_RCDATA: i16 = 0x0a;
    /// Constant indicating message table resource type.
    pub const RT_MESSAGETABLE: i16 = 0x0b;
    /// Constant indicating cursor group resource type.
    pub const RT_GROUP_CURSOR: i16 = 0x0c;
    // 0x0d is not defined...?
    /// Constant indicating icon group resource type.
    pub const RT_GROUP_ICON: i16 = 0x0e;
    // 0x0f is not defined...?
    /// Constant indicating version resource type.
    ///
    /// Note: Java declares this constant as a `byte` (`RT_VERSION = 0x10`), unlike every other
    /// constant on this class which is a `short`. That has no observable effect since `0x10`
    /// widens identically either way, so it is kept as `i16` here for uniformity with its
    /// siblings.
    pub const RT_VERSION: i16 = 0x10;

    /// Constructs a new resource type.
    ///
    /// # Arguments
    /// * `reader` - the binary reader
    /// * `alignment_shift_count` - the owning [`ResourceTable`](super::resource_table::ResourceTable)'s
    ///   alignment shift count, forwarded on to each [`Resource`]/[`ResourceStringTable`] this
    ///   constructs (see those types' docs for why the shift count is threaded through directly
    ///   instead of a back-reference to the owning table).
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader, alignment_shift_count: i16) -> io::Result<Self> {
        let type_id = reader.read_next_short()?;
        if type_id == 0 {
            // not a valid resource type...
            return Ok(ResourceType { type_id, count: 0, reserved: 0, resources: Vec::new() });
        }

        let count = reader.read_next_short()?;
        let reserved = reader.read_next_int()?;

        let mut resources = Vec::new();

        let count_int = (count as u16) as usize;
        for _ in 0..count_int {
            let entry = if (type_id & 0x7fff) == Self::RT_STRING {
                ResourceTypeEntry::StringTable(ResourceStringTable::new(
                    reader,
                    alignment_shift_count,
                )?)
            } else {
                ResourceTypeEntry::Resource(Resource::new(reader, alignment_shift_count)?)
            };
            resources.push(entry);
        }

        Ok(ResourceType { type_id, count, reserved, resources })
    }

    /// Returns the resource type ID.
    pub fn get_type_id(&self) -> i16 {
        self.type_id
    }

    /// Returns the number of resources of this type.
    pub fn get_count(&self) -> i16 {
        self.count
    }

    /// Returns the reserved value (purpose is unknown).
    pub fn get_reserved(&self) -> i32 {
        self.reserved
    }

    /// Returns the array of resources of this type.
    pub fn get_resources(&self) -> &[ResourceTypeEntry] {
        &self.resources
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if (self.type_id & 0x8000u16 as i16) == 0 {
            return write!(f, "UnknownResourceType_{}", self.type_id);
        }
        let idx = self.type_id & 0x7fff;
        let name = match idx {
            Self::RT_CURSOR => "Cursor",
            Self::RT_BITMAP => "Bitmap",
            Self::RT_ICON => "Icon",
            Self::RT_MENU => "Menu",
            Self::RT_DIALOG => "Dialog Box",
            Self::RT_STRING => "String Table",
            Self::RT_FONTDIR => "Font Directory",
            Self::RT_FONT => "Font",
            Self::RT_ACCELERATOR => "Accelerator Table",
            Self::RT_RCDATA => "Resource Data",
            Self::RT_MESSAGETABLE => "Message Table",
            Self::RT_GROUP_CURSOR => "Cursor Directory",
            Self::RT_GROUP_ICON => "Icon Directory",
            Self::RT_VERSION => "Version Information",
            _ => return write!(f, "Unknown_{}", idx),
        };
        f.write_str(name)
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
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    /// Minimal `BinaryReader` implementation backed by an in-memory byte vector, for testing.
    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        current_index: u64,
        little_endian: bool,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                current_index: 0,
                little_endian: true,
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
                current_index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    fn resource_bytes(file_offset: u16, file_length: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&file_offset.to_le_bytes()); // fileOffset
        v.extend_from_slice(&file_length.to_le_bytes()); // fileLength
        v.extend_from_slice(&0x0020u16.to_le_bytes()); // flagword
        v.extend_from_slice(&0x0001u16.to_le_bytes()); // resourceID
        v.extend_from_slice(&0x0000u16.to_le_bytes()); // handle
        v.extend_from_slice(&0x0000u16.to_le_bytes()); // usage
        v
    }

    #[test]
    fn type_id_zero_is_treated_as_invalid_sentinel() {
        // Java: `if (typeID == 0) { return; }` -- count/reserved/resources are left at their
        // Java default zero values (no resources array is even allocated). This port represents
        // that as zeroed fields and an empty resource list.
        let data = vec![0x00, 0x00];
        let mut reader = MockReader::new(data);

        let rt = ResourceType::new(&mut reader, 0).unwrap();

        assert_eq!(rt.get_type_id(), 0);
        assert_eq!(rt.get_count(), 0);
        assert_eq!(rt.get_reserved(), 0);
        assert!(rt.get_resources().is_empty());
        // Only 2 bytes (the type id) were consumed -- count/reserved are never read.
        assert_eq!(reader.get_pointer_index(), 2);
    }

    #[test]
    fn reads_generic_resource_type_with_plain_resources() {
        let mut data = Vec::new();
        data.extend_from_slice(&(ResourceType::RT_BITMAP | 0x8000u16 as i16).to_le_bytes()); // typeID
        data.extend_from_slice(&2i16.to_le_bytes()); // count
        data.extend_from_slice(&0i32.to_le_bytes()); // reserved
        data.extend_from_slice(&resource_bytes(0x10, 0x20));
        data.extend_from_slice(&resource_bytes(0x30, 0x40));

        let mut reader = MockReader::new(data);
        let rt = ResourceType::new(&mut reader, 0).unwrap();

        assert_eq!(rt.get_type_id(), ResourceType::RT_BITMAP | 0x8000u16 as i16);
        assert_eq!(rt.get_count(), 2);
        assert_eq!(rt.get_reserved(), 0);

        let resources = rt.get_resources();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].resource().get_file_offset(), 0x10);
        assert_eq!(resources[1].resource().get_file_offset(), 0x30);
        assert!(resources[0].as_string_table().is_none());
    }

    #[test]
    fn to_string_maps_known_type_ids() {
        let mut data = Vec::new();
        data.extend_from_slice(&(ResourceType::RT_ICON | 0x8000u16 as i16).to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes()); // count = 0
        data.extend_from_slice(&0i32.to_le_bytes()); // reserved

        let mut reader = MockReader::new(data);
        let rt = ResourceType::new(&mut reader, 0).unwrap();

        assert_eq!(rt.to_string(), "Icon");
        assert!(rt.get_resources().is_empty());
    }

    #[test]
    fn to_string_reports_unknown_high_bit_unset() {
        // High bit (0x8000) unset: Java's toString returns "UnknownResourceType_<id>" without
        // ever consulting the switch table.
        let mut data = Vec::new();
        data.extend_from_slice(&0x0006i16.to_le_bytes()); // typeID, high bit unset
        data.extend_from_slice(&0i16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());

        let mut reader = MockReader::new(data);
        let rt = ResourceType::new(&mut reader, 0).unwrap();

        assert_eq!(rt.to_string(), "UnknownResourceType_6");
    }

    #[test]
    fn to_string_reports_unknown_for_unmapped_low_bits() {
        // High bit set but low 15 bits (0x50) map to no known RT_* constant.
        let mut data = Vec::new();
        data.extend_from_slice(&(0x8050u16 as i16).to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());

        let mut reader = MockReader::new(data);
        let rt = ResourceType::new(&mut reader, 0).unwrap();

        assert_eq!(rt.to_string(), "Unknown_80");
    }

    #[test]
    fn rt_string_type_id_produces_resource_string_table_entries() {
        // alignment_shift_count = 0 keeps file offsets untranslated, so the string bytes can sit
        // immediately after the fixed-size headers in this small synthetic buffer.
        let alignment_shift_count = 0i16;

        // Layout: [typeID][count=1][reserved][Resource header][string table bytes]
        let string_table_offset: u16 = 2 + 2 + 4 + 12; // right after the one Resource header
        let mut string_bytes = Vec::new();
        string_bytes.push(3u8); // length=3
        string_bytes.extend_from_slice(b"abc");
        string_bytes.push(0u8); // sentinel length=0 terminates the LengthStringSet scan
        let string_table_length = string_bytes.len() as u16;

        let mut data = Vec::new();
        data.extend_from_slice(&(ResourceType::RT_STRING | 0x8000u16 as i16).to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes()); // count = 1
        data.extend_from_slice(&0i32.to_le_bytes()); // reserved
        data.extend_from_slice(&resource_bytes(string_table_offset, string_table_length));
        data.extend_from_slice(&string_bytes);

        let mut reader = MockReader::new(data);
        let rt = ResourceType::new(&mut reader, alignment_shift_count).unwrap();

        assert_eq!(rt.get_resources().len(), 1);
        let string_table = rt.get_resources()[0]
            .as_string_table()
            .expect("RT_STRING entries must be parsed as ResourceStringTable");
        assert_eq!(string_table.get_strings().len(), 1);
        assert_eq!(string_table.get_strings()[0].name(), Some("abc"));

        // The main reader cursor must land right after the fixed 12-byte Resource header (not
        // wherever the string-table scan left it), exactly as a plain `Resource` would, so that
        // `ResourceTable`'s sequential loop over the remaining resources of this type stays
        // aligned.
        assert_eq!(reader.get_pointer_index(), 2 + 2 + 4 + 12);
    }

    #[test]
    fn count_is_treated_as_unsigned_when_large() {
        // A negative Java `short` count (top bit set) still means "many resources" -- Java reads
        // `Short.toUnsignedInt(count)` iterations. Exercise a small-but-negative count instead of
        // 32768+ entries to keep the test fast.
        let mut data = Vec::new();
        data.extend_from_slice(&(ResourceType::RT_RCDATA | 0x8000u16 as i16).to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes()); // count = 1 (kept small for the test)
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&resource_bytes(0x1, 0x2));

        let mut reader = MockReader::new(data);
        let rt = ResourceType::new(&mut reader, 0).unwrap();
        assert_eq!(rt.get_resources().len(), 1);
    }

    #[test]
    fn propagates_io_error_on_truncated_resource() {
        let mut data = Vec::new();
        data.extend_from_slice(&(ResourceType::RT_BITMAP | 0x8000u16 as i16).to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes()); // count = 1
        data.extend_from_slice(&0i32.to_le_bytes());
        // Truncated: only 4 of the 12 required Resource header bytes present.
        data.extend_from_slice(&[0u8; 4]);

        let mut reader = MockReader::new(data);
        let err = ResourceType::new(&mut reader, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
