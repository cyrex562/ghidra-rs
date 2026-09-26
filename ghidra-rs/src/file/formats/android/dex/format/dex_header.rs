//! Port of `ghidra.file.formats.android.dex.format.DexHeader`.
//!
//! The Java class is a concrete `class DexHeader implements StructConverter` that nothing
//! extends, so per this crate's shape rules it ports to a `struct` + `impl`, not a trait.
//!
//! # Promotion
//!
//! A minimal placeholder for `DexHeader` already existed at (the now-deleted)
//! `crate::file::seam_stubs::DexHeader`, used opaquely (as a `&DexHeader` parameter, never read)
//! by [`StringIDItem::new`](super::string_id_item::StringIDItem::new),
//! [`PrototypesIDItem::new`](super::prototypes_id_item::PrototypesIDItem::new),
//! [`ClassDefItem::new`](super::class_def_item::ClassDefItem::new), and
//! `FieldAnnotationsItem::new`. This is the real replacement; every one of those has been updated
//! to import this type instead, and `DexUtil`'s (still-placeholder) methods that took `&DexHeader`
//! now take a reference to this real type.
//!
//! # What is and isn't ported
//!
//! The header fields themselves, `checkMagic`, `isDataOffsetRelative`, and `toDataType()` are
//! fully faithful ports. `parse(BinaryReader)` populates `strings`/`prototypes`/`classDefs` for
//! real (via the already-real [`StringIDItem`], [`PrototypesIDItem`], [`ClassDefItem`] -- each
//! `reader.setPointerIndex`-repositioned independently from an absolute offset stored in the
//! header, so skipping any one loop does not affect the others). It does **not** populate
//! `mapList`/`types`/`fields`/`methods`, and `getMethodAddress`/`getDataType` (which need a real
//! `Program`/`DataTypeManager` plus `TypeIDItem` lookups) are not ported: `MapList`, `TypeIDItem`,
//! `FieldIDItem`, and `MethodIDItem` are all still `TODO` in `PORT_MANIFEST.tsv`, and nothing in
//! this crate currently calls any of the omitted surface (confirmed by grepping every caller of
//! the placeholder this replaces), so nothing that previously compiled is broken by the omission.
//! The nested `AddressCache`/`DataTypeCache` (`FixedSizeHashMap` specializations backing those two
//! methods) are omitted for the same reason.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::class_def_item::ClassDefItem;
use crate::file::formats::android::dex::format::dex_constants::DexConstants;
use crate::file::formats::android::dex::format::prototypes_id_item::PrototypesIDItem;
use crate::file::formats::android::dex::format::string_id_item::StringIDItem;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;
use std::sync::Arc;

/// Minimal stand-in for `ghidra.app.util.bin.StructConverter.UTF8`
/// (`StringUTF8DataType.dataType`), used with an explicit override length for the combined
/// `magic`+`version` header field. See
/// [`crate::format::elf::info::elf_note`]'s `DWordPlaceholderDataType` for the identical situation
/// with a different leaf type.
struct Utf8PlaceholderDataType;

impl DataType for Utf8PlaceholderDataType {
    fn get_name(&self) -> String {
        "utf8".to_string()
    }
    fn get_length(&self) -> i32 {
        -1
    }
}

/// Minimal stand-in for `ghidra.app.util.bin.StructConverter.DWORD` (`DWordDataType.dataType`).
struct DWordPlaceholderDataType;

impl DataType for DWordPlaceholderDataType {
    fn get_name(&self) -> String {
        "dword".to_string()
    }
    fn get_length(&self) -> i32 {
        4
    }
}

/// Minimal stand-in for `new ArrayDataType(BYTE, 20, BYTE.getLength())`, used for the `signature`
/// field.
struct ByteArrayPlaceholderDataType {
    length: i32,
}

impl DataType for ByteArrayPlaceholderDataType {
    fn get_name(&self) -> String {
        format!("byte[{}]", self.length.max(0))
    }
    fn get_length(&self) -> i32 {
        self.length
    }
}

/// Represents the `header_item` of a DEX file.
///
/// Port of `ghidra.file.formats.android.dex.format.DexHeader`. See the module docs for the
/// promotion this replaces and what is/isn't ported.
///
/// See: <https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file.h#91>
pub struct DexHeader {
    magic: Vec<u8>,
    version: Vec<u8>,
    checksum: i32,
    signature: Vec<u8>,
    file_size: i32,
    header_size: i32,
    endian_tag: i32,
    link_size: i32,
    link_offset: i32,
    map_offset: i32,
    string_ids_size: i32,
    string_ids_offset: i32,
    type_ids_size: i32,
    type_ids_offset: i32,
    proto_ids_size: i32,
    proto_ids_offset: i32,
    field_ids_size: i32,
    field_ids_offset: i32,
    method_ids_size: i32,
    method_ids_offset: i32,
    class_defs_ids_size: i32,
    class_defs_ids_offset: i32,
    data_size: i32,
    data_offset: i32,

    strings: Vec<StringIDItem>,
    prototypes: Vec<PrototypesIDItem>,
    class_defs: Vec<ClassDefItem>,

    parsed: bool,
}

impl DexHeader {
    /// Port of `DexHeader(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Self::new_with_magic_check(reader, Self::check_magic)
    }

    /// Same as [`new`](Self::new), but with a caller-supplied magic-check strategy.
    ///
    /// Java's constructor calls the (overridable) instance method `checkMagic()` before any
    /// subclass fields exist, so `CDexHeader`'s override runs in place of `DexHeader`'s own
    /// check when constructing a `CDexHeader`. Rust has no virtual dispatch into a
    /// not-yet-constructed subclass, so this hook is the equivalent seam: `CDexHeader::new`
    /// calls this with its own magic check instead of [`check_magic`](Self::check_magic).
    pub fn new_with_magic_check(
        reader: &mut dyn BinaryReader,
        check_magic: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<Self> {
        let magic = reader.read_next_byte_array(DexConstants::DEX_MAGIC_BASE.len())?;
        let version = reader.read_next_byte_array(DexConstants::DEX_VERSION_LENGTH as usize)?;

        check_magic(&magic)?;

        let checksum = reader.read_next_int()?;
        let signature = reader.read_next_byte_array(20)?;
        let file_size = reader.read_next_int()?;
        let header_size = reader.read_next_int()?;
        let endian_tag = reader.read_next_int()?;
        let link_size = reader.read_next_int()?;
        let link_offset = reader.read_next_int()?;
        let map_offset = reader.read_next_int()?;
        let string_ids_size = reader.read_next_int()?;
        let string_ids_offset = reader.read_next_int()?;
        let type_ids_size = reader.read_next_int()?;
        let type_ids_offset = reader.read_next_int()?;
        let proto_ids_size = reader.read_next_int()?;
        let proto_ids_offset = reader.read_next_int()?;
        let field_ids_size = reader.read_next_int()?;
        let field_ids_offset = reader.read_next_int()?;
        let method_ids_size = reader.read_next_int()?;
        let method_ids_offset = reader.read_next_int()?;
        let class_defs_ids_size = reader.read_next_int()?;
        let class_defs_ids_offset = reader.read_next_int()?;
        let data_size = reader.read_next_int()?;
        let data_offset = reader.read_next_int()?;

        Ok(DexHeader {
            magic,
            version,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_offset,
            map_offset,
            string_ids_size,
            string_ids_offset,
            type_ids_size,
            type_ids_offset,
            proto_ids_size,
            proto_ids_offset,
            field_ids_size,
            field_ids_offset,
            method_ids_size,
            method_ids_offset,
            class_defs_ids_size,
            class_defs_ids_offset,
            data_size,
            data_offset,
            strings: Vec::new(),
            prototypes: Vec::new(),
            class_defs: Vec::new(),
            parsed: false,
        })
    }

    /// Port of `DexHeader.checkMagic()`.
    fn check_magic(magic: &[u8]) -> io::Result<()> {
        if String::from_utf8_lossy(magic) != DexConstants::DEX_MAGIC_BASE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a dex file."));
        }
        Ok(())
    }

    /// Port of `DexHeader.parse(BinaryReader)`. See the module docs for what is and isn't
    /// populated.
    pub fn parse(&mut self, reader: &mut dyn BinaryReader) -> io::Result<()> {
        if self.parsed {
            return Ok(());
        }
        self.parsed = true;

        reader.set_pointer_index(self.string_ids_offset as u64);
        let mut strings = Vec::with_capacity(self.string_ids_size.max(0) as usize);
        for _ in 0..self.string_ids_size {
            strings.push(StringIDItem::new(reader, self)?);
        }
        self.strings = strings;

        reader.set_pointer_index(self.proto_ids_offset as u64);
        let mut prototypes = Vec::with_capacity(self.proto_ids_size.max(0) as usize);
        for _ in 0..self.proto_ids_size {
            prototypes.push(PrototypesIDItem::new(reader, self)?);
        }
        self.prototypes = prototypes;

        if reader.is_valid_index(self.class_defs_ids_offset as u64) {
            reader.set_pointer_index(self.class_defs_ids_offset as u64);
            let mut class_defs = Vec::with_capacity(self.class_defs_ids_size.max(0) as usize);
            for _ in 0..self.class_defs_ids_size {
                class_defs.push(ClassDefItem::new(reader, self)?);
            }
            self.class_defs = class_defs;
        }

        Ok(())
    }

    /// Port of `DexHeader.isDataOffsetRelative()`.
    pub fn is_data_offset_relative(&self) -> bool {
        false
    }

    /// Port of `DexHeader.getMagic()`.
    pub fn get_magic(&self) -> &[u8] {
        &self.magic
    }
    /// Port of `DexHeader.getVersion()`.
    pub fn get_version(&self) -> &[u8] {
        &self.version
    }
    /// Port of `DexHeader.getChecksum()`.
    pub fn get_checksum(&self) -> i32 {
        self.checksum
    }
    /// Port of `DexHeader.getSignature()`.
    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }
    /// Port of `DexHeader.getFileSize()`.
    pub fn get_file_size(&self) -> i32 {
        self.file_size
    }
    /// Port of `DexHeader.getHeaderSize()`.
    pub fn get_header_size(&self) -> i32 {
        self.header_size
    }
    /// Port of `DexHeader.getEndianTag()`.
    pub fn get_endian_tag(&self) -> i32 {
        self.endian_tag
    }
    /// Port of `DexHeader.getStringIdsOffset()`.
    pub fn get_string_ids_offset(&self) -> i32 {
        self.string_ids_offset
    }
    /// Port of `DexHeader.getStringIdsSize()`.
    pub fn get_string_ids_size(&self) -> i32 {
        self.string_ids_size
    }
    /// Port of `DexHeader.getStrings()`.
    pub fn get_strings(&self) -> &[StringIDItem] {
        &self.strings
    }
    /// Port of `DexHeader.getClassDefsIdsOffset()`.
    pub fn get_class_defs_ids_offset(&self) -> i32 {
        self.class_defs_ids_offset
    }
    /// Port of `DexHeader.getClassDefsIdsSize()`.
    pub fn get_class_defs_ids_size(&self) -> i32 {
        self.class_defs_ids_size
    }
    /// Port of `DexHeader.getClassDefs()`.
    pub fn get_class_defs(&self) -> &[ClassDefItem] {
        &self.class_defs
    }
    /// Port of `DexHeader.getDataOffset()`.
    pub fn get_data_offset(&self) -> i32 {
        self.data_offset
    }
    /// Port of `DexHeader.getDataSize()`.
    pub fn get_data_size(&self) -> i32 {
        self.data_size
    }
    /// Port of `DexHeader.getFieldIdsOffset()`.
    pub fn get_field_ids_offset(&self) -> i32 {
        self.field_ids_offset
    }
    /// Port of `DexHeader.getFieldIdsSize()`.
    pub fn get_field_ids_size(&self) -> i32 {
        self.field_ids_size
    }
    /// Port of `DexHeader.getMethodIdsOffset()`.
    pub fn get_method_ids_offset(&self) -> i32 {
        self.method_ids_offset
    }
    /// Port of `DexHeader.getMethodIdsSize()`.
    pub fn get_method_ids_size(&self) -> i32 {
        self.method_ids_size
    }
    /// Port of `DexHeader.getTypeIdsOffset()`.
    pub fn get_type_ids_offset(&self) -> i32 {
        self.type_ids_offset
    }
    /// Port of `DexHeader.getTypeIdsSize()`.
    pub fn get_type_ids_size(&self) -> i32 {
        self.type_ids_size
    }
    /// Port of `DexHeader.getProtoIdsOffset()`.
    pub fn get_proto_ids_offset(&self) -> i32 {
        self.proto_ids_offset
    }
    /// Port of `DexHeader.getProtoIdsSize()`.
    pub fn get_proto_ids_size(&self) -> i32 {
        self.proto_ids_size
    }
    /// Port of `DexHeader.getPrototypes()`.
    pub fn get_prototypes(&self) -> &[PrototypesIDItem] {
        &self.prototypes
    }
    /// Port of `DexHeader.getLinkOffset()`.
    pub fn get_link_offset(&self) -> i32 {
        self.link_offset
    }
    /// Port of `DexHeader.getLinkSize()`.
    pub fn get_link_size(&self) -> i32 {
        self.link_size
    }
    /// Port of `DexHeader.getMapOffset()`.
    pub fn get_map_offset(&self) -> i32 {
        self.map_offset
    }

    /// Builds a minimal, valid `DexHeader` (correct magic/version, every offset/size zeroed) for
    /// use as a `&DexHeader` fixture by other DEX-format modules' tests -- mirroring what the
    /// deleted `crate::file::seam_stubs::DexHeader` unit-struct placeholder let them do trivially.
    /// `#[cfg(test)]` so it only exists in test builds, but `pub(crate)` so sibling test modules
    /// (not just this file's own) can use it.
    #[cfg(test)]
    pub(crate) fn minimal_for_tests() -> DexHeader {
        let mut bytes = Vec::new();
        bytes.extend(DexConstants::DEX_MAGIC_BASE.as_bytes()); // magic (4)
        bytes.extend([b'0', b'3', b'5', 0]); // version (4)
        bytes.extend(0i32.to_le_bytes()); // checksum
        bytes.extend([0u8; 20]); // signature
        for _ in 0..20 {
            bytes.extend(0i32.to_le_bytes()); // remaining 20 header ints (fileSize..dataOffset)
        }

        struct BytesReader {
            bytes: Vec<u8>,
            position: usize,
        }
        impl BinaryReader for BytesReader {
            fn length(&self) -> io::Result<u64> {
                Ok(self.bytes.len() as u64)
            }
            fn is_valid_index(&self, index: u64) -> bool {
                (index as usize) < self.bytes.len()
            }
            fn get_pointer_index(&self) -> u64 {
                self.position as u64
            }
            fn set_pointer_index(&mut self, index: u64) -> u64 {
                let old = self.position as u64;
                self.position = index as usize;
                old
            }
            fn is_little_endian(&self) -> bool {
                true
            }
            fn set_little_endian(&mut self, _is_little_endian: bool) {}
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
            fn get_byte_provider(&self) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::GByteStore>> {
                unimplemented!("not exercised by this fixture")
            }
            fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
                Box::new(BytesReader { bytes: self.bytes.clone(), position: new_index as usize })
            }
        }

        let mut reader = BytesReader { bytes, position: 0 };
        DexHeader::new(&mut reader).expect("fixture bytes are a valid minimal DexHeader")
    }
}

impl DexHeader {
    /// Builds the `header_item` structure backing [`StructConverter::to_data_type`], as a
    /// concrete [`StructureDataType`] rather than a boxed `dyn DataType`.
    ///
    /// Exposed `pub(crate)` so subtypes such as
    /// [`CDexHeader`](crate::file::formats::android::cdex::CDexHeader) can extend the same
    /// structure -- the Rust equivalent of `CDexHeader.toDataType()` calling
    /// `(Structure) super.toDataType()`.
    pub(crate) fn base_structure_data_type(&self) -> StructureDataType {
        let cp = CategoryPath::parse("/dex").expect("valid category path");
        let mut structure = StructureDataType::new(cp, "header_item", 0);

        structure.add(Arc::new(Utf8PlaceholderDataType), 8, Some("magic".to_string()), None);
        structure.add(Arc::new(DWordPlaceholderDataType), 4, Some("checksum".to_string()), Some("adler-32".to_string()));

        let comment = format!(
            "SHA1:{}",
            crate::util::seam_stubs::NumericUtilities::convert_bytes_to_string(&self.signature, "")
        );
        structure.add(
            Arc::new(ByteArrayPlaceholderDataType { length: 20 }),
            20,
            Some("signature".to_string()),
            Some(comment),
        );

        for (field_name, _) in [
            ("fileSize", ()),
            ("headerSize", ()),
            ("endianTag", ()),
            ("linkSize", ()),
            ("linkOffset", ()),
            ("mapOffset", ()),
            ("stringIdsSize", ()),
            ("stringIdsOffset", ()),
            ("typeIdsSize", ()),
            ("typeIdsOffset", ()),
            ("protoIdsSize", ()),
            ("protoIdsOffset", ()),
            ("fieldIdsSize", ()),
            ("fieldIdsOffset", ()),
            ("methodIdsSize", ()),
            ("methodIdsOffset", ()),
            ("classDefsIdsSize", ()),
            ("classDefsIdsOffset", ()),
            ("dataSize", ()),
            ("dataOffset", ()),
        ] {
            structure.add(Arc::new(DWordPlaceholderDataType), 4, Some(field_name.to_string()), None);
        }

        structure
    }
}

impl StructConverter for DexHeader {
    /// Port of `DexHeader.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.base_structure_data_type()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BytesReader {
        bytes: Vec<u8>,
        position: usize,
    }
    impl BinaryReader for BytesReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }
        fn get_pointer_index(&self) -> u64 {
            self.position as u64
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.position as u64;
            self.position = index as usize;
            old
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
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
        fn get_byte_provider(&self) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::GByteStore>> {
            unimplemented!("not exercised by these tests")
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(BytesReader { bytes: self.bytes.clone(), position: new_index as usize })
        }
    }

    /// Builds a full, valid minimal DEX header (108 bytes: 8-byte magic+version, then 25 more
    /// header ints/bytes), with `string_ids`/`proto_ids`/`class_defs_ids` sizes all zero so
    /// `parse()` has nothing to iterate -- matching real dex_file.h layout order.
    fn header_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(DexConstants::DEX_MAGIC_BASE.as_bytes()); // magic
        bytes.extend([b'0', b'3', b'5', 0]); // version
        bytes.extend(0xCAFEBABEu32.to_le_bytes()); // checksum
        bytes.extend((1..=20u8).collect::<Vec<u8>>()); // signature (distinguishable bytes)
        bytes.extend(100i32.to_le_bytes()); // fileSize
        bytes.extend(112i32.to_le_bytes()); // headerSize
        bytes.extend(0x12345678i32.to_le_bytes()); // endianTag
        bytes.extend(0i32.to_le_bytes()); // linkSize
        bytes.extend(0i32.to_le_bytes()); // linkOffset
        bytes.extend(0i32.to_le_bytes()); // mapOffset
        bytes.extend(0i32.to_le_bytes()); // stringIdsSize
        bytes.extend(0i32.to_le_bytes()); // stringIdsOffset
        bytes.extend(0i32.to_le_bytes()); // typeIdsSize
        bytes.extend(0i32.to_le_bytes()); // typeIdsOffset
        bytes.extend(0i32.to_le_bytes()); // protoIdsSize
        bytes.extend(0i32.to_le_bytes()); // protoIdsOffset
        bytes.extend(0i32.to_le_bytes()); // fieldIdsSize
        bytes.extend(0i32.to_le_bytes()); // fieldIdsOffset
        bytes.extend(0i32.to_le_bytes()); // methodIdsSize
        bytes.extend(0i32.to_le_bytes()); // methodIdsOffset
        bytes.extend(0i32.to_le_bytes()); // classDefsIdsSize
        bytes.extend(0i32.to_le_bytes()); // classDefsIdsOffset
        bytes.extend(0i32.to_le_bytes()); // dataSize
        bytes.extend(0i32.to_le_bytes()); // dataOffset
        bytes
    }

    #[test]
    fn decodes_header_fields() {
        let mut reader = BytesReader { bytes: header_bytes(), position: 0 };
        let header = DexHeader::new(&mut reader).unwrap();

        assert_eq!(header.get_magic(), DexConstants::DEX_MAGIC_BASE.as_bytes());
        assert_eq!(header.get_checksum(), 0xCAFEBABEu32 as i32);
        assert_eq!(header.get_signature(), (1..=20u8).collect::<Vec<u8>>().as_slice());
        assert_eq!(header.get_file_size(), 100);
        assert_eq!(header.get_header_size(), 112);
        assert_eq!(header.get_endian_tag(), 0x12345678);
        assert!(!header.is_data_offset_relative());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = header_bytes();
        bytes[0] = b'X'; // corrupt the magic
        let mut reader = BytesReader { bytes, position: 0 };
        assert!(DexHeader::new(&mut reader).is_err());
    }

    #[test]
    fn parse_is_idempotent_and_leaves_empty_lists_when_sizes_are_zero() {
        let bytes = header_bytes();
        let mut reader = BytesReader { bytes, position: 0 };
        let mut header = DexHeader::new(&mut reader).unwrap();

        header.parse(&mut reader).unwrap();
        assert!(header.get_strings().is_empty());
        assert!(header.get_prototypes().is_empty());
        assert!(header.get_class_defs().is_empty());

        // Second call should be a no-op (the `parsed` guard), not re-read/panic.
        header.parse(&mut reader).unwrap();
    }

    #[test]
    fn to_data_type_matches_java_structure_name_and_length() {
        let mut reader = BytesReader { bytes: header_bytes(), position: 0 };
        let header = DexHeader::new(&mut reader).unwrap();
        let dt = header.to_data_type().unwrap();

        assert_eq!(dt.get_name(), "header_item");
        // magic(8) + checksum(4) + signature(20) + 20 more DWORD fields(4 each) == 112.
        assert_eq!(dt.get_length(), 8 + 4 + 20 + 20 * 4);
    }

    #[test]
    fn minimal_for_tests_fixture_is_usable() {
        let header = DexHeader::minimal_for_tests();
        assert_eq!(header.get_string_ids_size(), 0);
        assert!(!header.is_data_offset_relative());
    }
}
