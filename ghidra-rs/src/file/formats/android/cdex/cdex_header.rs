//! Port of `ghidra.file.formats.android.cdex.CDexHeader`.
//!
//! The Java class is a concrete `class CDexHeader extends DexHeader` that nothing further
//! extends, so per this crate's shape rules it ports to a `struct` + `impl`, not a trait.
//!
//! Rust has no inheritance, so the Java `extends DexHeader` relationship becomes composition: a
//! `base: DexHeader` field plus the extra CDEX-only fields. The one wrinkle is that Java's
//! `DexHeader` constructor calls the (overridable) instance method `checkMagic()` -- for a
//! `CDexHeader`, that dynamically dispatches to `CDexHeader.checkMagic()`, which checks the CDEX
//! magic (`"cdex"`) instead of the plain-DEX magic. Rust cannot express a virtual call into a
//! not-yet-constructed subclass, so [`DexHeader::new_with_magic_check`] takes the check as a
//! parameter instead; this type supplies its own.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::cdex::cdex_constants::CDexConstants;
use crate::file::formats::android::dex::format::dex_header::DexHeader;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;

/// Minimal stand-in for `ghidra.app.util.bin.StructConverter.DWORD` (`DWordDataType.dataType`).
/// Mirrors the identical placeholder in `dex_header.rs`; kept local rather than shared since
/// neither is part of that module's public surface.
struct DWordPlaceholderDataType;

impl DataType for DWordPlaceholderDataType {
    fn get_name(&self) -> String {
        "dword".to_string()
    }
    fn get_length(&self) -> i32 {
        4
    }
}

/// CDEX header: extends the DEX header with additional compact-dex-only members.
///
/// Port of `ghidra.file.formats.android.cdex.CDexHeader`.
///
/// Mirrors `class Header : public DexFile::Header` in
/// <https://android.googlesource.com/platform/art/+/master/libdexfile/dex/compact_dex_file.h>.
pub struct CDexHeader {
    base: DexHeader,
    feature_flags: i32,
    debug_info_offsets_pos: i32,
    debug_info_offsets_table_offset: i32,
    debug_info_base: i32,
    owned_data_begin: i32,
    owned_data_end: i32,
}

impl CDexHeader {
    /// Port of `CDexHeader(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let base = DexHeader::new_with_magic_check(reader, Self::check_magic)?;

        let feature_flags = reader.read_next_int()?;
        let debug_info_offsets_pos = reader.read_next_int()?;
        let debug_info_offsets_table_offset = reader.read_next_int()?;
        let debug_info_base = reader.read_next_int()?;
        let owned_data_begin = reader.read_next_int()?;
        let owned_data_end = reader.read_next_int()?;

        Ok(CDexHeader {
            base,
            feature_flags,
            debug_info_offsets_pos,
            debug_info_offsets_table_offset,
            debug_info_base,
            owned_data_begin,
            owned_data_end,
        })
    }

    /// Port of `CDexHeader.checkMagic()` (overrides `DexHeader.checkMagic()`).
    fn check_magic(magic: &[u8]) -> io::Result<()> {
        if String::from_utf8_lossy(magic) != CDexConstants::MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a cdex file."));
        }
        Ok(())
    }

    /// Access to the composed `DexHeader` base, for callers that need the inherited fields
    /// (`getMagic`, `getStringIdsOffset`, ...).
    pub fn base(&self) -> &DexHeader {
        &self.base
    }

    /// Port of `CDexHeader.getFeatureFlags()`.
    pub fn get_feature_flags(&self) -> i32 {
        self.feature_flags
    }

    /// Position in the compact dex file for the debug info table data starts.
    ///
    /// Port of `CDexHeader.getDebugInfoOffsetsPos()`.
    pub fn get_debug_info_offsets_pos(&self) -> i32 {
        self.debug_info_offsets_pos
    }

    /// Offset into the debug info table data where the lookup table exists.
    ///
    /// Port of `CDexHeader.getDebugInfoOffsetsTableOffset()`.
    pub fn get_debug_info_offsets_table_offset(&self) -> i32 {
        self.debug_info_offsets_table_offset
    }

    /// Base offset of where debug info starts in the dex file.
    ///
    /// Port of `CDexHeader.getDebugInfoBase()`.
    pub fn get_debug_info_base(&self) -> i32 {
        self.debug_info_base
    }

    /// Range of the shared data section owned by the dex file.
    ///
    /// Port of `CDexHeader.getOwnedDataBegin()`.
    pub fn get_owned_data_begin(&self) -> i32 {
        self.owned_data_begin
    }

    /// Range of the shared data section owned by the dex file.
    ///
    /// Port of `CDexHeader.getOwnedDataEnd()`.
    pub fn get_owned_data_end(&self) -> i32 {
        self.owned_data_end
    }

    /// Port of `CDexHeader.isDataOffsetRelative()` (overrides `DexHeader.isDataOffsetRelative()`).
    pub fn is_data_offset_relative(&self) -> bool {
        true
    }
}

impl StructConverter for CDexHeader {
    /// Port of `CDexHeader.toDataType()`.
    ///
    /// Java calls `(Structure) super.toDataType()`, renames it to `"cdex_header"`, moves it to
    /// category `/cdex`, appends the CDEX-only fields, then strips every component's comment
    /// (`"remove comments to prevent data type conflicts"`). The seam-stub `StructureDataType`
    /// used here has no working rename-in-place (`set_name` is a documented no-op on the
    /// placeholder), so the equivalent is built directly: a fresh structure with the final name
    /// and category, seeded with the base structure's components (comments dropped) plus the
    /// CDEX-only fields (which never had comments to begin with).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let base_structure = self.base.base_structure_data_type();

        let cp = CategoryPath::parse("/cdex").expect("valid category path");
        let mut structure =
            crate::sarif::seam_stubs::StructureDataType::new(cp, "cdex_header", 0);

        for component in &base_structure.components {
            structure.add(
                component.data_type.clone(),
                component.length,
                component.field_name.clone(),
                None,
            );
        }

        for field_name in [
            "feature_flags_",
            "debug_info_offsets_pos_",
            "debug_info_offsets_table_offset_",
            "debug_info_base_",
            "owned_data_begin_",
            "owned_data_end_",
        ] {
            structure.add(Arc::new(DWordPlaceholderDataType), 4, Some(field_name.to_string()), None);
        }

        Ok(Box::new(structure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::android::dex::format::dex_constants::DexConstants;

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
        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>
        {
            unimplemented!("not exercised by this fixture")
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(BytesReader { bytes: self.bytes.clone(), position: new_index as usize })
        }
    }

    /// Builds the byte stream for a minimal, valid CDEX header: the standard 0x70-byte DEX
    /// `header_item` (with the CDEX magic instead of the DEX magic) followed by the six
    /// CDEX-only `int` fields.
    fn minimal_cdex_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(CDexConstants::MAGIC.as_bytes()); // magic (4): "cdex"
        bytes.extend([b'0', b'0', b'1', 0]); // version (4): "001\0"
        bytes.extend(0i32.to_le_bytes()); // checksum
        bytes.extend([0u8; 20]); // signature
        for _ in 0..20 {
            bytes.extend(0i32.to_le_bytes()); // fileSize..dataOffset
        }
        // CDEX-only fields.
        bytes.extend(0xAAu32.to_le_bytes()); // feature_flags_
        bytes.extend(0x10u32.to_le_bytes()); // debug_info_offsets_pos_
        bytes.extend(0x20u32.to_le_bytes()); // debug_info_offsets_table_offset_
        bytes.extend(0x30u32.to_le_bytes()); // debug_info_base_
        bytes.extend(0x40u32.to_le_bytes()); // owned_data_begin_
        bytes.extend(0x50u32.to_le_bytes()); // owned_data_end_
        bytes
    }

    #[test]
    fn parses_cdex_magic_and_extra_fields() {
        let mut reader = BytesReader { bytes: minimal_cdex_bytes(), position: 0 };
        let header = CDexHeader::new(&mut reader).expect("valid minimal CDexHeader");

        assert_eq!(header.base().get_magic(), CDexConstants::MAGIC.as_bytes());
        assert_eq!(header.get_feature_flags(), 0xAA);
        assert_eq!(header.get_debug_info_offsets_pos(), 0x10);
        assert_eq!(header.get_debug_info_offsets_table_offset(), 0x20);
        assert_eq!(header.get_debug_info_base(), 0x30);
        assert_eq!(header.get_owned_data_begin(), 0x40);
        assert_eq!(header.get_owned_data_end(), 0x50);
    }

    #[test]
    fn is_data_offset_relative_is_true() {
        let mut reader = BytesReader { bytes: minimal_cdex_bytes(), position: 0 };
        let header = CDexHeader::new(&mut reader).expect("valid minimal CDexHeader");
        assert!(header.is_data_offset_relative());
    }

    #[test]
    fn rejects_plain_dex_magic() {
        let mut bytes = Vec::new();
        bytes.extend(DexConstants::DEX_MAGIC_BASE.as_bytes());
        bytes.extend([b'0', b'3', b'5', 0]);
        bytes.extend(0i32.to_le_bytes());
        bytes.extend([0u8; 20]);
        for _ in 0..20 {
            bytes.extend(0i32.to_le_bytes());
        }
        let mut reader = BytesReader { bytes, position: 0 };
        let result = CDexHeader::new(&mut reader);
        match result {
            Ok(_) => panic!("plain DEX magic must be rejected"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidData),
        }
    }

    #[test]
    fn to_data_type_has_cdex_name_and_category_and_extra_fields() {
        let mut reader = BytesReader { bytes: minimal_cdex_bytes(), position: 0 };
        let header = CDexHeader::new(&mut reader).expect("valid minimal CDexHeader");

        let dt = header.to_data_type().expect("toDataType succeeds");
        assert_eq!(dt.get_name(), "cdex_header");
        assert_eq!(dt.get_category_path().get_path(), "/cdex");

        // Base `header_item` structure is 0x70 bytes; CDexHeader appends six DWORD (4-byte)
        // fields on top of it (feature_flags_, debug_info_offsets_{pos,table_offset}, base,
        // owned_data_{begin,end}).
        let base_len = header.base().to_data_type().expect("base toDataType succeeds").get_length();
        assert_eq!(dt.get_length(), base_len + 6 * 4);
    }
}
