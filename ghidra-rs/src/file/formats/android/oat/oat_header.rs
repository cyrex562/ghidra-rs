//! Port of `ghidra.file.formats.android.oat.OatHeader`.
//!
//! The Java class is `abstract class OatHeader implements StructConverter`, with both state
//! (five instance fields) and behaviour (concrete `parse`/`getMagic`/`getVersion`/`toDataType`
//! plus six abstract methods) and around two dozen version-specific in-repo subclasses. Per this
//! crate's shape rules for that combination, it splits into [`OatHeaderBase`] (the shared fields
//! and concrete methods, embedded by each concrete `OatHeader_*` subclass) and the [`OatHeader`]
//! trait (only the abstract methods, built on top of `base`/`base_mut`).
//!
//! # Promotion
//!
//! A minimal placeholder `struct OatHeader` (opaque, `unimplemented!`-bodied) previously lived at
//! `crate::file::seam_stubs::OatHeader`. Nothing in the crate ever imported it (confirmed by
//! grepping for `seam_stubs::OatHeader` and `use ... OatHeader` crate-wide), so it has simply been
//! deleted along with its `STUBS.tsv` line rather than needing an importer update.
//!
//! # Forward references
//!
//! `OatDexFile`/`OatDexFileFactory` (`ghidra.file.formats.android.oat.oatdexfile`) are not ported
//! -- both are concrete Java classes, not interfaces, so minimal placeholder structs for them live
//! in [`super::seam_stubs`] rather than as `dyn` trait objects.

use std::collections::HashMap;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::StructConverter;
use crate::file::formats::android::oat::bundle::OatBundle;
use crate::file::formats::android::oat::oat_constants::OatConstants;
use crate::file::formats::android::oat::oat_instruction_set::OatInstructionSet;
use crate::file::formats::android::oat::seam_stubs::{OatDexFile, OatDexFileFactory};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;
use std::sync::Arc;

/// Minimal stand-in for `ghidra.app.util.bin.StructConverter.STRING` (`StringDataType.dataType`),
/// used with an explicit override length for the `magic_`/`version_` header fields. See
/// [`crate::file::formats::android::dex::format::dex_header`]'s `Utf8PlaceholderDataType` for the
/// identical situation with a different leaf type.
struct StringPlaceholderDataType;

impl DataType for StringPlaceholderDataType {
    fn get_name(&self) -> String {
        "string".to_string()
    }
    fn get_length(&self) -> i32 {
        -1
    }
}

/// The shared state and concrete behaviour of an OAT header.
///
/// Port of the instance fields and non-abstract methods of `OatHeader`. Java's fields are
/// `protected`, so a concrete `OatHeader_*` subclass reads and writes them directly; this struct
/// makes the same fields `pub` for the same reason.
pub struct OatHeaderBase {
    /// The MAGIC string, i.e. `"oat\n"`. Port of the `magic` field.
    pub magic: String,
    /// The VERSION string, e.g. `"001"`, `"009"`, etc. Port of the `version` field.
    pub version: String,
    /// Keys of the key/value store, in the order they were parsed. Port of the `orderedKeyList`
    /// field.
    pub ordered_key_list: Vec<String>,
    /// The key/value store contents. Port of the `key_value_store_` field.
    pub key_value_store: HashMap<String, String>,
    /// The parsed OAT DEX file headers. Port of the `oatDexFileList` field.
    pub oat_dex_file_list: Vec<OatDexFile>,
}

impl OatHeaderBase {
    /// Reads the MAGIC and VERSION fields.
    ///
    /// Port of the protected `OatHeader(BinaryReader)` constructor.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let magic_bytes = reader.read_next_byte_array(OatConstants::MAGIC.len())?;
        let magic = String::from_utf8_lossy(&magic_bytes).into_owned();
        let version = reader.read_next_ascii_string_fixed(4)?;
        Ok(OatHeaderBase {
            magic,
            version,
            ordered_key_list: Vec::new(),
            key_value_store: HashMap::new(),
            oat_dex_file_list: Vec::new(),
        })
    }
}

/// The abstract operations of an OAT header that a concrete version must supply, plus the
/// concrete methods built on top of [`base`](OatHeader::base)/[`base_mut`](OatHeader::base_mut).
///
/// Port of `OatHeader`. `OatHeader implements StructConverter` in Java and provides `toDataType()`
/// itself, so that is a default method here rather than a supertrait requirement (unlike
/// `OatClass`, which never implements it).
pub trait OatHeader: StructConverter {
    /// Access the shared header state.
    fn base(&self) -> &OatHeaderBase;

    /// Mutably access the shared header state.
    fn base_mut(&mut self) -> &mut OatHeaderBase;

    /// Returns the binary offset to the DEX files.
    ///
    /// Port of `getOatDexFilesOffset(BinaryReader)`.
    fn get_oat_dex_files_offset(&self, reader: &dyn BinaryReader) -> i32;

    /// Returns the number of DEX files embedded inside this OAT file.
    ///
    /// Port of `getDexFileCount()`.
    fn get_dex_file_count(&self) -> i32;

    /// Returns the size (in bytes) of the key/value store contained inside this OAT file.
    ///
    /// Port of `getKeyValueStoreSize()`.
    fn get_key_value_store_size(&self) -> i32;

    /// Returns the parsed OAT DEX file headers.
    ///
    /// Port of `getOatDexFileList()`. Abstract in Java despite `oatDexFileList` already being a
    /// base-class field -- every concrete subclass simply returns it, e.g.
    /// `self.base().oat_dex_file_list.as_slice()`.
    fn get_oat_dex_file_list(&self) -> &[OatDexFile];

    /// Returns the OAT instruction set (ARM, X86, etc).
    ///
    /// Port of `getInstructionSet()`.
    fn get_instruction_set(&self) -> OatInstructionSet;

    /// Returns the offset to the executable code, relative to the `oatdata` symbol.
    ///
    /// Port of `getExecutableOffset()`.
    fn get_executable_offset(&self) -> i32;

    /// Returns the OAT checksum value.
    ///
    /// Port of `getChecksum()`.
    fn get_checksum(&self) -> i32;

    /// Returns the MAGIC string, i.e. `"oat\n"`.
    ///
    /// Port of `getMagic()`.
    fn get_magic(&self) -> String {
        self.base().magic.clone()
    }

    /// Returns the VERSION string, e.g. `"001"`, `"009"`, etc.
    ///
    /// Port of `getVersion()`.
    fn get_version(&self) -> String {
        self.base().version.clone()
    }

    /// Parses the OAT header beyond the MAGIC and VERSION fields.
    ///
    /// Port of `parse(BinaryReader, OatBundle)`. Java's `throws` clause also lists
    /// `UnsupportedOatVersionException`, but nothing in this method's body can actually raise
    /// one -- only `OatDexFileFactory.getOatDexFile` is called, and it only throws
    /// `IOException` -- so this returns a plain [`io::Result`].
    fn parse(&mut self, reader: &mut dyn BinaryReader, bundle: &dyn OatBundle) -> io::Result<()> {
        let target = self.get_key_value_store_size();
        let mut count = 0i32;
        while count < target {
            let key = reader.read_next_ascii_string()?;
            let value = reader.read_next_ascii_string()?;
            count += key.len() as i32 + 1;
            count += value.len() as i32 + 1;
            self.base_mut().ordered_key_list.push(key.clone());
            self.base_mut().key_value_store.insert(key, value);
        }

        let offset = self.get_oat_dex_files_offset(reader);
        reader.set_pointer_index(offset as u64);

        let version = self.get_version();
        let dex_file_count = self.get_dex_file_count();
        for _ in 0..dex_file_count {
            let dex_file = OatDexFileFactory::get_oat_dex_file(reader, &version, bundle)?;
            self.base_mut().oat_dex_file_list.push(dex_file);
        }
        Ok(())
    }

    /// Builds a structure datatype for this header: a `magic_`/`version_` pair of 4-byte string
    /// fields, named `OatHeader_<version>` and categorized under `/oat`.
    ///
    /// Port of `toDataType()`.
    fn to_data_type_impl(&self) -> Box<dyn DataType> {
        let cp = CategoryPath::parse("/oat").expect("valid category path");
        let mut structure =
            StructureDataType::new(cp, &format!("OatHeader_{}", self.base().version), 0);
        structure.add(Arc::new(StringPlaceholderDataType), 4, Some("magic_".to_string()), None);
        structure.add(Arc::new(StringPlaceholderDataType), 4, Some("version_".to_string()), None);
        Box::new(structure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::struct_converter::ToDataTypeError;
    use std::any::Any;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct BytesReader {
        bytes: Vec<u8>,
        position: u64,
        little_endian: bool,
    }

    impl BytesReader {
        fn new(bytes: Vec<u8>) -> Self {
            BytesReader { bytes, position: 0, little_endian: true }
        }
    }

    impl BinaryReader for BytesReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }
        fn get_pointer_index(&self) -> u64 {
            self.position
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.position;
            self.position = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
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
            if end > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.bytes[start..end].to_vec())
        }
        fn get_byte_provider(
            &self,
        ) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            unimplemented!("not needed for this test")
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(BytesReader {
                bytes: self.bytes.clone(),
                position: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    struct MockBundle;

    impl OatBundle for MockBundle {
        fn close(&self) {}
        fn get_oat_header(&self) -> Option<&dyn Any> {
            None
        }
        fn get_art_header(&self) -> Option<&dyn Any> {
            None
        }
        fn get_vdex_header(&self) -> Option<&dyn Any> {
            None
        }
        fn get_dex_headers(&self) -> Vec<&dyn Any> {
            Vec::new()
        }
        fn get_dex_header_by_checksum(&self, _checksum: i32) -> Option<&dyn Any> {
            None
        }
    }

    struct MockOatHeader {
        base: OatHeaderBase,
        key_value_store_size: i32,
        dex_file_count: i32,
        dex_files_offset: i32,
    }

    impl StructConverter for MockOatHeader {
        fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
            Ok(self.to_data_type_impl())
        }
    }

    impl OatHeader for MockOatHeader {
        fn base(&self) -> &OatHeaderBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut OatHeaderBase {
            &mut self.base
        }
        fn get_oat_dex_files_offset(&self, _reader: &dyn BinaryReader) -> i32 {
            self.dex_files_offset
        }
        fn get_dex_file_count(&self) -> i32 {
            self.dex_file_count
        }
        fn get_key_value_store_size(&self) -> i32 {
            self.key_value_store_size
        }
        fn get_oat_dex_file_list(&self) -> &[OatDexFile] {
            &self.base.oat_dex_file_list
        }
        fn get_instruction_set(&self) -> OatInstructionSet {
            OatInstructionSet::Arm
        }
        fn get_executable_offset(&self) -> i32 {
            0
        }
        fn get_checksum(&self) -> i32 {
            0
        }
    }

    // "oat\n" magic + "007\0" version (real KitKat OAT version string).
    fn magic_and_version_bytes() -> Vec<u8> {
        let mut v = b"oat\n".to_vec();
        v.extend_from_slice(b"007\0");
        v
    }

    #[test]
    fn new_reads_magic_and_version() {
        let mut reader = BytesReader::new(magic_and_version_bytes());
        let base = OatHeaderBase::new(&mut reader).unwrap();

        assert_eq!(base.magic, OatConstants::MAGIC);
        assert_eq!(base.version, "007");
        assert!(base.ordered_key_list.is_empty());
        assert!(base.key_value_store.is_empty());
        assert!(base.oat_dex_file_list.is_empty());
        assert_eq!(reader.get_pointer_index(), 8);
    }

    #[test]
    fn get_magic_and_version_delegate_to_base() {
        let mut reader = BytesReader::new(magic_and_version_bytes());
        let base = OatHeaderBase::new(&mut reader).unwrap();
        let header = MockOatHeader { base, key_value_store_size: 0, dex_file_count: 0, dex_files_offset: 8 };

        assert_eq!(header.get_magic(), "oat\n");
        assert_eq!(header.get_version(), "007");
    }

    #[test]
    fn parse_reads_key_value_store_and_dex_files() {
        let mut bytes = magic_and_version_bytes();
        // Key/value store: "k\0" + "v\0" -> 2 entries of length 2 each == 4 total.
        bytes.extend_from_slice(b"k\0v\0");
        let kv_size = 4;
        let dex_files_offset = bytes.len() as i32;

        let mut reader = BytesReader::new(bytes);
        let base = OatHeaderBase::new(&mut reader).unwrap();
        let mut header = MockOatHeader {
            base,
            key_value_store_size: kv_size,
            dex_file_count: 1,
            dex_files_offset,
        };

        header.parse(&mut reader, &MockBundle).unwrap();

        assert_eq!(header.base().ordered_key_list, vec!["k".to_string()]);
        assert_eq!(header.base().key_value_store.get("k"), Some(&"v".to_string()));
        assert_eq!(header.get_oat_dex_file_list().len(), 1);
    }

    #[test]
    fn parse_propagates_unsupported_version_as_io_error() {
        let mut bytes = magic_and_version_bytes();
        let dex_files_offset = bytes.len() as i32;
        bytes.truncate(bytes.len()); // no key/value bytes needed, kv_size = 0

        let mut reader = BytesReader::new(bytes);
        let mut base = OatHeaderBase::new(&mut reader).unwrap();
        base.version = "not-a-real-version".to_string();
        let mut header = MockOatHeader {
            base,
            key_value_store_size: 0,
            dex_file_count: 1,
            dex_files_offset,
        };

        let err = header.parse(&mut reader, &MockBundle).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn to_data_type_has_versioned_name_and_oat_category() {
        let mut reader = BytesReader::new(magic_and_version_bytes());
        let base = OatHeaderBase::new(&mut reader).unwrap();
        let header = MockOatHeader { base, key_value_store_size: 0, dex_file_count: 0, dex_files_offset: 8 };

        let dt = header.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "OatHeader_007");
        assert_eq!(dt.get_category_path().get_path(), "/oat");
        assert_eq!(dt.get_length(), 8);
    }
}
