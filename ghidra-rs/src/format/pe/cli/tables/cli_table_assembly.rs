//! Port of `ghidra.app.util.bin.format.pe.cli.tables.CliTableAssembly`.
//!
//! Describes the Assembly table: a one-row table storing information about the current
//! assembly.
//!
//! Java's version `extends CliAbstractTable`, an unported abstract base class that provides
//! shared bookkeeping every `CliTableXxx` subclass needs (`readerOffset`/`tableType`/`numRows`/
//! `rows`/`strings`/`blobs`/`userStrings` fields, `readBlobIndex`/`readStringIndex`/
//! `readGuidIndex`/`readTableIndex` helpers, and the generic `toDataType`/`getTableSize`/`getRow`
//! built on an abstract `getRowDataType()`) and also implements `StructConverter`+`PeMarkupable`.
//! Rather than model that whole hierarchy for one subclass, the state and behavior this type
//! actually uses are folded directly into this concrete struct, following the precedent set by
//! [`ExceptionDataDirectory`](crate::format::pe::exception_data_directory::ExceptionDataDirectory)
//! for its own unported `DataDirectory` base class.
//!
//! **Row byte length**: Java computes it by calling `this.toDataType()` (a `StructureDataType`)
//! and taking `getLength()`. `to_data_type` is not buildable in this port yet (see its own docs),
//! so [`row_length`](CliTableAssembly::row_length) instead computes the same total directly from
//! the fixed-width fields plus the metadata stream's (2- or 4-byte) blob/string index widths --
//! exactly what `to_data_type` would add up to, just without needing a `StructureDataType`
//! instance to ask.
//!
//! **`markup`**: Java's only real work is, for each row with a public key, decoding the
//! `CliSigAssembly` blob and writing its markup at the blob's stream address via
//! `CliAbstractStream.getStreamMarkupAddress`/`CliStreamBlob.updateBlob`. The entire `cli.streams`
//! subpackage those come from is unported, so that step is left as a logged, documented gap
//! rather than invented.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::cli::tables::cli_type_table::CliTypeTable;
use crate::format::pe::cli::tables::flags::cli_flags;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::format::seam_stubs::{CliStreamMetadata, MessageLog, NTHeader};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Port of `CliAbstractTable.PATH`.
pub const PATH: &str = "/PE/CLI/Metadata/Tables";

/// Port of the inner class `CliTableAssembly.CliAssemblyRow`.
///
/// **Dropped back-reference**: Java's `CliAssemblyRow` is a non-static inner class, so
/// `getRepresentation()` reaches the enclosing `CliTableAssembly.metadataStream` implicitly. That
/// back-reference is not modeled (same reasoning as
/// [`CliStreamHeader`](crate::format::pe::cli::cli_stream_header::CliStreamHeader)'s dropped
/// `metadataRoot` field); instead, [`get_representation`](CliAssemblyRow::get_representation)
/// takes the metadata stream as an explicit parameter.
pub struct CliAssemblyRow {
    pub hash_alg: i32,
    pub major_version: i16,
    pub minor_version: i16,
    pub build_number: i16,
    pub revision_number: i16,
    pub flags: i32,
    pub public_key_index: i32,
    pub name_index: i32,
    pub culture_index: i32,
}

impl CliAssemblyRow {
    /// Port of `CliAssemblyRow.getRepresentation()`.
    pub fn get_representation(&self, metadata_stream: &dyn CliStreamMetadata) -> String {
        let name = metadata_stream.get_strings_stream().get_string(self.name_index);
        let flags_name = cli_flags::cli_enum_assembly_flags()
            .get_name_for_value((self.flags as u32) as i64)
            .unwrap_or_else(|| format!("0x{:x}", self.flags as u32));
        format!(
            "{} v{}.{} build{} rev{} pubkey index {:x} culture index {:x} flags {}",
            name,
            self.major_version,
            self.minor_version,
            self.build_number,
            self.revision_number,
            self.public_key_index,
            self.culture_index,
            flags_name
        )
    }
}

/// Port of `ghidra.app.util.bin.format.pe.cli.tables.CliTableAssembly`.
pub struct CliTableAssembly {
    reader_offset: u64,
    table_type: CliTypeTable,
    metadata_stream: Arc<dyn CliStreamMetadata>,
    rows: Vec<CliAssemblyRow>,
    blobs: Vec<i32>,
    strings: Vec<i32>,
}

impl CliTableAssembly {
    /// Port of `CliTableAssembly(BinaryReader, CliStreamMetadata, CliTypeTable)` (which chains
    /// through `CliAbstractTable`'s constructor first, folded in here -- see module docs).
    pub fn new(
        reader: &mut dyn BinaryReader,
        metadata_stream: Arc<dyn CliStreamMetadata>,
        table_type: CliTypeTable,
    ) -> io::Result<Self> {
        let reader_offset = reader.get_pointer_index();
        let num_rows = metadata_stream.get_number_rows_for_table(&table_type).max(0);

        let mut table = CliTableAssembly {
            reader_offset,
            table_type,
            metadata_stream,
            rows: Vec::with_capacity(num_rows as usize),
            blobs: Vec::new(),
            strings: Vec::new(),
        };

        let row_len = table.row_length() as u64;
        for i in 0..num_rows as u64 {
            reader.set_pointer_index(reader_offset + row_len * i);
            let hash_alg = reader.read_next_int()?;
            let major_version = reader.read_next_short()?;
            let minor_version = reader.read_next_short()?;
            let build_number = reader.read_next_short()?;
            let revision_number = reader.read_next_short()?;
            let flags = reader.read_next_int()?;
            let public_key_index = table.read_blob_index(reader)?;
            let name_index = table.read_string_index(reader)?;
            let culture_index = table.read_string_index(reader)?;

            table.blobs.push(public_key_index);
            table.strings.push(name_index);
            table.strings.push(culture_index);
            table.rows.push(CliAssemblyRow {
                hash_alg,
                major_version,
                minor_version,
                build_number,
                revision_number,
                flags,
                public_key_index,
                name_index,
                culture_index,
            });
        }
        reader.set_pointer_index(reader_offset);

        Ok(table)
    }

    /// Port of `CliAbstractTable.getTableType()`.
    pub fn get_table_type(&self) -> CliTypeTable {
        self.table_type
    }

    /// Port of `CliAbstractTable.getNumRows()`.
    pub fn get_num_rows(&self) -> i32 {
        self.rows.len() as i32
    }

    /// Port of `CliAbstractTable.getRow(int)`. Per ISO/IEC 23271:2012(E) III.1.9, row indices
    /// start from 1, while heap/stream indices start from 0.
    pub fn get_row(&self, row_index: i32) -> Option<&CliAssemblyRow> {
        if row_index < 1 {
            return None;
        }
        self.rows.get((row_index - 1) as usize)
    }

    /// The `blobs` indices collected while parsing (public key indices), matching
    /// `CliAbstractTable.blobs`.
    pub fn blob_indices(&self) -> &[i32] {
        &self.blobs
    }

    /// The `strings` indices collected while parsing (name/culture indices), matching
    /// `CliAbstractTable.strings`.
    pub fn string_indices(&self) -> &[i32] {
        &self.strings
    }

    /// Port of the protected `CliAbstractTable.readBlobIndex(BinaryReader)`. Java compares
    /// `metadataStream.getBlobIndexDataType()` against the `DWordDataType.dataType` singleton by
    /// identity; this port compares the returned `DataType`'s length instead (4 bytes for a
    /// DWORD-width index, 2 otherwise), which is equivalent and does not need that singleton.
    fn read_blob_index(&self, reader: &mut dyn BinaryReader) -> io::Result<i32> {
        if self.metadata_stream.get_blob_index_data_type().get_length() == 4 {
            reader.read_next_int()
        } else {
            Ok((reader.read_next_short()? as i32) & 0xffff)
        }
    }

    /// Port of the protected `CliAbstractTable.readStringIndex(BinaryReader)`.
    fn read_string_index(&self, reader: &mut dyn BinaryReader) -> io::Result<i32> {
        if self.metadata_stream.get_string_index_data_type().get_length() == 4 {
            reader.read_next_int()
        } else {
            Ok((reader.read_next_short()? as i32) & 0xffff)
        }
    }

    /// The byte length of one row -- see this module's docs for why it is computed directly
    /// rather than via `to_data_type().get_length()`.
    fn row_length(&self) -> i32 {
        let blob_index_len = self.metadata_stream.get_blob_index_data_type().get_length();
        let string_index_len = self.metadata_stream.get_string_index_data_type().get_length();
        // HashAlg (DWORD=4) + 4 WORDs (2 each) + Flags (DWORD=4) + PublicKey + Name + Culture.
        4 + 4 * 2 + 4 + blob_index_len + 2 * string_index_len
    }
}

impl PeMarkupable for CliTableAssembly {
    /// Port of `CliTableAssembly.markup(Program, boolean, TaskMonitor, MessageLog, NTHeader)`.
    ///
    /// See this module's docs: the real public-key blob markup needs the unported `cli.streams`
    /// subpackage (`CliAbstractStream.getStreamMarkupAddress`, `CliStreamBlob.getBlob`/
    /// `updateBlob`), so rows with a public key are logged rather than actually marked up.
    fn markup(
        &self,
        _program: &dyn Program,
        _is_binary: bool,
        _monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
        _nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for row in &self.rows {
            if row.public_key_index > 0 {
                log.append_msg(
                    "CliTableAssembly: Assembly public-key blob markup is not yet supported \
                     (CliAbstractStream/CliStreamBlob markup machinery is not ported)",
                );
            }
        }
        Ok(())
    }
}

impl StructConverter for CliTableAssembly {
    /// Mirrors `toDataType()` (which for this class doubles as `getRowDataType()`). Not yet
    /// buildable: Java's row structure is `CliEnumAssemblyHashAlgorithm HashAlg; WORD
    /// MajorVersion; WORD MinorVersion; WORD BuildNumber; WORD RevisionNumber;
    /// CliEnumAssemblyFlags Flags; <blob index> PublicKey; <string index> Name; <string index>
    /// Culture;` -- `WordDataType` has no concrete, instantiable singleton in this crate yet
    /// (still a trait -- see `crate::program::model::data::word_data_type`'s module docs), even
    /// though the two `CliEnumXxx` fields and the blob/string index fields all are available.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CliTableAssembly::to_data_type requires a WORD DataType singleton, which is not \
             yet ported to a concrete instantiable form",
        )))
    }
}

impl std::fmt::Display for CliTableAssembly {
    /// Port of `CliAbstractTable.toString()`, which returns `tableType.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.table_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::{CliStreamBlob, CliStreamGuid, CliStreamStrings, CliStreamUserStrings};
    use crate::program::model::data::category_path::ROOT;

    /// A minimal `DataType` fixture standing in for `WordDataType`/`DWordDataType` (neither has a
    /// concrete, instantiable singleton in this crate yet), exposing only the fixed byte length
    /// `CliTableAssembly::row_length`/`read_blob_index`/`read_string_index` actually inspect.
    struct FixtureScalarType {
        length: i32,
    }
    impl DataType for FixtureScalarType {
        fn get_name(&self) -> String {
            format!("scalar{}", self.length)
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            ROOT.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length()
        }
    }

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
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct FixtureReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl FixtureReader {
        fn new(data: Vec<u8>) -> Self {
            FixtureReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for FixtureReader {
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
            Box::new(FixtureReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    struct FixtureMetadataStream {
        names: std::collections::HashMap<i32, String>,
        wide_indices: bool,
    }

    impl CliStreamMetadata for FixtureMetadataStream {
        fn get_name(&self) -> String {
            "#~".to_string()
        }
        fn parse(&self) -> io::Result<bool> {
            Ok(true)
        }
        fn get_guid_stream(&self) -> Box<dyn CliStreamGuid> {
            unimplemented!("not needed by these tests")
        }
        fn get_user_strings_stream(&self) -> Box<dyn CliStreamUserStrings> {
            unimplemented!("not needed by these tests")
        }
        fn get_strings_stream(&self) -> Box<dyn CliStreamStrings> {
            Box::new(FixtureStringsStream { names: self.names.clone() })
        }
        fn get_blob_stream(&self) -> Box<dyn CliStreamBlob> {
            unimplemented!("not needed by these tests")
        }
        fn get_major_version(&self) -> i16 {
            1
        }
        fn get_minor_version(&self) -> i16 {
            0
        }
        fn get_sorted(&self) -> i64 {
            0
        }
        fn get_valid(&self) -> i64 {
            0
        }
        fn get_table(
            &self,
            _table_type: &CliTypeTable,
        ) -> Box<dyn crate::format::seam_stubs::CliAbstractTable> {
            unimplemented!("not needed by these tests")
        }
        fn get_number_rows_for_table(&self, _table_type: &CliTypeTable) -> i32 {
            1
        }
        fn get_string_index_data_type(&self) -> Box<dyn DataType> {
            if self.wide_indices { Box::new(FixtureScalarType { length: 4 }) } else { Box::new(FixtureScalarType { length: 2 }) }
        }
        fn get_guid_index_data_type(&self) -> Box<dyn DataType> {
            Box::new(FixtureScalarType { length: 2 })
        }
        fn get_blob_index_data_type(&self) -> Box<dyn DataType> {
            if self.wide_indices { Box::new(FixtureScalarType { length: 4 }) } else { Box::new(FixtureScalarType { length: 2 }) }
        }
        fn get_table_index_data_type(&self, _table: &CliTypeTable) -> Box<dyn DataType> {
            Box::new(FixtureScalarType { length: 2 })
        }
        fn markup(
            &self,
            // `CliStreamMetadata::markup` is declared against `crate::format::seam_stubs::Program`
            // (a zero-method placeholder distinct from the real
            // `crate::program::model::listing::program::Program` this module otherwise uses for
            // `PeMarkupable`) -- see `crate::format::seam_stubs::Program`'s doc comment.
            _program: &dyn crate::format::seam_stubs::Program,
            _is_binary: bool,
            _monitor: &dyn TaskMonitor,
            _log: &dyn MessageLog,
            _nt_header: &dyn NTHeader,
        ) -> io::Result<()> {
            Ok(())
        }
        fn to_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not needed by these tests")
        }
    }

    struct FixtureStringsStream {
        names: std::collections::HashMap<i32, String>,
    }
    impl CliStreamStrings for FixtureStringsStream {
        fn get_string(&self, index: i32) -> String {
            self.names.get(&index).cloned().unwrap_or_default()
        }
    }

    /// One Assembly-table row using narrow (2-byte) blob/string indices: HashAlg(4) + 4
    /// WORDs(8) + Flags(4) + PublicKey(2) + Name(2) + Culture(2) = 22 bytes.
    fn narrow_row_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x8004i32.to_le_bytes()); // HashAlg = SHA1
        b.extend_from_slice(&1i16.to_le_bytes()); // MajorVersion
        b.extend_from_slice(&2i16.to_le_bytes()); // MinorVersion
        b.extend_from_slice(&3i16.to_le_bytes()); // BuildNumber
        b.extend_from_slice(&4i16.to_le_bytes()); // RevisionNumber
        b.extend_from_slice(&0x0000_0100u32.to_le_bytes()); // Flags = Retargetable
        b.extend_from_slice(&0x10i16.to_le_bytes()); // PublicKey index
        b.extend_from_slice(&0x20i16.to_le_bytes()); // Name index
        b.extend_from_slice(&0x30i16.to_le_bytes()); // Culture index
        b
    }

    #[test]
    fn parses_single_row_with_narrow_indices() {
        let bytes = narrow_row_bytes();
        assert_eq!(bytes.len(), 22);
        let mut reader = FixtureReader::new(bytes);
        let stream: Arc<dyn CliStreamMetadata> = Arc::new(FixtureMetadataStream {
            names: [(0x20, "MyAssembly".to_string())].into_iter().collect(),
            wide_indices: false,
        });

        let table = CliTableAssembly::new(&mut reader, stream, CliTypeTable::Assembly).unwrap();

        assert_eq!(table.get_num_rows(), 1);
        let row = table.get_row(1).unwrap();
        assert_eq!(row.hash_alg, 0x8004);
        assert_eq!(row.major_version, 1);
        assert_eq!(row.minor_version, 2);
        assert_eq!(row.build_number, 3);
        assert_eq!(row.revision_number, 4);
        assert_eq!(row.public_key_index, 0x10);
        assert_eq!(row.name_index, 0x20);
        assert_eq!(row.culture_index, 0x30);
        assert_eq!(table.blob_indices(), &[0x10]);
        assert_eq!(table.string_indices(), &[0x20, 0x30]);
        assert!(table.get_row(0).is_none());
        assert!(table.get_row(2).is_none());
        assert_eq!(reader.get_pointer_index(), 0);
    }

    #[test]
    fn get_representation_includes_name_and_flags() {
        let bytes = narrow_row_bytes();
        let mut reader = FixtureReader::new(bytes);
        let stream: Arc<dyn CliStreamMetadata> = Arc::new(FixtureMetadataStream {
            names: [(0x20, "MyAssembly".to_string())].into_iter().collect(),
            wide_indices: false,
        });
        let table = CliTableAssembly::new(&mut reader, stream.clone(), CliTypeTable::Assembly).unwrap();

        let row = table.get_row(1).unwrap();
        let rep = row.get_representation(stream.as_ref());

        assert!(rep.contains("MyAssembly"));
        assert!(rep.contains("v1.2"));
        assert!(rep.contains("build3"));
        assert!(rep.contains("rev4"));
        assert!(rep.contains("Retargetable"));
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let bytes = narrow_row_bytes();
        let mut reader = FixtureReader::new(bytes);
        let stream: Arc<dyn CliStreamMetadata> =
            Arc::new(FixtureMetadataStream { names: Default::default(), wide_indices: false });
        let table = CliTableAssembly::new(&mut reader, stream, CliTypeTable::Assembly).unwrap();
        assert!(table.to_data_type().is_err());
    }
}
