//! Port of `ghidra.app.util.bin.format.pe.cli.CliStreamHeader`.
//!
//! A structure used by a `CliMetadataRoot` to describe a `CliAbstractStream`. Note that this
//! type of "header" isn't found at the start of the stream, but as elements of a list of headers
//! at the end of a `CliMetadataRoot`. They are kind of like PE section headers.
//!
//! **Dropped field**: Java stores a `metadataRoot` back-reference to the owning `CliMetadataRoot`
//! (passed into the constructor) purely for the `getMetadataRoot()` convenience accessor. No
//! in-repo caller (ported or not) ever calls that accessor on a real `CliStreamHeader` --
//! `CliAbstractStream.java`'s one call site belongs to the still-unported `cli.streams`
//! subpackage. Keeping it would mean either a circular `Rc<RefCell<CliMetadataRoot>>` between a
//! collection and its own elements, or an unsafe back-pointer, for an accessor nothing exercises
//! -- see `OWNERSHIP_MIGRATION.md`'s guidance against modeling a Java field with a getter as
//! reason enough for extra indirection. Dropped entirely; `CliStreamHeader::new` therefore only
//! takes the `reader`, not a `metadataRoot`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::cli::seam_stubs::CliAbstractStream;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::app::util::importer::message_log::MessageLog;
use crate::format::seam_stubs::{NTHeader};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Port of `CliStreamHeader.NAME`.
const NAME: &str = "CLI_Stream_Header";
/// Port of `CliStreamHeader.PATH`.
#[allow(dead_code)]
const PATH: &str = "/PE/CLI/Streams/Headers";

/// The on-disk width of a Java `DWordDataType`/`DWORD`, used twice (for `offset` and `size`) when
/// computing this header's fixed byte length. `DWordDataType` has no concrete instantiable
/// singleton in this crate yet (still a trait -- see
/// `crate::program::model::data::dword_data_type`), but its length is always 4 regardless, so the
/// constant is reproduced directly rather than going through a `DataType`.
const DWORD_LEN: i32 = 4;

/// Port of `ghidra.app.util.bin.format.pe.cli.CliStreamHeader`.
pub struct CliStreamHeader {
    stream: Option<Box<dyn CliAbstractStream>>,
    offset: i32,
    size: i32,
    name: String,
    name_len: i32,
}

impl CliStreamHeader {
    /// Port of `CliStreamHeader(CliMetadataRoot, BinaryReader)`, minus the dropped `metadataRoot`
    /// back-reference (see this module's docs).
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let header_start_index = reader.get_pointer_index();

        let offset = reader.read_next_int()?;
        let size = reader.read_next_int()?;

        // Name is an ASCII string aligned to the next 4-byte boundary.
        let start_index = reader.get_pointer_index();
        let name = reader.read_next_ascii_string()?;
        let end_index = reader.get_pointer_index();
        let string_bytes = end_index - start_index;
        let bytes_to_round_up = if string_bytes % 4 != 0 { 4 - (string_bytes % 4) } else { 0 };
        let name_len = (string_bytes + bytes_to_round_up) as i32;

        let total_len = 2 * DWORD_LEN + name_len;
        reader.set_pointer_index(header_start_index + total_len as u64);

        Ok(CliStreamHeader { stream: None, offset, size, name, name_len })
    }

    /// Port of `CliStreamHeader.getStream()`.
    pub fn get_stream(&self) -> Option<&dyn CliAbstractStream> {
        self.stream.as_deref()
    }

    /// Port of `CliStreamHeader.getOffset()`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Port of `CliStreamHeader.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Port of `CliStreamHeader.getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Port of `CliStreamHeader.getNameLength()`.
    pub fn get_name_length(&self) -> i32 {
        self.name_len
    }

    /// Port of the protected `CliStreamHeader.setStream(CliAbstractStream)`.
    pub fn set_stream(&mut self, stream: Box<dyn CliAbstractStream>) {
        self.stream = Some(stream);
    }
}

impl PeMarkupable for CliStreamHeader {
    /// Port of `CliStreamHeader.markup(Program, boolean, TaskMonitor, MessageLog, NTHeader)`.
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(stream) = &self.stream {
            stream.markup(program, is_binary, monitor, log, nt_header)?;
        }
        Ok(())
    }
}

impl StructConverter for CliStreamHeader {
    /// Mirrors `toDataType()`. Not yet buildable: Java's structure is `DWORD offset; DWORD size;
    /// CHAR name[nameLen];`, and neither `DWordDataType` nor `CharDataType` has a concrete,
    /// instantiable singleton in this crate yet (both are still traits -- see
    /// `crate::program::model::data::dword_data_type`/`char_data_type`'s module docs).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CliStreamHeader::to_data_type requires DWORD/CHAR DataType singletons, which are \
             not yet ported to a concrete instantiable form",
        )))
    }
}

impl std::fmt::Display for CliStreamHeader {
    /// Port of `CliStreamHeader.toString()`, which returns `getName()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
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

    /// Builds the bytes for a `#Blob`-named header: offset, size, then the ASCII name
    /// null-terminated and padded to the next 4-byte boundary.
    fn header_bytes(offset: i32, size: i32, name: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0); // null terminator, which readNextAsciiString consumes.
        while name_bytes.len() % 4 != 0 {
            name_bytes.push(0);
        }
        b.extend_from_slice(&name_bytes);
        b
    }

    #[test]
    fn parses_offset_size_and_name() {
        // "#Blob" is 5 chars + 1 null terminator = 6 bytes, rounded up to 8.
        let bytes = header_bytes(0x74, 0x10, "#Blob");
        assert_eq!(bytes.len(), 8 + 8); // 2 DWORDs (8) + 8-byte padded name.
        let mut reader = FixtureReader::new(bytes);

        let header = CliStreamHeader::new(&mut reader).unwrap();

        assert_eq!(header.get_offset(), 0x74);
        assert_eq!(header.get_size(), 0x10);
        assert_eq!(header.get_name(), "#Blob");
        assert_eq!(header.get_name_length(), 8);
        assert_eq!(reader.get_pointer_index(), 8 + 8);
        assert!(header.get_stream().is_none());
    }

    #[test]
    fn name_length_rounds_up_to_four_byte_boundary() {
        // "#~" is 2 chars + 1 null terminator = 3 bytes, rounded up to 4.
        let bytes = header_bytes(0, 0, "#~");
        let mut reader = FixtureReader::new(bytes);

        let header = CliStreamHeader::new(&mut reader).unwrap();

        assert_eq!(header.get_name(), "#~");
        assert_eq!(header.get_name_length(), 4);
    }

    #[test]
    fn display_matches_get_name() {
        let bytes = header_bytes(1, 2, "#Strings");
        let mut reader = FixtureReader::new(bytes);
        let header = CliStreamHeader::new(&mut reader).unwrap();
        assert_eq!(header.to_string(), "#Strings");
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let bytes = header_bytes(0, 0, "#GUID");
        let mut reader = FixtureReader::new(bytes);
        let header = CliStreamHeader::new(&mut reader).unwrap();
        assert!(header.to_data_type().is_err());
    }
}
