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
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
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
        let mut reader = BinaryReader::from_bytes(bytes, true);

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
        let mut reader = BinaryReader::from_bytes(bytes, true);

        let header = CliStreamHeader::new(&mut reader).unwrap();

        assert_eq!(header.get_name(), "#~");
        assert_eq!(header.get_name_length(), 4);
    }

    #[test]
    fn display_matches_get_name() {
        let bytes = header_bytes(1, 2, "#Strings");
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = CliStreamHeader::new(&mut reader).unwrap();
        assert_eq!(header.to_string(), "#Strings");
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let bytes = header_bytes(0, 0, "#GUID");
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = CliStreamHeader::new(&mut reader).unwrap();
        assert!(header.to_data_type().is_err());
    }
}
