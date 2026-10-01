//! Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureGenericBlob`.
//!
//! Represents a `CS_GenericBlob` structure. See `osfmk/kern/cs_blobs.h`.
//!
//! The Java class is concrete and the base of `CodeSignatureSuperBlob` and
//! `CodeSignatureCodeDirectory`; those embed a [`CodeSignatureGenericBlob`] for its
//! `magic`/`length`/`base` state, and [`CodeSignatureBlob`](super::code_signature_blob_parser::CodeSignatureBlob)
//! is the closed set the parser produces.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{array, byte, dword, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
pub(crate) struct Du;
impl DataUtilities for Du {}

/// A `CS_GenericBlob`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureGenericBlob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeSignatureGenericBlob {
    magic: i32,
    length: i64,
    base: u64,
}

impl CodeSignatureGenericBlob {
    /// Java: `CodeSignatureGenericBlob(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = reader.get_pointer_index();
        let magic = reader.read_next_int()?;
        let length = reader.read_next_unsigned_int()? as i64;
        Ok(CodeSignatureGenericBlob { magic, length, base })
    }

    /// Java: `getMagic()`.
    pub fn get_magic(&self) -> i32 {
        self.magic
    }

    /// Java: `getLength()`.
    pub fn get_length(&self) -> i64 {
        self.length
    }

    /// Java's `protected base` field: the reader index where the blob starts.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Java: `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`. Marks up the blob's
    /// payload (everything after the 8-byte header) as a byte array.
    pub fn markup(
        &self,
        program: &dyn Program,
        address: &Address,
        _header: &MachHeader,
        _monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        if self.length - 8 == 0 {
            return;
        }
        let result: Result<(), String> = (|| {
            let dt = array(byte(), (self.length - 8) as i32).map_err(|e| e.to_string())?;
            let header_len = self.to_structure().map_err(|e| e.to_string())?.get_length();
            let hash_addr = address.add(header_len as i64).map_err(|e| e.to_string())?;
            Du.create_data(program, &hash_addr, dt, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| e.to_string())?;
            let mut listing = program.get_listing().ok_or("no listing")?;
            listing.set_comment(&hash_addr, CommentType::Pre, Some("CS_GenericBlob hash".to_string()));
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(Some("CodeSignatureGenericBlob"), "Failed to markup CS_GenericBlob");
        }
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("CS_GenericBlob");
        s.add(dword(), "magic", Some("magic number"))?;
        s.add(dword(), "length", Some("total length of blob"))?;
        s.finish_structure()
    }
}

impl StructConverter for CodeSignatureGenericBlob {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_generic_blob_header() {
        let mut b = vec![0u8; 4];
        b.extend(0xfade_0c01u32.to_be_bytes());
        b.extend(0x20u32.to_be_bytes());
        let mut r = BinaryReader::from_bytes(b, false);
        r.set_pointer_index(4);
        let blob = CodeSignatureGenericBlob::new(&mut r).unwrap();
        assert_eq!(blob.base(), 4);
        assert_eq!(blob.get_magic() as u32, 0xfade_0c01);
        assert_eq!(blob.get_length(), 0x20);
        assert_eq!(blob.to_structure().unwrap().get_length(), 8);
    }
}
