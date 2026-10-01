//! Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureSuperBlob`.
//!
//! Represents a `CS_SuperBlob` structure: an index of nested blobs. See `osfmk/kern/cs_blobs.h`.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{set_endian, StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::codesignature::code_signature_blob_index::CodeSignatureBlobIndex;
use crate::format::macho::commands::codesignature::code_signature_blob_parser::{self, CodeSignatureBlob};
use crate::format::macho::commands::codesignature::code_signature_generic_blob::{CodeSignatureGenericBlob, Du};
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{array, dword, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// A `CS_SuperBlob`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureSuperBlob`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureSuperBlob {
    generic: CodeSignatureGenericBlob,
    count: i32,
    index_list: Vec<CodeSignatureBlobIndex>,
    index_blobs: Vec<CodeSignatureBlob>,
}

impl CodeSignatureSuperBlob {
    /// Java: `CodeSignatureSuperBlob(BinaryReader)`. Each indexed blob is parsed from
    /// `base + offset`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let generic = CodeSignatureGenericBlob::new(reader)?;
        let count = reader.read_next_int()?;
        let mut index_list = Vec::with_capacity(count.max(0) as usize);
        for _ in 0..count {
            index_list.push(CodeSignatureBlobIndex::new(reader)?);
        }
        let mut index_blobs = Vec::with_capacity(index_list.len());
        for blob_index in &index_list {
            reader.set_pointer_index(generic.base().wrapping_add(blob_index.get_offset() as u64));
            index_blobs.push(code_signature_blob_parser::parse(reader)?);
        }
        Ok(CodeSignatureSuperBlob { generic, count, index_list, index_blobs })
    }

    /// The inherited `CodeSignatureGenericBlob` state.
    pub fn generic(&self) -> &CodeSignatureGenericBlob {
        &self.generic
    }

    /// Java: `getCount()`.
    pub fn get_count(&self) -> i32 {
        self.count
    }

    /// Java: `getIndexEntries()`.
    pub fn get_index_entries(&self) -> &[CodeSignatureBlobIndex] {
        &self.index_list
    }

    /// Java: `getIndexBlobs()`.
    pub fn get_index_blobs(&self) -> &[CodeSignatureBlob] {
        &self.index_blobs
    }

    /// Java: `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`. Lays down each
    /// indexed blob's structure (big-endian) and lets it mark up its own payload.
    pub fn markup(
        &self,
        program: &dyn Program,
        addr: &Address,
        header: &MachHeader,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        let result: Result<(), String> = (|| {
            for (blob_index, blob) in self.index_list.iter().zip(&self.index_blobs) {
                let blob_addr = addr.add(blob_index.get_offset()).map_err(|e| e.to_string())?;
                let dt = blob.to_data_type().map_err(|e| e.to_string())?;
                let d = Du
                    .create_data(program, &blob_addr, dt, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| e.to_string())?;
                set_big_endian(d)?;
                blob.markup(program, &blob_addr, header, monitor, log);
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(Some("CodeSignatureSuperBlob"), "Failed to markup CS_SuperBlob");
        }
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("CS_SuperBlob");
        s.add(dword(), "magic", Some("magic number"))?;
        s.add(dword(), "length", Some("total length of SuperBlob"))?;
        s.add(dword(), "count", Some("number of index entries following"))?;
        if let Some(first) = self.index_list.first() {
            s.add(array(first.to_data_type()?, self.count)?, "index", Some("(count) entries"))?;
        }
        s.finish_structure()
    }
}

/// Java: `StructConverter.setEndian(d, true)` on freshly created data.
///
/// The crate's `set_endian` needs exclusive access to the [`Data`]; a listing that keeps its own
/// handle to the new data cannot grant it, which is reported as a markup failure.
pub(crate) fn set_big_endian(mut d: Arc<dyn Data>) -> Result<(), String> {
    let data = Arc::get_mut(&mut d).ok_or("created data is shared; cannot set its endian settings")?;
    set_endian(data, true);
    Ok(())
}

impl StructConverter for CodeSignatureSuperBlob {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}
