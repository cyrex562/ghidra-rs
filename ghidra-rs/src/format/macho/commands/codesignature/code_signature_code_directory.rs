//! Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureCodeDirectory`.
//!
//! Represents a `CS_CodeDirectory` structure. See `osfmk/kern/cs_blobs.h`. Fields beyond `spare2`
//! exist only from the version that introduced them; absent ones read as 0, as in Java.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::codesignature::code_signature_generic_blob::{CodeSignatureGenericBlob, Du};
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{array, byte, dword, fixed_string, qword, word, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// A `CS_CodeDirectory`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureCodeDirectory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureCodeDirectory {
    generic: CodeSignatureGenericBlob,
    version: i32,
    flags: i32,
    hash_offset: i32,
    ident_offset: i32,
    n_special_slots: i32,
    n_code_slots: i32,
    code_limit: i32,
    hash_size: i32,
    hash_type: i32,
    platform: i32,
    page_size: i32,
    spare2: i32,
    scatter_offset: i32,
    team_offset: i32,
    spare3: i32,
    code_limit64: i64,
    exec_seg_base: i64,
    exec_seg_limit: i64,
    exec_seg_flags: i64,
    runtime: i32,
    pre_encrypt_offset: i32,
    linkage_hash_type: i32,
    linkage_hash_application_type: i32,
    linkage_application_sub_type: i32,
    linkage_offset: i32,
    linkage_size: i32,
}

impl CodeSignatureCodeDirectory {
    /// Java: `CodeSignatureCodeDirectory(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let generic = CodeSignatureGenericBlob::new(reader)?;
        let version = reader.read_next_int()?;
        let flags = reader.read_next_int()?;
        let hash_offset = reader.read_next_int()?;
        let ident_offset = reader.read_next_int()?;
        let n_special_slots = reader.read_next_int()?;
        let n_code_slots = reader.read_next_int()?;
        let code_limit = reader.read_next_int()?;
        let hash_size = reader.read_next_unsigned_byte()? as i32;
        let hash_type = reader.read_next_unsigned_byte()? as i32;
        let platform = reader.read_next_unsigned_byte()? as i32;
        let page_size = reader.read_next_unsigned_byte()? as i32;
        let spare2 = reader.read_next_int()?;
        let mut scatter_offset = 0;
        let mut team_offset = 0;
        let mut spare3 = 0;
        let mut code_limit64 = 0;
        let mut exec_seg_base = 0;
        let mut exec_seg_limit = 0;
        let mut exec_seg_flags = 0;
        let mut runtime = 0;
        let mut pre_encrypt_offset = 0;
        let mut linkage_hash_type = 0;
        let mut linkage_hash_application_type = 0;
        let mut linkage_application_sub_type = 0;
        let mut linkage_offset = 0;
        let mut linkage_size = 0;
        if version >= 0x20100 {
            scatter_offset = reader.read_next_int()?;
        }
        if version >= 0x20200 {
            team_offset = reader.read_next_int()?;
        }
        if version >= 0x20300 {
            spare3 = reader.read_next_int()?;
            code_limit64 = reader.read_next_long()?;
        }
        if version >= 0x20400 {
            exec_seg_base = reader.read_next_long()?;
            exec_seg_limit = reader.read_next_long()?;
            exec_seg_flags = reader.read_next_long()?;
        }
        if version >= 0x20500 {
            runtime = reader.read_next_int()?;
            pre_encrypt_offset = reader.read_next_int()?;
        }
        if version >= 0x20600 {
            linkage_hash_type = reader.read_next_unsigned_byte()? as i32;
            linkage_hash_application_type = reader.read_next_unsigned_byte()? as i32;
            linkage_application_sub_type = reader.read_next_unsigned_short()? as i32;
            linkage_offset = reader.read_next_int()?;
            linkage_size = reader.read_next_int()?;
        }
        Ok(CodeSignatureCodeDirectory { generic, version, flags, hash_offset, ident_offset, n_special_slots, n_code_slots, code_limit, hash_size, hash_type, platform, page_size, spare2, scatter_offset, team_offset, spare3, code_limit64, exec_seg_base, exec_seg_limit, exec_seg_flags, runtime, pre_encrypt_offset, linkage_hash_type, linkage_hash_application_type, linkage_application_sub_type, linkage_offset, linkage_size })
    }

    /// The inherited `CodeSignatureGenericBlob` state.
    pub fn generic(&self) -> &CodeSignatureGenericBlob {
        &self.generic
    }

    /// Java's `version` field.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Java's `flags` field.
    pub fn flags(&self) -> i32 {
        self.flags
    }

    /// Java's `hashOffset` field.
    pub fn hash_offset(&self) -> i32 {
        self.hash_offset
    }

    /// Java's `identOffset` field.
    pub fn ident_offset(&self) -> i32 {
        self.ident_offset
    }

    /// Java's `nSpecialSlots` field.
    pub fn n_special_slots(&self) -> i32 {
        self.n_special_slots
    }

    /// Java's `nCodeSlots` field.
    pub fn n_code_slots(&self) -> i32 {
        self.n_code_slots
    }

    /// Java's `codeLimit` field.
    pub fn code_limit(&self) -> i32 {
        self.code_limit
    }

    /// Java's `hashSize` field.
    pub fn hash_size(&self) -> i32 {
        self.hash_size
    }

    /// Java's `hashType` field.
    pub fn hash_type(&self) -> i32 {
        self.hash_type
    }

    /// Java's `platform` field.
    pub fn platform(&self) -> i32 {
        self.platform
    }

    /// Java's `pageSize` field.
    pub fn page_size(&self) -> i32 {
        self.page_size
    }

    /// Java's `spare2` field.
    pub fn spare2(&self) -> i32 {
        self.spare2
    }

    /// Java's `scatterOffset` field.
    pub fn scatter_offset(&self) -> i32 {
        self.scatter_offset
    }

    /// Java's `teamOffset` field.
    pub fn team_offset(&self) -> i32 {
        self.team_offset
    }

    /// Java's `spare3` field.
    pub fn spare3(&self) -> i32 {
        self.spare3
    }

    /// Java's `codeLimit64` field.
    pub fn code_limit64(&self) -> i64 {
        self.code_limit64
    }

    /// Java's `execSegBase` field.
    pub fn exec_seg_base(&self) -> i64 {
        self.exec_seg_base
    }

    /// Java's `execSegLimit` field.
    pub fn exec_seg_limit(&self) -> i64 {
        self.exec_seg_limit
    }

    /// Java's `execSegFlags` field.
    pub fn exec_seg_flags(&self) -> i64 {
        self.exec_seg_flags
    }

    /// Java's `runtime` field.
    pub fn runtime(&self) -> i32 {
        self.runtime
    }

    /// Java's `preEncryptOffset` field.
    pub fn pre_encrypt_offset(&self) -> i32 {
        self.pre_encrypt_offset
    }

    /// Java's `linkageHashType` field.
    pub fn linkage_hash_type(&self) -> i32 {
        self.linkage_hash_type
    }

    /// Java's `linkageHashApplicationType` field.
    pub fn linkage_hash_application_type(&self) -> i32 {
        self.linkage_hash_application_type
    }

    /// Java's `linkageApplicationSubType` field.
    pub fn linkage_application_sub_type(&self) -> i32 {
        self.linkage_application_sub_type
    }

    /// Java's `linkageOffset` field.
    pub fn linkage_offset(&self) -> i32 {
        self.linkage_offset
    }

    /// Java's `linkageSize` field.
    pub fn linkage_size(&self) -> i32 {
        self.linkage_size
    }

    /// Java: `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`: the identifier and
    /// team strings and the code hash table.
    pub fn markup(
        &self,
        program: &dyn Program,
        addr: &Address,
        _header: &MachHeader,
        _monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        let result: Result<(), String> = (|| {
            let err = |e: &dyn std::fmt::Display| e.to_string();
            let comment = |a: &Address, text: &str| -> Result<(), String> {
                let mut listing = program.get_listing().ok_or("no listing")?;
                listing.set_comment(a, CommentType::Pre, Some(text.to_string()));
                Ok(())
            };
            if self.ident_offset != 0 {
                let ident_addr = addr.add(self.ident_offset as i64).map_err(|e| err(&e))?;
                Du.create_data(program, &ident_addr, fixed_string().map_err(|e| err(&e))?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| err(&e))?;
                comment(&ident_addr, "CS_CodeDirectory identifer")?;
            }
            if self.team_offset != 0 {
                let team_addr = addr.add(self.team_offset as i64).map_err(|e| err(&e))?;
                Du.create_data(program, &team_addr, fixed_string().map_err(|e| err(&e))?, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| err(&e))?;
                comment(&team_addr, "CS_CodeDirectory team identifier")?;
            }
            if self.hash_offset != 0 && self.hash_size != 0 {
                let hash_addr = addr.add(self.hash_offset as i64).map_err(|e| err(&e))?;
                let hash_array = array(byte(), self.hash_size).map_err(|e| err(&e))?;
                let hashes = crate::format::macho::struct_builder::array_with_element_length(hash_array, self.n_code_slots, 1)
                    .map_err(|e| err(&e))?;
                Du.create_data(program, &hash_addr, hashes, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| err(&e))?;
                comment(&hash_addr, "CS_CodeDirectory hashes")?;
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(Some("CodeSignatureCodeDirectory"), "Failed to markup CS_CodeDirectory");
        }
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("CS_CodeDirectory");
        s.add(dword(), "magic", Some("magic number (CSMAGIC_CODEDIRECTORY)"))?;
        s.add(dword(), "length", Some("total length of CodeDirectory blob"))?;
        s.add(dword(), "version", Some("compatibility version"))?;
        s.add(dword(), "flags", Some("setup and mode flags"))?;
        s.add(dword(), "hashOffset", Some("offset of hash slot element at index zero"))?;
        s.add(dword(), "identOffset", Some("offset of identifier string"))?;
        s.add(dword(), "nSpecialSlots", Some("number of special hash slots"))?;
        s.add(dword(), "nCodeSlots", Some("number of ordinary (code) hash slots"))?;
        s.add(dword(), "codeLimit", Some("limit to main image signature range"))?;
        s.add(byte(), "hashSize", Some("size of each hash in bytes"))?;
        s.add(byte(), "hashType", Some("type of hash (cdHashType* constants)"))?;
        s.add(byte(), "platform", Some("platform identifier; zero if not platform binary"))?;
        s.add(byte(), "pageSize", Some("log2(page size in bytes); 0 => infinite"))?;
        s.add(dword(), "spare2", Some("unused (must be zero)"))?;
        if self.version >= 0x20100 {
            s.add(dword(), "scatterOffset", Some("offset of optional scatter vector"))?;
        }
        if self.version >= 0x20200 {
            s.add(dword(), "teamOffset", Some("offset of optional team identifier"))?;
        }
        if self.version >= 0x20300 {
            s.add(dword(), "spare3", Some("unused (must be zero)"))?;
            s.add(qword(), "codeLimit64", Some("limit to main image signature range, 64 bits"))?;
        }
        if self.version >= 0x20400 {
            s.add(qword(), "execSegBase", Some("offset of executable segment"))?;
            s.add(qword(), "execSegLimit", Some("limit of executable segment"))?;
            s.add(qword(), "execSegFlags", Some("executable segment flags"))?;
        }
        if self.version >= 0x20500 {
            s.add(dword(), "runtime", Some(""))?;
            s.add(dword(), "preEncryptOffset", Some(""))?;
        }
        if self.version >= 0x20600 {
            s.add(byte(), "linkageHashType", Some(""))?;
            s.add(byte(), "linkageHashApplicationType", Some(""))?;
            s.add(word(), "linkageApplicationSubType", Some(""))?;
            s.add(dword(), "linkageOffset", Some(""))?;
            s.add(dword(), "linkageSize", Some(""))?;
        }
        s.finish_structure()
    }
}

impl StructConverter for CodeSignatureCodeDirectory {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}
