//! Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureBlobParser`.
//!
//! The Java class holds one static method, so it is a module here: [`parse`] picks the blob type
//! by magic. Java returns the concrete-but-extensible `CodeSignatureGenericBlob`; the set it can
//! return is closed (the generic blob and its two subclasses), so this port returns the
//! [`CodeSignatureBlob`] enum. See <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::codesignature::code_signature_code_directory::CodeSignatureCodeDirectory;
use crate::format::macho::commands::codesignature::code_signature_constants::{
    CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE,
};
use crate::format::macho::commands::codesignature::code_signature_generic_blob::CodeSignatureGenericBlob;
use crate::format::macho::commands::codesignature::code_signature_super_blob::CodeSignatureSuperBlob;
use crate::format::macho::mach_header::MachHeader;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// A parsed code signature blob: Java's `CodeSignatureGenericBlob` or one of its subclasses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSignatureBlob {
    /// A plain `CS_GenericBlob`.
    Generic(CodeSignatureGenericBlob),
    /// A `CS_SuperBlob` (`CSMAGIC_EMBEDDED_SIGNATURE`).
    SuperBlob(CodeSignatureSuperBlob),
    /// A `CS_CodeDirectory` (`CSMAGIC_CODEDIRECTORY`).
    CodeDirectory(CodeSignatureCodeDirectory),
}

impl CodeSignatureBlob {
    /// The `CodeSignatureGenericBlob` state every blob carries.
    pub fn generic(&self) -> &CodeSignatureGenericBlob {
        match self {
            CodeSignatureBlob::Generic(b) => b,
            CodeSignatureBlob::SuperBlob(b) => b.generic(),
            CodeSignatureBlob::CodeDirectory(b) => b.generic(),
        }
    }

    /// Java: `getMagic()`.
    pub fn get_magic(&self) -> i32 {
        self.generic().get_magic()
    }

    /// Java: `getLength()`.
    pub fn get_length(&self) -> i64 {
        self.generic().get_length()
    }

    /// Java: the (virtual) `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`.
    pub fn markup(
        &self,
        program: &dyn Program,
        address: &Address,
        header: &MachHeader,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        match self {
            CodeSignatureBlob::Generic(b) => b.markup(program, address, header, monitor, log),
            CodeSignatureBlob::SuperBlob(b) => b.markup(program, address, header, monitor, log),
            CodeSignatureBlob::CodeDirectory(b) => b.markup(program, address, header, monitor, log),
        }
    }
}

impl StructConverter for CodeSignatureBlob {
    /// Java: the (virtual) `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        match self {
            CodeSignatureBlob::Generic(b) => b.to_data_type(),
            CodeSignatureBlob::SuperBlob(b) => b.to_data_type(),
            CodeSignatureBlob::CodeDirectory(b) => b.to_data_type(),
        }
    }
}

/// Java: `parse(BinaryReader)`. Parses the blob at the reader's position, choosing its type by
/// magic.
pub fn parse(reader: &mut BinaryReader) -> io::Result<CodeSignatureBlob> {
    let magic = reader.peek_next_int()? as u32;
    Ok(match magic {
        CSMAGIC_EMBEDDED_SIGNATURE => CodeSignatureBlob::SuperBlob(CodeSignatureSuperBlob::new(reader)?),
        CSMAGIC_CODEDIRECTORY => CodeSignatureBlob::CodeDirectory(CodeSignatureCodeDirectory::new(reader)?),
        _ => CodeSignatureBlob::Generic(CodeSignatureGenericBlob::new(reader)?),
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::commands::codesignature::code_signature_constants::{
        CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_REQUIREMENTS,
    };
    use crate::format::macho::mach_header::test_support::Bytes;

    /// A big-endian embedded signature: a super blob indexing a version-0x20400 code directory
    /// (identifier "com.ex", two 32-byte hashes) and a 12-byte requirements blob.
    pub(crate) fn signature() -> Vec<u8> {
        let mut cd = Bytes::new(false);
        let cd_header = 88; // through execSegFlags
        let ident_off = cd_header;
        let hash_off = ident_off + 8;
        let cd_len = hash_off + 64;
        cd.u32(CSMAGIC_CODEDIRECTORY).u32(cd_len as u32).u32(0x20400).u32(0x2);
        cd.u32(hash_off as u32).u32(ident_off as u32).u32(0).u32(2).u32(0x2000);
        cd.u8(32).u8(2).u8(0).u8(12).u32(0);
        cd.u32(0).u32(0).u32(0).u64(0).u64(0).u64(0x4000).u64(1);
        assert_eq!(cd.len(), cd_header);
        cd.name("com.ex", 8).raw(&[0xaa; 64]);

        let mut b = Bytes::new(false);
        let header = 12 + 2 * 8;
        b.u32(CSMAGIC_EMBEDDED_SIGNATURE).u32((header + cd.len() + 12) as u32).u32(2);
        b.u32(0).u32(header as u32);
        b.u32(2).u32((header + cd.len()) as u32);
        b.raw(&cd.buf);
        b.u32(CSMAGIC_REQUIREMENTS).u32(12).u32(0);
        b.buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::signature;
    use super::*;
    use crate::format::macho::commands::codesignature::code_signature_constants::CSMAGIC_REQUIREMENTS;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_super_blob_with_code_directory_and_generic_blob() {
        let mut r = BinaryReader::from_bytes(signature(), false);
        let blob = parse(&mut r).unwrap();
        let CodeSignatureBlob::SuperBlob(sb) = &blob else { panic!("expected a super blob") };
        assert_eq!(blob.get_magic() as u32, CSMAGIC_EMBEDDED_SIGNATURE);
        assert_eq!(sb.get_count(), 2);
        assert_eq!(sb.get_index_entries()[1].get_type(), 2);
        let CodeSignatureBlob::CodeDirectory(cd) = &sb.get_index_blobs()[0] else {
            panic!("expected a code directory")
        };
        assert_eq!(cd.version(), 0x20400);
        assert_eq!(cd.hash_size(), 32);
        assert_eq!(cd.page_size(), 12);
        assert_eq!(cd.n_code_slots(), 2);
        assert_eq!(cd.code_limit(), 0x2000);
        assert_eq!(cd.exec_seg_limit(), 0x4000);
        assert_eq!(cd.runtime(), 0, "not present before 0x20500");
        let cd_names = names(&cd.to_structure().unwrap());
        assert_eq!(cd_names.last().unwrap(), "execSegFlags");
        assert_eq!(cd.to_structure().unwrap().get_length(), 88);
        let generic = &sb.get_index_blobs()[1];
        assert!(matches!(generic, CodeSignatureBlob::Generic(_)));
        assert_eq!(generic.get_magic() as u32, CSMAGIC_REQUIREMENTS);
        assert_eq!(generic.get_length(), 12);
        let sb_dt = sb.to_structure().unwrap();
        assert_eq!(names(&sb_dt), ["magic", "length", "count", "index"]);
        assert_eq!(sb_dt.get_length(), 12 + 16);
    }

    #[test]
    fn unknown_magic_is_generic() {
        let mut b = 0x1234_5678u32.to_be_bytes().to_vec();
        b.extend(8u32.to_be_bytes());
        let blob = parse(&mut BinaryReader::from_bytes(b, false)).unwrap();
        assert!(matches!(blob, CodeSignatureBlob::Generic(_)));
        assert_eq!(blob.get_length(), 8);
    }
}
