//! Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixupHeader`.
//!
//! Represents a `dyld_chained_fixups_header` structure. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::chained::dyld_chained_imports::DyldChainedImports;
use crate::format::macho::commands::chained::dyld_chained_starts_in_image::DyldChainedStartsInImage;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{dword, fixed_string, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::ref_type::RefType;
use crate::program::model::symbol::SourceType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

/// A `dyld_chained_fixups_header`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixupHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldChainedFixupHeader {
    fixups_version: i64,
    starts_offset: i64,
    imports_offset: i64,
    symbols_offset: i64,
    imports_count: i64,
    imports_format: i32,
    symbols_format: i32,
    chained_starts_in_image: DyldChainedStartsInImage,
    chained_imports: DyldChainedImports,
}

impl DyldChainedFixupHeader {
    /// Java `DyldChainedFixupHeader(BinaryReader)`: `reader` positioned at the start of the
    /// structure; the starts/imports/symbols offsets are relative to that start.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let ptr_index = reader.get_pointer_index() as i64;

        let fixups_version = reader.read_next_unsigned_int()? as i64;
        let starts_offset = reader.read_next_unsigned_int()? as i64;
        let imports_offset = reader.read_next_unsigned_int()? as i64;
        let symbols_offset = reader.read_next_unsigned_int()? as i64;
        let imports_count = reader.read_next_unsigned_int()? as i64;
        let imports_format = reader.read_next_int()?;
        let symbols_format = reader.read_next_int()?;

        reader.set_pointer_index((ptr_index + starts_offset) as u64);
        let chained_starts_in_image = DyldChainedStartsInImage::new(reader)?;

        reader.set_pointer_index((ptr_index + imports_offset) as u64);
        let mut chained_imports = DyldChainedImports::new(reader, imports_count, imports_format)?;

        reader.set_pointer_index((ptr_index + symbols_offset) as u64);
        chained_imports.init_symbols(reader)?;

        Ok(DyldChainedFixupHeader {
            fixups_version,
            starts_offset,
            imports_offset,
            symbols_offset,
            imports_count,
            imports_format,
            symbols_format,
            chained_starts_in_image,
            chained_imports,
        })
    }

    /// Java `markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`: lays down the
    /// starts-in-image structure (and its per-segment structures), each import, each import's
    /// name string, and a data reference from each import to its name. Failures are logged, not
    /// propagated.
    pub fn markup(
        &self,
        program: &dyn Program,
        address: &Address,
        header: &MachHeader,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        let err = |e: &dyn std::fmt::Display| e.to_string();
        let result: Result<(), String> = (|| {
            if self.starts_offset != 0 {
                let starts_addr = address.add(self.starts_offset).map_err(|e| err(&e))?;
                let dt = self.chained_starts_in_image.to_data_type().map_err(|e| err(&e))?;
                Du.create_data(program, &starts_addr, dt, -1, ClearDataMode::CheckForSpace)
                    .map_err(|e| err(&e))?;
                self.chained_starts_in_image
                    .markup(program, &starts_addr, header, monitor, log)
                    .map_err(|e| err(&e))?;
            }

            if self.imports_offset != 0 && self.symbols_offset != 0 {
                let imports_addr = address.add(self.imports_offset).map_err(|e| err(&e))?;
                let symbols_addr = address.add(self.symbols_offset).map_err(|e| err(&e))?;
                let imports = self.chained_imports.get_chained_imports();
                for i in 0..self.imports_count {
                    let chained_import = imports.get(i as usize).ok_or("import index out of range")?;
                    let dt = chained_import.to_data_type().map_err(|e| err(&e))?;
                    let len = dt.get_length() as i64;
                    let d = Du
                        .create_data(
                            program,
                            &imports_addr.add(i * len).map_err(|e| err(&e))?,
                            dt,
                            -1,
                            ClearDataMode::CheckForSpace,
                        )
                        .map_err(|e| err(&e))?;
                    let str_addr =
                        symbols_addr.add(chained_import.get_name_offset()).map_err(|e| err(&e))?;
                    Du.create_data(
                        program,
                        &str_addr,
                        fixed_string().map_err(|e| err(&e))?,
                        -1,
                        ClearDataMode::CheckForSpace,
                    )
                    .map_err(|e| err(&e))?;
                    let mut rm = program.get_reference_manager().ok_or("no reference manager")?;
                    rm.add_memory_reference(d.get_min_address(), str_addr, RefType::Data, SourceType::Imported, 0);
                }
            }
            Ok(())
        })();
        if result.is_err() {
            log.append_msg_from(
                Some("DyldChainedFixupHeader"),
                "Failed to markup dyld_chained_fixups_header",
            );
        }
        Ok(())
    }

    /// Java `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_chained_fixups_header");
        for (name, comment) in [
            ("fixups_version", "0"),
            ("starts_offset", "offset of dyld_chained_starts_in_image in chain_data"),
            ("imports_offset", "offset of imports table in chain_data"),
            ("symbols_offset", "offset of symbol strings in chain_data"),
            ("imports_count", "number of imported symbol names"),
            ("imports_format", "DYLD_CHAINED_IMPORT*"),
            ("symbols_format", "0 => uncompressed, 1 => zlib compressed"),
        ] {
            s.add(dword(), name, Some(comment))?;
        }
        s.finish_structure()
    }

    /// Java `getFixupsVersion()`.
    pub fn get_fixups_version(&self) -> i64 {
        self.fixups_version
    }

    /// Java `getStartsOffset()`.
    pub fn get_starts_offset(&self) -> i64 {
        self.starts_offset
    }

    /// Java `getImportsOffset()`.
    pub fn get_imports_offset(&self) -> i64 {
        self.imports_offset
    }

    /// Java `getSymbolsOffset()`.
    pub fn get_symbols_offset(&self) -> i64 {
        self.symbols_offset
    }

    /// Java `getImportsCount()`.
    pub fn get_imports_count(&self) -> i64 {
        self.imports_count
    }

    /// Java `getImportsFormat()`.
    pub fn get_imports_format(&self) -> i32 {
        self.imports_format
    }

    /// Java `getSymbolsFormat()`.
    pub fn get_symbols_format(&self) -> i32 {
        self.symbols_format
    }

    /// Java `isCompress()`.
    pub fn is_compress(&self) -> bool {
        self.symbols_format != 0
    }

    /// Java `getChainedStartsInImage()`.
    pub fn get_chained_starts_in_image(&self) -> &DyldChainedStartsInImage {
        &self.chained_starts_in_image
    }

    /// Java `getChainedImports()`.
    pub fn get_chained_imports(&self) -> &DyldChainedImports {
        &self.chained_imports
    }
}

impl StructConverter for DyldChainedFixupHeader {
    /// Java `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::commands::chained::dyld_chained_starts_in_segment::test_support::segment_bytes;

    /// A complete little-endian `dyld_chained_fixups_header` blob: one segment
    /// (`pointer_format`, segment offset `seg_offset`, one page starting at 0) and the given
    /// `DYLD_CHAINED_IMPORT` imports `(lib_ordinal, name)`.
    pub(crate) fn fixups_blob(pointer_format: u16, seg_offset: u64, imports: &[(u8, &str)]) -> Vec<u8> {
        let starts_offset = 28u32;
        // starts_in_image: seg_count 1, offset 8 -> segment (24 bytes with one page start)
        let mut starts = Vec::new();
        starts.extend_from_slice(&1i32.to_le_bytes());
        starts.extend_from_slice(&8i32.to_le_bytes());
        starts.extend(segment_bytes(pointer_format, seg_offset, &[0]));
        let imports_offset = starts_offset + starts.len() as u32;
        let mut pool = vec![0u8];
        let mut table = Vec::new();
        for (ord, name) in imports {
            let off = pool.len() as u32;
            table.extend_from_slice(&(*ord as u32 | (off << 9)).to_le_bytes());
            pool.extend_from_slice(name.as_bytes());
            pool.push(0);
        }
        let symbols_offset = imports_offset + table.len() as u32;
        let mut v = Vec::new();
        for f in [0u32, starts_offset, imports_offset, symbols_offset, imports.len() as u32, 1, 0] {
            v.extend_from_slice(&f.to_le_bytes());
        }
        v.extend(starts);
        v.extend(table);
        v.extend(pool);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::fixups_blob;
    use super::*;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_header_starts_and_imports() {
        let mut r = BinaryReader::from_bytes(fixups_blob(6, 0x4000, &[(1, "_malloc"), (0xfe, "_flat")]), true);
        let h = DyldChainedFixupHeader::new(&mut r).unwrap();
        assert_eq!(h.get_fixups_version(), 0);
        assert_eq!(h.get_starts_offset(), 28);
        assert_eq!(h.get_imports_offset(), 28 + 8 + 24);
        assert_eq!(h.get_symbols_offset(), 60 + 8);
        assert_eq!(h.get_imports_count(), 2);
        assert_eq!(h.get_imports_format(), 1);
        assert!(!h.is_compress());
        let seg = &h.get_chained_starts_in_image().get_chained_starts()[0];
        assert_eq!(seg.get_segment_offset(), 0x4000);
        let imports = h.get_chained_imports();
        assert_eq!(imports.get_chained_import(0).unwrap().get_name(), Some("_malloc"));
        assert_eq!(imports.get_chained_import(1).unwrap().get_name(), Some("_flat"));
        assert_eq!(imports.get_chained_import(1).unwrap().get_lib_ordinal(), -2);
    }

    #[test]
    fn to_data_type_has_seven_dwords() {
        let mut r = BinaryReader::from_bytes(fixups_blob(6, 0, &[]), true);
        let s = DyldChainedFixupHeader::new(&mut r).unwrap().to_structure().unwrap();
        assert_eq!(s.get_name(), "dyld_chained_fixups_header");
        assert_eq!(s.get_length(), 28);
        assert_eq!(
            names(&s),
            [
                "fixups_version",
                "starts_offset",
                "imports_offset",
                "symbols_offset",
                "imports_count",
                "imports_format",
                "symbols_format"
            ]
        );
    }
}
