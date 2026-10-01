//! Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImport`.
//!
//! Represents a `dyld_chained_import` structure (one of the three `DYLD_CHAINED_IMPORT*`
//! formats). See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::dyld::binding_table::Binding;
use crate::format::macho::mach_constants::DATA_TYPE_CATEGORY;
use crate::format::macho::struct_builder::{dword, qword};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

const DYLD_CHAINED_IMPORT: i32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: i32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: i32 = 3;

/// A `dyld_chained_import`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldChainedImport {
    imports_format: i32,
    lib_ordinal: i32,
    weak_import: bool,
    name_offset: i64,
    addend: i64,
    symbol_name: Option<String>,
}

impl DyldChainedImport {
    /// Java's package-private `DyldChainedImport(BinaryReader, DyldChainedFixupHeader, int)`
    /// (the header argument is unused in Java).
    pub fn new(reader: &mut BinaryReader, imports_format: i32) -> io::Result<Self> {
        let (lib_ordinal, weak_import, name_offset, addend) = match imports_format {
            DYLD_CHAINED_IMPORT | DYLD_CHAINED_IMPORT_ADDEND => {
                let ival = reader.read_next_int()?;
                let ordinal = ival & 0xff;
                let lib_ordinal = if ordinal > 0xf0 { ordinal as i8 as i32 } else { ordinal };
                let weak = ((ival >> 8) & 1) == 1;
                let name_offset = ((ival >> 9) & 0x7fffff) as i64;
                let addend = if imports_format == DYLD_CHAINED_IMPORT_ADDEND {
                    reader.read_next_int()? as i64
                } else {
                    0
                };
                (lib_ordinal, weak, name_offset, addend)
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let ival = reader.read_next_long()?;
                let ordinal = (ival & 0xffff) as i32;
                let lib_ordinal = if ordinal > 0xfff0 { ordinal as i16 as i32 } else { ordinal };
                let weak = ((ival >> 16) & 1) == 1;
                let name_offset = (ival >> 32) & 0xffff_ffff;
                let addend = reader.read_next_long()?;
                (lib_ordinal, weak, name_offset, addend)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Bad Chained import format: {imports_format}"),
                ))
            }
        };
        Ok(DyldChainedImport {
            imports_format,
            lib_ordinal,
            weak_import,
            name_offset,
            addend,
            symbol_name: None,
        })
    }

    /// Java `DyldChainedImport(Binding)`: an import synthesized from a classic `dyld_info`
    /// binding (format 0, no name offset or addend).
    pub fn from_binding(binding: &Binding) -> Self {
        DyldChainedImport {
            imports_format: 0,
            lib_ordinal: binding.get_library_ordinal(),
            weak_import: binding.is_weak(),
            name_offset: 0,
            addend: 0,
            symbol_name: binding.get_symbol_name().map(str::to_string),
        }
    }

    /// Java `toDataType()`, returning the concrete (packed, bit-field) structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut dt = StructureDataType::new("dyld_chained_import", 0);
        dt.set_packing_enabled(true);
        // Java ignores `InvalidDataTypeException` from the bit-field adds.
        let bits = |dt: &mut StructureDataType, base: Box<dyn DataType>, size: i32, name: &str| {
            let _ = Composite::add_bit_field(dt, base, size, Some(name.to_string()), None);
        };
        match self.imports_format {
            DYLD_CHAINED_IMPORT | DYLD_CHAINED_IMPORT_ADDEND => {
                bits(&mut dt, dword(), 8, "lib_ordinal");
                bits(&mut dt, dword(), 1, "weak_import");
                bits(&mut dt, dword(), 23, "name_offset");
                if self.imports_format == DYLD_CHAINED_IMPORT_ADDEND {
                    Composite::add_with_name(&mut dt, dword(), Some("addend".to_string()), None)
                        .map_err(invalid)?;
                }
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                bits(&mut dt, qword(), 16, "lib_ordinal");
                bits(&mut dt, qword(), 1, "weak_import");
                bits(&mut dt, qword(), 15, "reserved");
                bits(&mut dt, qword(), 32, "name_offset");
                Composite::add_with_name(&mut dt, qword(), Some("addend".to_string()), None)
                    .map_err(invalid)?;
            }
            other => {
                return Err(invalid(format!("Bad Chained import format: {other}")));
            }
        }
        dt.set_category_path(CategoryPath::parse(DATA_TYPE_CATEGORY).map_err(invalid)?)?;
        Ok(dt)
    }

    /// Java `getLibOrdinal()`.
    pub fn get_lib_ordinal(&self) -> i32 {
        self.lib_ordinal
    }

    /// Java `isWeakImport()`.
    pub fn is_weak_import(&self) -> bool {
        self.weak_import
    }

    /// Java `getNameOffset()`.
    pub fn get_name_offset(&self) -> i64 {
        self.name_offset
    }

    /// Java `getAddend()`.
    pub fn get_addend(&self) -> i64 {
        self.addend
    }

    /// Java `getName()`. `None` stands in for Java's `null` (name not yet read via
    /// [`init_string`](Self::init_string)).
    pub fn get_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }

    /// Java `initString(BinaryReader)`: reads the NUL-terminated symbol name at `reader`'s
    /// current position.
    pub fn init_string(&mut self, reader: &mut BinaryReader) -> io::Result<()> {
        self.symbol_name = Some(reader.read_next_ascii_string()?);
        Ok(())
    }
}

fn invalid(message: String) -> ToDataTypeError {
    ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

impl StructConverter for DyldChainedImport {
    /// Java `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: Vec<u8>, format: i32) -> io::Result<DyldChainedImport> {
        DyldChainedImport::new(&mut BinaryReader::from_bytes(bytes, true), format)
    }

    #[test]
    fn decodes_dyld_chained_import() {
        // lib_ordinal 2, weak, name_offset 0x15
        let ival: u32 = 2 | (1 << 8) | (0x15 << 9);
        let imp = parse(ival.to_le_bytes().to_vec(), 1).unwrap();
        assert_eq!(imp.get_lib_ordinal(), 2);
        assert!(imp.is_weak_import());
        assert_eq!(imp.get_name_offset(), 0x15);
        assert_eq!(imp.get_addend(), 0);
        assert_eq!(imp.get_name(), None);
        assert_eq!(imp.to_structure().unwrap().get_length(), 4);
    }

    #[test]
    fn special_ordinals_sign_extend() {
        // BIND_SPECIAL_DYLIB_FLAT_LOOKUP (-2) encoded as 0xfe
        let imp = parse(0xfeu32.to_le_bytes().to_vec(), 1).unwrap();
        assert_eq!(imp.get_lib_ordinal(), -2);
        // 0xf0 is not special
        let imp = parse(0xf0u32.to_le_bytes().to_vec(), 1).unwrap();
        assert_eq!(imp.get_lib_ordinal(), 0xf0);
        // 64-bit: 0xfffe -> -2
        let mut v = 0xfffeu64.to_le_bytes().to_vec();
        v.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(parse(v, 3).unwrap().get_lib_ordinal(), -2);
    }

    #[test]
    fn decodes_addend_formats() {
        let mut v = (1u32 | (4 << 9)).to_le_bytes().to_vec();
        v.extend_from_slice(&(-8i32).to_le_bytes());
        let imp = parse(v, 2).unwrap();
        assert_eq!(imp.get_lib_ordinal(), 1);
        assert_eq!(imp.get_name_offset(), 4);
        assert_eq!(imp.get_addend(), -8);
        assert_eq!(imp.to_structure().unwrap().get_length(), 8);

        let ival: u64 = 3 | (1 << 16) | (0x1234 << 32);
        let mut v = ival.to_le_bytes().to_vec();
        v.extend_from_slice(&0x10i64.to_le_bytes());
        let imp = parse(v, 3).unwrap();
        assert_eq!(imp.get_lib_ordinal(), 3);
        assert!(imp.is_weak_import());
        assert_eq!(imp.get_name_offset(), 0x1234);
        assert_eq!(imp.get_addend(), 0x10);
        let s = imp.to_structure().unwrap();
        assert_eq!(s.get_length(), 16);
        assert_eq!(s.get_category_path().to_string(), "/MachO");
    }

    #[test]
    fn bad_format_is_an_error() {
        let err = parse(vec![0; 8], 7).unwrap_err();
        assert_eq!(err.to_string(), "Bad Chained import format: 7");
    }

    #[test]
    fn from_binding_and_init_string() {
        let b = Binding::with_symbol(Some("_foo".to_string()), 3, true);
        let imp = DyldChainedImport::from_binding(&b);
        assert_eq!(imp.get_name(), Some("_foo"));
        assert_eq!(imp.get_lib_ordinal(), 3);
        assert!(imp.is_weak_import());
        assert!(imp.to_structure().is_err(), "format 0 has no data type in Java");

        let mut imp = parse(1u32.to_le_bytes().to_vec(), 1).unwrap();
        imp.init_string(&mut BinaryReader::from_bytes(b"_bar\0".to_vec(), true)).unwrap();
        assert_eq!(imp.get_name(), Some("_bar"));
    }
}
