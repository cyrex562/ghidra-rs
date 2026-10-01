//! Port of `ghidra.app.util.bin.format.macho.commands.TableOfContents`.
//!
//! Represents a `dylib_table_of_contents` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `dylib_table_of_contents` entry.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.TableOfContents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableOfContents {
    symbol_index: i32,
    module_index: i32,
}

impl TableOfContents {
    /// Java: `TableOfContents(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let symbol_index = reader.read_next_int()?;
        let module_index = reader.read_next_int()?;
        Ok(TableOfContents { symbol_index, module_index })
    }

    /// Java: `getSymbolIndex()`.
    pub fn get_symbol_index(&self) -> i32 {
        self.symbol_index
    }

    /// Java: `getModuleIndex()`.
    pub fn get_module_index(&self) -> i32 {
        self.module_index
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dylib_table_of_contents");
        s.dword("symbol_index")?.dword("module_index")?;
        s.finish_structure()
    }
}

impl StructConverter for TableOfContents {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toc_entry() {
        let mut b = 7u32.to_le_bytes().to_vec();
        b.extend(2u32.to_le_bytes());
        let t = TableOfContents::new(&mut BinaryReader::from_bytes(b, true)).unwrap();
        assert_eq!((t.get_symbol_index(), t.get_module_index()), (7, 2));
        assert_eq!(t.to_structure().unwrap().get_length(), 8);
    }
}
