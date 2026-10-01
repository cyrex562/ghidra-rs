//! Port of `ghidra.app.util.bin.format.pef.ImportedSymbol`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pef::abstract_symbol::{AbstractSymbol, PEF_WEAK_IMPORT_SYM_MASK};
use crate::format::pef::loader_info_header::LoaderInfoHeader;
use crate::format::pef::symbol_class::SymbolClass;
use crate::format::seam_stubs::StructConverterUtilDataType;
use crate::program::model::data::data_type::DataType;

/// Fixed size, in bytes, of the on-disk packed `ImportedSymbol` word.
///
/// Port of `ImportedSymbol.SIZEOF`.
pub const SIZEOF: i32 = 4;

/// A symbol imported by a PEF container from one of its imported libraries.
///
/// Port of `ghidra.app.util.bin.format.pef.ImportedSymbol`.
pub struct ImportedSymbol {
    symbol_class: i32,
    symbol_name_offset: i32,
    name: String,
}

impl ImportedSymbol {
    /// Reads an [`ImportedSymbol`] from `reader`, resolving its name via an absolute offset into
    /// `loader`'s loader string table.
    ///
    /// Port of `ImportedSymbol(BinaryReader, LoaderInfoHeader)`.
    pub fn new(reader: &mut BinaryReader, loader: &LoaderInfoHeader) -> io::Result<Self> {
        let value = reader.read_next_int()?;

        // `((value & 0xff000000) >> 24) & 0xff` in Java: the intermediate `>>` is an *arithmetic*
        // shift that sign-extends, but the trailing `& 0xff` immediately clips that back down to
        // an unsigned byte -- net effect is an unsigned shift, expressed here directly.
        let symbol_class = ((value as u32) >> 24) as i32;
        let symbol_name_offset = value & 0x00ff_ffff;

        let offset = loader.section().get_container_offset() as i64
            + loader.loader_strings_offset() as i64
            + symbol_name_offset as i64;
        let name = reader.read_ascii_string(offset as u64)?;

        Ok(ImportedSymbol { symbol_class, symbol_name_offset, name })
    }

    /// The imported symbol does not have to be present at fragment preparation time in order for
    /// execution to continue.
    ///
    /// Port of `ImportedSymbol.isWeak()`.
    pub fn is_weak(&self) -> bool {
        (self.symbol_class as u32 & PEF_WEAK_IMPORT_SYM_MASK as u32) != 0
    }

    /// The offset (in bytes) from the beginning of the loader string table to the
    /// null-terminated name of the symbol.
    ///
    /// Port of `ImportedSymbol.getSymbolNameOffset()`.
    pub fn symbol_name_offset(&self) -> i32 {
        self.symbol_name_offset
    }
}

impl AbstractSymbol for ImportedSymbol {
    fn name(&self) -> &str {
        &self.name
    }

    fn symbol_class(&self) -> Option<SymbolClass> {
        SymbolClass::from_value((self.symbol_class & 0xf) as u8)
    }
}

impl fmt::Debug for ImportedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedSymbol")
            .field("symbol_class", &self.symbol_class)
            .field("symbol_name_offset", &self.symbol_name_offset)
            .field("name", &self.name)
            .finish()
    }
}

impl StructConverter for ImportedSymbol {
    /// Port of `ImportedSymbol.toDataType()`. See
    /// [`exported_symbol_key`](crate::format::pef::exported_symbol_key)'s module docs for why
    /// this returns a [`StructConverterUtilDataType`] placeholder rather than a real
    /// `TypedefDataType`-wrapping-`DWORD`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(StructConverterUtilDataType::to_data_type("ImportedSymbol", SIZEOF)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::SectionHeader;

    struct MockSectionHeader {
        container_offset: i32,
    }

    impl SectionHeader for MockSectionHeader {
        fn get_container_offset(&self) -> i32 {
            self.container_offset
        }
    }

    fn write_i32_be(buf: &mut Vec<u8>, value: i32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Builds a real [`LoaderInfoHeader`] fixture with `containerOffset` 0 and the given
    /// `loaderStringsOffset`, with no imported libraries/symbols/relocations of its own and a
    /// single all-zero export hash slot (the minimum well-formed header).
    fn loader_info_header_with(loader_strings_offset: i32) -> LoaderInfoHeader {
        let mut buf = Vec::new();
        for _ in 0..6 {
            write_i32_be(&mut buf, 0); // mainSection .. termOffset
        }
        write_i32_be(&mut buf, 0); // importedLibraryCount
        write_i32_be(&mut buf, 0); // totalImportedSymbolCount
        write_i32_be(&mut buf, 0); // relocSectionCount
        write_i32_be(&mut buf, 0); // relocInstrOffset
        write_i32_be(&mut buf, loader_strings_offset);
        write_i32_be(&mut buf, 56); // exportHashOffset (right after the 56-byte header)
        write_i32_be(&mut buf, 0); // exportHashTablePower -> 1 hash slot
        write_i32_be(&mut buf, 0); // exportedSymbolCount
        assert_eq!(buf.len(), 56);
        write_i32_be(&mut buf, 0); // the single export hash slot
        assert_eq!(buf.len(), 60);

        let mut reader = BinaryReader::from_bytes(buf, false);
        let section = Box::new(MockSectionHeader { container_offset: 0 });
        LoaderInfoHeader::new(&mut reader, section).unwrap()
    }

    #[test]
    fn parses_symbol_class_offset_and_resolves_name() {
        let loader = loader_info_header_with(20);

        // symbolClass = kPEFCodeSymbol (0x00), symbolNameOffset = 0 -> name begins exactly at
        // loaderStringsOffset (20).
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0x0000_0000);
        buf.resize(20, 0);
        buf.extend_from_slice(b"foo\0");
        let mut reader = BinaryReader::from_bytes(buf, false);

        let symbol = ImportedSymbol::new(&mut reader, &loader).unwrap();

        assert_eq!(symbol.name(), "foo");
        assert_eq!(symbol.symbol_name_offset(), 0);
        assert_eq!(symbol.symbol_class(), Some(SymbolClass::Code));
        assert!(!symbol.is_weak());
    }

    #[test]
    fn weak_bit_and_name_offset_are_decoded_from_packed_word() {
        let loader = loader_info_header_with(10);

        // symbolClass = kPEFDataSymbol (0x01) | weak bit (0x80) = 0x81, symbolNameOffset = 5.
        let mut buf = Vec::new();
        write_i32_be(&mut buf, (0x81 << 24) | 5);
        buf.resize(15, 0); // loaderStringsOffset (10) + symbolNameOffset (5) = 15
        buf.extend_from_slice(b"bar\0");
        let mut reader = BinaryReader::from_bytes(buf, false);

        let symbol = ImportedSymbol::new(&mut reader, &loader).unwrap();

        assert_eq!(symbol.name(), "bar");
        assert_eq!(symbol.symbol_name_offset(), 5);
        assert_eq!(symbol.symbol_class(), Some(SymbolClass::Data));
        assert!(symbol.is_weak());
    }

    #[test]
    fn symbol_class_is_none_for_unknown_class_code() {
        // Faithful to Java's `SymbolClass.get(int)`, which returns `null` for a value that
        // doesn't match any of the six known constants (here, class code 5, masked to 0x5).
        let loader = loader_info_header_with(4);

        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0x0500_0000);
        buf.resize(4, 0);
        buf.push(0); // empty (zero-length) name
        let mut reader = BinaryReader::from_bytes(buf, false);

        let symbol = ImportedSymbol::new(&mut reader, &loader).unwrap();

        assert_eq!(symbol.symbol_class(), None);
    }

    #[test]
    fn advances_reader_past_the_four_byte_word_only() {
        let loader = loader_info_header_with(4);

        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0);
        buf.resize(4, 0);
        buf.push(0);
        let mut reader = BinaryReader::from_bytes(buf, false);

        ImportedSymbol::new(&mut reader, &loader).unwrap();

        // The name lookup is an absolute read via read_ascii_string, which must not disturb the
        // reader's sequential pointer index.
        assert_eq!(reader.get_pointer_index(), 4);
    }

    #[test]
    fn to_data_type_reports_fixed_length() {
        let loader = loader_info_header_with(4);
        let mut buf = Vec::new();
        write_i32_be(&mut buf, 0);
        buf.resize(4, 0);
        buf.push(0);
        let mut reader = BinaryReader::from_bytes(buf, false);
        let symbol = ImportedSymbol::new(&mut reader, &loader).unwrap();

        let dt = symbol.to_data_type().unwrap();
        assert_eq!(dt.get_length(), SIZEOF);
        assert_eq!(dt.get_name(), "ImportedSymbol");
    }
}
