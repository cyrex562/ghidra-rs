use std::io;

use crate::app::util::bin::binary_reader::{BinaryReader, SIZEOF_BYTE, SIZEOF_INT, SIZEOF_SHORT};
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::debug::debug_coff_symbol_table::DebugCOFFSymbolTable;
use crate::format::seam_stubs::DebugCOFFSymbolAux;
use crate::program::model::data::data_type::DataType;

/// The name field is a fixed-width 8-byte union when the symbol's short name is stored inline.
const NAME_LENGTH: usize = 8;

/// The size of `ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbolAux`'s `IMAGE_AUX_SYMBOL`
/// structure, in bytes. Duplicated here (rather than referenced from that class) because
/// `DebugCOFFSymbolAux` is not yet ported; see the field's own docs for why its instances are not
/// constructed here either.
const IMAGE_SIZEOF_AUX_SYMBOL: u64 = 18;

/// A class to represent the COFF symbol data structure.
///
/// Mirrors the `DebugCOFFSymbol` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct _IMAGE_SYMBOL {
///     union {
///         BYTE    ShortName[8];
///         struct {
///             DWORD   Short;     // if 0, use LongName
///             DWORD   Long;      // offset into string table
///         } Name;
///         DWORD   LongName[2];    // PBYTE [2]
///     } N;
///     DWORD   Value;
///     SHORT   SectionNumber;
///     WORD    Type;
///     BYTE    StorageClass;
///     BYTE    NumberOfAuxSymbols;
/// } IMAGE_SYMBOL;
/// ```
///
/// `DebugCOFFSymbolTable` (the only in-repo consumer) already stored its symbols as
/// `Vec<Box<dyn DebugCOFFSymbol>>` in anticipation of this port; per this crate's shape rule for a
/// concrete Java class with no subclasses, this ports as a plain `struct` instead, and
/// [`DebugCOFFSymbolTable`]'s field/constructor are updated to hold `DebugCOFFSymbol` by value.
///
/// The Java constructor also parses `numberOfAuxSymbols` trailing `DebugCOFFSymbolAux` entries.
/// That class is not yet ported (only a minimal `to_string`-only stub exists in
/// `format::seam_stubs`, with no constructor to call), so [`DebugCOFFSymbol::new`] cannot
/// construct real aux-symbol instances; it still reads `number_of_aux_symbols` faithfully and
/// advances the reader past the aux-symbol bytes (each `IMAGE_SIZEOF_AUX_SYMBOL` == 18 bytes, so
/// whatever follows in the file is read from the correct offset), but leaves
/// [`aux_symbols`](Self::aux_symbols) empty until `DebugCOFFSymbolAux` lands.
///
/// [`DebugCOFFSymbolTable`]: crate::format::pe::debug::debug_coff_symbol_table::DebugCOFFSymbolTable
pub struct DebugCOFFSymbol {
    name: Option<String>,
    value: i32,
    section_number: i16,
    type_: i16,
    storage_class: u8,
    number_of_aux_symbols: u8,
    aux_symbols: Vec<Box<dyn DebugCOFFSymbolAux>>,
}

impl DebugCOFFSymbol {
    /// The size of the `IMAGE_SYMBOL` structure.
    pub const IMAGE_SIZEOF_SYMBOL: i32 = 18;

    // Section values.
    pub const IMAGE_SYM_UNDEFINED: i16 = 0;
    pub const IMAGE_SYM_ABSOLUTE: i16 = -1;
    pub const IMAGE_SYM_DEBUG: i16 = -2;

    // Type (fundamental) values.
    pub const IMAGE_SYM_TYPE_NULL: i16 = 0x0000;
    pub const IMAGE_SYM_TYPE_VOID: i16 = 0x0001;
    pub const IMAGE_SYM_TYPE_CHAR: i16 = 0x0002;
    pub const IMAGE_SYM_TYPE_SHORT: i16 = 0x0003;
    pub const IMAGE_SYM_TYPE_INT: i16 = 0x0004;
    pub const IMAGE_SYM_TYPE_LONG: i16 = 0x0005;
    pub const IMAGE_SYM_TYPE_FLOAT: i16 = 0x0006;
    pub const IMAGE_SYM_TYPE_DOUBLE: i16 = 0x0007;
    pub const IMAGE_SYM_TYPE_STRUCT: i16 = 0x0008;
    pub const IMAGE_SYM_TYPE_UNION: i16 = 0x0009;
    pub const IMAGE_SYM_TYPE_ENUM: i16 = 0x000A;
    pub const IMAGE_SYM_TYPE_MOE: i16 = 0x000B;
    pub const IMAGE_SYM_TYPE_BYTE: i16 = 0x000C;
    pub const IMAGE_SYM_TYPE_WORD: i16 = 0x000D;
    pub const IMAGE_SYM_TYPE_UINT: i16 = 0x000E;
    pub const IMAGE_SYM_TYPE_DWORD: i16 = 0x000F;
    pub const IMAGE_SYM_TYPE_PCODE: i16 = 0x8000u16 as i16;

    // Type (derived) values.
    pub const IMAGE_SYM_DTYPE_NULL: i16 = 0;
    pub const IMAGE_SYM_DTYPE_POINTER: i16 = 1;
    pub const IMAGE_SYM_DTYPE_FUNCTION: i16 = 2;
    pub const IMAGE_SYM_DTYPE_ARRAY: i16 = 3;

    // Storage classes.
    pub const IMAGE_SYM_CLASS_END_OF_FUNCTION: u8 = 0xff;
    pub const IMAGE_SYM_CLASS_NULL: u8 = 0x00;
    pub const IMAGE_SYM_CLASS_AUTOMATIC: u8 = 0x01;
    pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 0x02;
    pub const IMAGE_SYM_CLASS_STATIC: u8 = 0x03;
    pub const IMAGE_SYM_CLASS_REGISTER: u8 = 0x04;
    pub const IMAGE_SYM_CLASS_EXTERNAL_DEF: u8 = 0x05;
    pub const IMAGE_SYM_CLASS_LABEL: u8 = 0x06;
    pub const IMAGE_SYM_CLASS_UNDEFINED_LABEL: u8 = 0x07;
    pub const IMAGE_SYM_CLASS_MEMBER_OF_STRUCT: u8 = 0x08;
    pub const IMAGE_SYM_CLASS_ARGUMENT: u8 = 0x09;
    pub const IMAGE_SYM_CLASS_STRUCT_TAG: u8 = 0x0A;
    pub const IMAGE_SYM_CLASS_MEMBER_OF_UNION: u8 = 0x0B;
    pub const IMAGE_SYM_CLASS_UNION_TAG: u8 = 0x0C;
    pub const IMAGE_SYM_CLASS_TYPE_DEFINITION: u8 = 0x0D;
    pub const IMAGE_SYM_CLASS_UNDEFINED_STATIC: u8 = 0x0E;
    pub const IMAGE_SYM_CLASS_ENUM_TAG: u8 = 0x0F;
    pub const IMAGE_SYM_CLASS_MEMBER_OF_ENUM: u8 = 0x10;
    pub const IMAGE_SYM_CLASS_REGISTER_PARAM: u8 = 0x11;
    pub const IMAGE_SYM_CLASS_BIT_FIELD: u8 = 0x12;
    pub const IMAGE_SYM_CLASS_FAR_EXTERNAL: u8 = 0x44;
    pub const IMAGE_SYM_CLASS_BLOCK: u8 = 0x64;
    pub const IMAGE_SYM_CLASS_FUNCTION: u8 = 0x65;
    pub const IMAGE_SYM_CLASS_END_OF_STRUCT: u8 = 0x66;
    pub const IMAGE_SYM_CLASS_FILE: u8 = 0x67;
    pub const IMAGE_SYM_CLASS_SECTION: u8 = 0x68;
    pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 0x69;

    /// Creates a new `DebugCOFFSymbol` by reading from the given binary reader, taking the
    /// string table index from `symbol_table`.
    ///
    /// Mirrors the Java constructor `DebugCOFFSymbol(BinaryReader, int, DebugCOFFSymbolTable)`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new_with_table(
        reader: &dyn BinaryReader,
        index: u64,
        symbol_table: &DebugCOFFSymbolTable,
    ) -> io::Result<Self> {
        Self::new(reader, index, symbol_table.get_string_table_index())
    }

    /// Creates a new `DebugCOFFSymbol` by reading from the given binary reader.
    ///
    /// Mirrors the Java constructor `DebugCOFFSymbol(BinaryReader, int, long)`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, mut index: u64, string_table_index: u64) -> io::Result<Self> {
        // Read the union first.
        let mut name = None;
        let short_val = reader.read_int(index)?;
        if short_val != 0 {
            name = Some(reader.read_ascii_string_fixed(index, NAME_LENGTH)?.trim().to_string());
            index += 8;
        } else {
            index += SIZEOF_INT;
            let long_val = reader.read_int(index)?;
            index += SIZEOF_INT;
            if long_val > 0 {
                name = Some(reader.read_ascii_string(string_table_index + long_val as u64)?);
            }
        }

        let value = reader.read_int(index)?;
        index += SIZEOF_INT;
        let section_number = reader.read_short(index)?;
        index += SIZEOF_SHORT;
        let type_ = reader.read_short(index)?;
        index += SIZEOF_SHORT;
        let storage_class = reader.read_byte(index)?;
        index += SIZEOF_BYTE;
        let number_of_aux_symbols = reader.read_byte(index)?;
        index += SIZEOF_BYTE;

        // See the struct's own docs for why aux symbols are counted but not constructed.
        for _ in 0..number_of_aux_symbols {
            index += IMAGE_SIZEOF_AUX_SYMBOL;
        }

        Ok(DebugCOFFSymbol {
            name,
            value,
            section_number,
            type_,
            storage_class,
            number_of_aux_symbols,
            aux_symbols: Vec::new(),
        })
    }

    /// Returns the auxiliary symbols related to this symbol.
    pub fn get_auxiliary_symbols(&self) -> &[Box<dyn DebugCOFFSymbolAux>] {
        &self.aux_symbols
    }

    /// Returns the name of this symbol.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the value of this symbol.
    pub fn get_value(&self) -> i32 {
        self.value
    }

    /// Returns a string equivalent of the value of this symbol.
    pub fn get_value_as_string(&self) -> String {
        format!("{:x}", self.value)
    }

    /// Returns the section number of this symbol.
    pub fn get_section_number(&self) -> i32 {
        self.section_number as i32
    }

    /// Returns a string equivalent of the section number of this symbol.
    pub fn get_section_number_as_string(&self) -> String {
        match self.section_number {
            Self::IMAGE_SYM_UNDEFINED => "UNDEF".to_string(),
            Self::IMAGE_SYM_ABSOLUTE => "ABS".to_string(),
            Self::IMAGE_SYM_DEBUG => "DEBUG".to_string(),
            other => format!("{:x}", (other as u16)),
        }
    }

    /// Returns the type of this symbol.
    pub fn get_type(&self) -> i32 {
        self.type_ as i32
    }

    /// Returns a string equivalent of the type of this symbol.
    pub fn get_type_as_string(&self) -> String {
        format!("{:x}", self.type_ as u16)
    }

    /// Returns the storage class of this symbol.
    pub fn get_storage_class(&self) -> i32 {
        self.storage_class as i32
    }

    /// Returns a string equivalent of the storage class of this symbol.
    pub fn get_storage_class_as_string(&self) -> String {
        match self.storage_class {
            Self::IMAGE_SYM_CLASS_END_OF_FUNCTION => "END_OF_FUNCTION".to_string(),
            Self::IMAGE_SYM_CLASS_NULL => "NULL".to_string(),
            Self::IMAGE_SYM_CLASS_AUTOMATIC => "AUTOMATIC".to_string(),
            Self::IMAGE_SYM_CLASS_EXTERNAL => "EXTERNAL".to_string(),
            Self::IMAGE_SYM_CLASS_STATIC => "STATIC".to_string(),
            Self::IMAGE_SYM_CLASS_REGISTER => "REGISTER".to_string(),
            Self::IMAGE_SYM_CLASS_EXTERNAL_DEF => "EXTERNAL_DEF".to_string(),
            Self::IMAGE_SYM_CLASS_LABEL => "LABEL".to_string(),
            Self::IMAGE_SYM_CLASS_UNDEFINED_LABEL => "UNDEFINED_LABEL".to_string(),
            Self::IMAGE_SYM_CLASS_MEMBER_OF_STRUCT => "MEMBER_OF_STRUCT".to_string(),
            Self::IMAGE_SYM_CLASS_ARGUMENT => "ARGUMENT".to_string(),
            Self::IMAGE_SYM_CLASS_STRUCT_TAG => "STRUCT_TAG".to_string(),
            Self::IMAGE_SYM_CLASS_MEMBER_OF_UNION => "MEMBER_OF_UNION".to_string(),
            Self::IMAGE_SYM_CLASS_UNION_TAG => "UNION_TAG".to_string(),
            Self::IMAGE_SYM_CLASS_TYPE_DEFINITION => "TYPE_DEFINITION".to_string(),
            Self::IMAGE_SYM_CLASS_UNDEFINED_STATIC => "UNDEFINED_STATIC".to_string(),
            Self::IMAGE_SYM_CLASS_ENUM_TAG => "ENUM_TAG".to_string(),
            Self::IMAGE_SYM_CLASS_MEMBER_OF_ENUM => "MEMBER_OF_ENUM".to_string(),
            Self::IMAGE_SYM_CLASS_REGISTER_PARAM => "REGISTER_PARAM".to_string(),
            Self::IMAGE_SYM_CLASS_BIT_FIELD => "BIT_FIELD".to_string(),
            Self::IMAGE_SYM_CLASS_FAR_EXTERNAL => "FAR_EXTERNAL".to_string(),
            Self::IMAGE_SYM_CLASS_BLOCK => "BLOCK".to_string(),
            Self::IMAGE_SYM_CLASS_FUNCTION => "FUNCTION".to_string(),
            Self::IMAGE_SYM_CLASS_END_OF_STRUCT => "END_OF_STRUCT".to_string(),
            Self::IMAGE_SYM_CLASS_FILE => "FILE".to_string(),
            Self::IMAGE_SYM_CLASS_SECTION => "SECTION".to_string(),
            Self::IMAGE_SYM_CLASS_WEAK_EXTERNAL => "WEAK_EXTERNAL".to_string(),
            other => format!("STORAGE_CLASS_{:x}", other),
        }
    }

    /// Returns the number of auxiliary symbols defined with this symbol.
    pub fn get_number_of_aux_symbols(&self) -> i32 {
        self.number_of_aux_symbols as i32
    }
}

impl StructConverter for DebugCOFFSymbol {
    /// Mirrors `toDataType()`. Not yet buildable: it requires `StructureDataType` (a mutable,
    /// constructible `Structure`) and `DebugCOFFSymbolAux::toDataType`, neither of which is
    /// ported yet (see the struct's own docs on `aux_symbols`).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "DebugCOFFSymbol::to_data_type requires StructureDataType, which is not yet ported",
        )))
    }
}

impl std::fmt::Display for DebugCOFFSymbol {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} section={} value=0x{:x} type=0x{:x} class=0x{:x} aux={}",
            self.name.as_deref().unwrap_or(""),
            self.section_number,
            self.value,
            self.type_,
            self.storage_class,
            self.number_of_aux_symbols
        )
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

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
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
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    /// Builds an `IMAGE_SYMBOL` record with an inline short name (union's first 4 bytes
    /// non-zero), matching the layout `DebugCOFFSymbol::new` expects.
    fn short_name_symbol_bytes(name: &str, value: i32, section: i16, type_: i16, storage_class: u8) -> Vec<u8> {
        let mut data = Vec::new();
        let mut name_bytes = [0u8; 8];
        let bytes = name.as_bytes();
        name_bytes[..bytes.len()].copy_from_slice(bytes);
        data.extend_from_slice(&name_bytes);
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(&section.to_le_bytes());
        data.extend_from_slice(&type_.to_le_bytes());
        data.push(storage_class);
        data.push(0); // numberOfAuxSymbols
        data
    }

    #[test]
    fn parses_inline_short_name() {
        let data = short_name_symbol_bytes("main", 0x1000, 1, 0x20, DebugCOFFSymbol::IMAGE_SYM_CLASS_EXTERNAL);
        let reader = MockReader::new(data, true);
        let sym = DebugCOFFSymbol::new(&reader, 0, 0).expect("failed to parse symbol");
        assert_eq!(sym.get_name(), Some("main"));
        assert_eq!(sym.get_value(), 0x1000);
        assert_eq!(sym.get_section_number(), 1);
        assert_eq!(sym.get_type(), 0x20);
        assert_eq!(sym.get_storage_class(), DebugCOFFSymbol::IMAGE_SYM_CLASS_EXTERNAL as i32);
        assert_eq!(sym.get_number_of_aux_symbols(), 0);
    }

    #[test]
    fn parses_long_name_from_string_table() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes()); // Short == 0 -> use long name
        data.extend_from_slice(&4i32.to_le_bytes()); // Long: offset 4 into string table
        data.extend_from_slice(&0x2000i32.to_le_bytes()); // value
        data.extend_from_slice(&(-1i16).to_le_bytes()); // sectionNumber ABSOLUTE
        data.extend_from_slice(&0i16.to_le_bytes()); // type
        data.push(DebugCOFFSymbol::IMAGE_SYM_CLASS_STATIC); // storageClass
        data.push(0); // numberOfAuxSymbols

        // String table starts at offset 100; the name lives at 100 + 4.
        let string_table_index: u64 = 100;
        let mut full = data.clone();
        full.resize(100, 0);
        full.extend_from_slice(b"\0\0\0\0longsymbolname\0");

        let reader = MockReader::new(full, true);
        let sym = DebugCOFFSymbol::new(&reader, 0, string_table_index).expect("failed to parse symbol");
        assert_eq!(sym.get_name(), Some("longsymbolname"));
        assert_eq!(sym.get_section_number_as_string(), "ABS");
        assert_eq!(sym.get_storage_class_as_string(), "STATIC");
    }

    #[test]
    fn to_string_matches_java_format() {
        let data = short_name_symbol_bytes("foo", 0x10, 2, 0x30, DebugCOFFSymbol::IMAGE_SYM_CLASS_LABEL);
        let reader = MockReader::new(data, true);
        let sym = DebugCOFFSymbol::new(&reader, 0, 0).expect("failed to parse symbol");
        assert_eq!(
            sym.to_string(),
            "foo section=2 value=0x10 type=0x30 class=0x6 aux=0"
        );
    }
}
