//! Port of `ghidra.app.util.bin.format.elf.ElfSymbol`.
//!
//! The ELF 32-bit and 64-bit symbol data structures:
//!
//! ```text
//! typedef struct {
//!     Elf32_Word      st_name;     //Symbol name (string tbl index)
//!     Elf32_Addr      st_value;    //Symbol value
//!     Elf32_Word      st_size;     //Symbol size
//!     unsigned char   st_info;     //Symbol type and binding
//!     unsigned char   st_other;    //Symbol visibility
//!     Elf32_Section   st_shndx;    //Section index
//! } Elf32_Sym;
//!
//! typedef struct {
//!     Elf64_Word       st_name;    //Symbol name (string tbl index)
//!     unsigned char    st_info;    //Symbol type and binding
//!     unsigned char    st_other;   //Symbol visibility
//!     Elf64_Section    st_shndx;   //Section index
//!     Elf64_Addr       st_value;   //Symbol value
//!     Elf64_Xword      st_size;    //Symbol size
//! } Elf64_Sym;
//! ```
//!
//! Two deliberate departures from the Java class:
//!
//! * The `st_*` members are unsigned in the ELF ABI and are modeled with unsigned Rust types
//!   (Java has no unsigned primitives, so `ElfSymbol.java` stores them signed and reaches for
//!   `Short.toUnsignedInt`/`Short.compareUnsigned` at every use site).
//! * The Java class keeps a back-pointer to the `ElfSymbolTable` that owns it. A child holding a
//!   reference to its owner is a reference cycle in Rust, so the (single) operation that needs the
//!   table -- [`ElfSymbol::get_extended_section_header_index`] -- takes it as a parameter instead.
//!   [`ElfSymbol::get_symbol_table_index`] still identifies the symbol within its table.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::elf::elf_section_header_constants::{
    SHN_HIPROC, SHN_LOPROC, SHN_LORESERVE, SHN_UNDEF,
};
use crate::format::elf::elf_section_header_constants::{SHN_ABS, SHN_COMMON};
use crate::format::seam_stubs::{ElfHeader, ElfStringTable, ElfSymbolTable};

/// Name reported by [`ElfSymbol::get_formatted_name`] for a symbol with no usable name.
pub const FORMATTED_NO_NAME: &str = "<no name>";

/// Local symbols are not visible outside the object file containing their definition.
pub const STB_LOCAL: u8 = 0;
/// Global symbols are visible to all object files being combined.
pub const STB_GLOBAL: u8 = 1;
/// Weak symbols resemble global symbols, but their definitions have lower precedence.
pub const STB_WEAK: u8 = 2;
/// Symbol is unique in namespace.
pub const STB_GNU_UNIQUE: u8 = 10;

/// The symbol's type is not specified.
pub const STT_NOTYPE: u8 = 0;
/// The symbol is associated with a data object, such as a variable, an array, etc.
pub const STT_OBJECT: u8 = 1;
/// The symbol is associated with a function or other executable code.
pub const STT_FUNC: u8 = 2;
/// The symbol is associated with a section. (Used for relocation and normally have `STB_LOCAL`
/// binding.)
pub const STT_SECTION: u8 = 3;
/// The symbol's name gives the name of the source file associated with the object file.
pub const STT_FILE: u8 = 4;
/// An uninitialized common block.
pub const STT_COMMON: u8 = 5;
/// Thread local storage symbol.
///
/// In object files `st_value` contains the offset from the beginning of the section; in DSOs it
/// contains the offset in the TLS initialization image (inside of `.tdata`).
pub const STT_TLS: u8 = 6;
/// Symbol is in support of complex relocation.
pub const STT_RELC: u8 = 8;
/// Symbol is in support of complex relocation (signed value).
pub const STT_SRELC: u8 = 9;

/// Default symbol visibility rules.
pub const STV_DEFAULT: u8 = 0;
/// Processor specific hidden class.
pub const STV_INTERNAL: u8 = 1;
/// Symbol unavailable in other modules.
pub const STV_HIDDEN: u8 = 2;
/// Not preemptible, not exported.
pub const STV_PROTECTED: u8 = 3;

/// A single ELF symbol table entry.
#[derive(Debug, Clone)]
pub struct ElfSymbol {
    symbol_table_index: u32,

    st_name: u32,
    st_value: u64,
    st_size: u64,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,

    /// `None` until [`ElfSymbol::init_symbol_name`] resolves it against the string table (or,
    /// for a section symbol with no name index, until the section supplies it).
    name_as_string: Option<String>,
}

impl Default for ElfSymbol {
    /// The special null symbol, as produced by the Java no-argument constructor.
    fn default() -> Self {
        ElfSymbol {
            symbol_table_index: 0,
            st_name: 0,
            st_value: 0,
            st_size: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            name_as_string: Some(String::new()),
        }
    }
}

impl ElfSymbol {
    /// Construct the special null symbol which corresponds to symbol index 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a normal `ElfSymbol` from the reader's current position.
    ///
    /// Warning: [`init_symbol_name`](Self::init_symbol_name) must be called on the symbol later to
    /// initialize the string name. This is a performance enhancement.
    ///
    /// # Arguments
    /// * `reader` - reads the symbol entry at the current position (the reader is not retained,
    ///   its position is altered)
    /// * `symbol_index` - index of the symbol being read
    /// * `header` - ELF header
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during parse.
    pub fn parse(
        reader: &mut impl BinaryReader,
        symbol_index: u32,
        header: &impl ElfHeader,
    ) -> io::Result<Self> {
        let (st_name, st_value, st_size, st_info, st_other, st_shndx) = if header.is32_bit() {
            let st_name = reader.read_next_int()? as u32;
            let st_value = reader.read_next_unsigned_int()?;
            let st_size = reader.read_next_unsigned_int()?;
            let st_info = reader.read_next_byte()?;
            let st_other = reader.read_next_byte()?;
            let st_shndx = reader.read_next_short()? as u16;
            (st_name, st_value, st_size, st_info, st_other, st_shndx)
        } else {
            let st_name = reader.read_next_int()? as u32;
            let st_info = reader.read_next_byte()?;
            let st_other = reader.read_next_byte()?;
            let st_shndx = reader.read_next_short()? as u16;
            let st_value = reader.read_next_long()? as u64;
            let st_size = reader.read_next_long()? as u64;
            (st_name, st_value, st_size, st_info, st_other, st_shndx)
        };

        let mut symbol = ElfSymbol {
            symbol_table_index: symbol_index,
            st_name,
            st_value,
            st_size,
            st_info,
            st_other,
            st_shndx,
            // Resolved later, by init_symbol_name() or from the section below.
            name_as_string: None,
        };

        // A section symbol has no name of its own; it borrows the name of the section it labels.
        // Any other named symbol has its string resolved later, in init_symbol_name().
        if symbol.st_name == 0 && symbol.get_type() == STT_SECTION {
            let sections = header.get_sections();
            // FIXME: handle extended section indexing
            let section_index = symbol.st_shndx as usize;
            if symbol.st_shndx < SHN_LORESERVE && section_index < sections.len() {
                symbol.name_as_string = Some(sections[section_index].get_name_as_string());
            }
        }

        Ok(symbol)
    }

    /// Initialize the string name of the symbol.
    ///
    /// NOTE: this routine MUST be called for each `ElfSymbol` after the ELF symbols have been
    /// created.
    ///
    /// This is done separately from the initial symbol entry read because the string names are in
    /// a separate location. If they are read at the same time the reading buffer will jump around
    /// and significantly degrade reading performance.
    ///
    /// # Arguments
    /// * `reader` - reader to read from (position remains unchanged)
    /// * `string_table` - string table used to resolve the name
    pub fn init_symbol_name(&mut self, reader: &dyn BinaryReader, string_table: &impl ElfStringTable) {
        if self.name_as_string.is_none() {
            self.name_as_string = Some(string_table.read_string(reader, self.st_name as i64));
        }
    }

    /// The index of this symbol within its symbol table.
    pub fn get_symbol_table_index(&self) -> u32 {
        self.symbol_table_index
    }

    /// Returns true if this symbol's type is not specified.
    pub fn is_no_type(&self) -> bool {
        self.get_type() == STT_NOTYPE
    }

    /// Returns true if this symbol is local.
    ///
    /// Local symbols are not visible outside the object file containing their definition. Local
    /// symbols of the same name may exist in multiple files without colliding.
    pub fn is_local(&self) -> bool {
        self.get_bind() == STB_LOCAL
    }

    /// Returns true if this symbol is global.
    ///
    /// Global symbols are visible to all object files being combined. One object file's definition
    /// of a global symbol will satisfy another file's undefined reference to the same global
    /// symbol.
    pub fn is_global(&self) -> bool {
        self.get_bind() == STB_GLOBAL
    }

    /// Returns true if this symbol is weak.
    ///
    /// Weak symbols resemble global symbols, but their definitions have lower precedence.
    pub fn is_weak(&self) -> bool {
        self.get_bind() == STB_WEAK
    }

    /// Returns true if this is an external symbol, i.e. its binding is global (or weak) and it has
    /// no value, size, type or defining section.
    pub fn is_external(&self) -> bool {
        (self.is_global() || self.is_weak())
            && self.get_value() == 0
            && self.get_size() == 0
            && self.get_type() == STT_NOTYPE
            && self.get_section_header_index() == SHN_UNDEF
    }

    /// Returns true if this symbol defines a section.
    pub fn is_section(&self) -> bool {
        self.get_type() == STT_SECTION
    }

    /// Returns true if this symbol defines a function.
    pub fn is_function(&self) -> bool {
        self.get_type() == STT_FUNC
    }

    /// Returns true if this symbol defines an object.
    pub fn is_object(&self) -> bool {
        self.get_type() == STT_OBJECT
    }

    /// Returns true if this symbol defines a file.
    pub fn is_file(&self) -> bool {
        self.get_type() == STT_FILE
    }

    /// Returns true if this symbol defines a thread-local symbol.
    pub fn is_tls(&self) -> bool {
        self.get_type() == STT_TLS
    }

    /// Returns true if the symbol has an absolute value that will not change because of
    /// relocation.
    pub fn is_absolute(&self) -> bool {
        self.st_shndx == SHN_ABS
    }

    /// Returns true if this symbol labels a common block that has not yet been allocated.
    ///
    /// The symbol's value gives alignment constraints, similar to a section's `sh_addralign`
    /// member: the link editor will allocate the storage for the symbol at an address that is a
    /// multiple of `st_value`. The symbol's size tells how many bytes are required.
    pub fn is_common(&self) -> bool {
        self.st_shndx == SHN_COMMON
    }

    /// The symbol's type and binding attributes (`st_info`).
    pub fn get_info(&self) -> u8 {
        self.st_info
    }

    /// The symbol's visibility, e.g. [`STV_DEFAULT`].
    pub fn get_visibility(&self) -> u8 {
        self.st_other & 0x03
    }

    /// The symbol's binding, e.g. [`STB_GLOBAL`].
    pub fn get_bind(&self) -> u8 {
        self.st_info >> 4
    }

    /// The symbol's type, e.g. [`STT_SECTION`].
    pub fn get_type(&self) -> u8 {
        self.st_info & 0x0f
    }

    /// The index (`st_name`) into the object file's symbol string table, which holds the character
    /// representations of the symbol names. If the value is non-zero, it gives the symbol name;
    /// otherwise the symbol table entry has no name.
    pub fn get_name(&self) -> u32 {
        self.st_name
    }

    /// The actual string name for this symbol, or `None` while it is still unresolved.
    ///
    /// The symbol itself only stores an index into the string table where the name is located; the
    /// name is filled in by [`init_symbol_name`](Self::init_symbol_name). May be an empty string.
    pub fn get_name_as_string(&self) -> Option<&str> {
        self.name_as_string.as_deref()
    }

    /// The formatted string name for this symbol. If the name is blank or could not be resolved
    /// due to a missing string table, the literal string [`FORMATTED_NO_NAME`] is returned.
    pub fn get_formatted_name(&self) -> &str {
        match &self.name_as_string {
            Some(name) if !name.trim().is_empty() => name,
            _ => FORMATTED_NO_NAME,
        }
    }

    /// The `st_other` member, which currently holds 0 and has no defined meaning.
    pub fn get_other(&self) -> u8 {
        self.st_other
    }

    /// The raw section index value (`st_shndx`) for this symbol.
    ///
    /// Special values (`SHN_LORESERVE` and higher) must be treated properly. The value
    /// `SHN_XINDEX` indicates that the extended value must be used to obtain the actual section
    /// index (see [`get_extended_section_header_index`](Self::get_extended_section_header_index)).
    pub fn get_section_header_index(&self) -> u16 {
        self.st_shndx
    }

    /// The extended symbol section index value, used when `st_shndx`
    /// ([`get_section_header_index`](Self::get_section_header_index)) has the value `SHN_XINDEX`.
    ///
    /// This requires a lookup into a table defined by an associated `SHT_SYMTAB_SHNDX` section, so
    /// the owning symbol table must be supplied. Symbols with no owning table (such as the null
    /// symbol from [`ElfSymbol::new`]) have an extended index of 0.
    pub fn get_extended_section_header_index(&self, symbol_table: &impl ElfSymbolTable) -> i32 {
        symbol_table.get_extended_section_index(self)
    }

    /// Determine if `st_shndx` is within the reserved processor-specific index range
    /// `SHN_LOPROC..=SHN_HIPROC`.
    pub fn has_processor_specific_symbol_section_index(&self) -> bool {
        (SHN_LOPROC..=SHN_HIPROC).contains(&self.st_shndx)
    }

    /// The symbol's size. Many symbols have associated sizes; for example, a data object's size is
    /// the number of bytes contained in the object. This is 0 if the symbol has no size or an
    /// unknown size.
    pub fn get_size(&self) -> u64 {
        self.st_size
    }

    /// The value of the associated symbol. Depending on the context this may be an absolute value,
    /// an address, etc.
    pub fn get_value(&self) -> u64 {
        self.st_value
    }
}

/// Mirrors `ElfSymbol.equals`: two symbols are equal when their raw entry fields and their index
/// within the symbol table match. The resolved name is derived state and is not compared.
impl PartialEq for ElfSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.st_info == other.st_info
            && self.st_name == other.st_name
            && self.st_other == other.st_other
            && self.st_shndx == other.st_shndx
            && self.st_size == other.st_size
            && self.st_value == other.st_value
            && self.symbol_table_index == other.symbol_table_index
    }
}

impl Eq for ElfSymbol {}

/// Hashes exactly the fields [`PartialEq`] compares, matching `ElfSymbol.hashCode`.
impl std::hash::Hash for ElfSymbol {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.st_info.hash(state);
        self.st_name.hash(state);
        self.st_other.hash(state);
        self.st_shndx.hash(state);
        self.st_size.hash(state);
        self.st_value.hash(state);
        self.symbol_table_index.hash(state);
    }
}

impl fmt::Display for ElfSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} - st_value: 0x{:x} - st_size: 0x{:x} - st_info: 0x{:x} - st_other: 0x{:x} - st_shndx: 0x{:x}",
            self.name_as_string.as_deref().unwrap_or(""),
            self.st_value,
            self.st_size,
            self.st_info,
            self.st_other,
            self.st_shndx
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::elf::elf_section_header_constants::SHN_XINDEX;
    use crate::format::seam_stubs::ElfSectionHeader;

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
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
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

    struct MockSection(&'static str);

    impl ElfSectionHeader for MockSection {
        fn get_name_as_string(&self) -> String {
            self.0.to_string()
        }
        fn get_elf_header(&self) -> std::sync::Arc<dyn ElfHeader> {
            std::sync::Arc::new(MockHeader { is32: true, section_names: Vec::new() })
        }
        fn get_address(&self) -> i64 {
            0
        }
        fn get_flags(&self) -> i64 {
            0
        }
        fn get_logical_size(&self) -> i64 {
            0
        }
    }

    struct MockHeader {
        is32: bool,
        section_names: Vec<&'static str>,
    }

    impl ElfHeader for MockHeader {
        fn is32_bit(&self) -> bool {
            self.is32
        }
        fn is_relocatable(&self) -> bool {
            false
        }
        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
            self.section_names
                .iter()
                .map(|n| Box::new(MockSection(n)) as Box<dyn ElfSectionHeader>)
                .collect()
        }
    }

    /// String table holding NUL-terminated names at byte offsets, read out of the same reader.
    struct MockStringTable {
        offset: u64,
    }

    impl ElfStringTable for MockStringTable {
        fn read_string(&self, reader: &dyn BinaryReader, string_offset: i64) -> String {
            reader.read_ascii_string(self.offset + string_offset as u64).unwrap()
        }
    }

    struct MockSymbolTable {
        extended_index: i32,
    }

    impl ElfSymbolTable for MockSymbolTable {
        fn get_extended_section_index(&self, _sym: &ElfSymbol) -> i32 {
            self.extended_index
        }
    }

    /// `Elf32_Sym`: name, value, size, info, other, shndx.
    fn sym32(name: u32, value: u32, size: u32, info: u8, other: u8, shndx: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&name.to_le_bytes());
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.push(info);
        data.push(other);
        data.extend_from_slice(&shndx.to_le_bytes());
        data
    }

    /// `Elf64_Sym`: name, info, other, shndx, value, size.
    fn sym64(name: u32, info: u8, other: u8, shndx: u16, value: u64, size: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&name.to_le_bytes());
        data.push(info);
        data.push(other);
        data.extend_from_slice(&shndx.to_le_bytes());
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data
    }

    fn header32() -> MockHeader {
        MockHeader { is32: true, section_names: vec![] }
    }

    fn header64() -> MockHeader {
        MockHeader { is32: false, section_names: vec![] }
    }

    #[test]
    fn null_symbol_matches_java_no_arg_constructor() {
        let sym = ElfSymbol::new();

        assert_eq!(sym.get_symbol_table_index(), 0);
        assert_eq!(sym.get_name(), 0);
        assert_eq!(sym.get_value(), 0);
        assert_eq!(sym.get_size(), 0);
        assert_eq!(sym.get_info(), 0);
        assert_eq!(sym.get_other(), 0);
        assert_eq!(sym.get_section_header_index(), SHN_UNDEF);
        // The Java no-arg constructor sets nameAsString to "" (not null), so the name is already
        // resolved and getFormattedName() falls back to the literal.
        assert_eq!(sym.get_name_as_string(), Some(""));
        assert_eq!(sym.get_formatted_name(), FORMATTED_NO_NAME);
        assert!(sym.is_no_type());
        assert!(sym.is_local());
    }

    #[test]
    fn parses_elf32_entry_field_order() {
        // st_info 0x12 == STB_GLOBAL | STT_FUNC
        let mut reader = MockReader::new(sym32(0x0d, 0x8048_400, 0x2a, 0x12, 0x02, 1));
        let sym = ElfSymbol::parse(&mut reader, 3, &header32()).unwrap();

        assert_eq!(sym.get_name(), 0x0d);
        assert_eq!(sym.get_value(), 0x0804_8400);
        assert_eq!(sym.get_size(), 42);
        assert_eq!(sym.get_info(), 0x12);
        assert_eq!(sym.get_bind(), STB_GLOBAL);
        assert_eq!(sym.get_type(), STT_FUNC);
        assert_eq!(sym.get_visibility(), STV_HIDDEN);
        assert_eq!(sym.get_other(), 0x02);
        assert_eq!(sym.get_section_header_index(), 1);
        assert_eq!(sym.get_symbol_table_index(), 3);
        assert!(sym.is_global() && sym.is_function() && !sym.is_local());
        // 16 bytes consumed: 4 + 4 + 4 + 1 + 1 + 2
        assert_eq!(reader.get_pointer_index(), 16);
        // Name is not resolved by the entry parse.
        assert_eq!(sym.get_name_as_string(), None);
        assert_eq!(sym.get_formatted_name(), FORMATTED_NO_NAME);
    }

    #[test]
    fn parses_elf64_entry_field_order() {
        // st_info 0x11 == STB_GLOBAL | STT_OBJECT
        let mut reader =
            MockReader::new(sym64(7, 0x11, 0x00, 5, 0x0000_7fff_dead_beef, 0x1_0000_0000));
        let sym = ElfSymbol::parse(&mut reader, 9, &header64()).unwrap();

        assert_eq!(sym.get_name(), 7);
        assert_eq!(sym.get_value(), 0x0000_7fff_dead_beef);
        assert_eq!(sym.get_size(), 0x1_0000_0000);
        assert_eq!(sym.get_bind(), STB_GLOBAL);
        assert_eq!(sym.get_type(), STT_OBJECT);
        assert_eq!(sym.get_visibility(), STV_DEFAULT);
        assert_eq!(sym.get_section_header_index(), 5);
        assert_eq!(sym.get_symbol_table_index(), 9);
        assert!(sym.is_object());
        // 24 bytes consumed: 4 + 1 + 1 + 2 + 8 + 8
        assert_eq!(reader.get_pointer_index(), 24);
    }

    #[test]
    fn elf32_value_and_size_are_read_unsigned() {
        // Java reads these with readNextUnsignedInt(), so 0xffff_fff0 must not sign-extend.
        let mut reader = MockReader::new(sym32(1, 0xffff_fff0, 0xffff_ffff, 0x11, 0, 1));
        let sym = ElfSymbol::parse(&mut reader, 1, &header32()).unwrap();

        assert_eq!(sym.get_value(), 0xffff_fff0);
        assert_eq!(sym.get_size(), 0xffff_ffff);
    }

    #[test]
    fn unnamed_section_symbol_takes_its_section_name() {
        let header = MockHeader { is32: false, section_names: vec!["", ".text", ".data"] };
        // st_name == 0, STT_SECTION (bind STB_LOCAL), shndx 2 -> ".data"
        let mut reader = MockReader::new(sym64(0, STT_SECTION, 0, 2, 0, 0));
        let sym = ElfSymbol::parse(&mut reader, 2, &header).unwrap();

        assert!(sym.is_section());
        assert_eq!(sym.get_name_as_string(), Some(".data"));
        assert_eq!(sym.get_formatted_name(), ".data");
    }

    #[test]
    fn section_symbol_with_reserved_or_out_of_range_index_stays_unnamed() {
        let header = MockHeader { is32: false, section_names: vec!["", ".text"] };

        // SHN_ABS is >= SHN_LORESERVE: it is not a section table index.
        let mut reader = MockReader::new(sym64(0, STT_SECTION, 0, SHN_ABS, 0, 0));
        let abs_sym = ElfSymbol::parse(&mut reader, 1, &header).unwrap();
        assert_eq!(abs_sym.get_name_as_string(), None);

        // In range of the u16 index space but past the end of the section list.
        let mut reader = MockReader::new(sym64(0, STT_SECTION, 0, 40, 0, 0));
        let oob_sym = ElfSymbol::parse(&mut reader, 2, &header).unwrap();
        assert_eq!(oob_sym.get_name_as_string(), None);
    }

    #[test]
    fn unnamed_non_section_symbol_is_not_named_from_sections() {
        let header = MockHeader { is32: false, section_names: vec!["", ".text"] };
        let mut reader = MockReader::new(sym64(0, STT_FUNC, 0, 1, 0x1000, 4));
        let sym = ElfSymbol::parse(&mut reader, 1, &header).unwrap();

        assert_eq!(sym.get_name_as_string(), None);
    }

    #[test]
    fn init_symbol_name_resolves_from_string_table_once() {
        let mut data = sym64(1, 0x12, 0, 1, 0x4000, 8);
        let string_table_offset = data.len() as u64;
        data.extend_from_slice(b"\0main\0other\0");

        let mut reader = MockReader::new(data);
        let mut sym = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        assert_eq!(sym.get_name_as_string(), None);

        let position_after_parse = reader.get_pointer_index();
        sym.init_symbol_name(&reader, &MockStringTable { offset: string_table_offset });

        assert_eq!(sym.get_name_as_string(), Some("main"));
        assert_eq!(sym.get_formatted_name(), "main");
        // "position remains unchanged"
        assert_eq!(reader.get_pointer_index(), position_after_parse);

        // A second call must not overwrite an already-resolved name.
        sym.init_symbol_name(&reader, &MockStringTable { offset: string_table_offset + 5 });
        assert_eq!(sym.get_name_as_string(), Some("main"));
    }

    #[test]
    fn formatted_name_falls_back_for_blank_names() {
        let mut data = sym64(1, 0x12, 0, 1, 0, 0);
        let string_table_offset = data.len() as u64;
        data.extend_from_slice(b"\0   \0");

        let mut reader = MockReader::new(data);
        let mut sym = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        sym.init_symbol_name(&reader, &MockStringTable { offset: string_table_offset });

        // StringUtils.isBlank() treats an all-whitespace name as blank.
        assert_eq!(sym.get_name_as_string(), Some("   "));
        assert_eq!(sym.get_formatted_name(), FORMATTED_NO_NAME);
    }

    #[test]
    fn is_external_requires_global_or_weak_undefined_notype() {
        // STB_GLOBAL | STT_NOTYPE, value 0, size 0, SHN_UNDEF
        let mut reader = MockReader::new(sym64(1, 0x10, 0, SHN_UNDEF, 0, 0));
        let external = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        assert!(external.is_external());

        // STB_WEAK | STT_NOTYPE also qualifies.
        let mut reader = MockReader::new(sym64(1, 0x20, 0, SHN_UNDEF, 0, 0));
        let weak = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        assert!(weak.is_weak() && weak.is_external());

        // Defined in a section -> not external.
        let mut reader = MockReader::new(sym64(1, 0x10, 0, 4, 0, 0));
        let defined = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        assert!(!defined.is_external());

        // Local binding -> not external.
        let mut reader = MockReader::new(sym64(1, 0x00, 0, SHN_UNDEF, 0, 0));
        let local = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        assert!(local.is_local() && !local.is_external());

        // Non-zero size -> not external.
        let mut reader = MockReader::new(sym64(1, 0x10, 0, SHN_UNDEF, 0, 8));
        let sized = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        assert!(!sized.is_external());
    }

    #[test]
    fn section_index_classification() {
        let abs = ElfSymbol { st_shndx: SHN_ABS, ..Default::default() };
        assert!(abs.is_absolute() && !abs.is_common());

        let common = ElfSymbol { st_shndx: SHN_COMMON, ..Default::default() };
        assert!(common.is_common() && !common.is_absolute());

        for shndx in [SHN_LOPROC, 0xff10, SHN_HIPROC] {
            let sym = ElfSymbol { st_shndx: shndx, ..Default::default() };
            assert!(
                sym.has_processor_specific_symbol_section_index(),
                "0x{shndx:x} should be processor-specific"
            );
        }
        for shndx in [SHN_UNDEF, 1, 0xfeff, SHN_HIPROC + 1, SHN_ABS, SHN_XINDEX] {
            let sym = ElfSymbol { st_shndx: shndx, ..Default::default() };
            assert!(
                !sym.has_processor_specific_symbol_section_index(),
                "0x{shndx:x} should not be processor-specific"
            );
        }
    }

    #[test]
    fn info_is_split_into_bind_and_type() {
        // Bind and type are the two nibbles of st_info; a GNU-unique binding lives in the high
        // nibble alongside an ordinary type.
        let sym = ElfSymbol { st_info: (STB_GNU_UNIQUE << 4) | STT_OBJECT, ..Default::default() };
        assert_eq!(sym.get_bind(), STB_GNU_UNIQUE);
        assert_eq!(sym.get_type(), STT_OBJECT);
        assert!(sym.is_object() && !sym.is_global());

        let tls = ElfSymbol { st_info: (STB_LOCAL << 4) | STT_TLS, ..Default::default() };
        assert!(tls.is_tls() && tls.is_local());

        let file = ElfSymbol { st_info: STT_FILE, ..Default::default() };
        assert!(file.is_file());
    }

    #[test]
    fn visibility_is_the_low_two_bits_of_other() {
        for (other, expected) in [
            (0x00, STV_DEFAULT),
            (0x01, STV_INTERNAL),
            (0x02, STV_HIDDEN),
            (0x03, STV_PROTECTED),
            // Upper bits are reserved and must be masked off.
            (0xfe, STV_HIDDEN),
        ] {
            let sym = ElfSymbol { st_other: other, ..Default::default() };
            assert_eq!(sym.get_visibility(), expected, "st_other 0x{other:x}");
            assert_eq!(sym.get_other(), other);
        }
    }

    #[test]
    fn extended_section_index_is_looked_up_in_the_owning_table() {
        let mut reader = MockReader::new(sym64(1, 0x10, 0, SHN_XINDEX, 0, 0));
        let sym = ElfSymbol::parse(&mut reader, 4, &header64()).unwrap();

        assert_eq!(sym.get_section_header_index(), SHN_XINDEX);
        assert_eq!(
            sym.get_extended_section_header_index(&MockSymbolTable { extended_index: 66 }),
            66
        );
    }

    #[test]
    fn equality_ignores_the_resolved_name() {
        let mut data = sym64(1, 0x12, 0, 1, 0x4000, 8);
        let string_table_offset = data.len() as u64;
        data.extend_from_slice(b"\0main\0");
        let mut reader = MockReader::new(data);

        let plain = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        let mut named = plain.clone();
        named.init_symbol_name(&reader, &MockStringTable { offset: string_table_offset });

        assert_eq!(named.get_name_as_string(), Some("main"));
        assert_eq!(plain, named);

        // ...but the symbol table index is part of identity.
        let mut other_index = plain.clone();
        other_index.symbol_table_index = 2;
        assert_ne!(plain, other_index);

        let mut other_value = plain.clone();
        other_value.st_value = 0x4001;
        assert_ne!(plain, other_value);

        assert_ne!(plain, ElfSymbol::new());
    }

    #[test]
    fn display_matches_java_to_string() {
        let mut data = sym64(1, 0x12, 0x03, 0xfff1, 0xdead_beef, 0x20);
        let string_table_offset = data.len() as u64;
        data.extend_from_slice(b"\0printf\0");
        let mut reader = MockReader::new(data);

        let mut sym = ElfSymbol::parse(&mut reader, 1, &header64()).unwrap();
        sym.init_symbol_name(&reader, &MockStringTable { offset: string_table_offset });

        assert_eq!(
            sym.to_string(),
            "printf - st_value: 0xdeadbeef - st_size: 0x20 - st_info: 0x12 - st_other: 0x3 - st_shndx: 0xfff1"
        );
    }
}
