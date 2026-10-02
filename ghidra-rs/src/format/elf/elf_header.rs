//! Port of `ghidra.app.util.bin.format.elf.ElfHeader`.
//!
//! A class to represent the Executable and Linking Format (ELF) header and specification:
//! construction reads the `Elf32_Ehdr`/`Elf64_Ehdr` identification and header fields from a
//! [`ByteProvider`]; [`ElfHeader::parse`] then reads the program headers, section headers,
//! dynamic table, string tables, dynamic library names and symbol tables.
//!
//! # Ownership
//!
//! Java's header and its children point at each other (every section/segment/table keeps an
//! `ElfHeader` back-pointer). Here the header *owns* its children in plain `Vec`s; each child
//! carries a copy of the small immutable [`ElfHeaderContext`] (word size, `e_type`, pre-link
//! base and load adapter) for the questions it used to ask its header, and the few child
//! operations that need the header's mutable registries take `&ElfHeader` at call time. Children
//! are identified by index where Java compares references (e.g. a string table's section).
//! Symbol tables are shared with relocation processing, so they are held as
//! `Arc<ElfSymbolTable>`.
//!
//! # Departures from the Java class
//!
//! * The pre-link image base (`getPreLinkImageBase`) is a pure function of the file's last 8
//!   bytes; it is computed once at construction instead of lazily, so that it can be copied into
//!   the children's [`ElfHeaderContext`].
//! * `ElfExtensionFactory.getLoadAdapter(this)` (a `ClassSearcher` scan for processor
//!   `ElfExtension`s whose `canHandle(ElfHeader)` accepts this image) has no ported extensions to
//!   find; with none, Java keeps the default [`ElfLoadAdapter`], which is what this port does.
//! * **Relocation tables are not parsed yet.** `parseRelocationTables` depends on
//!   `ElfRelocationTable`/`ElfRelocation`, which are still `format::seam_stubs` placeholders
//!   (parked); [`get_relocation_tables`](ElfHeader::get_relocation_tables) therefore has nothing
//!   to return until they are ported. Everything else `parse()` does is ported.
//! * `Msg.debug` diagnostics are dropped; `errorConsumer` messages are delivered unchanged.

use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::bin::unlimited_byte_provider_wrapper::UnlimitedByteProviderWrapper;
use crate::format::elf::elf_constants::{
    ELF_CLASS_32, ELF_CLASS_64, ELF_DATA_BE, ELF_DATA_LE, EI_DATA, EI_NIDENT, ET_DYN, ET_EXEC,
    ET_REL, MAGIC_BYTES, MAGIC_STR, PN_XNUM,
};
use crate::format::elf::elf_dynamic::ElfDynamic;
use crate::format::elf::elf_dynamic_table::ElfDynamicTable;
use crate::format::elf::elf_dynamic_type::{self, ElfDynamicType};
use crate::format::elf::elf_exception::ElfException;
use crate::format::elf::elf_file_section::ElfFileSection;
use crate::format::elf::elf_program_header::ElfProgramHeader;
use crate::format::elf::elf_program_header_constants::{PT_DYNAMIC, PT_LOAD, PT_PHDR};
use crate::format::elf::elf_program_header_type::{self, ElfProgramHeaderType};
use crate::format::elf::elf_section_header::ElfSectionHeader;
use crate::format::elf::elf_section_header_constants::{
    DOT_DYNSYM, SHN_LORESERVE, SHN_XINDEX, SHT_DYNAMIC, SHT_DYNSYM, SHT_GNU_VERDEF,
    SHT_GNU_VERNEED, SHT_NULL, SHT_STRTAB, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
};
use crate::format::elf::elf_section_header_type::{self, ElfSectionHeaderType};
use crate::format::elf::elf_string_table::ElfStringTable;
use crate::format::elf::elf_structs::{array, byte, dword, qword, string, word, ElfStruct};
use crate::format::elf::elf_symbol_table::ElfSymbolTable;
use crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter;
use crate::program::model::data::data_type::DataType;
use crate::util::exception::NotFoundException;

const MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE: i32 = 20;

const PAD_LENGTH: usize = 7;

/// `ElfConstants.EI_NIDENT + 18`: the bytes needed to sanity-check the header's endianness.
const INITIAL_READ_LEN: u64 = EI_NIDENT as u64 + 18;

/// The immutable, header-wide facts a section, segment or table needs from its owning
/// [`ElfHeader`]. Stands in for the Java children's `ElfHeader` back-pointer (see the
/// [module documentation](self)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeaderContext {
    /// `ElfHeader.is32Bit()`.
    pub is_32_bit: bool,
    /// `ElfHeader.isRelocatable()` (`e_type == ET_REL`).
    pub is_relocatable: bool,
    /// The pre-link image base, or `-1` if the image is not pre-linked.
    pre_link_image_base: i64,
    /// `ElfHeader.getLoadAdapter()`.
    pub load_adapter: ElfLoadAdapter,
}

impl ElfHeaderContext {
    /// `ElfHeader.adjustAddressForPrelink(long)`: adds the pre-link base (0 if none).
    pub fn adjust_address_for_prelink(&self, address: i64) -> i64 {
        let base = if self.pre_link_image_base == -1 { 0 } else { self.pre_link_image_base };
        base.wrapping_add(address)
    }

    /// `ElfHeader.unadjustAddressForPrelink(long)`: subtracts the pre-link base (0 if none).
    pub fn unadjust_address_for_prelink(&self, address: i64) -> i64 {
        let base = if self.pre_link_image_base == -1 { 0 } else { self.pre_link_image_base };
        address.wrapping_sub(base)
    }
}

/// A parsed ELF header and (after [`parse`](Self::parse)) its program headers, section headers,
/// dynamic table, string tables and symbol tables.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfHeader`.
pub struct ElfHeader {
    program_header_type_map: Option<HashMap<i32, ElfProgramHeaderType>>,
    section_header_type_map: Option<HashMap<i32, ElfSectionHeaderType>>,
    dynamic_type_map: Option<HashMap<i32, ElfDynamicType>>,

    /// original byte provider
    provider: Rc<dyn ByteProvider>,
    /// unlimited reader
    reader: BinaryReader,

    e_ident_class: u8,
    e_ident_data: u8,
    e_ident_version: u8,
    e_ident_osabi: u8,
    e_ident_abiversion: u8,
    e_ident_pad: Vec<u8>,
    e_type: i16,
    e_machine: i16,
    e_version: i32,
    e_entry: i64,
    e_phoff: i64,
    e_shoff: i64,
    e_flags: i32,
    e_ehsize: i16,
    e_phentsize: i16,
    e_phnum: i32,
    e_shentsize: i16,
    e_shnum: i32,
    e_shstrndx: i32,

    parsed: bool,
    parsed_section_headers: bool,

    elf_load_adapter: ElfLoadAdapter,
    pre_link_image_base: i64,

    section0: Option<ElfSectionHeader>,
    section_headers: Vec<ElfSectionHeader>,
    program_headers: Vec<ElfProgramHeader>,
    string_tables: Vec<ElfStringTable>,
    symbol_tables: Vec<Arc<ElfSymbolTable>>,
    dynamic_table: Option<ElfDynamicTable>,

    /// Index into `string_tables`.
    dynamic_string_table: Option<usize>,
    /// Index into `symbol_tables`.
    dynamic_symbol_table: Option<usize>,
    /// if SHT_SYMTAB_SHNDX sections exist
    has_extended_symbol_section_index_table: bool,

    dynamic_library_names: Vec<String>,

    has_little_endian_headers: bool,

    error_consumer: Box<dyn Fn(&str)>,

    elf_image_base: Cell<Option<i64>>,
}

impl std::fmt::Debug for ElfHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElfHeader")
            .field("e_ident_class", &self.e_ident_class)
            .field("e_ident_data", &self.e_ident_data)
            .field("e_type", &self.e_type)
            .field("e_machine", &self.e_machine)
            .field("e_entry", &self.e_entry)
            .field("e_phnum", &self.e_phnum)
            .field("e_shnum", &self.e_shnum)
            .finish_non_exhaustive()
    }
}

fn io_err(e: io::Error) -> ElfException {
    ElfException::from_cause(Box::new(e))
}

impl ElfHeader {
    /// Construct an `ElfHeader` from a byte provider, reading the ELF identification and header
    /// fields (not the program/section headers -- see [`parse`](Self::parse)).
    ///
    /// Mirrors `ElfHeader(ByteProvider, Consumer<String>)`; `None` for `error_consumer` discards
    /// error messages.
    ///
    /// # Errors
    /// `ElfException` if the header parse failed (bad magic, too short, unsupported `EI_CLASS`,
    /// or an IO error).
    pub fn new(
        provider: Rc<dyn ByteProvider>,
        error_consumer: Option<Box<dyn Fn(&str)>>,
    ) -> Result<Self, ElfException> {
        let error_consumer: Box<dyn Fn(&str)> = error_consumer.unwrap_or_else(|| Box::new(|_| {}));

        let magic = provider.read_bytes(0, MAGIC_BYTES.len() as u64).map_err(io_err)?;
        if magic != MAGIC_BYTES {
            return Err(ElfException::new("Not a valid ELF executable."));
        }

        let has_little_endian_headers =
            determine_header_endianness(provider.as_ref(), &*error_consumer)?;

        // reader uses unbounded provider wrapper to allow handling of missing/truncated headers
        let unlimited: Rc<dyn ByteProvider> =
            Rc::new(UnlimitedByteProviderWrapper::new(Rc::clone(&provider)));
        let mut reader = BinaryReader::new(unlimited, has_little_endian_headers);
        reader.set_pointer_index(MAGIC_BYTES.len() as u64);

        let e_ident_class = reader.read_next_byte().map_err(io_err)?;
        let e_ident_data = reader.read_next_byte().map_err(io_err)?;
        let e_ident_version = reader.read_next_byte().map_err(io_err)?;
        let e_ident_osabi = reader.read_next_byte().map_err(io_err)?;
        let e_ident_abiversion = reader.read_next_byte().map_err(io_err)?;
        let e_ident_pad = reader.read_next_byte_array(PAD_LENGTH).map_err(io_err)?;
        let e_type = reader.read_next_short().map_err(io_err)?;
        let e_machine = reader.read_next_short().map_err(io_err)?;
        let e_version = reader.read_next_int().map_err(io_err)?;

        let (e_entry, e_phoff, e_shoff) = if e_ident_class == ELF_CLASS_32 {
            (
                reader.read_next_unsigned_int().map_err(io_err)? as i64,
                reader.read_next_unsigned_int().map_err(io_err)? as i64,
                reader.read_next_unsigned_int().map_err(io_err)? as i64,
            )
        } else if e_ident_class == ELF_CLASS_64 {
            (
                reader.read_next_long().map_err(io_err)?,
                reader.read_next_long().map_err(io_err)?,
                reader.read_next_long().map_err(io_err)?,
            )
        } else {
            return Err(ElfException::new(format!(
                "Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x{:x})",
                e_ident_class as i8 as i32
            )));
        };

        let e_flags = reader.read_next_int().map_err(io_err)?;
        let e_ehsize = reader.read_next_short().map_err(io_err)?;
        let e_phentsize = reader.read_next_short().map_err(io_err)?;
        let phnum = reader.read_next_unsigned_short().map_err(io_err)? as i32;
        let e_shentsize = reader.read_next_short().map_err(io_err)?;
        let shnum = reader.read_next_unsigned_short().map_err(io_err)? as i32;
        let shstrndx = reader.read_next_unsigned_short().map_err(io_err)? as i32;

        let mut header = ElfHeader {
            program_header_type_map: None,
            section_header_type_map: None,
            dynamic_type_map: None,
            provider,
            reader,
            e_ident_class,
            e_ident_data,
            e_ident_version,
            e_ident_osabi,
            e_ident_abiversion,
            e_ident_pad,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum: phnum,
            e_shentsize,
            e_shnum: shnum,
            e_shstrndx: shstrndx,
            parsed: false,
            parsed_section_headers: false,
            elf_load_adapter: ElfLoadAdapter::new(),
            pre_link_image_base: -1,
            section0: None,
            section_headers: Vec::new(),
            program_headers: Vec::new(),
            string_tables: Vec::new(),
            symbol_tables: Vec::new(),
            dynamic_table: None,
            dynamic_string_table: None,
            dynamic_symbol_table: None,
            has_extended_symbol_section_index_table: false,
            dynamic_library_names: Vec::new(),
            has_little_endian_headers,
            error_consumer,
            elf_image_base: Cell::new(None),
        };
        header.pre_link_image_base = header.read_pre_link_image_base();

        if phnum == PN_XNUM as i32 {
            // use extended stored program header count
            header.e_phnum = header.read_extended_program_header_count().map_err(io_err)?;
        }
        if shnum == 0 || shnum >= SHN_LORESERVE as i32 {
            // use extended stored section header count
            header.e_shnum = header.read_extended_section_header_count().map_err(io_err)?;
        }
        if header.e_shnum == 0 {
            header.e_shstrndx = 0;
        } else if shstrndx == SHN_XINDEX as i32 {
            header.e_shstrndx =
                header.read_extended_section_header_string_table_index().map_err(io_err)?;
        }
        Ok(header)
    }

    /// The facts children copy from this header (see [`ElfHeaderContext`]).
    pub fn context(&self) -> ElfHeaderContext {
        ElfHeaderContext {
            is_32_bit: self.is32_bit(),
            is_relocatable: self.is_relocatable(),
            pre_link_image_base: self.pre_link_image_base,
            load_adapter: self.elf_load_adapter,
        }
    }

    /// The unconstrained binary reader (reads beyond EOF return 0-bytes).
    pub fn get_reader(&self) -> &BinaryReader {
        &self.reader
    }

    /// The original byte provider.
    pub fn get_byte_provider(&self) -> &Rc<dyn ByteProvider> {
        &self.provider
    }

    /// Reports `msg` to the error consumer. Mirrors the package-private `logError(String)`.
    pub fn log_error(&self, msg: &str) {
        (self.error_consumer)(msg);
    }

    fn get_section0(&mut self) -> io::Result<Option<&ElfSectionHeader>> {
        if self.section0.is_none() && self.e_shoff != 0 {
            if !self.provider_contains_region(self.e_shoff, self.e_shentsize as i32) {
                return Ok(None);
            }
            let s = ElfSectionHeader::new(self.reader.clone_at(self.e_shoff as u64), self)?;
            self.section0 = Some(s);
        }
        Ok(self.section0.as_ref())
    }

    /// Extended program header count (`e_phnum`) stored in the first (`SHT_NULL`) section
    /// header's `sh_info`, restricted to `0..=0x7fffffff`; 0 if not found or out of range.
    fn read_extended_program_header_count(&mut self) -> io::Result<i32> {
        if let Some(s) = self.get_section0()? {
            if s.get_type() == SHT_NULL as i32 {
                let val = s.get_info();
                return Ok(if val < 0 { 0 } else { val });
            }
        }
        Ok(0)
    }

    /// Extended section header count (`e_shnum`) stored in the first (`SHT_NULL`) section
    /// header's `sh_size`, restricted to `0..=0x7fffffff`; 0 if not found or out of range.
    fn read_extended_section_header_count(&mut self) -> io::Result<i32> {
        if let Some(s) = self.get_section0()? {
            if s.get_type() == SHT_NULL as i32 {
                let val = s.get_size();
                return Ok(if !(0..=i32::MAX as i64).contains(&val) { 0 } else { val as i32 });
            }
        }
        Ok(0)
    }

    /// Extended section header string table index (`e_shstrndx`) stored in the first
    /// (`SHT_NULL`) section header's `sh_link`; 0 if not found or out of range.
    fn read_extended_section_header_string_table_index(&mut self) -> io::Result<i32> {
        if let Some(s) = self.get_section0()? {
            if s.get_type() == SHT_NULL as i32 {
                let val = s.get_link();
                return Ok(if val < 0 { 0 } else { val });
            }
        }
        Ok(0)
    }

    fn init_elf_load_adapter(&mut self) {
        let mut program_header_type_map = HashMap::new();
        elf_program_header_type::add_default_types(&mut program_header_type_map);
        self.program_header_type_map = Some(program_header_type_map);

        let mut section_header_type_map = HashMap::new();
        elf_section_header_type::add_default_types(&mut section_header_type_map);
        self.section_header_type_map = Some(section_header_type_map);

        let mut dynamic_type_map = HashMap::new();
        elf_dynamic_type::add_default_types(&mut dynamic_type_map);
        self.dynamic_type_map = Some(dynamic_type_map);

        // ElfExtensionFactory.getLoadAdapter(this): no processor extensions are ported, so no
        // extension can handle this header and the default adapter stays installed.
    }

    /// Perform parse of all supported headers. Idempotent.
    ///
    /// # Errors
    /// Propagates a file IO error.
    pub fn parse(&mut self) -> io::Result<()> {
        if self.parsed {
            return Ok(());
        }

        self.init_elf_load_adapter();

        self.parsed = true;

        self.parse_program_headers()?;

        self.parse_section_headers()?;

        self.parse_dynamic_table()?;

        self.parse_string_tables();
        self.parse_dynamic_library_names();
        self.parse_symbol_tables()?;
        // parseRelocationTables(): not yet ported -- see the module documentation.

        self.parse_gnu_d();
        self.parse_gnu_r();
        Ok(())
    }

    /// The installed extension adapter. If [`parse`](Self::parse) has not yet been invoked, the
    /// default adapter is returned.
    pub fn get_load_adapter(&self) -> ElfLoadAdapter {
        self.elf_load_adapter
    }

    /// Adjust address offset for certain pre-linked binaries which do not adjust certain header
    /// fields (e.g., dynamic table address entries). Standard GNU/Linux pre-linked shared
    /// libraries have adjusted header entries and this method should have no effect.
    pub fn adjust_address_for_prelink(&self, address: i64) -> i64 {
        self.context().adjust_address_for_prelink(address)
    }

    /// Unadjust address offset for certain pre-linked binaries. This may be needed when updating
    /// a header address field which requires pre-link adjustment.
    pub fn unadjust_address_for_prelink(&self, address: i64) -> i64 {
        self.context().unadjust_address_for_prelink(address)
    }

    /// The program header type registry, or `None` before [`parse`](Self::parse).
    pub fn get_program_header_type_map(&self) -> Option<&HashMap<i32, ElfProgramHeaderType>> {
        self.program_header_type_map.as_ref()
    }

    /// The section header type registry, or `None` before [`parse`](Self::parse).
    pub fn get_section_header_type_map(&self) -> Option<&HashMap<i32, ElfSectionHeaderType>> {
        self.section_header_type_map.as_ref()
    }

    /// The program header type for `type_`, or `None` if not found.
    pub fn get_program_header_type(&self, type_: i32) -> Option<&ElfProgramHeaderType> {
        self.program_header_type_map.as_ref()?.get(&type_)
    }

    /// The section header type for `type_`, or `None` if not found.
    pub fn get_section_header_type(&self, type_: i32) -> Option<&ElfSectionHeaderType> {
        self.section_header_type_map.as_ref()?.get(&type_)
    }

    /// The dynamic type registry, or `None` before [`parse`](Self::parse).
    pub fn get_dynamic_type_map(&self) -> Option<&HashMap<i32, ElfDynamicType>> {
        self.dynamic_type_map.as_ref()
    }

    /// The dynamic type for `type_`, or `None` if not found.
    pub fn get_dynamic_type(&self, type_: i32) -> Option<&ElfDynamicType> {
        self.dynamic_type_map.as_ref()?.get(&type_)
    }

    /// The load adapter's data type suffix, or `None` if it has none (or an empty one). Mirrors
    /// the package-private `getTypeSuffix()`.
    pub fn get_type_suffix(&self) -> Option<String> {
        self.elf_load_adapter
            .get_data_type_suffix()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn parse_gnu_d(&self) {
        let sections = self.get_sections_of_type(SHT_GNU_VERDEF as i32);
        if sections.is_empty() {
            #[allow(clippy::needless_return)]
            return;
        }
        // Java: "TODO: ElfSectionHeader gnuVersionD = sections[0];" -- nothing is parsed.
    }

    fn parse_gnu_r(&self) {
        let sections = self.get_sections_of_type(SHT_GNU_VERNEED as i32);
        if sections.is_empty() {
            #[allow(clippy::needless_return)]
            return;
        }
        // Java: "TODO ElfSectionHeader gnuVersionR = sections[0];" -- nothing is parsed.
    }

    /// Linked section at `section_index`, optionally required to be one of `expected_types`.
    fn get_linked_section(
        &self,
        section_index: i32,
        expected_types: &[i32],
    ) -> Result<&ElfSectionHeader, NotFoundException> {
        if section_index < 0 || section_index as usize >= self.section_headers.len() {
            return Err(NotFoundException(format!(
                "invalid linked section index {section_index}"
            )));
        }
        let section = &self.section_headers[section_index as usize];
        if expected_types.is_empty() || expected_types.contains(&section.get_type()) {
            return Ok(section);
        }
        Err(NotFoundException(format!(
            "unexpected section type for section index {section_index}"
        )))
    }

    fn parse_dynamic_library_names(&mut self) {
        let Some(dynamic_table) = &self.dynamic_table else {
            self.dynamic_library_names = Vec::new();
            return;
        };

        let needed: Vec<&ElfDynamic> =
            dynamic_table.get_dynamics_of_type(&elf_dynamic_type::dt_needed());
        let log = |msg: &str| (self.error_consumer)(msg);
        let names: Vec<String> = needed
            .iter()
            .enumerate()
            .map(|(i, dyn_)| {
                self.dynamic_string_table
                    .map(|t| &self.string_tables[t])
                    .and_then(|st| st.read_string(&self.reader, dyn_.get_value() as i64, &log))
                    .unwrap_or_else(|| format!("UNK_LIB_NAME_{i}"))
            })
            .collect();
        self.dynamic_library_names = names;
    }

    fn parse_dynamic_table(&mut self) -> io::Result<()> {
        let dynamic_headers = self.get_program_headers_of_type(PT_DYNAMIC as i32);
        if dynamic_headers.len() == 1 {
            // no more than one expected

            // The p_offset may not refer to the start of the DYNAMIC table so we must use
            // p_vaddr to find it relative to a PT_LOAD segment
            let dyn_header = dynamic_headers[0];
            let vaddr = dyn_header.get_virtual_address();
            if vaddr == 0 || dyn_header.get_file_size() == 0 {
                self.log_error("ELF Dynamic table appears to have been stripped from binary");
                return Ok(());
            }

            // Assume p_offset can be used reliably if no corresponding PT_LOAD
            let load_header = self.get_program_load_header_containing(vaddr).unwrap_or(dyn_header);
            let dynamic_table_offset = load_header
                .get_offset()
                .wrapping_add(dyn_header.get_virtual_address().wrapping_sub(load_header.get_virtual_address()));
            let table = ElfDynamicTable::new(
                &self.reader,
                self,
                dynamic_table_offset,
                dyn_header.get_virtual_address(),
            )?;
            self.dynamic_table = Some(table);
            return Ok(());
        }
        if dynamic_headers.len() > 1 {
            self.log_error("Multiple ELF Dynamic table program headers found");
        }

        let dynamic_sections = self.get_sections_of_type(SHT_DYNAMIC as i32);
        if dynamic_sections.len() == 1 {
            let dyn_section = dynamic_sections[0];
            if let Some(load_header) =
                self.get_program_load_header_containing(dyn_section.get_address())
            {
                let dynamic_table_offset = load_header.get_offset().wrapping_add(
                    dyn_section.get_address().wrapping_sub(load_header.get_virtual_address()),
                );
                let table = ElfDynamicTable::new(
                    &self.reader,
                    self,
                    dynamic_table_offset,
                    dyn_section.get_address(),
                )?;
                self.dynamic_table = Some(table);
            }
        }
        Ok(())
    }

    fn parse_string_tables(&mut self) {
        // identify dynamic symbol table address
        let mut dynamic_string_table_addr: i64 = -1;
        if let Some(dynamic_table) = &self.dynamic_table {
            match dynamic_table.get_dynamic_value_of_type(&elf_dynamic_type::dt_strtab()) {
                Ok(v) => dynamic_string_table_addr = self.adjust_address_for_prelink(v),
                Err(_) => {
                    self.log_error("ELF does not contain a dynamic string table (DT_STRTAB)")
                }
            }
        }

        let ctx = self.context();
        let mut string_table_list = Vec::new();
        let mut dynamic_string_table = None;
        for (i, section) in self.section_headers.iter().enumerate() {
            if section.get_type() == SHT_STRTAB as i32 {
                let string_table = ElfStringTable::new(
                    ctx,
                    Some(i),
                    section.get_offset(),
                    section.get_address(),
                    section.get_size(),
                );
                if string_table.get_address_offset() == dynamic_string_table_addr {
                    dynamic_string_table = Some(string_table_list.len());
                }
                string_table_list.push(string_table);
            }
        }

        if dynamic_string_table.is_none() && dynamic_string_table_addr != -1 {
            if let Some(t) = self.parse_dynamic_string_table(dynamic_string_table_addr) {
                dynamic_string_table = Some(string_table_list.len());
                string_table_list.push(t);
            }
        }

        self.string_tables = string_table_list;
        self.dynamic_string_table = dynamic_string_table;
    }

    fn parse_dynamic_string_table(&self, dynamic_string_table_addr: i64) -> Option<ElfStringTable> {
        let dynamic_table = self.dynamic_table.as_ref()?;
        let strsz = elf_dynamic_type::dt_strsz();
        if !dynamic_table.contains_dynamic_value_of_type(&strsz) {
            self.log_error("Failed to parse DT_STRTAB, missing dynamic dependency");
            return None;
        }

        let string_table_size = dynamic_table
            .get_dynamic_value_of_type(&strsz)
            .expect("containsDynamicValue(DT_STRSZ) was just checked");

        if dynamic_string_table_addr == 0 {
            self.log_error(&format!(
                "ELF Dynamic String Table of size {string_table_size} appears to have been stripped from binary"
            ));
            return None;
        }

        let Some(string_table_load_header) =
            self.get_program_load_header_containing(dynamic_string_table_addr)
        else {
            self.log_error(&format!(
                "Failed to locate DT_STRTAB in memory at 0x{dynamic_string_table_addr:x}"
            ));
            return None;
        };

        let offset = match string_table_load_header.get_offset_of(dynamic_string_table_addr) {
            Ok(o) => o,
            Err(e) => {
                self.log_error(&e);
                return None;
            }
        };
        Some(ElfStringTable::new(
            self.context(),
            None,
            offset,
            dynamic_string_table_addr,
            string_table_size,
        ))
    }

    fn get_extended_symbol_section_index_table(
        &self,
        symbol_table_section_index: usize,
    ) -> Option<Vec<i32>> {
        if !self.has_extended_symbol_section_index_table {
            return None;
        }

        // Find SHT_SYMTAB_SHNDX section linked to specified symbol table section
        let n = self.section_headers.len();
        let symbol_section_index_header = self.section_headers.iter().find(|section| {
            if section.get_type() != SHT_SYMTAB_SHNDX as i32 {
                return false;
            }
            let link_index = section.get_link();
            link_index > 0 && (link_index as usize) < n && link_index as usize == symbol_table_section_index
        })?;

        // determine number of 32-bit index elements for int[]
        let count = (symbol_section_index_header.get_size() / 4) as i32;
        let mut index_table = vec![0i32; count.max(0) as usize];

        let mut r = self.reader.clone_at(symbol_section_index_header.get_offset() as u64);
        for slot in index_table.iter_mut() {
            match r.read_next_int() {
                Ok(v) => *slot = v,
                Err(_) => {
                    self.log_error(&format!(
                        "Failed to read symbol section index table at 0x{:x}: {}",
                        symbol_section_index_header.get_offset(),
                        symbol_section_index_header.get_name_as_string()
                    ));
                    break;
                }
            }
        }
        Some(index_table)
    }

    fn parse_symbol_tables(&mut self) -> io::Result<()> {
        // identify dynamic symbol table address
        let mut dynamic_symbol_table_addr: i64 = -1;
        if let Some(dynamic_table) = &self.dynamic_table {
            match dynamic_table.get_dynamic_value_of_type(&elf_dynamic_type::dt_symtab()) {
                Ok(v) => dynamic_symbol_table_addr = self.adjust_address_for_prelink(v),
                Err(_) => {
                    self.log_error("ELF does not contain a dynamic symbol table (DT_SYMTAB)")
                }
            }
        }

        // Add section based symbol tables
        let mut symbol_table_list: Vec<Arc<ElfSymbolTable>> = Vec::new();
        let mut dynamic_symbol_table = None;
        for (i, section) in self.section_headers.iter().enumerate() {
            let t = section.get_type();
            if t == SHT_SYMTAB as i32 || t == SHT_DYNSYM as i32 {
                if section.is_invalid_offset() {
                    continue;
                }

                // Java indexes sectionHeaders[link] directly (an out-of-range link throws).
                let link = section.get_link();
                if link < 0 || link as usize >= self.section_headers.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Index {link} out of bounds for length {}", self.section_headers.len()),
                    ));
                }
                let string_table_section = &self.section_headers[link as usize];
                let string_table = self.get_string_table(string_table_section).cloned();

                let is_dynamic = DOT_DYNSYM == section.get_name_as_string();

                // get extended symbol section index table if present
                let symbol_section_index_table = self.get_extended_symbol_section_index_table(i);

                let symbol_table = ElfSymbolTable::new(
                    &self.reader,
                    self,
                    Some(i),
                    section.get_offset(),
                    section.get_address(),
                    section.get_size(),
                    section.get_entry_size(),
                    string_table,
                    symbol_section_index_table,
                    is_dynamic,
                )?;
                if symbol_table.get_address_offset() == dynamic_symbol_table_addr {
                    // remember dynamic symbol table
                    dynamic_symbol_table = Some(symbol_table_list.len());
                }
                symbol_table_list.push(Arc::new(symbol_table));
            }
        }

        if dynamic_symbol_table.is_none() && dynamic_symbol_table_addr != -1 {
            if let Some(t) = self.parse_dynamic_symbol_table()? {
                dynamic_symbol_table = Some(symbol_table_list.len());
                symbol_table_list.push(Arc::new(t));
            }
        }

        self.symbol_tables = symbol_table_list;
        self.dynamic_symbol_table = dynamic_symbol_table;
        Ok(())
    }

    fn get_dynamic_hash_table_type(&self) -> Option<ElfDynamicType> {
        let dynamic_table = self.dynamic_table.as_ref()?;
        [elf_dynamic_type::dt_hash(), elf_dynamic_type::dt_gnu_hash(), elf_dynamic_type::dt_gnu_xhash()]
            .into_iter()
            .find(|t| dynamic_table.contains_dynamic_value_of_type(t))
    }

    fn parse_dynamic_symbol_table(&self) -> io::Result<Option<ElfSymbolTable>> {
        let Some(dynamic_table) = self.dynamic_table.as_ref() else {
            return Ok(None);
        };
        let dynamic_hash_type = self.get_dynamic_hash_table_type();
        let symtab = elf_dynamic_type::dt_symtab();
        let syment = elf_dynamic_type::dt_syment();

        let Some(dynamic_hash_type) = dynamic_hash_type.filter(|_| {
            dynamic_table.contains_dynamic_value_of_type(&symtab)
                && dynamic_table.contains_dynamic_value_of_type(&syment)
        }) else {
            if self.dynamic_string_table.is_some() {
                self.log_error("Failed to parse DT_SYMTAB, missing dynamic dependency");
            }
            return Ok(None);
        };

        let value = |t: &ElfDynamicType| {
            dynamic_table.get_dynamic_value_of_type(t).expect("presence was just checked")
        };

        let mut table_addr = value(&symtab);
        if table_addr == 0 {
            self.log_error("ELF Dynamic String Table of size appears to have been stripped from binary");
        }

        let Some(dynamic_string_table) = self.dynamic_string_table else {
            self.log_error("Failed to process DT_SYMTAB, missing dynamic string table");
            return Ok(None);
        };

        if table_addr == 0 {
            return Ok(None);
        }

        table_addr = self.adjust_address_for_prelink(table_addr);
        let table_entry_size = value(&syment);

        // Use dynamic symbol hash table DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH to determine
        // symbol table count/length
        let hash_table_addr = self.adjust_address_for_prelink(value(&dynamic_hash_type));

        let Some(symbol_table_load_header) = self.get_program_load_header_containing(table_addr)
        else {
            self.log_error(&format!("Failed to locate DT_SYMTAB in memory at 0x{table_addr:x}"));
            return Ok(None);
        };
        let Some(hash_table_load_header) = self.get_program_load_header_containing(hash_table_addr)
        else {
            self.log_error(&format!(
                "Failed to locate DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH in memory at 0x{hash_table_addr:x}"
            ));
            return Ok(None);
        };

        let unsupported = |e: String| io::Error::new(io::ErrorKind::Unsupported, e);

        // Create dynamic symbol table if not defined as a section
        let symbol_table_offset =
            symbol_table_load_header.get_offset_of(table_addr).map_err(unsupported)?;

        // determine symbol count from dynamic symbol hash table
        let symbol_hash_table_offset =
            hash_table_load_header.get_offset_of(hash_table_addr).map_err(unsupported)?;
        let sym_count = if dynamic_hash_type.value == elf_dynamic_type::dt_gnu_hash().value {
            self.derive_gnu_hash_dynamic_symbol_count(symbol_hash_table_offset)?
        } else if dynamic_hash_type.value == elf_dynamic_type::dt_gnu_xhash().value {
            self.derive_gnu_xhash_dynamic_symbol_count(symbol_hash_table_offset)?
        } else {
            // DT_HASH table, nchain corresponds is same as symbol count
            self.reader.read_int(symbol_hash_table_offset as u64 + 4)? // nchain from DT_HASH
        };

        // NOTE: When parsed from dynamic table and not found via section header parse it is
        // assumed that the extended symbol section table is not used.

        ElfSymbolTable::new(
            &self.reader,
            self,
            None,
            symbol_table_offset,
            table_addr,
            table_entry_size.wrapping_mul(sym_count as i64),
            table_entry_size,
            Some(self.string_tables[dynamic_string_table].clone()),
            None,
            true,
        )
        .map(Some)
    }

    /// Walk `DT_GNU_HASH` table to determine dynamic symbol count.
    fn derive_gnu_hash_dynamic_symbol_count(&self, gnu_hash_table_offset: i64) -> io::Result<i32> {
        let r = &self.reader;
        let base = gnu_hash_table_offset as u64;
        let num_buckets = r.read_int(base)?;
        let symbol_base = r.read_int(base + 4)?;
        let bloom_size = r.read_unsigned_int(base + 8)? as i64;
        // int bloomShift = reader.readInt(gnuHashTableOffset + 12);
        let bloom_word_size: i64 = if self.is64_bit() { 8 } else { 4 };
        let buckets_offset = gnu_hash_table_offset + 16 + bloom_word_size * bloom_size;

        // Identify restricted region which contains GNU hash table (arbitrary min-length)
        let max_offset = self.get_max_offset_for_loaded_region_containing(gnu_hash_table_offset, 12);
        if max_offset <= 0 {
            self.log_error("Failed to idenitify loaded GNU Hash table");
            return Ok(0);
        }

        let mut bucket_offset = buckets_offset;
        let mut max_symbol_index: i32 = 0;
        for _ in 0..num_buckets {
            if bucket_offset < gnu_hash_table_offset || bucket_offset > max_offset {
                self.log_error("Error occured while inspecting GNU Hash table");
                return Ok(0);
            }
            let symbol_index = r.read_int(bucket_offset as u64)?;
            if symbol_index > max_symbol_index {
                max_symbol_index = symbol_index;
            }
            bucket_offset += 4;
        }

        let chain_index = max_symbol_index.wrapping_sub(symbol_base);

        max_symbol_index = max_symbol_index.wrapping_add(1);
        // chains immediately follow buckets
        let mut chain_offset = bucket_offset + 4 * chain_index as i64;
        loop {
            if chain_offset < gnu_hash_table_offset || chain_offset > max_offset {
                self.log_error("Error occured while inspecting GNU Hash table");
                return Ok(0);
            }
            let chain_value = r.read_int(chain_offset as u64)?;
            if (chain_value & 1) != 0 {
                break;
            }
            max_symbol_index = max_symbol_index.wrapping_add(1);
            chain_offset += 4;
        }
        Ok(max_symbol_index)
    }

    fn get_max_offset_for_loaded_region_containing(&self, offset: i64, min_size: i64) -> i64 {
        let mut max_offset = -1;
        if self.e_shnum != 0 {
            if let Some(s) = self.get_section_header_containing_file_range(offset, min_size) {
                max_offset = s.get_offset() + s.get_size() - 1;
            }
        } else if let Some(seg) = self.get_program_load_header_containing_file_offset(offset) {
            max_offset = seg.get_offset() + seg.get_file_size() - 1;
        }
        max_offset
    }

    /// Walk `DT_GNU_XHASH` table to determine dynamic symbol count: `symndx + ngnusyms`.
    fn derive_gnu_xhash_dynamic_symbol_count(&self, gnu_hash_table_offset: i64) -> io::Result<i32> {
        // Elf32_Word  ngnusyms;  // number of entries in chains (and xlat); dynsymcount=symndx+ngnusyms
        // Elf32_Word  nbuckets;  // number of hash table buckets
        // Elf32_Word  symndx;  // number of initial .dynsym entires skipped in chains[] (and xlat[])
        let ngnusyms = self.reader.read_int(gnu_hash_table_offset as u64)?;
        let symndx = self.reader.read_int(gnu_hash_table_offset as u64 + 8)?;
        Ok(symndx.wrapping_add(ngnusyms))
    }

    /// Offset region check against the byte provider (the reader is unbounded).
    fn provider_contains_region(&self, offset: i64, length: i32) -> bool {
        offset >= 0 && offset.saturating_add(length as i64) <= self.provider.length() as i64
    }

    /// Reads the section header table. Idempotent; also run by [`parse`](Self::parse).
    pub fn parse_section_headers(&mut self) -> io::Result<()> {
        if self.parsed_section_headers {
            return Ok(());
        }

        self.parsed_section_headers = true;
        let mut missing = false;
        let mut section_headers = Vec::with_capacity(self.e_shnum.max(0) as usize);
        for i in 0..self.e_shnum {
            let index = self
                .e_shoff
                .wrapping_add((i as i64).wrapping_mul(self.e_shentsize as i64));
            if !missing && !self.provider_contains_region(index, self.e_shentsize as i32) {
                let unread_cnt = self.e_shnum - i;
                self.log_error(&format!(
                    "{unread_cnt} of {} section headers are truncated/missing from file",
                    self.e_shnum
                ));
                missing = true;
            }
            let section = ElfSectionHeader::new(self.reader.clone_at(index as u64), self)?;
            if section.get_type() == SHT_SYMTAB_SHNDX as i32 {
                self.has_extended_symbol_section_index_table = true;
            }
            section_headers.push(section);
        }

        // note: we cannot retrieve all the names until after we have read all the section
        // headers. this is because one of the section headers is a string table that contains
        // the names of the sections.
        let names: Vec<String> = section_headers
            .iter()
            .map(|s| s.compute_name(&section_headers, self.e_shstrndx))
            .collect();
        for (s, name) in section_headers.iter_mut().zip(names) {
            s.set_name(name);
        }

        if let Some(first) = section_headers.first() {
            self.section0 = Some(first.clone());
        }
        self.section_headers = section_headers;
        Ok(())
    }

    fn parse_program_headers(&mut self) -> io::Result<()> {
        let mut missing = false;
        let mut program_headers = Vec::with_capacity(self.e_phnum.max(0) as usize);
        for i in 0..self.e_phnum {
            let index = self
                .e_phoff
                .wrapping_add((i as i64).wrapping_mul(self.e_phentsize as i64));
            if !missing && !self.provider_contains_region(index, self.e_phentsize as i32) {
                let unread_cnt = self.e_phnum - i;
                self.log_error(&format!(
                    "{unread_cnt} of {} program headers are truncated/missing from file",
                    self.e_phnum
                ));
                missing = true;
            }
            program_headers.push(ElfProgramHeader::new(self.reader.clone_at(index as u64), self)?);
        }

        // TODO: Find sample file which requires this hack to verify its necessity
        // HACK: 07/01/2013 - Added hack for malformed ELF file with only program header sections
        let size: i64 = program_headers.iter().map(|p| p.get_file_size()).fold(0, i64::wrapping_add);
        if size as u64 == self.reader.length()? {
            // adjust program section file offset to be based on relative read offset
            let mut rel_offset = 0i64;
            for pheader in program_headers.iter_mut() {
                pheader.set_offset(rel_offset);
                rel_offset = rel_offset.wrapping_add(pheader.get_file_size());
            }
        }
        self.program_headers = program_headers;
        Ok(())
    }

    /// True if this ELF was created for a big endian processor.
    pub fn is_big_endian(&self) -> bool {
        self.e_ident_data == ELF_DATA_BE
    }

    /// True if this ELF was created for a little endian processor.
    pub fn is_little_endian(&self) -> bool {
        self.e_ident_data == ELF_DATA_LE
    }

    /// True if this ELF was created for a 32-bit processor.
    pub fn is32_bit(&self) -> bool {
        self.e_ident_class == ELF_CLASS_32
    }

    /// True if this ELF was created for a 64-bit processor.
    pub fn is64_bit(&self) -> bool {
        self.e_ident_class == ELF_CLASS_64
    }

    fn get_min_base(&self, mut addr: i64, mut min_base: i64) -> i64 {
        if self.is32_bit() {
            addr = addr as i32 as u32 as i64;
        }
        if (addr as u64) < (min_base as u64) {
            min_base = addr;
        }
        min_base
    }

    /// Inspect the ELF header and determine where the default image base should be (the minimum
    /// `PT_LOAD` virtual address among the first 20 program headers, read directly from the
    /// file), or 0 if none.
    pub fn find_image_base(&self) -> i64 {
        let mut min_base: i64 = -1;
        let n = self.e_phnum.min(MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
        let ctx = self.context();
        for i in 0..n {
            let index = self.e_phoff.wrapping_add(i as i64 * self.e_phentsize as i64);
            if !self.provider_contains_region(index, self.e_phentsize as i32) {
                break;
            }
            if let Ok(header_type) = self.reader.read_int(index as u64) {
                if header_type == PT_LOAD as i32 {
                    let mut r = self.reader.clone_at(index as u64);
                    if let Ok(header) = ElfProgramHeader::read(&mut r, ctx) {
                        min_base = self.get_min_base(header.get_virtual_address(), min_base);
                    }
                }
            }
        }
        if min_base == -1 {
            0
        } else {
            min_base
        }
    }

    /// The image base of this ELF: the pre-link base if pre-linked, otherwise the minimum
    /// `PT_LOAD` virtual address among the first 20 parsed program headers (0 if none). Cached.
    pub fn get_image_base(&self) -> i64 {
        if let Some(base) = self.elf_image_base.get() {
            return base;
        }

        let base = if self.pre_link_image_base != -1 {
            self.pre_link_image_base
        } else {
            let n = (self.program_headers.len() as i32).min(MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
            let mut min_base: i64 = -1;
            for header in &self.program_headers[..n as usize] {
                if header.get_type() == PT_LOAD as i32 {
                    min_base = self.get_min_base(header.get_virtual_address(), min_base);
                }
            }
            if min_base == -1 {
                0
            } else {
                min_base
            }
        };
        self.elf_image_base.set(Some(base));
        base
    }

    /// True if this is a pre-linked ELF image (a `PRE` trailer, or a `DT_GNU_PRELINKED` dynamic
    /// entry).
    pub fn is_pre_linked(&self) -> bool {
        if self.pre_link_image_base != -1 {
            return true;
        }
        if let Some(dynamic_table) = &self.dynamic_table {
            if dynamic_table.contains_dynamic_value_of_type(&elf_dynamic_type::dt_gnu_prelinked()) {
                return true;
            }
        }
        false
    }

    /// The pre-link image base from the file's 8-byte trailer (`<base:int>"PRE "`), or -1.
    fn read_pre_link_image_base(&self) -> i64 {
        let result = (|| -> io::Result<i64> {
            let file_length = self.reader.get_byte_provider().length();

            // not enough bytes
            if file_length < 8 {
                return Ok(-1);
            }
            let pre_link_image_base_int = self.reader.read_int(file_length - 8)?;
            let pre_link_magic_string = self.reader.read_ascii_string_fixed(file_length - 4, 4)?;

            if pre_link_magic_string.trim_matches(|c: char| c <= ' ') == "PRE" {
                return Ok(pre_link_image_base_int as u32 as i64);
            }
            Ok(-1)
        })();
        match result {
            Ok(v) => v,
            Err(_) => {
                self.log_error("Elf prelink read failure (see log)");
                -1
            }
        }
    }

    /// Determine if the specified section is contained within a `PT_LOAD` segment's memory range.
    pub fn is_section_loaded(&self, section: &ElfSectionHeader) -> bool {
        if section.get_type() == SHT_NULL as i32 {
            return false;
        }
        let section_start = section.get_address();
        if section_start == 0 {
            return false;
        }
        let section_end = section.get_size() - 1 + section_start;
        self.program_headers.iter().any(|segment| {
            if segment.get_type() != PT_LOAD as i32 {
                return false;
            }
            let segment_start = segment.get_virtual_address();
            let segment_end = segment.get_memory_size() - 1 + segment_start;
            segment_start <= section_start && segment_end >= section_end
        })
    }

    /// `e_ehsize`: the ELF header's size in bytes.
    pub fn e_ehsize(&self) -> i16 {
        self.e_ehsize
    }

    /// `e_entry`, pre-link adjusted (0 stays 0): the virtual address of the entry point.
    pub fn e_entry(&self) -> i64 {
        // guard against adjustment of 0
        if self.e_entry == 0 {
            return 0;
        }
        self.adjust_address_for_prelink(self.e_entry)
    }

    /// `e_flags`: processor-specific flags.
    pub fn e_flags(&self) -> i32 {
        self.e_flags
    }

    /// `e_machine`: the required architecture.
    pub fn e_machine(&self) -> i16 {
        self.e_machine
    }

    /// `e_ident[EI_OSABI]`.
    pub fn e_ident_osabi(&self) -> u8 {
        self.e_ident_osabi
    }

    /// `e_ident[EI_ABIVERSION]`.
    pub fn e_ident_abiversion(&self) -> u8 {
        self.e_ident_abiversion
    }

    /// `e_phentsize`: the size in bytes of one program header table entry.
    pub fn e_phentsize(&self) -> i16 {
        self.e_phentsize
    }

    /// The number of entries in the program header table (`e_phnum`, possibly extended).
    pub fn get_program_header_count(&self) -> i32 {
        self.e_phnum
    }

    /// `e_phoff`: the program header table's file offset in bytes.
    pub fn e_phoff(&self) -> i64 {
        self.e_phoff
    }

    /// `e_shentsize`: the size in bytes of one section header table entry.
    pub fn e_shentsize(&self) -> i16 {
        self.e_shentsize
    }

    /// The number of entries in the section header table (`e_shnum`, possibly extended).
    pub fn get_section_header_count(&self) -> i32 {
        self.e_shnum
    }

    /// `e_shoff`: the section header table's file offset in bytes.
    pub fn e_shoff(&self) -> i64 {
        self.e_shoff
    }

    /// The section header table index of the section name string table (possibly extended).
    pub fn e_shstrndx(&self) -> i32 {
        self.e_shstrndx
    }

    /// `e_type`: the object file type.
    pub fn e_type(&self) -> i16 {
        self.e_type
    }

    /// `e_ident[EI_VERSION]` is not exposed by Java; `e_version` is the object file version.
    pub fn e_version(&self) -> i32 {
        self.e_version
    }

    /// True if this is a relocatable (`ET_REL`) object file.
    pub fn is_relocatable(&self) -> bool {
        self.e_type == ET_REL as i16
    }

    /// True if this is a shared object (`ET_DYN`).
    pub fn is_shared_object(&self) -> bool {
        self.e_type == ET_DYN as i16
    }

    /// True if this is an executable (`ET_EXEC`).
    pub fn is_executable(&self) -> bool {
        self.e_type == ET_EXEC as i16
    }

    /// The section headers as defined in this ELF file.
    pub fn get_sections(&self) -> &[ElfSectionHeader] {
        &self.section_headers
    }

    /// Mutable access to the section headers (e.g. for
    /// [`ElfSectionHeader::set_address`]).
    pub fn get_sections_mut(&mut self) -> &mut [ElfSectionHeader] {
        &mut self.section_headers
    }

    /// The section headers with the specified type. Mirrors `getSections(int)`.
    pub fn get_sections_of_type(&self, type_: i32) -> Vec<&ElfSectionHeader> {
        self.section_headers.iter().filter(|s| s.get_type() == type_).collect()
    }

    /// The section header with the specified name, or `None`.
    ///
    /// # Errors
    /// Java's `RuntimeException` when more than one section has that name.
    pub fn get_section(&self, name: &str) -> Result<Option<&ElfSectionHeader>, String> {
        let list: Vec<&ElfSectionHeader> =
            self.section_headers.iter().filter(|s| s.get_name_as_string() == name).collect();
        match list.len() {
            0 => Ok(None),
            1 => Ok(Some(list[0])),
            _ => Err(format!(">1 section with name of {name}")),
        }
    }

    /// The allocated section header that starts at `address`, or `None`.
    pub fn get_section_at(&self, address: i64) -> Option<&ElfSectionHeader> {
        self.section_headers.iter().find(|s| s.is_alloc() && s.get_address() == address)
    }

    /// The allocated section header that contains `address`, or `None`.
    pub fn get_section_load_header_containing(&self, address: i64) -> Option<&ElfSectionHeader> {
        self.section_headers.iter().find(|s| {
            if !s.is_alloc() {
                return false;
            }
            let start = s.get_address();
            let end = start.wrapping_add(s.get_size());
            start <= address && address < end
        })
    }

    /// The section header which fully contains the specified file range, or `None`.
    pub fn get_section_header_containing_file_range(
        &self,
        file_offset: i64,
        file_range_length: i64,
    ) -> Option<&ElfSectionHeader> {
        let max_offset = file_offset + file_range_length - 1;
        self.section_headers.iter().find(|section| {
            if section.get_type() == SHT_NULL as i32 || section.is_invalid_offset() {
                return false;
            }
            let size = section.get_size();
            if size == 0 {
                return false;
            }
            let start = section.get_offset();
            let end = start + size - 1;
            file_offset >= start && max_offset <= end
        })
    }

    /// The index of `section` (by identity) in the section header table.
    ///
    /// # Errors
    /// Java's `RuntimeException("Section not located.")`.
    pub fn get_section_index(&self, section: &ElfSectionHeader) -> Result<i32, String> {
        self.section_headers
            .iter()
            .position(|s| std::ptr::eq(s, section))
            .map(|i| i as i32)
            .ok_or_else(|| "Section not located.".to_string())
    }

    /// The program headers as defined in this ELF file.
    pub fn get_program_headers(&self) -> &[ElfProgramHeader] {
        &self.program_headers
    }

    /// The program headers with the specified type. Mirrors `getProgramHeaders(int)`.
    pub fn get_program_headers_of_type(&self, type_: i32) -> Vec<&ElfProgramHeader> {
        self.program_headers.iter().filter(|p| p.get_type() == type_).collect()
    }

    /// The dynamic table defined by section `SHT_DYNAMIC` / segment `PT_DYNAMIC`, or `None`.
    pub fn get_dynamic_table(&self) -> Option<&ElfDynamicTable> {
        self.dynamic_table.as_ref()
    }

    /// The single `PT_PHDR` program header, or `None` if there is not exactly one.
    pub fn get_program_header_program_header(&self) -> Option<&ElfProgramHeader> {
        let pharr = self.get_program_headers_of_type(PT_PHDR as i32);
        if pharr.len() != 1 {
            return None;
        }
        Some(pharr[0])
    }

    /// The `PT_LOAD` program header starting at `virtual_addr`, or `None`.
    pub fn get_program_header_at(&self, virtual_addr: i64) -> Option<&ElfProgramHeader> {
        self.program_headers.iter().find(|p| {
            p.get_type() == PT_LOAD as i32 && p.get_virtual_address() == virtual_addr
        })
    }

    /// The `PT_LOAD` program header whose memory range contains `virtual_addr`, or `None`.
    pub fn get_program_load_header_containing(&self, virtual_addr: i64) -> Option<&ElfProgramHeader> {
        self.program_headers.iter().find(|p| {
            if p.get_type() != PT_LOAD as i32 {
                return false;
            }
            let start = p.get_virtual_address();
            let end = p.get_adjusted_memory_size() - 1 + start;
            virtual_addr >= start && virtual_addr <= end
        })
    }

    /// The `PT_LOAD` program header whose file range contains `offset`, or `None`.
    pub fn get_program_load_header_containing_file_offset(
        &self,
        offset: i64,
    ) -> Option<&ElfProgramHeader> {
        self.program_headers.iter().find(|p| {
            if p.get_type() != PT_LOAD as i32 || p.is_invalid_offset() {
                return false;
            }
            let start = p.get_offset();
            let end = start + (p.get_file_size() - 1);
            offset >= start && offset <= end
        })
    }

    /// The names of the dynamic libraries this image needs (`DT_NEEDED`), or
    /// `UNK_LIB_NAME_<n>` where a name cannot be read.
    pub fn get_dynamic_library_names(&self) -> &[String] {
        &self.dynamic_library_names
    }

    /// The dynamic string table (`DT_STRTAB`), or `None`.
    pub fn get_dynamic_string_table(&self) -> Option<&ElfStringTable> {
        self.dynamic_string_table.map(|i| &self.string_tables[i])
    }

    /// All string tables (section-based plus a dynamic-table-only one).
    pub fn get_string_tables(&self) -> &[ElfStringTable] {
        &self.string_tables
    }

    /// The string table associated with `section` (matched by file offset), or `None`.
    pub fn get_string_table(&self, section: &ElfSectionHeader) -> Option<&ElfStringTable> {
        self.string_tables.iter().find(|t| t.get_file_offset() == section.get_offset())
    }

    /// The dynamic symbol table, or `None`.
    pub fn get_dynamic_symbol_table(&self) -> Option<&Arc<ElfSymbolTable>> {
        self.dynamic_symbol_table.map(|i| &self.symbol_tables[i])
    }

    /// All symbol tables.
    pub fn get_symbol_tables(&self) -> &[Arc<ElfSymbolTable>] {
        &self.symbol_tables
    }

    /// The symbol table associated with `symbol_table_section` (matched by file offset), or
    /// `None` (also for a `None` section).
    pub fn get_symbol_table(
        &self,
        symbol_table_section: Option<&ElfSectionHeader>,
    ) -> Option<&Arc<ElfSymbolTable>> {
        let section = symbol_table_section?;
        self.symbol_tables.iter().find(|t| t.get_file_offset() == section.get_offset())
    }

    /// `Short.toString(e_machine)`.
    pub fn get_machine_name(&self) -> String {
        self.e_machine.to_string()
    }

    /// `Integer.toString(e_flags)`.
    pub fn get_flags(&self) -> String {
        self.e_flags.to_string()
    }

    /// Ordinal of the `e_entry` component in [`to_data_type`](StructConverter::to_data_type).
    pub fn get_entry_component_ordinal(&self) -> i32 {
        11
    }

    /// Ordinal of the `e_phoff` component.
    pub fn get_phoff_component_ordinal(&self) -> i32 {
        12
    }

    /// Ordinal of the `e_shoff` component.
    pub fn get_shoff_component_ordinal(&self) -> i32 {
        13
    }
}

/// Mirrors `ElfHeader.determineHeaderEndianness()`: little-endian unless `EI_DATA` says big
/// endian -- and even then little-endian if the first byte of `e_version` is 1 (some toolchains
/// always use little endian ELF headers).
fn determine_header_endianness(
    provider: &dyn ByteProvider,
    error_consumer: &dyn Fn(&str),
) -> Result<bool, ElfException> {
    if provider.length() < INITIAL_READ_LEN {
        return Err(ElfException::new("Not enough bytes to be a valid ELF executable."));
    }

    let mut has_little_endian_headers = true;
    let bytes = provider.read_bytes(0, INITIAL_READ_LEN).map_err(io_err)?;
    if bytes[EI_DATA] == ELF_DATA_BE {
        has_little_endian_headers = false;
    } else if bytes[EI_DATA] != ELF_DATA_LE {
        error_consumer(&format!(
            "Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x{:x})",
            bytes[EI_DATA] as i8 as i32
        ));
    }
    if !has_little_endian_headers && bytes[EI_NIDENT] != 0 {
        // Header endianness sanity check
        // Some toolchains always use little endian Elf Headers

        // Check first byte of version (allow switch if equal 1)
        if bytes[EI_NIDENT + 4] == 1 {
            has_little_endian_headers = true;
        }
    }
    Ok(has_little_endian_headers)
}

impl StructConverter for ElfHeader {
    /// The `Elf32_Ehdr`/`Elf64_Ehdr` structure.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let name = if self.is32_bit() { "Elf32_Ehdr" } else { "Elf64_Ehdr" };
        let mut s = ElfStruct::new(name);
        s.add(byte(), "e_ident_magic_num")?;
        s.add_len(string(), MAGIC_STR.len() as i32, "e_ident_magic_str")?;
        s.add(byte(), "e_ident_class")?;
        s.add(byte(), "e_ident_data")?;
        s.add(byte(), "e_ident_version")?;
        s.add(byte(), "e_ident_osabi")?;
        s.add(byte(), "e_ident_abiversion")?;
        s.add(array(byte(), PAD_LENGTH as i32, 1)?, "e_ident_pad")?;
        s.add(word(), "e_type")?;
        s.add(word(), "e_machine")?;
        s.add(dword(), "e_version")?;

        let addr = if self.is32_bit() { dword } else { qword };
        s.add(addr(), "e_entry")?;
        s.add(addr(), "e_phoff")?;
        s.add(addr(), "e_shoff")?;

        s.add(dword(), "e_flags")?;
        s.add(word(), "e_ehsize")?;
        s.add(word(), "e_phentsize")?;
        s.add(word(), "e_phnum")?;
        s.add(word(), "e_shentsize")?;
        s.add(word(), "e_shnum")?;
        s.add(word(), "e_shstrndx")?;
        Ok(s.finish())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::format::elf::elf_section_header_constants::{
        SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_HASH, SHT_PROGBITS,
    };
    use crate::format::elf::elf_symbol::{STB_GLOBAL, STT_FUNC, STT_SECTION};
    use crate::format::elf::elf_test_image::{parse_bytes, provider, ElfImage, StrTab};

    const BASE: u64 = 0x10000;

    /// An image with one `PT_LOAD` covering the file from offset 0 at `BASE`, a `.text`
    /// section, and a `.symtab`/`.strtab` pair holding the null symbol, a `STT_SECTION`
    /// symbol for `.text` and a global function `main`.
    fn static_image(is64: bool, le: bool) -> ElfImage {
        let mut img = ElfImage::new(is64, le);
        img.e_type = ET_DYN;
        img.e_machine = if is64 { 62 } else { 40 };
        img.e_flags = 0x0500_0200;
        let e = img.enc;

        let text_off = img.next_offset();
        let text = img.add_section(
            ".text",
            SHT_PROGBITS,
            (SHF_ALLOC | SHF_EXECINSTR) as u64,
            BASE + text_off,
            &[0x90u8; 0x20],
        );
        img.e_entry = BASE + text_off + 4;

        let mut strtab = StrTab::new();
        let main = strtab.add("main");
        let strtab_bytes = strtab.bytes();
        let strtab_idx = img.add_section(".strtab", SHT_STRTAB, 0, 0, &strtab_bytes);

        let mut syms = e.sym(0, 0, 0, 0, 0, 0);
        syms.extend(e.sym(0, BASE + text_off, 0, STT_SECTION, 0, text as u16));
        syms.extend(e.sym(main, BASE + text_off + 4, 0x10, (STB_GLOBAL << 4) | STT_FUNC, 0, text as u16));
        let symtab = img.add_section(".symtab", SHT_SYMTAB, 0, 0, &syms);
        img.section_mut(symtab).sh_link = strtab_idx;
        img.section_mut(symtab).sh_info = 2;
        img.section_mut(symtab).sh_entsize = e.sym_size();

        let end = img.next_offset();
        img.add_segment(PT_LOAD, 5, 0, BASE, end, end);
        img
    }

    fn check_static_image(is64: bool, le: bool) {
        let img = static_image(is64, le);
        let bytes = img.build();
        let mut elf = ElfHeader::new(provider(bytes), None).unwrap();

        // identification and header fields (before parse)
        assert_eq!(elf.is64_bit(), is64);
        assert_eq!(elf.is32_bit(), !is64);
        assert_eq!(elf.is_little_endian(), le);
        assert_eq!(elf.is_big_endian(), !le);
        assert!(elf.is_shared_object());
        assert!(!elf.is_relocatable());
        assert!(!elf.is_executable());
        assert_eq!(elf.e_type(), 3);
        assert_eq!(elf.e_machine(), if is64 { 62 } else { 40 });
        assert_eq!(elf.get_machine_name(), if is64 { "62" } else { "40" });
        assert_eq!(elf.e_flags(), 0x0500_0200);
        assert_eq!(elf.get_flags(), "83886592");
        assert_eq!(elf.e_version(), 1);
        assert_eq!(elf.e_ehsize(), if is64 { 64 } else { 52 });
        assert_eq!(elf.e_phentsize(), if is64 { 56 } else { 32 });
        assert_eq!(elf.e_phoff(), elf.e_ehsize() as i64);
        assert_eq!(elf.get_program_header_count(), 1);
        assert_eq!(elf.get_section_header_count(), 5); // null, .text, .strtab, .symtab, .shstrtab
        assert_eq!(elf.e_shstrndx(), 4);
        assert_eq!(elf.e_entry(), img.e_entry as i64);
        assert!(elf.get_sections().is_empty(), "sections are read by parse()");
        assert_eq!(elf.find_image_base(), BASE as i64);
        assert!(!elf.is_pre_linked());

        elf.parse().unwrap();
        elf.parse().unwrap(); // idempotent

        // program headers
        let phdrs = elf.get_program_headers();
        assert_eq!(phdrs.len(), 1);
        assert_eq!(phdrs[0].get_type(), PT_LOAD as i32);
        assert_eq!(phdrs[0].get_virtual_address(), BASE as i64);
        assert_eq!(phdrs[0].get_offset(), 0);
        assert!(phdrs[0].is_read() && phdrs[0].is_execute() && !phdrs[0].is_write());
        assert_eq!(phdrs[0].get_type_as_string(&elf), "PT_LOAD");
        assert_eq!(elf.get_image_base(), BASE as i64);
        assert!(elf.get_program_load_header_containing(BASE as i64 + 0x10).is_some());
        assert!(elf.get_program_load_header_containing(0x10).is_none());
        assert!(elf.get_program_header_at(BASE as i64).is_some());

        // section headers and names
        let names: Vec<String> = elf.get_sections().iter().map(|s| s.get_name_as_string()).collect();
        assert_eq!(names, ["SECTION0", ".text", ".strtab", ".symtab", ".shstrtab"]);
        let text = elf.get_section(".text").unwrap().unwrap();
        assert!(text.is_alloc() && text.is_executable() && !text.is_writable());
        assert_eq!(text.get_size(), 0x20);
        assert_eq!(text.get_type_as_string(&elf), "SHT_PROGBITS");
        assert_eq!(elf.get_section_index(text), Ok(1));
        assert!(std::ptr::eq(elf.get_section_at(text.get_address()).unwrap(), text));
        assert!(std::ptr::eq(
            elf.get_section_load_header_containing(text.get_address() + 0x1f).unwrap(),
            text
        ));
        assert!(elf.is_section_loaded(text));
        assert!(!elf.is_section_loaded(&elf.get_sections()[2]), ".strtab has no address");
        assert_eq!(elf.get_sections_of_type(SHT_SYMTAB as i32).len(), 1);
        assert_eq!(elf.get_section("nope"), Ok(None));

        // string and symbol tables
        assert_eq!(elf.get_string_tables().len(), 2); // .strtab and .shstrtab
        assert!(elf.get_dynamic_table().is_none());
        assert!(elf.get_dynamic_string_table().is_none());
        assert!(elf.get_dynamic_symbol_table().is_none());
        assert!(elf.get_dynamic_library_names().is_empty());
        let symtabs = elf.get_symbol_tables();
        assert_eq!(symtabs.len(), 1);
        let symtab = &symtabs[0];
        assert!(!symtab.is_dynamic());
        assert_eq!(symtab.get_symbol_count(), 3);
        assert_eq!(symtab.get_entry_size() as u64, img.enc.sym_size());
        assert_eq!(symtab.get_table_section_header(), Some(3));
        assert_eq!(symtab.get_symbol_name(2).as_deref(), Some("main"));
        assert_eq!(symtab.get_symbol_name(1).as_deref(), Some(".text"), "section symbol");
        assert_eq!(symtab.get_formatted_symbol_name(9), "<no name>");
        let main = symtab.get_symbol(2).unwrap();
        assert!(main.is_function() && main.is_global());
        assert_eq!(main.get_value(), BASE + 0x400 + 4);
        assert_eq!(main.get_size(), 0x10);
        assert_eq!(symtab.get_symbol_index(main), 2);
        assert_eq!(symtab.get_global_symbols().len(), 1);
        assert!(std::ptr::eq(
            elf.get_symbol_table(elf.get_section(".symtab").unwrap()).unwrap().as_ref(),
            symtab.as_ref()
        ));

        // data types
        let dt = elf.to_data_type().unwrap();
        assert_eq!(dt.get_name(), if is64 { "Elf64_Ehdr" } else { "Elf32_Ehdr" });
        assert_eq!(dt.get_length(), if is64 { 64 } else { 52 });
        let pdt = phdrs[0].to_data_type(&elf).unwrap();
        assert_eq!(pdt.get_length(), if is64 { 56 } else { 32 });
        let sdt = text.to_data_type(&elf).unwrap();
        assert_eq!(sdt.get_length(), if is64 { 64 } else { 40 });
        let symdt = symtab.to_data_type().unwrap();
        assert_eq!(symdt.get_length() as u64, 3 * img.enc.sym_size());
    }

    #[test]
    fn parses_elf32_little_endian() {
        check_static_image(false, true);
    }

    #[test]
    fn parses_elf32_big_endian() {
        check_static_image(false, false);
    }

    #[test]
    fn parses_elf64_little_endian() {
        check_static_image(true, true);
    }

    #[test]
    fn parses_elf64_big_endian() {
        check_static_image(true, false);
    }

    /// An image with a `PT_DYNAMIC` segment whose table names `libc.so.6`, plus `.dynstr`,
    /// `.dynsym` and `.hash`. With `with_sections == false` the section header table is omitted,
    /// so the dynamic string/symbol tables must be recovered from the dynamic table alone (the
    /// symbol count from `DT_HASH`'s `nchain`).
    fn dynamic_image(is64: bool, le: bool, with_sections: bool) -> Vec<u8> {
        let mut img = ElfImage::new(is64, le);
        img.e_type = ET_DYN;
        img.no_sections = !with_sections;
        let e = img.enc;

        let mut dynstr = StrTab::new();
        let libc = dynstr.add("libc.so.6");
        let puts = dynstr.add("puts");
        let dynstr_bytes = dynstr.bytes();
        let dynstr_off = img.next_offset();
        let dynstr_idx =
            img.add_section(".dynstr", SHT_STRTAB, SHF_ALLOC as u64, BASE + dynstr_off, &dynstr_bytes);

        let mut syms = e.sym(0, 0, 0, 0, 0, 0);
        syms.extend(e.sym(puts, 0, 0, (STB_GLOBAL << 4) | STT_FUNC, 0, 0));
        let dynsym_off = img.next_offset();
        let dynsym_idx = img.add_section(".dynsym", SHT_DYNSYM, SHF_ALLOC as u64, BASE + dynsym_off, &syms);
        img.section_mut(dynsym_idx).sh_link = dynstr_idx;
        img.section_mut(dynsym_idx).sh_entsize = e.sym_size();

        // DT_HASH: nbucket = 1, nchain = 2, bucket[0] = 1, chain = [0, 0]
        let mut hash = Vec::new();
        for w in [1u32, 2, 1, 0, 0] {
            hash.extend(e.u32(w));
        }
        let hash_off = img.next_offset();
        img.add_section(".hash", SHT_HASH, SHF_ALLOC as u64, BASE + hash_off, &hash);

        let mut dyns = Vec::new();
        for (tag, val) in [
            (1i64, libc as u64), // DT_NEEDED
            (4, BASE + hash_off),  // DT_HASH
            (5, BASE + dynstr_off), // DT_STRTAB
            (6, BASE + dynsym_off), // DT_SYMTAB
            (10, dynstr_bytes.len() as u64), // DT_STRSZ
            (11, e.sym_size()),     // DT_SYMENT
            (0, 0),                 // DT_NULL
        ] {
            dyns.extend(e.dyn_(tag, val));
        }
        let dyn_off = img.next_offset();
        let dyn_len = dyns.len() as u64;
        img.add_section(".dynamic", SHT_DYNAMIC, (SHF_ALLOC | SHF_WRITE) as u64, BASE + dyn_off, &dyns);

        let end = img.next_offset();
        img.add_segment(PT_LOAD, 6, 0, BASE, end, end);
        img.add_segment(PT_DYNAMIC, 6, dyn_off, BASE + dyn_off, dyn_len, dyn_len);
        img.build()
    }

    fn check_dynamic(is64: bool, le: bool, with_sections: bool) {
        let elf = parse_bytes(dynamic_image(is64, le, with_sections));

        let dynamic = elf.get_dynamic_table().expect("PT_DYNAMIC parsed");
        assert_eq!(dynamic.get_dynamics().len(), 7);
        assert_eq!(dynamic.get_entry_size(), if is64 { 16 } else { 8 });
        assert_eq!(dynamic.get_dynamic_value(10).unwrap(), 16); // "\0libc.so.6\0puts\0"
        assert!(dynamic.get_dynamic_value(0x1234).is_err());
        assert_eq!(
            dynamic.get_dynamics()[0].get_tag_as_string(&elf),
            "DT_NEEDED"
        );
        assert_eq!(elf.get_dynamic_library_names(), ["libc.so.6".to_string()]);

        let dynstr = elf.get_dynamic_string_table().expect("DT_STRTAB located");
        assert_eq!(dynstr.get_length(), 16);
        let dynsym = elf.get_dynamic_symbol_table().expect("DT_SYMTAB located");
        assert!(dynsym.is_dynamic());
        assert_eq!(dynsym.get_symbol_count(), 2);
        assert_eq!(dynsym.get_symbol_name(1).as_deref(), Some("puts"));
        assert_eq!(dynsym.get_table_section_header().is_some(), with_sections);
        assert_eq!(elf.get_symbol_tables().len(), 1);
        assert_eq!(elf.get_sections().is_empty(), !with_sections);

        let dt = dynamic.to_data_type(&elf).unwrap();
        assert_eq!(dt.get_length(), 7 * dynamic.get_entry_size());
    }

    #[test]
    fn parses_dynamic_table_with_sections() {
        for (is64, le) in [(false, true), (false, false), (true, true), (true, false)] {
            check_dynamic(is64, le, true);
        }
    }

    #[test]
    fn recovers_dynamic_tables_without_section_headers() {
        for (is64, le) in [(false, true), (true, false)] {
            check_dynamic(is64, le, false);
        }
    }

    #[test]
    fn rejects_non_elf_short_and_bad_class() {
        let err = ElfHeader::new(provider(b"MZ\x90\x00 not an elf file at all......".to_vec()), None)
            .unwrap_err();
        assert_eq!(err.to_string(), "Not a valid ELF executable.");

        let err = ElfHeader::new(provider(b"\x7fELF\x01\x01\x01".to_vec()), None).unwrap_err();
        assert_eq!(err.to_string(), "Not enough bytes to be a valid ELF executable.");

        let mut bytes = static_image(false, true).build();
        bytes[4] = 3; // EI_CLASS
        let err = ElfHeader::new(provider(bytes), None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x3)"
        );

        let err = ElfHeader::new(provider(b"\x7fEL".to_vec()), None).unwrap_err();
        assert!(matches!(err, ElfException::Cause(_)));
    }

    fn collecting() -> (Rc<RefCell<Vec<String>>>, Box<dyn Fn(&str)>) {
        let errors = Rc::new(RefCell::new(Vec::new()));
        let sink = Rc::clone(&errors);
        (errors, Box::new(move |m: &str| sink.borrow_mut().push(m.to_string())))
    }

    #[test]
    fn invalid_ei_data_is_reported_and_little_endian_assumed() {
        let mut bytes = static_image(false, true).build();
        bytes[5] = 7; // EI_DATA
        let (errors, consumer) = collecting();
        let elf = ElfHeader::new(provider(bytes), Some(consumer)).unwrap();
        assert_eq!(
            errors.borrow().as_slice(),
            ["Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x7)"]
        );
        assert_eq!(elf.e_machine(), 40);
        assert!(!elf.is_little_endian() && !elf.is_big_endian());
    }

    #[test]
    fn truncated_section_headers_are_reported_and_read_as_zero() {
        let bytes = static_image(true, true).build();
        let shoff = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) as usize;
        // keep the null section and .text, cut the remaining three 64-byte entries
        let truncated = bytes[..shoff + 2 * 64].to_vec();
        let (errors, consumer) = collecting();
        let mut elf = ElfHeader::new(provider(truncated), Some(consumer)).unwrap();
        elf.parse().unwrap();
        assert_eq!(elf.get_sections().len(), 5);
        assert_eq!(elf.get_sections()[3].get_type(), SHT_NULL as i32);
        assert!(errors
            .borrow()
            .contains(&"3 of 5 section headers are truncated/missing from file".to_string()));
    }

    #[test]
    fn prelink_trailer_adjusts_addresses() {
        let mut bytes = static_image(false, true).build();
        bytes.extend(0x4000_0000u32.to_le_bytes());
        bytes.extend(b"PRE ");
        let elf = parse_bytes(bytes);
        assert!(elf.is_pre_linked());
        assert_eq!(elf.get_image_base(), 0x4000_0000);
        assert_eq!(elf.adjust_address_for_prelink(0x10), 0x4000_0010);
        assert_eq!(elf.unadjust_address_for_prelink(0x4000_0010), 0x10);
        assert_eq!(elf.get_program_headers()[0].get_virtual_address(), 0x4000_0000 + BASE as i64);
        let text = elf.get_section(".text").unwrap().unwrap();
        assert_eq!(text.get_address(), 0x4000_0000 + BASE as i64 + 0x400);
    }

    #[test]
    fn extended_symbol_section_index_table_is_linked_to_its_symbol_table() {
        let mut img = static_image(true, true);
        let e = img.enc;
        // SHT_SYMTAB_SHNDX for .symtab (section 3): symbol 2 -> section 0x1234
        let mut table = Vec::new();
        for v in [0u32, 0, 0x1234] {
            table.extend(e.u32(v));
        }
        let shndx = img.add_section(".symtab_shndx", SHT_SYMTAB_SHNDX, 0, 0, &table);
        img.section_mut(shndx).sh_link = 3;
        // make symbol 2's st_shndx SHN_XINDEX
        let symtab_off = img.sections[2].sh_offset as usize;
        let sym2 = symtab_off + 2 * 24 + 6;
        let mut bytes = img.build();
        bytes[sym2..sym2 + 2].copy_from_slice(&SHN_XINDEX.to_le_bytes());

        let elf = parse_bytes(bytes);
        let symtab = &elf.get_symbol_tables()[0];
        let main = symtab.get_symbol(2).unwrap();
        assert_eq!(main.get_section_header_index(), SHN_XINDEX);
        assert_eq!(main.get_extended_section_header_index(symtab), 0x1234);
        assert_eq!(symtab.get_extended_section_index(symtab.get_symbol(1).unwrap()), 0);
    }

    #[test]
    fn section_names_fall_back_without_a_string_table() {
        let mut bytes = static_image(false, true).build();
        // e_shstrndx = 0 (ELF32: offset 50)
        bytes[50..52].copy_from_slice(&0u16.to_le_bytes());
        let elf = parse_bytes(bytes);
        let names: Vec<String> = elf.get_sections().iter().map(|s| s.get_name_as_string()).collect();
        assert_eq!(names, ["SECTION0", "SECTION1", "SECTION2", "SECTION3", "SECTION4"]);
    }

    /// Smoke test against a real binary, when the machine has one.
    #[test]
    fn parses_bin_ls_when_present() {
        let Ok(bytes) = std::fs::read("/bin/ls") else {
            return;
        };
        if bytes.get(..4) != Some(&MAGIC_BYTES[..]) {
            return;
        }
        let (errors, consumer) = collecting();
        let mut elf = ElfHeader::new(provider(bytes), Some(consumer)).unwrap();
        elf.parse().unwrap();
        assert!(!elf.get_program_headers().is_empty());
        assert_eq!(elf.get_program_headers().len() as i32, elf.get_program_header_count());
        assert_eq!(elf.get_sections().len() as i32, elf.get_section_header_count());
        let names: Vec<String> = elf.get_sections().iter().map(|s| s.get_name_as_string()).collect();
        assert!(names.iter().any(|n| n == ".text"), "{names:?}");
        assert!(elf.get_program_load_header_containing(elf.e_entry()).is_some());
        if elf.get_dynamic_table().is_some() {
            assert!(elf.get_dynamic_string_table().is_some());
            assert!(elf.get_dynamic_symbol_table().is_some());
            assert!(
                elf.get_dynamic_library_names().iter().any(|n| n.starts_with("libc.so")),
                "{:?}",
                elf.get_dynamic_library_names()
            );
        }
        assert!(errors.borrow().is_empty(), "{:?}", errors.borrow());
    }
}
