//! Port of `ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter`.
//!
//! The load adapter is the base ELF extension: it supplies the *default* answer to every question
//! the ELF loader asks about a particular image (where a segment wants to live, which permissions
//! a section carries, how large a memory block has to be, and so on). Architecture-specific
//! extensions -- `ElfExtension` and, through it, the ~20 per-processor classes -- refine those
//! answers.
//!
//! # Shape
//!
//! Java's `ElfLoadAdapter` is a concrete class with a single direct subclass (`ElfExtension`), and
//! it carries no state: inheritance is used purely to share these default bodies. The Rust port is
//! therefore a (zero-sized) struct whose inherent methods *are* the defaults; an extension port
//! embeds an `ElfLoadAdapter` and delegates to it for whatever it does not specialize.
//!
//! # Departures from the Java class
//!
//! * `addDynamicTypes`/`addProgramHeaderTypes`/`addSectionHeaderTypes` walk
//!   `getClass().getDeclaredFields()` to find the `public static final ElfDynamicType DT_*`
//!   constants an extension declares. Rust has no reflection, so each of the three ports as the
//!   no-op the *base* class performs (it declares no such constants) and an extension registers
//!   its own types explicitly -- see [`ElfLoadAdapter::add_dynamic_types`].
//! * Java overloads `canHandle` on `ElfHeader`/`ElfLoadHelper`; Rust has no overloading, so the
//!   two become [`can_handle_header`](ElfLoadAdapter::can_handle_header) and
//!   [`can_handle_load_helper`](ElfLoadAdapter::can_handle_load_helper).
//! * `getRelocationClass` returns a `Class<? extends ElfRelocation>` that the relocation table
//!   instantiates reflectively. The port returns an [`ElfRelocationFactory`] -- a constructor
//!   function -- which is what that reflection amounts to.
//! * The methods whose Java return type is the *nullable* `Boolean`/`Long`/`AddressSpace` return
//!   `Option`, since `None` is meaningful there: it tells the loader to fall back to its own
//!   standard handling.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use crate::app::util::opinion::elf_loader_options_factory::{
    IMAGE32_BASE_DEFAULT, IMAGE64_BASE_DEFAULT,
};
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_program_header_constants::{PF_R, PF_W, PF_X};
use crate::format::elf::elf_section_header_constants::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::seam_stubs::{
    ElfDefaultGotPltMarkup, ElfDynamicType, ElfHeader, ElfProgramHeader, ElfProgramHeaderType,
    ElfRelocation, ElfSectionHeader, ElfSectionHeaderType, MemoryLoadable,
};
use crate::program::model::address::{Address, AddressSpace};
use crate::util::exception::{CancelledException, NoValueException};
use crate::util::task::TaskMonitor;

/// Stands in for Java's `Class<? extends ElfRelocation>`: a constructor for the relocation entry
/// type a table should be parsed with. Java instantiates the class reflectively through its no-arg
/// constructor, which is exactly what calling this does.
pub type ElfRelocationFactory = fn() -> Box<dyn ElfRelocation>;

/// The base ELF load adapter: the default answers to every extension point the ELF loader offers.
///
/// See the [module documentation](self) for why this is a struct rather than a trait.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ElfLoadAdapter;

impl ElfLoadAdapter {
    /// The default (unspecialized) adapter.
    pub fn new() -> Self {
        ElfLoadAdapter
    }

    /// Add all extension specific Dynamic table entry types (e.g., `DT_` prefix).
    ///
    /// Java reflects over the adapter's own `static ElfDynamicType` fields; the base class
    /// declares none, so this adds nothing. An extension port cannot be reached reflectively and
    /// must insert its own types into `dynamic_type_map` before (or instead of) calling this.
    pub fn add_dynamic_types(&self, dynamic_type_map: &mut HashMap<i32, Box<dyn ElfDynamicType>>) {
        let _ = dynamic_type_map;
    }

    /// Add all extension specific Program Header types (e.g., `PT_` prefix).
    ///
    /// Adds nothing, for the same reason as [`add_dynamic_types`](Self::add_dynamic_types).
    pub fn add_program_header_types(
        &self,
        program_header_type_map: &mut HashMap<i32, Box<dyn ElfProgramHeaderType>>,
    ) {
        let _ = program_header_type_map;
    }

    /// Add all extension specific Section Header types (e.g., `SHT_` prefix).
    ///
    /// Adds nothing, for the same reason as [`add_dynamic_types`](Self::add_dynamic_types).
    pub fn add_section_header_types(
        &self,
        section_header_type_map: &mut HashMap<i32, Box<dyn ElfSectionHeaderType>>,
    ) {
        let _ = section_header_type_map;
    }

    /// Get the preferred load address space for an allocated program segment.
    ///
    /// An executable segment goes in the default (code) space, anything else in the language's
    /// default data space. The OTHER space is reserved and is never returned, nor is an overlay
    /// space.
    ///
    /// `None` where Java would have thrown: the ported `Program` seam has neither an address
    /// factory nor a language attached.
    pub fn get_preferred_segment_address_space(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        elf_program_header: &dyn ElfProgramHeader,
    ) -> Option<Arc<AddressSpace>> {
        let program = elf_load_helper.get_program();
        if elf_program_header.is_execute() {
            return program.get_address_factory()?.get_default_address_space();
        }
        // segment is not marked execute, use the data space by default
        Some(program.get_language()?.get_default_data_space())
    }

    /// Get the preferred load address for a program segment. Never an overlay address.
    ///
    /// The segment's `p_vaddr` is an addressable word offset; the image base adjustment applies to
    /// the default address space only.
    pub fn get_preferred_segment_address(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        elf_program_header: &dyn ElfProgramHeader,
    ) -> Option<Address> {
        let program = elf_load_helper.get_program();

        let space = self.get_preferred_segment_address_space(elf_load_helper, elf_program_header)?;

        let mut addr_word_offset = elf_program_header.get_virtual_address();

        if is_default_address_space(&space, elf_load_helper) {
            addr_word_offset =
                addr_word_offset.wrapping_add(elf_load_helper.get_image_base_word_adjustment_offset());
        }

        Some(truncated_word_address(&space, addr_word_offset))
    }

    /// Get the default alignment within the default address space.
    ///
    /// A word-addressed space aligns to its addressable unit; a byte-addressed one aligns to the
    /// image's pointer size.
    pub fn get_default_alignment(&self, elf_load_helper: &dyn ElfLoadHelper) -> i32 {
        let program = elf_load_helper.get_program();
        let unit_size = program
            .get_address_factory()
            .and_then(|factory| factory.get_default_address_space())
            .map_or(1, |space| space.unit_size());
        if unit_size != 1 {
            return unit_size;
        }
        if elf_load_helper.get_elf_header().is64_bit() {
            8
        } else {
            4
        }
    }

    /// Get the preferred load address space for an allocated section. The OTHER space is reserved
    /// and is never returned, nor is an overlay space.
    pub fn get_preferred_section_address_space(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        elf_section_header: &dyn ElfSectionHeader,
    ) -> Option<Arc<AddressSpace>> {
        let program = elf_load_helper.get_program();
        if elf_section_header.is_executable() {
            return program.get_address_factory()?.get_default_address_space();
        }
        // section is not marked execute, use the data space by default
        Some(program.get_language()?.get_default_data_space())
    }

    /// Get the preferred load address for an allocated program section. Never an overlay address.
    pub fn get_preferred_section_address(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        elf_section_header: &dyn ElfSectionHeader,
    ) -> Option<Address> {
        let space = self.get_preferred_section_address_space(elf_load_helper, elf_section_header)?;

        let mut addr_word_offset = elf_section_header.get_address();

        if is_default_address_space(&space, elf_load_helper) {
            addr_word_offset =
                addr_word_offset.wrapping_add(elf_load_helper.get_image_base_word_adjustment_offset());
        }

        Some(truncated_word_address(&space, addr_word_offset))
    }

    /// Check if this extension can handle the specified elf header. When true, the extension is
    /// used to obtain extended type definitions and to perform additional load processing.
    ///
    /// Ports the `canHandle(ElfHeader)` overload; the base extension handles nothing.
    pub fn can_handle_header(&self, elf: &dyn ElfHeader) -> bool {
        let _ = elf;
        false
    }

    /// Check if this extension can handle the specified elf image. This is a more accurate check
    /// than [`can_handle_header`](Self::can_handle_header) because it can consult the language
    /// actually in use, which may be incompatible with the machine-id in the header.
    ///
    /// Ports the `canHandle(ElfLoadHelper)` overload; the base extension handles nothing.
    pub fn can_handle_load_helper(&self, elf_load_helper: &dyn ElfLoadHelper) -> bool {
        let _ = elf_load_helper;
        false
    }

    /// The data type naming suffix to use for types derived from data supplied by this extension,
    /// or `None` (Java's `null`) for no suffix.
    pub fn get_data_type_suffix(&self) -> Option<&'static str> {
        None
    }

    /// Perform any required offset adjustment to account for differences between offset values
    /// contained within ELF headers and the language modeling of the associated address space.
    ///
    /// The returned offset does not account for image base alterations.
    ///
    /// **WARNING:** experimental and not yet fully supported. Currently used for symbol address
    /// offset adjustment only.
    pub fn get_adjusted_memory_offset(&self, elf_offset: i64, space: &AddressSpace) -> i64 {
        let _ = space;
        elf_offset
    }

    /// Perform extension specific processing of the ELF image during program load.
    ///
    /// By the time this runs, all program and section headers have been processed, resolved and
    /// loaded, and the ELF header, program headers, section headers, dynamic table, string tables
    /// and symbol tables have been marked up. Relocation tables have *not* been applied yet.
    ///
    /// The base extension does nothing extra.
    pub fn process_elf(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let _ = (elf_load_helper, monitor);
        Ok(())
    }

    /// Perform extension specific processing of ELF GOT/PLT tables and any other related function
    /// relocation mechanism (e.g. function descriptors) after normal REL/RELA relocation fix-ups
    /// have been applied.
    ///
    /// The legacy GOT/PLT processing is performed by default.
    pub fn process_got_plt(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let got_plt_markup = ElfDefaultGotPltMarkup::new(elf_load_helper);
        got_plt_markup.process(monitor)
    }

    /// Invoked before the ELF loader creates a function, to permit an extension to adjust the
    /// address and/or apply context to the intended location. The adjusted address is required.
    pub fn creating_function(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        function_address: Address,
    ) -> Address {
        let _ = elf_load_helper;
        function_address
    }

    /// Override the default address calculation for loading a symbol.
    ///
    /// Generally only necessary when a symbol requires handling of processor-specific flags or
    /// section index. `None` means default symbol processing is sufficient, which is what the base
    /// extension always answers.
    ///
    /// # Errors
    /// [`NoValueException`] if an extension logged an error and address calculation failed.
    pub fn calculate_symbol_address(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        elf_symbol: &ElfSymbol,
    ) -> Result<Option<Address>, NoValueException> {
        let _ = (elf_load_helper, elf_symbol);
        Ok(None)
    }

    /// Invoked during symbol processing to permit an extension to adjust the address and/or apply
    /// context to the intended symbol location.
    ///
    /// `address` is where the symbol will be created; `is_external` is true when the symbol is
    /// treated as external to the program and has been assigned a fake address in the EXTERNAL
    /// memory block. `None` means the extension will apply the symbol itself (and must then also
    /// call `ElfLoadHelper.setElfSymbolAddress`), or that the symbol should not be applied.
    pub fn evaluate_elf_symbol(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        elf_symbol: &ElfSymbol,
        address: Address,
        is_external: bool,
    ) -> Option<Address> {
        let _ = (elf_load_helper, elf_symbol, is_external);
        Some(address)
    }

    /// The write permission for the specified segment, or `None` to use the standard ELF program
    /// header flags to make the determination.
    pub fn is_segment_writable(&self, segment: &dyn ElfProgramHeader) -> Option<bool> {
        Some((segment.get_flags() & PF_W as i32) != 0)
    }

    /// The read permission for the specified segment, or `None` to use the standard ELF program
    /// header flags to make the determination.
    pub fn is_segment_readable(&self, segment: &dyn ElfProgramHeader) -> Option<bool> {
        Some((segment.get_flags() & PF_R as i32) != 0)
    }

    /// The execute permission for the specified segment, or `None` to use the standard ELF program
    /// header flags to make the determination.
    pub fn is_segment_executable(&self, segment: &dyn ElfProgramHeader) -> Option<bool> {
        Some((segment.get_flags() & PF_X as i32) != 0)
    }

    /// The write permission for the specified section, or `None` to use the standard ELF section
    /// flags to make the determination.
    pub fn is_section_writable(&self, section: &dyn ElfSectionHeader) -> Option<bool> {
        Some((section.get_flags() & SHF_WRITE as i64) != 0)
    }

    /// The execute permission (i.e. instructions permitted) for the specified section, or `None`
    /// to use the standard ELF section flags to make the determination.
    pub fn is_section_executable(&self, section: &dyn ElfSectionHeader) -> Option<bool> {
        Some((section.get_flags() & SHF_EXECINSTR as i64) != 0)
    }

    /// Whether the specified section is "allocated" within memory, or `None` to use the standard
    /// ELF section flags to make the determination.
    pub fn is_section_allocated(&self, section: &dyn ElfSectionHeader) -> Option<bool> {
        Some((section.get_flags() & SHF_ALLOC as i64) != 0)
    }

    /// The memory bytes to be loaded from the underlying file for the specified program header,
    /// consistent with any byte filtering which may be required.
    pub fn get_adjusted_load_size(&self, elf_program_header: &dyn ElfProgramHeader) -> i64 {
        elf_program_header.get_file_size()
    }

    /// The memory segment size in bytes for the specified program header, consistent with any byte
    /// filtering which may be required.
    pub fn get_adjusted_memory_size(&self, elf_program_header: &dyn ElfProgramHeader) -> i64 {
        elf_program_header.get_memory_size()
    }

    /// The dynamic memory block allocation alignment, as addressable units within the default
    /// memory space.
    pub fn get_linkage_block_alignment(&self) -> i32 {
        0x1000 // 4K alignment
    }

    /// The preferred free range size for the EXTERNAL memory block, as addressable units within
    /// the default memory space.
    pub fn get_preferred_external_block_size(&self) -> i32 {
        0x20000 // 128K
    }

    /// The reserve size of the EXTERNAL memory block, as addressable units within the default
    /// memory space. This is the largest expansion of the block that could occur during relocation
    /// processing.
    pub fn get_external_block_reserve_size(&self) -> i32 {
        0x10000 // 64K
    }

    /// The memory section size in bytes for the specified section header, consistent with any byte
    /// filtering and decompression which may be required.
    ///
    /// Defaults to the section's [logical size](ElfSectionHeader::get_logical_size).
    pub fn get_adjusted_size(&self, section: &dyn ElfSectionHeader) -> i64 {
        section.get_logical_size()
    }

    /// Filtered input stream for loading a memory block (including non-loaded OTHER blocks).
    ///
    /// The base extension applies no filtering and hands `data_input` straight back. An extension
    /// that overrides this must override
    /// [`has_filtered_load_input_stream`](Self::has_filtered_load_input_stream) consistently.
    ///
    /// `data_length` is the in-memory data length in bytes; more bytes than that may be read from
    /// `data_input`.
    ///
    /// # Errors
    /// Propagates any error raised while initializing a filtered stream.
    pub fn get_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        loadable: &dyn MemoryLoadable,
        start: &Address,
        data_length: i64,
        data_input: Box<dyn Read>,
    ) -> std::io::Result<Box<dyn Read>> {
        let _ = (elf_load_helper, loadable, start, data_length);
        Ok(data_input)
    }

    /// Whether
    /// [`get_filtered_load_input_stream`](Self::get_filtered_load_input_stream) has to be used
    /// when loading a memory block. A filtered input stream prevents the use of a direct mapping
    /// to file bytes, so the base extension answers false.
    ///
    /// `loadable` is the `ElfSectionHeader` or `ElfProgramHeader` for the block to be loaded, and
    /// `start` its memory load address.
    pub fn has_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        loadable: &dyn MemoryLoadable,
        start: &Address,
    ) -> bool {
        let _ = (elf_load_helper, loadable, start);
        false
    }

    /// The relocation entry constructor which should be used to parse the relocation tables, or
    /// `None` for default behaviour.
    ///
    /// `elf_header` is for header field access only.
    pub fn get_relocation_class(&self, elf_header: &dyn ElfHeader) -> Option<ElfRelocationFactory> {
        let _ = elf_header;
        None
    }

    /// Add extension-specific load options to `options`. The base extension adds none.
    pub fn add_load_options(
        &self,
        elf: &dyn ElfHeader,
        options: &mut Vec<Box<dyn crate::app::seam_stubs::Option>>,
    ) {
        let _ = (elf, options);
    }

    /// The default image base to be used when one cannot be determined.
    pub fn get_default_image_base(&self, elf_header: &dyn ElfHeader) -> i64 {
        if elf_header.is64_bit() {
            IMAGE64_BASE_DEFAULT
        } else {
            IMAGE32_BASE_DEFAULT
        }
    }

    /// The section-relative offset for an ELF symbol bound to `section`, or `None` if the symbol's
    /// value/offset is absolute.
    ///
    /// `section_base` is the memory address where the section was loaded, which may be within an
    /// overlay space if a load conflict occurred. For Harvard architectures an extension may have
    /// to adjust the offset when the section was mapped to a non-default data space.
    ///
    /// The default behaviour is to return [`ElfSymbol::get_value`] when the image is
    /// [relocatable](ElfHeader::is_relocatable).
    pub fn get_section_symbol_relative_offset(
        &self,
        section: &dyn ElfSectionHeader,
        section_base: &Address,
        elf_symbol: &ElfSymbol,
    ) -> Option<i64> {
        let _ = section_base;
        if section.get_elf_header().is_relocatable() {
            return Some(elf_symbol.get_value() as i64);
        }
        None
    }
}

/// Java compares the space against `program.getAddressFactory().getDefaultAddressSpace()` to decide
/// whether the image base adjustment applies.
fn is_default_address_space(space: &Arc<AddressSpace>, elf_load_helper: &dyn ElfLoadHelper) -> bool {
    elf_load_helper
        .get_program()
        .get_address_factory()
        .and_then(|factory| factory.get_default_address_space())
        .is_some_and(|default_space| default_space == *space)
}

/// `AddressSpace.getTruncatedAddress(offset, true)`: truncate an addressable *word* offset into the
/// space and build the address it names.
fn truncated_word_address(space: &Arc<AddressSpace>, word_offset: i64) -> Address {
    let byte_offset = space
        .truncate_addressable_word_offset(word_offset)
        .wrapping_mul(space.unit_size() as i64);
    space.address(byte_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::elf::elf_section_header_constants::SHN_UNDEF;
    use crate::format::elf::elf_symbol::{STB_GLOBAL, STT_FUNC};
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressFactory, AddressSpaceType};
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::Language;
    use crate::program::model::listing::program::Program;

    // ---------------------------------------------------------------- test doubles

    fn code_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn data_space() -> Arc<AddressSpace> {
        AddressSpace::new("data", 32, 1, AddressSpaceType::Ram, 1)
    }

    /// A word-addressed space, as a Harvard-architecture data space would be.
    fn word_space() -> Arc<AddressSpace> {
        AddressSpace::new("word", 32, 2, AddressSpaceType::Ram, 2)
    }

    struct MockHeader {
        is32: bool,
        relocatable: bool,
    }

    impl MockHeader {
        fn new() -> Self {
            MockHeader { is32: true, relocatable: false }
        }
    }

    impl ElfHeader for MockHeader {
        fn is32_bit(&self) -> bool {
            self.is32
        }
        fn is_relocatable(&self) -> bool {
            self.relocatable
        }
        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockProgram {
        /// The space `getAddressFactory().getDefaultAddressSpace()` answers, if any.
        default_space: Option<Arc<AddressSpace>>,
        data_space: Arc<AddressSpace>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            let space = self.default_space.clone()?;
            Some(Arc::new(DefaultAddressFactory::with_default_space(
                vec![space.clone(), self.data_space.clone()],
                Some(space),
            )))
        }
        fn get_language(&self) -> Option<Arc<dyn Language>> {
            Some(Arc::new(MockLanguage { data_space: self.data_space.clone() }))
        }
    }

    struct MockLoadHelper {
        program: Arc<MockProgram>,
        header: Arc<MockHeader>,
        image_base_word_adjustment: i64,
    }

    impl MockLoadHelper {
        fn new() -> Self {
            MockLoadHelper {
                program: Arc::new(MockProgram {
                    default_space: Some(code_space()),
                    data_space: data_space(),
                }),
                header: Arc::new(MockHeader::new()),
                image_base_word_adjustment: 0,
            }
        }
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_option_bool(&self, _option_name: &str, default_value: bool) -> bool {
            default_value
        }
        fn get_option_string(
            &self,
            _option_name: &str,
            default_value: std::option::Option<String>,
        ) -> std::option::Option<String> {
            default_value
        }
        fn get_option_i32(&self, _option_name: &str, default_value: i32) -> i32 {
            default_value
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            self.header.clone()
        }
        fn get_log(&self) -> Arc<dyn crate::format::seam_stubs::MessageLog> {
            unimplemented!("not exercised by these tests")
        }
        fn log(&self, _msg: &str) {}
        fn log_exception(&self, _t: &dyn std::error::Error) {}
        fn mark_as_code(&self, _address: Address) {}
        fn create_one_byte_function(
            &self,
            _name: std::option::Option<&str>,
            _address: Address,
            _is_entry: bool,
        ) -> Arc<dyn crate::program::model::listing::function::Function> {
            unimplemented!("not exercised by these tests")
        }
        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: std::option::Option<Address>,
        ) -> std::option::Option<Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> std::option::Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> std::option::Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: std::option::Option<Address>) {}
        fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> std::option::Option<Address> {
            None
        }
        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: std::option::Option<
                Arc<dyn crate::program::model::symbol::namespace::Namespace>,
            >,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::Symbol>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn find_load_address(
            &self,
            _section: &dyn MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> std::option::Option<Address> {
            None
        }
        fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            self.image_base_word_adjustment
        }
        fn get_got_value(&self) -> Option<i64> {
            None
        }
        fn allocate_linkage_block(
            &self,
            _alignment: i32,
            _size: i32,
            _purpose: &str,
        ) -> std::option::Option<crate::program::model::address::range::AddressRange> {
            None
        }
        fn get_original_value(
            &self,
            _addr: Address,
            _sign_extend: bool,
        ) -> Result<i64, crate::program::model::mem::memory_access_exception::MemoryAccessException>
        {
            unimplemented!("not exercised by these tests")
        }
        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }

    struct MockProgramHeader {
        flags: i32,
        virtual_address: i64,
        file_size: i64,
        memory_size: i64,
    }

    impl ElfProgramHeader for MockProgramHeader {
        fn get_flags(&self) -> i32 {
            self.flags
        }
        fn get_virtual_address(&self) -> i64 {
            self.virtual_address
        }
        fn get_file_size(&self) -> i64 {
            self.file_size
        }
        fn get_memory_size(&self) -> i64 {
            self.memory_size
        }
    }

    struct MockSectionHeader {
        header: Arc<MockHeader>,
        address: i64,
        flags: i64,
        logical_size: i64,
    }

    impl ElfSectionHeader for MockSectionHeader {
        fn get_name_as_string(&self) -> String {
            ".text".to_string()
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            self.header.clone()
        }
        fn get_address(&self) -> i64 {
            self.address
        }
        fn get_flags(&self) -> i64 {
            self.flags
        }
        fn get_logical_size(&self) -> i64 {
            self.logical_size
        }
    }

    struct MockLanguage {
        data_space: Arc<AddressSpace>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.data_space.clone()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            code_space()
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(
            &self,
            _address: &Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_register_at(
            &self,
            _addr: &Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by these tests")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(
            &self,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by these tests")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// An `ElfSymbol` with the given `st_value`, parsed from a synthetic little-endian
    /// `Elf32_Sym` entry.
    fn symbol_with_value(value: u32) -> ElfSymbol {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // st_name
        bytes.extend_from_slice(&value.to_le_bytes()); // st_value
        bytes.extend_from_slice(&4u32.to_le_bytes()); // st_size
        bytes.push((STB_GLOBAL << 4) | STT_FUNC); // st_info
        bytes.push(0); // st_other
        bytes.extend_from_slice(&SHN_UNDEF.to_le_bytes()); // st_shndx

        let mut reader = VecReader::new(bytes);
        ElfSymbol::parse(&mut reader, 1, &MockHeader::new()).expect("symbol entry parses")
    }

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            self.0
                .get(start..start + length)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// Smallest little-endian [`BinaryReader`] over a byte vector; the crate has no concrete
    /// reader yet.
    struct VecReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        current_index: u64,
    }

    impl VecReader {
        fn new(data: Vec<u8>) -> Self {
            VecReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                current_index: 0,
            }
        }
    }

    impl BinaryReader for VecReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            std::mem::replace(&mut self.current_index, index)
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(VecReader {
                provider: Rc::clone(&self.provider),
                current_index: new_index,
            })
        }
    }

    // ---------------------------------------------------------------- tests

    #[test]
    fn block_sizing_constants_match_the_java_defaults() {
        let adapter = ElfLoadAdapter::new();
        assert_eq!(adapter.get_linkage_block_alignment(), 0x1000);
        assert_eq!(adapter.get_preferred_external_block_size(), 0x20000);
        assert_eq!(adapter.get_external_block_reserve_size(), 0x10000);
    }

    #[test]
    fn base_extension_handles_nothing_and_supplies_no_overrides() {
        let adapter = ElfLoadAdapter::new();
        let header = MockHeader::new();
        let helper = MockLoadHelper::new();

        assert!(!adapter.can_handle_header(&header));
        assert!(!adapter.can_handle_load_helper(&helper));
        assert_eq!(adapter.get_data_type_suffix(), None);
        assert!(adapter.get_relocation_class(&header).is_none());

        // Java's calculateSymbolAddress returns null: defer to default symbol processing.
        let sym = symbol_with_value(0x1000);
        assert_eq!(adapter.calculate_symbol_address(&helper, &sym).unwrap(), None);

        let mut options = Vec::new();
        adapter.add_load_options(&header, &mut options);
        assert!(options.is_empty());
    }

    #[test]
    fn extension_type_maps_are_left_untouched_by_the_base_adapter() {
        let adapter = ElfLoadAdapter::new();

        // The base class declares no static DT_/PT_/SHT_ constants, so Java's reflective loop
        // adds nothing to any of the three maps.
        let mut dynamic_types: HashMap<i32, Box<dyn ElfDynamicType>> = HashMap::new();
        let mut program_header_types: HashMap<i32, Box<dyn ElfProgramHeaderType>> = HashMap::new();
        let mut section_header_types: HashMap<i32, Box<dyn ElfSectionHeaderType>> = HashMap::new();

        adapter.add_dynamic_types(&mut dynamic_types);
        adapter.add_program_header_types(&mut program_header_types);
        adapter.add_section_header_types(&mut section_header_types);

        assert!(dynamic_types.is_empty());
        assert!(program_header_types.is_empty());
        assert!(section_header_types.is_empty());
    }

    #[test]
    fn default_image_base_depends_on_the_elf_class() {
        let adapter = ElfLoadAdapter::new();

        let elf32 = MockHeader { is32: true, relocatable: false };
        assert_eq!(adapter.get_default_image_base(&elf32), 0x10000);

        let elf64 = MockHeader { is32: false, relocatable: false };
        assert_eq!(adapter.get_default_image_base(&elf64), 0x100000);
    }

    #[test]
    fn segment_permissions_come_from_the_p_flags_bits() {
        let adapter = ElfLoadAdapter::new();
        let rx = MockProgramHeader {
            flags: (PF_R | PF_X) as i32,
            virtual_address: 0,
            file_size: 0,
            memory_size: 0,
        };

        assert_eq!(adapter.is_segment_readable(&rx), Some(true));
        assert_eq!(adapter.is_segment_executable(&rx), Some(true));
        assert_eq!(adapter.is_segment_writable(&rx), Some(false));

        let rw = MockProgramHeader { flags: (PF_R | PF_W) as i32, ..rx };
        assert_eq!(adapter.is_segment_writable(&rw), Some(true));
        assert_eq!(adapter.is_segment_executable(&rw), Some(false));
    }

    #[test]
    fn section_permissions_come_from_the_sh_flags_bits() {
        let adapter = ElfLoadAdapter::new();
        let header = Arc::new(MockHeader::new());
        let data = MockSectionHeader {
            header: header.clone(),
            address: 0,
            flags: (SHF_WRITE | SHF_ALLOC) as i64,
            logical_size: 0,
        };

        assert_eq!(adapter.is_section_writable(&data), Some(true));
        assert_eq!(adapter.is_section_allocated(&data), Some(true));
        assert_eq!(adapter.is_section_executable(&data), Some(false));

        let text = MockSectionHeader { flags: (SHF_EXECINSTR | SHF_ALLOC) as i64, ..data };
        assert_eq!(adapter.is_section_executable(&text), Some(true));
        assert_eq!(adapter.is_section_writable(&text), Some(false));
    }

    #[test]
    fn adjusted_sizes_are_the_unfiltered_header_sizes() {
        let adapter = ElfLoadAdapter::new();
        let segment = MockProgramHeader {
            flags: PF_R as i32,
            virtual_address: 0x8000,
            file_size: 0x120,
            memory_size: 0x400, // .bss makes memsz exceed filesz
        };

        assert_eq!(adapter.get_adjusted_load_size(&segment), 0x120);
        assert_eq!(adapter.get_adjusted_memory_size(&segment), 0x400);

        let section = MockSectionHeader {
            header: Arc::new(MockHeader::new()),
            address: 0x8000,
            flags: SHF_ALLOC as i64,
            logical_size: 0x2a0,
        };
        assert_eq!(adapter.get_adjusted_size(&section), 0x2a0);
    }

    #[test]
    fn executable_segments_load_into_the_code_space_and_others_into_the_data_space() {
        let adapter = ElfLoadAdapter::new();
        let helper = MockLoadHelper::new();

        let text = MockProgramHeader {
            flags: (PF_R | PF_X) as i32,
            virtual_address: 0x8000,
            file_size: 0,
            memory_size: 0,
        };
        assert_eq!(
            adapter.get_preferred_segment_address_space(&helper, &text),
            Some(code_space())
        );

        let data = MockProgramHeader { flags: (PF_R | PF_W) as i32, ..text };
        assert_eq!(
            adapter.get_preferred_segment_address_space(&helper, &data),
            Some(data_space())
        );
    }

    #[test]
    fn image_base_adjustment_applies_to_the_default_space_only() {
        let adapter = ElfLoadAdapter::new();
        let helper = MockLoadHelper { image_base_word_adjustment: 0x1000, ..MockLoadHelper::new() };

        let text = MockProgramHeader {
            flags: (PF_R | PF_X) as i32,
            virtual_address: 0x8000,
            file_size: 0,
            memory_size: 0,
        };
        // Executable segment lands in the default space, so the adjustment is applied.
        assert_eq!(
            adapter.get_preferred_segment_address(&helper, &text),
            Some(Address::new(code_space(), 0x9000))
        );

        // The data space is not the default space, so p_vaddr is used verbatim.
        let data = MockProgramHeader { flags: (PF_R | PF_W) as i32, ..text };
        assert_eq!(
            adapter.get_preferred_segment_address(&helper, &data),
            Some(Address::new(data_space(), 0x8000))
        );
    }

    #[test]
    fn section_address_follows_sh_addr_with_the_same_image_base_rule() {
        let adapter = ElfLoadAdapter::new();
        let helper = MockLoadHelper { image_base_word_adjustment: 0x40, ..MockLoadHelper::new() };
        let header = Arc::new(MockHeader::new());

        let text = MockSectionHeader {
            header: header.clone(),
            address: 0x8000,
            flags: (SHF_EXECINSTR | SHF_ALLOC) as i64,
            logical_size: 0x10,
        };
        assert_eq!(
            adapter.get_preferred_section_address_space(&helper, &text),
            Some(code_space())
        );
        assert_eq!(
            adapter.get_preferred_section_address(&helper, &text),
            Some(Address::new(code_space(), 0x8040))
        );

        let data = MockSectionHeader { flags: (SHF_WRITE | SHF_ALLOC) as i64, ..text };
        assert_eq!(
            adapter.get_preferred_section_address(&helper, &data),
            Some(Address::new(data_space(), 0x8000))
        );
    }

    #[test]
    fn default_alignment_prefers_the_addressable_unit_then_the_pointer_size() {
        let adapter = ElfLoadAdapter::new();

        // Byte-addressed default space: fall through to the ELF class.
        let elf32 = MockLoadHelper::new();
        assert_eq!(adapter.get_default_alignment(&elf32), 4);

        let elf64 = MockLoadHelper {
            header: Arc::new(MockHeader { is32: false, relocatable: false }),
            ..MockLoadHelper::new()
        };
        assert_eq!(adapter.get_default_alignment(&elf64), 8);

        // Word-addressed default space: the addressable unit size wins over the ELF class.
        let word_addressed = MockLoadHelper {
            program: Arc::new(MockProgram {
                default_space: Some(word_space()),
                data_space: data_space(),
            }),
            header: Arc::new(MockHeader { is32: false, relocatable: false }),
            ..MockLoadHelper::new()
        };
        assert_eq!(adapter.get_default_alignment(&word_addressed), 2);
    }

    #[test]
    fn section_symbol_offset_is_relative_only_for_a_relocatable_image() {
        let adapter = ElfLoadAdapter::new();
        let sym = symbol_with_value(0x24);
        let section_base = Address::new(code_space(), 0x8000);

        let relocatable = MockSectionHeader {
            header: Arc::new(MockHeader { is32: true, relocatable: true }),
            address: 0,
            flags: SHF_ALLOC as i64,
            logical_size: 0x100,
        };
        assert_eq!(
            adapter.get_section_symbol_relative_offset(&relocatable, &section_base, &sym),
            Some(0x24)
        );

        // An executable/shared object carries absolute symbol values, so Java returns null.
        let executable = MockSectionHeader {
            header: Arc::new(MockHeader { is32: true, relocatable: false }),
            ..relocatable
        };
        assert_eq!(
            adapter.get_section_symbol_relative_offset(&executable, &section_base, &sym),
            None
        );
    }

    #[test]
    fn no_byte_filtering_is_applied_by_default() {
        struct AnyLoadable;
        impl MemoryLoadable for AnyLoadable {}

        let adapter = ElfLoadAdapter::new();
        let helper = MockLoadHelper::new();
        let start = Address::new(code_space(), 0x8000);

        assert!(!adapter.has_filtered_load_input_stream(&helper, &AnyLoadable, &start));

        let bytes: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let mut stream = adapter
            .get_filtered_load_input_stream(
                &helper,
                &AnyLoadable,
                &start,
                bytes.len() as i64,
                Box::new(std::io::Cursor::new(bytes.clone())),
            )
            .expect("the unfiltered stream is handed straight back");

        let mut read_back = Vec::new();
        stream.read_to_end(&mut read_back).unwrap();
        assert_eq!(read_back, bytes);
    }

    #[test]
    fn address_and_offset_hooks_are_identities() {
        let adapter = ElfLoadAdapter::new();
        let helper = MockLoadHelper::new();
        let space = code_space();
        let addr = Address::new(space.clone(), 0x8000);

        assert_eq!(adapter.get_adjusted_memory_offset(0x1234, &space), 0x1234);
        assert_eq!(adapter.creating_function(&helper, addr.clone()), addr);

        let sym = symbol_with_value(0x1000);
        assert_eq!(
            adapter.evaluate_elf_symbol(&helper, &sym, addr.clone(), false),
            Some(addr)
        );
    }
}
