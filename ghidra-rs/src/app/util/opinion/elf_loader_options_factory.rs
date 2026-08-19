//! Port of `ghidra.app.util.opinion.ElfLoaderOptionsFactory`.
//!
//! Java's version is a final class of statics (private constructor, only `static`/`static final`
//! members); ported as a plain module of `pub const`s and `pub fn`s rather than a zero-instance
//! struct, per this crate's convention for statics holders.
//!
//! # Departures from the Java class
//!
//! * `addOptions`/`validateOptions` take `LoadSpec loadSpec` and, inside, call
//!   `loadSpec.getLanguageCompilerSpec().getLanguage()`, which Java resolves via the
//!   `DefaultLanguageService` singleton (`DefaultLanguageService.getLanguageService()`). That
//!   singleton accessor was dropped when `DefaultLanguageService` was ported (see its module
//!   docs), so both functions here take an explicit `&dyn LanguageService` parameter instead,
//!   mirroring the same substitution already made in `program_architecture_translator`'s
//!   `resolve_language_by_id`.
//! * `addOptions` also constructs its own header via `new ElfHeader(provider, null)`. `ElfHeader`
//!   is not yet ported beyond a placeholder trait with no such constructor, so [`add_options`]
//!   takes an already-parsed `elf: &dyn ElfHeader` instead of a `ByteProvider`; the (unported)
//!   `ElfLoader` caller is expected to have parsed one already. Since `ElfHeader::get_load_adapter`
//!   already stands in for the same lookup `ElfExtensionFactory.getLoadAdapter(elf)` performs (see
//!   that method's docs), this port calls it directly rather than adding a separate
//!   `ElfExtensionFactory` seam for the same concept.
//! * `getRecommendedMinimumDataImageBase(ElfHeader, Language)` never reads its `elf` parameter, so
//!   [`get_recommended_minimum_data_image_base`] drops it.
//! * `validateOptions` wraps a caught `LanguageNotFoundException` in an unchecked
//!   `RuntimeException` and rethrows; [`validate_options`] mirrors that by panicking (`.expect`)
//!   on the same lookup failure instead of threading a `Result` through a function whose Java
//!   signature returns only `String`.

use std::sync::Arc;

use crate::app::seam_stubs::{new_boolean, new_integer, new_string, option_utils, LoadSpec, Option};
use crate::app::util::opinion::loader::COMMAND_LINE_ARG_PREFIX;
use crate::format::seam_stubs::ElfHeader;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::ghidra_language_property_keys::GhidraLanguagePropertyKeys;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::seam_stubs::LanguageNotFoundException;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::string_utilities::StringUtilities;

/// `ElfLoaderOptionsFactory.PERFORM_RELOCATIONS_NAME`.
pub const PERFORM_RELOCATIONS_NAME: &str = "Perform Symbol Relocations";
/// `ElfLoaderOptionsFactory.PERFORM_RELOCATIONS_DEFAULT`.
pub const PERFORM_RELOCATIONS_DEFAULT: bool = true;

/// `ElfLoaderOptionsFactory.APPLY_UNDEFINED_SYMBOL_DATA_NAME`.
pub const APPLY_UNDEFINED_SYMBOL_DATA_NAME: &str = "Apply Undefined Symbol Data";
/// `ElfLoaderOptionsFactory.APPLY_UNDEFINED_SYMBOL_DATA_DEFAULT`.
pub const APPLY_UNDEFINED_SYMBOL_DATA_DEFAULT: bool = true;

// NOTE: Using too large of an image base can cause problems for relocation processing
// for some language scenarios which utilize 32-bit relocations.  This may be due to
// an assumed virtual memory of 32-bits.

/// `ElfLoaderOptionsFactory.IMAGE_BASE_OPTION_NAME`.
pub const IMAGE_BASE_OPTION_NAME: &str = "Image Base";
/// `ElfLoaderOptionsFactory.IMAGE16_BASE_DEFAULT`.
pub const IMAGE16_BASE_DEFAULT: i64 = 0x0000_1000;
/// `ElfLoaderOptionsFactory.IMAGE32_BASE_DEFAULT`.
pub const IMAGE32_BASE_DEFAULT: i64 = 0x0001_0000;
/// `ElfLoaderOptionsFactory.IMAGE64_BASE_DEFAULT`.
pub const IMAGE64_BASE_DEFAULT: i64 = 0x0010_0000;

/// `ElfLoaderOptionsFactory.IMAGE_DATA_IMAGE_BASE_OPTION_NAME`.
pub const IMAGE_DATA_IMAGE_BASE_OPTION_NAME: &str = "Data Image Base";

/// `ElfLoaderOptionsFactory.INCLUDE_OTHER_BLOCKS` (as OTHER overlay blocks).
pub const INCLUDE_OTHER_BLOCKS: &str = "Import Non-Loaded Data";
/// `ElfLoaderOptionsFactory.INCLUDE_OTHER_BLOCKS_DEFAULT`.
pub const INCLUDE_OTHER_BLOCKS_DEFAULT: bool = true;

/// `ElfLoaderOptionsFactory.DISCARDABLE_SEGMENT_SIZE_OPTION_NAME`.
pub const DISCARDABLE_SEGMENT_SIZE_OPTION_NAME: &str = "Max Zero-Segment Discard Size";

/// `ElfLoaderOptionsFactory.DEFAULT_DISCARDABLE_SEGMENT_SIZE`: maximum length of a discardable
/// segment. If the program contains section headers, any zeroed segment smaller than this size
/// is eligible for removal.
pub const DEFAULT_DISCARDABLE_SEGMENT_SIZE: i32 = 0xff;

/// Default implementor of [`GhidraLanguagePropertyKeys`], used only to read the standard
/// `minimumDataImageBase` property key name (mirrors the same pattern used by
/// `pcode_userop_library_factory::DefaultLanguagePropertyKeys`).
struct DefaultLanguagePropertyKeys;
impl GhidraLanguagePropertyKeys for DefaultLanguagePropertyKeys {}

/// `ElfLoaderOptionsFactory.addOptions(List<Option>, ByteProvider, LoadSpec)`. See the module docs
/// for how the `ByteProvider`/`ElfHeader` construction and the `LanguageNotFoundException`-causing
/// language lookup were adapted.
///
/// NOTE: add-to-program is not supported.
pub fn add_options(
    options: &mut Vec<Box<dyn Option>>,
    elf: &dyn ElfHeader,
    load_spec: &LoadSpec,
    language_service: &dyn LanguageService,
) -> Result<(), LanguageNotFoundException> {
    options.push(
        new_boolean(PERFORM_RELOCATIONS_NAME)
            .value(Box::new(PERFORM_RELOCATIONS_DEFAULT))
            .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-applyRelocations"))
            .build(),
    );

    options.push(
        new_boolean(APPLY_UNDEFINED_SYMBOL_DATA_NAME)
            .value(Box::new(APPLY_UNDEFINED_SYMBOL_DATA_DEFAULT))
            .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-applyUndefinedData"))
            .build(),
    );

    let extension_adapter = elf.get_load_adapter();

    let language = load_spec.get_language(language_service)?;

    let mut image_base = elf.find_image_base();
    if image_base == 0 && (elf.is_relocatable() || elf.is_shared_object()) {
        image_base = match &extension_adapter {
            Some(adapter) => adapter.get_default_image_base(elf),
            None => {
                if elf.is64_bit() {
                    IMAGE64_BASE_DEFAULT
                } else {
                    IMAGE32_BASE_DEFAULT
                }
            }
        };
    }

    let default_space = language.get_default_space();

    let mut hex_value_str = get_base_address_offset_string(image_base, &default_space);
    options.push(
        new_string(IMAGE_BASE_OPTION_NAME)
            .value(Box::new(hex_value_str))
            .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-imagebase"))
            .build(),
    );

    if include_data_image_base_option(elf, language.as_ref()) {
        let min_data_image_base = get_recommended_minimum_data_image_base(language.as_ref());
        hex_value_str =
            get_base_address_offset_string(min_data_image_base, &language.get_default_data_space());
        options.push(
            new_string(IMAGE_DATA_IMAGE_BASE_OPTION_NAME)
                .value(Box::new(hex_value_str))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-dataImageBase"))
                .build(),
        );
    }

    options.push(
        new_boolean(INCLUDE_OTHER_BLOCKS)
            .value(Box::new(INCLUDE_OTHER_BLOCKS_DEFAULT))
            .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-includeOtherBlocks"))
            .build(),
    );

    options.push(
        new_integer(DISCARDABLE_SEGMENT_SIZE_OPTION_NAME)
            .value(Box::new(DEFAULT_DISCARDABLE_SEGMENT_SIZE))
            .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-maxSegmentDiscardSize"))
            .build(),
    );

    if let Some(adapter) = &extension_adapter {
        adapter.add_load_options(elf, options);
    }

    Ok(())
}

/// `ElfLoaderOptionsFactory.includeDataImageBaseOption(ElfHeader, Language)`: only include the
/// option if all segments and sections have a `0` address.
fn include_data_image_base_option(elf: &dyn ElfHeader, language: &dyn Language) -> bool {
    let default_space = language.get_default_space();
    let default_data_space = language.get_default_data_space();
    if default_data_space.as_ref() == default_space.as_ref() {
        return false;
    }
    elf.is_relocatable() && elf.get_image_base() == 0
}

/// `ElfLoaderOptionsFactory.getRecommendedMinimumDataImageBase(ElfHeader, Language)`. See the
/// module docs for why the (unused in Java) `elf` parameter is dropped.
fn get_recommended_minimum_data_image_base(language: &dyn Language) -> i64 {
    let keys = DefaultLanguagePropertyKeys;
    if let Some(min_data_offset) = language.get_property(keys.minimum_data_image_base()) {
        return NumericUtilities::parse_hex_long(&min_data_offset)
            .expect("language-defined minimumDataImageBase property must be valid hex");
    }

    let default_data_space = language.get_default_data_space();
    let unit_size = default_data_space.unit_size() as i64;

    // logic assumes memory mapped registers reside at low-end addresses (e.g., 0)
    let mut min_offset: i64 = 0;
    for reg in language.get_registers() {
        let reg = reg.borrow();
        let addr = reg.address();
        if default_data_space.as_ref() == addr.space().as_ref() {
            let offset = addr.offset();
            if offset < 0 {
                continue;
            }
            let offset = offset + reg.minimum_byte_size() as i64;
            if offset > min_offset {
                min_offset = offset;
            }
        }
    }

    // set minimum align
    let align = 16 * unit_size;
    min_offset += align - (min_offset % align);
    min_offset / unit_size
}

/// `ElfLoaderOptionsFactory.getBaseAddressOffsetString(long, AddressSpace)`.
fn get_base_address_offset_string(image_base: i64, space: &Arc<AddressSpace>) -> String {
    let max_offset = space.max_address().addressable_word_offset();
    let mut image_base = image_base as u64;
    while image_base > max_offset as u64 {
        image_base >>= 4;
    }
    let mut base_offset_str = format!("{image_base:x}");
    let min_nibbles = std::cmp::min(8, space.size() / 4);
    let base_offset_str_len = base_offset_str.len() as i32;
    if base_offset_str_len < min_nibbles {
        base_offset_str = base_offset_str.pad('0', min_nibbles - base_offset_str_len);
    }
    base_offset_str
}

/// `ElfLoaderOptionsFactory.validateOptions(LoadSpec, List<Option>)`. See the module docs for why
/// this panics (rather than returning a `Result`) on a language lookup failure.
pub fn validate_options(
    load_spec: &LoadSpec,
    options: &[Box<dyn Option>],
    language_service: &dyn LanguageService,
) -> std::option::Option<String> {
    let language = load_spec
        .get_language(language_service)
        .expect("LoadSpec's language/compiler spec must resolve to a known language");

    for option in options {
        let name = option.get_name();
        if name == PERFORM_RELOCATIONS_NAME
            || name == INCLUDE_OTHER_BLOCKS
            || name == APPLY_UNDEFINED_SYMBOL_DATA_NAME
        {
            if option.get_value().downcast_ref::<bool>().is_none() {
                return Some(format!("Invalid type for option: {name} - expected a boolean value"));
            }
        } else if name == IMAGE_BASE_OPTION_NAME {
            if let Some(err) =
                validate_address_space_offset_option(option.as_ref(), &language.get_default_space())
            {
                return Some(err);
            }
        } else if name == IMAGE_DATA_IMAGE_BASE_OPTION_NAME {
            if let Some(err) = validate_address_space_offset_option(
                option.as_ref(),
                &language.get_default_data_space(),
            ) {
                return Some(err);
            }
        } else if name == DISCARDABLE_SEGMENT_SIZE_OPTION_NAME {
            match option.get_value().downcast_ref::<i32>() {
                None => {
                    return Some(format!(
                        "Invalid type for option: {name} - expected an integer value"
                    ));
                }
                Some(&val) => {
                    if val < 0 || val > DEFAULT_DISCARDABLE_SEGMENT_SIZE {
                        return Some(format!(
                            "Option value out-of-range: {name} (0..{DEFAULT_DISCARDABLE_SEGMENT_SIZE})"
                        ));
                    }
                }
            }
        }
    }
    None
}

/// `ElfLoaderOptionsFactory.validateAddressSpaceOffsetOption(Option, AddressSpace)`.
fn validate_address_space_offset_option(
    option: &dyn Option,
    space: &Arc<AddressSpace>,
) -> std::option::Option<String> {
    let name = option.get_name();
    let value = match option.get_value().downcast_ref::<String>() {
        Some(v) => v.clone(),
        None => {
            return Some(format!("Invalid type for option: {name} - expected a string value"));
        }
    };
    let offset = match NumericUtilities::parse_hex_long(&value) {
        Ok(offset) => offset,
        Err(_) => return Some(format!("Invalid {name} - expecting hexidecimal address offset")),
    };
    // verify valid address
    match space.address_from_word_offset(offset) {
        Ok(_) => None,
        Err(e) => Some(format!("Invalid {name} - {}", e.message())),
    }
}

/// `ElfLoaderOptionsFactory.performRelocations(List<Option>)`.
pub fn perform_relocations(options: &[Box<dyn Option>]) -> bool {
    option_utils::get_bool_option(PERFORM_RELOCATIONS_NAME, options, PERFORM_RELOCATIONS_DEFAULT)
}

/// `ElfLoaderOptionsFactory.applyUndefinedSymbolData(List<Option>)`.
pub fn apply_undefined_symbol_data(options: &[Box<dyn Option>]) -> bool {
    option_utils::get_bool_option(
        APPLY_UNDEFINED_SYMBOL_DATA_NAME,
        options,
        APPLY_UNDEFINED_SYMBOL_DATA_DEFAULT,
    )
}

/// `ElfLoaderOptionsFactory.includeOtherBlocks(List<Option>)`.
pub fn include_other_blocks(options: &[Box<dyn Option>]) -> bool {
    option_utils::get_bool_option(INCLUDE_OTHER_BLOCKS, options, INCLUDE_OTHER_BLOCKS_DEFAULT)
}

/// `ElfLoaderOptionsFactory.hasImageBaseOption(List<Option>)`.
pub fn has_image_base_option(options: &[Box<dyn Option>]) -> bool {
    option_utils::contains_option(IMAGE_BASE_OPTION_NAME, options)
}

/// `ElfLoaderOptionsFactory.getImageBaseOption(List<Option>)`.
pub fn get_image_base_option(options: &[Box<dyn Option>]) -> std::option::Option<String> {
    option_utils::get_string_option(IMAGE_BASE_OPTION_NAME, options, None)
}

/// `ElfLoaderOptionsFactory.getDataImageBaseOption(List<Option>)`.
pub fn get_data_image_base_option(options: &[Box<dyn Option>]) -> std::option::Option<String> {
    option_utils::get_string_option(IMAGE_DATA_IMAGE_BASE_OPTION_NAME, options, None)
}

/// `ElfLoaderOptionsFactory.getMaxSegmentDiscardSize(List<Option>)`.
pub fn get_max_segment_discard_size(options: &[Box<dyn Option>]) -> i32 {
    option_utils::get_int_option(
        DISCARDABLE_SEGMENT_SIZE_OPTION_NAME,
        options,
        DEFAULT_DISCARDABLE_SEGMENT_SIZE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::ElfSectionHeader;
    use crate::program::model::address::{Address, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{LanguageCompilerSpecPair, Processor};
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    // --- get_base_address_offset_string: locks in a real (and slightly surprising) upstream
    // quirk in `StringUtilities.pad`'s caller: `pad(str, '0', minNibbles - str.length())` passes
    // a *padding amount* where `pad` expects a *total target length*, so the padded result ends
    // up `minNibbles - str.length()` characters long, not `minNibbles`. This is exactly what real
    // Ghidra does, so the port must reproduce it rather than "fix" it.

    #[test]
    fn base_address_offset_string_short_value_reproduces_upstream_pad_quirk() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        // "1000" is 4 hex chars; minNibbles = min(8, 32/4) = 8; pad amount passed = 8-4 = 4;
        // pad's internal `n = length - source.len()` = 4-4 = 0, so no characters are added.
        assert_eq!(get_base_address_offset_string(0x1000, &space), "1000");
    }

    #[test]
    fn base_address_offset_string_zero_reproduces_upstream_pad_quirk() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        // "0" is 1 hex char; minNibbles = 8; pad amount passed = 8-1 = 7;
        // pad's internal n = 7-1 = 6, so 6 zeros are prepended: 7 chars total, not 8.
        assert_eq!(get_base_address_offset_string(0, &space), "0000000");
    }

    #[test]
    fn base_address_offset_string_shifts_out_of_range_image_base() {
        let space = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 0);
        // max addressable word offset is 0xFFFF; 0x100000 exceeds it twice over (>>4 => 0x10000,
        // still too big; >>4 again => 0x1000, which fits), landing on "1000".
        assert_eq!(get_base_address_offset_string(0x100000, &space), "1000");
    }

    #[test]
    fn numeric_utilities_parse_hex_long_matches_java_behavior() {
        assert_eq!(NumericUtilities::parse_hex_long("1000").unwrap(), 0x1000);
        assert_eq!(NumericUtilities::parse_hex_long("0x1000").unwrap(), 0x1000);
        assert_eq!(NumericUtilities::parse_hex_long("0X1000").unwrap(), 0x1000);
        assert!(NumericUtilities::parse_hex_long("not-hex").is_err());
    }

    struct MockProcessor(&'static str);
    impl Processor for MockProcessor {
        fn name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockLanguage {
        default_space: Arc<AddressSpace>,
        default_data_space: Arc<AddressSpace>,
        registers: Vec<RegisterRef>,
        min_data_image_base_property: std::option::Option<String>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }

        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> std::option::Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor("test"))
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.default_space.clone()
        }

        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.default_data_space.clone()
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
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>, ParseError>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> std::option::Option<String> {
            None
        }

        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> std::option::Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.clone()
        }

        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_register_by_name(&self, _name: &str) -> std::option::Option<RegisterRef> {
            None
        }

        fn get_register_at(&self, _addr: &Address, _size: i32) -> std::option::Option<RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> std::option::Option<RegisterRef> {
            None
        }

        fn get_context_base_register(&self) -> std::option::Option<RegisterRef> {
            None
        }

        fn get_context_registers(&self) -> Vec<RegisterRef> {
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
            unimplemented!("not exercised by this smoke test")
        }

        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}

        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }

        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }

        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
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

        fn get_property(&self, key: &str) -> std::option::Option<String> {
            let keys = DefaultLanguagePropertyKeys;
            if key == keys.minimum_data_image_base() {
                return self.min_data_image_base_property.clone();
            }
            None
        }

        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn has_manual(&self) -> bool {
            false
        }

        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> std::option::Option<crate::util::manual_entry::ManualEntry> {
            None
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn get_manual_exception(&self) -> std::option::Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_maximum_instruction_length(&self) -> std::option::Option<i32> {
            None
        }
    }

    struct MockElfHeader {
        is_64_bit: bool,
        is_relocatable: bool,
        is_shared_object: bool,
        find_image_base: i64,
        get_image_base: i64,
    }

    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            !self.is_64_bit
        }

        fn is_relocatable(&self) -> bool {
            self.is_relocatable
        }

        fn is_shared_object(&self) -> bool {
            self.is_shared_object
        }

        fn find_image_base(&self) -> i64 {
            self.find_image_base
        }

        fn get_image_base(&self) -> i64 {
            self.get_image_base
        }

        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockLanguageService {
        language: Arc<MockLanguage>,
    }

    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            Ok(Box::new(MockLanguageInstance(self.language.clone())))
        }

        fn get_default_language(
            &self,
            _processor: &dyn Processor,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_description(
            &self,
            _language_id: &LanguageID,
        ) -> Result<
            Box<dyn crate::program::model::lang::language_description::LanguageDescription>,
            LanguageNotFoundException,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            Vec::new()
        }

        #[allow(deprecated)]
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: std::option::Option<crate::program::model::lang::endian::Endian>,
            _size: std::option::Option<i32>,
            _variant: std::option::Option<&str>,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_compiler_spec_pairs(
            &self,
            _query: &crate::program::seam_stubs::LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &crate::program::seam_stubs::ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn Processor,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// Thin `Language` forwarder over a shared `MockLanguage`, needed because
    /// `LanguageService::get_language` must return an owned `Box<dyn Language>` each call.
    struct MockLanguageInstance(Arc<MockLanguage>);

    impl std::ops::Deref for MockLanguageInstance {
        type Target = MockLanguage;
        fn deref(&self) -> &MockLanguage {
            &self.0
        }
    }

    impl Language for MockLanguageInstance {
        fn get_language_id(&self) -> LanguageID {
            self.0.get_language_id()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            self.0.get_language_description()
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> std::option::Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            self.0.get_parallel_instruction_helper()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            self.0.get_processor()
        }
        fn get_version(&self) -> i32 {
            self.0.get_version()
        }
        fn get_minor_version(&self) -> i32 {
            self.0.get_minor_version()
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            self.0.get_address_factory()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.0.get_default_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.0.get_default_data_space()
        }
        fn is_big_endian(&self) -> bool {
            self.0.is_big_endian()
        }
        fn get_instruction_alignment(&self) -> i32 {
            self.0.get_instruction_alignment()
        }
        fn supports_pcode(&self) -> bool {
            self.0.supports_pcode()
        }
        fn is_volatile(&self, addr: &Address) -> bool {
            self.0.is_volatile(addr)
        }
        fn parse(
            &self,
            buf: &dyn MemBuffer,
            context: &mut dyn ProcessorContext,
            in_delay_slot: bool,
        ) -> Result<Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>, ParseError>
        {
            self.0.parse(buf, context, in_delay_slot)
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            self.0.get_number_of_user_defined_op_names()
        }
        fn get_user_defined_op_name(&self, index: i32) -> std::option::Option<String> {
            self.0.get_user_defined_op_name(index)
        }
        fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
            self.0.get_registers_at(address)
        }
        fn get_register_in_space(
            &self,
            addrspc: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
        ) -> std::option::Option<RegisterRef> {
            self.0.get_register_in_space(addrspc, offset, size)
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.0.get_registers()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.0.get_register_names()
        }
        fn get_register_by_name(&self, name: &str) -> std::option::Option<RegisterRef> {
            self.0.get_register_by_name(name)
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> std::option::Option<RegisterRef> {
            self.0.get_register_at(addr, size)
        }
        fn get_program_counter(&self) -> std::option::Option<RegisterRef> {
            self.0.get_program_counter()
        }
        fn get_context_base_register(&self) -> std::option::Option<RegisterRef> {
            self.0.get_context_base_register()
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            self.0.get_context_registers()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            self.0.get_default_memory_blocks()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            self.0.get_default_symbols()
        }
        fn get_segmented_space(&self) -> String {
            self.0.get_segmented_space()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            self.0.get_volatile_addresses()
        }
        fn apply_context_settings(&self, ctx: &mut dyn DefaultProgramContext) {
            self.0.apply_context_settings(ctx)
        }
        fn reload_language(&self, task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            self.0.reload_language(task_monitor)
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            self.0.get_compatible_compiler_spec_descriptions()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            self.0.get_compiler_spec_by_id(compiler_spec_id)
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            self.0.get_default_compiler_spec()
        }
        fn has_property(&self, key: &str) -> bool {
            self.0.has_property(key)
        }
        fn get_property_as_int(&self, key: &str, default_int: i32) -> i32 {
            self.0.get_property_as_int(key, default_int)
        }
        fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool {
            self.0.get_property_as_boolean(key, default_boolean)
        }
        fn get_property_or(&self, key: &str, default_string: &str) -> String {
            self.0.get_property_or(key, default_string)
        }
        fn get_property(&self, key: &str) -> std::option::Option<String> {
            self.0.get_property(key)
        }
        fn get_property_keys(&self) -> HashSet<String> {
            self.0.get_property_keys()
        }
        fn has_manual(&self) -> bool {
            self.0.has_manual()
        }
        fn get_manual_entry(&self, instruction_mnemonic: &str) -> std::option::Option<crate::util::manual_entry::ManualEntry> {
            self.0.get_manual_entry(instruction_mnemonic)
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            self.0.get_manual_instruction_mnemonic_keys()
        }
        fn get_manual_exception(&self) -> std::option::Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            self.0.get_manual_exception()
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            self.0.get_sorted_vector_registers()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            self.0.get_register_addresses()
        }
        fn get_maximum_instruction_length(&self) -> std::option::Option<i32> {
            self.0.get_maximum_instruction_length()
        }
    }

    fn make_language_service(ram_space: Arc<AddressSpace>) -> MockLanguageService {
        MockLanguageService {
            language: Arc::new(MockLanguage {
                default_space: ram_space.clone(),
                default_data_space: ram_space,
                registers: Vec::new(),
                min_data_image_base_property: None,
            }),
        }
    }

    fn make_load_spec() -> LoadSpec {
        LoadSpec::new(LanguageCompilerSpecPair::new(
            LanguageID::new("test:LE:32:default").unwrap(),
            CompilerSpecID::new(Some("default")),
        ))
    }

    #[test]
    fn add_options_then_validate_options_round_trips_cleanly() {
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let language_service = make_language_service(ram_space);
        let load_spec = make_load_spec();
        let elf = MockElfHeader {
            is_64_bit: false,
            is_relocatable: false,
            is_shared_object: false,
            find_image_base: 0x1000,
            get_image_base: 0x1000,
        };

        let mut options = Vec::new();
        add_options(&mut options, &elf, &load_spec, &language_service)
            .expect("language lookup should succeed");

        // Same default_space/default_data_space, so no data-image-base option is added.
        assert_eq!(options.len(), 5);
        assert!(perform_relocations(&options));
        assert!(apply_undefined_symbol_data(&options));
        assert!(include_other_blocks(&options));
        assert!(has_image_base_option(&options));
        assert_eq!(get_image_base_option(&options), Some("1000".to_string()));
        assert_eq!(get_data_image_base_option(&options), None);
        assert_eq!(get_max_segment_discard_size(&options), DEFAULT_DISCARDABLE_SEGMENT_SIZE);

        assert_eq!(validate_options(&load_spec, &options, &language_service), None);
    }

    #[test]
    fn add_options_uses_default_image_base_when_relocatable_with_no_recorded_base() {
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let language_service = make_language_service(ram_space);
        let load_spec = make_load_spec();
        let elf = MockElfHeader {
            is_64_bit: false,
            is_relocatable: true,
            is_shared_object: false,
            find_image_base: 0,
            get_image_base: 0,
        };

        let mut options = Vec::new();
        add_options(&mut options, &elf, &load_spec, &language_service).unwrap();

        // No extension adapter (elf.get_load_adapter() defaults to None) and is32_bit, so the
        // 32-bit default image base is used, matching `IMAGE32_BASE_DEFAULT`. "10000" is 5 hex
        // chars; minNibbles = 8; the pad amount passed (8-5=3) is less than the source length, so
        // (per the same upstream `pad` quirk locked in above) no padding is actually added.
        assert_eq!(get_image_base_option(&options), Some(format!("{IMAGE32_BASE_DEFAULT:x}")));
    }

    #[test]
    fn validate_options_rejects_out_of_range_discardable_segment_size() {
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let language_service = make_language_service(ram_space);
        let load_spec = make_load_spec();

        let options: Vec<Box<dyn Option>> = vec![new_integer(DISCARDABLE_SEGMENT_SIZE_OPTION_NAME)
            .value(Box::new(DEFAULT_DISCARDABLE_SEGMENT_SIZE + 1))
            .command_line_argument(String::new())
            .build()];

        let err = validate_options(&load_spec, &options, &language_service);
        assert!(err.is_some());
        assert!(err.unwrap().contains("out-of-range"));
    }

    #[test]
    fn include_data_image_base_option_requires_distinct_spaces() {
        let same_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let language = MockLanguage {
            default_space: same_space.clone(),
            default_data_space: same_space,
            registers: Vec::new(),
            min_data_image_base_property: None,
        };
        let elf = MockElfHeader {
            is_64_bit: false,
            is_relocatable: true,
            is_shared_object: false,
            find_image_base: 0,
            get_image_base: 0,
        };
        assert!(!include_data_image_base_option(&elf, &language));

        let data_space = AddressSpace::new("data", 32, 1, AddressSpaceType::Ram, 1);
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let language = MockLanguage {
            default_space: ram_space,
            default_data_space: data_space,
            registers: Vec::new(),
            min_data_image_base_property: None,
        };
        assert!(include_data_image_base_option(&elf, &language));
    }

    #[test]
    fn recommended_minimum_data_image_base_uses_language_property_when_present() {
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let language = MockLanguage {
            default_space: ram_space.clone(),
            default_data_space: ram_space,
            registers: Vec::new(),
            min_data_image_base_property: Some("2000".to_string()),
        };
        assert_eq!(get_recommended_minimum_data_image_base(&language), 0x2000);
    }

    #[test]
    fn recommended_minimum_data_image_base_derives_from_registers_when_no_property() {
        let ram_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let reg_addr = Address::new(ram_space.clone(), 0x10);
        let register: RegisterRef = Register::new("r0", "test register", reg_addr, 4, false, 0);
        let language = MockLanguage {
            default_space: ram_space.clone(),
            default_data_space: ram_space,
            registers: vec![register],
            min_data_image_base_property: None,
        };
        // min_offset starts from reg address (0x10) + minimum_byte_size (4) = 0x14; aligned up to
        // the next multiple of 16 (align = 16 * unit_size(1) = 16): 0x14 -> 0x20; divided by
        // unit_size(1) => 0x20.
        assert_eq!(get_recommended_minimum_data_image_base(&language), 0x20);
    }
}
