//! Port of `ghidra.app.util.opinion.BinaryLoader`: loads a file's raw bytes as one initialized
//! memory block, for any language.
//!
//! As for [`ElfLoader`](crate::app::util::opinion::elf_loader::ElfLoader), the `Loader` methods
//! are inherent methods taking the pieces of `ImporterSettings` they read (the language service
//! included, since `getLanguageService()` resolves a dropped singleton). The inherited parts
//! come from [`AbstractProgramLoader`].
//!
//! # Not yet ported
//!
//! `loadProgram(ImporterSettings)` -- it needs `AbstractProgramLoader.createProgram` and
//! `createDefaultMemoryBlocks` (see that module's docs). A caller creates the program (e.g. a
//! `ProgramDB` on the chosen language) and calls
//! [`load_program_into`](AbstractProgramLoader::load_program_into).

use std::io;

use crate::app::seam_stubs::{new_address, new_boolean, new_hex_long, new_string, LoadSpec, Option};
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::hex_long::HexLong;
use crate::app::util::importer::message_log::MessageLog;
use crate::app::util::memory_block_utils;
use crate::app::util::opinion::abstract_program_loader::{io_error, AbstractProgramLoader};
use crate::app::util::opinion::loader::{LoadIntoError, COMMAND_LINE_ARG_PREFIX};
use crate::app::util::opinion::loader_tier::LoaderTier;
use crate::program::database::mem::memory_map_db::MAX_BINARY_SIZE;
use crate::program::model::address::{Address, AddressSetView as _};
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::Program;
use crate::program::model::mem::memory::CreateBlockError;
use crate::program::seam_stubs::LanguageCompilerSpecPair;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::task::TaskMonitor;

/// `BinaryLoader.BINARY_NAME`.
pub const BINARY_NAME: &str = "Raw Binary";
/// `BinaryLoader.OPTION_NAME_LEN`.
pub const OPTION_NAME_LEN: &str = "Length";
/// `BinaryLoader.OPTION_NAME_FILE_OFFSET`.
pub const OPTION_NAME_FILE_OFFSET: &str = "File Offset";
/// `BinaryLoader.OPTION_NAME_BASE_ADDR`.
pub const OPTION_NAME_BASE_ADDR: &str = "Base Address";
/// `BinaryLoader.OPTION_NAME_BLOCK_NAME`.
pub const OPTION_NAME_BLOCK_NAME: &str = "Block Name";
/// `BinaryLoader.OPTION_NAME_IS_OVERLAY`.
pub const OPTION_NAME_IS_OVERLAY: &str = "Overlay";

/// The raw-binary loader.
#[derive(Debug, Default, Clone, Copy)]
pub struct BinaryLoader;

/// Java's `parseLong(Option)` failure (a `NumberFormatException`/`ClassCastException`).
#[derive(Debug)]
struct ParseLongError;

/// `parseLong(Option)`: the option's value rendered as a string, an optional `0x` stripped, parsed
/// as hex; `Ok(None)` for a `null` value.
fn parse_long(option: &dyn Option) -> Result<std::option::Option<i64>, ParseLongError> {
    let value = option.get_value();
    let rendered = if let Some(h) = value.downcast_ref::<HexLong>() {
        h.to_string()
    } else if let Some(s) = value.downcast_ref::<String>() {
        s.clone()
    } else if let Some(i) = value.downcast_ref::<i32>() {
        i.to_string()
    } else if let Some(i) = value.downcast_ref::<i64>() {
        i.to_string()
    } else {
        return Err(ParseLongError);
    };
    let rendered = if rendered.to_lowercase().starts_with("0x") { &rendered[2..] } else { &rendered[..] };
    NumericUtilities::parse_hex_long(rendered).map(Some).map_err(|_| ParseLongError)
}

fn base_addr_value(option: &dyn Option) -> std::option::Option<std::option::Option<Address>> {
    let value = option.get_value();
    value.downcast_ref::<std::option::Option<Address>>().cloned()
}

impl BinaryLoader {
    pub fn new() -> Self {
        BinaryLoader
    }

    /// `getTier()`.
    pub fn get_tier(&self) -> LoaderTier {
        LoaderTier::UntargetedLoader
    }

    /// `getTierPriority()`.
    pub fn get_tier_priority(&self) -> i32 {
        100
    }

    /// `supportsLoadIntoProgram()`.
    pub fn supports_load_into_program(&self) -> bool {
        true
    }

    /// `getName()`.
    pub fn get_name(&self) -> &'static str {
        BINARY_NAME
    }

    /// `findSupportedLoadSpecs(ByteProvider)`: one non-preferred load spec per (language,
    /// compatible compiler spec) pair the language service knows (deprecated languages excluded).
    pub fn find_supported_load_specs(&self, language_service: &dyn LanguageService) -> Vec<LoadSpec> {
        let mut load_specs = Vec::new();
        for language_description in language_service.get_language_descriptions(false) {
            for compiler_spec_description in language_description.get_compatible_compiler_spec_descriptions() {
                let lcs = LanguageCompilerSpecPair::new(
                    language_description.get_language_id(),
                    compiler_spec_description.get_compiler_spec_id(),
                );
                load_specs.push(LoadSpec::with_language_compiler_spec(0, lcs, false));
            }
        }
        load_specs
    }

    /// `validateOptions(ByteProvider, LoadSpec, List<Option>, Program)`. `None` means valid.
    pub fn validate_options(
        &self,
        provider: &dyn ByteProvider,
        options: &[Box<dyn Option>],
        program: std::option::Option<&dyn Program>,
    ) -> std::option::Option<String> {
        let mut base_addr: std::option::Option<Address> = None;
        let mut length: i64 = 0;
        let mut file_offset: i64 = 0;
        let mut is_overlay = false;
        let orig_file_length = provider.length() as i64;

        for option in options {
            if option.get_name() == OPTION_NAME_BASE_ADDR {
                match base_addr_value(option.as_ref()) {
                    Some(addr) => base_addr = addr,
                    None => {
                        return Some(format!(
                            "Invalid value for {} - {}",
                            option.get_name(),
                            render(option.as_ref())
                        ))
                    }
                }
            }
        }
        let Some(base_addr) = base_addr else {
            return Some("Invalid base address".to_string());
        };

        for option in options {
            let opt_name = option.get_name();
            if opt_name == OPTION_NAME_BASE_ADDR {
                // skip - handled above
            } else if opt_name == OPTION_NAME_FILE_OFFSET {
                file_offset = match parse_long(option.as_ref()) {
                    Ok(Some(v)) => v,
                    Ok(None) => return Some(format!("Invalid value for {opt_name} - null")),
                    Err(_) => -1,
                };
                if file_offset < 0 || file_offset >= orig_file_length {
                    return Some(format!(
                        "File Offset must be greater than or equal to 0 and less than file length {orig_file_length} (0x{orig_file_length:x})"
                    ));
                }
            } else if opt_name == OPTION_NAME_LEN {
                length = match parse_long(option.as_ref()) {
                    Ok(Some(v)) => v,
                    Ok(None) => return Some(format!("Invalid value for {opt_name} - null")),
                    Err(_) => -1,
                };
                if length < 0 || length > orig_file_length {
                    return Some(format!(
                        "Length must be greater than or equal to 0 and less than or equal to file length {orig_file_length} (0x{orig_file_length:x})"
                    ));
                }

                let base_offset = base_addr.offset();
                let space = base_addr.space();
                let mut max_length = MAX_BINARY_SIZE;
                if space.size() < 64 {
                    max_length = max_length.min(space.max_offset().wrapping_add(1).wrapping_sub(base_offset));
                } else if base_offset < 0 && base_offset > -MAX_BINARY_SIZE {
                    max_length = -base_offset;
                }
                if length > max_length {
                    return Some(format!(
                        "Length must not exceed maximum allowed size of {max_length} (0x{max_length:x}) bytes"
                    ));
                }
            } else if opt_name == OPTION_NAME_BLOCK_NAME {
                if !option.get_value().is::<String>() {
                    return Some(format!("{OPTION_NAME_BLOCK_NAME} must be a String"));
                }
            } else if opt_name == OPTION_NAME_IS_OVERLAY {
                match option.get_value().downcast_ref::<bool>() {
                    Some(v) => is_overlay = *v,
                    None => return Some(format!("{OPTION_NAME_IS_OVERLAY} must be a boolean")),
                }
            }
        }
        if file_offset + length > orig_file_length {
            return Some(format!(
                "File Offset + Length (0x{:x}) too large; set length to 0x{:x}",
                file_offset + length,
                orig_file_length - file_offset
            ));
        }
        if file_offset == -1 {
            return Some("Invalid file offset specified".to_string());
        }
        if length == -1 {
            return Some("Invalid length specified".to_string());
        }
        if let Some(program) = program {
            if let (Some(memory), Ok(end)) = (program.get_memory(), base_addr.add(length - 1)) {
                if !memory.intersect_range(&base_addr, &end).is_empty() && !is_overlay {
                    return Some("Memory Conflict: Use <Options...> to change the base address!".to_string());
                }
            }
        }
        AbstractProgramLoader::validate_options(self, options)
    }

    /// `getDefaultOptions(ByteProvider, LoadSpec, DomainObject, boolean, boolean)`.
    /// `program` is the `DomainObject` when it is a program (its default space's address 0 is the
    /// default base address).
    pub fn get_default_options(
        &self,
        provider: &dyn ByteProvider,
        program: std::option::Option<&dyn Program>,
        load_into_program: bool,
    ) -> Vec<Box<dyn Option>> {
        let file_offset: i64 = 0;
        let orig_file_length = provider.length() as i64;
        let mut length = orig_file_length;
        let is_overlay = false;
        let block_name = String::new();
        let base_addr = program
            .and_then(|p| p.get_address_factory())
            .and_then(|f| f.get_default_address_space())
            .map(|space| space.address(0));

        let temp_length = orig_file_length - file_offset;
        let len = temp_length.min(orig_file_length);
        length = length.min(len);

        let mut list: Vec<Box<dyn Option>> = Vec::new();
        if load_into_program {
            list.push(new_boolean(OPTION_NAME_IS_OVERLAY).value(Box::new(is_overlay)).build());
        }
        list.push(
            new_string(OPTION_NAME_BLOCK_NAME)
                .value(Box::new(block_name))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-blockName"))
                .build(),
        );
        list.push(
            new_address(OPTION_NAME_BASE_ADDR)
                .value(Box::new(base_addr))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-baseAddr"))
                .build(),
        );
        list.push(
            new_hex_long(OPTION_NAME_FILE_OFFSET)
                .value(Box::new(HexLong::new(file_offset)))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-fileOffset"))
                .build(),
        );
        list.push(
            new_hex_long(OPTION_NAME_LEN)
                .value(Box::new(HexLong::new(length)))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-length"))
                .build(),
        );
        list.extend(AbstractProgramLoader::get_default_options(self));
        list
    }

    /// `createBlock(Program, boolean, String, Address, FileBytes, long, MessageLog)`.
    fn create_block(
        program: &dyn Program,
        is_overlay: bool,
        block_name: &str,
        base_addr: &Address,
        file_bytes: &std::sync::Arc<dyn crate::program::database::mem::file_bytes::FileBytes>,
        length: i64,
        log: &MessageLog,
    ) -> Result<(), CreateBlockError> {
        let end = base_addr.add(length - 1)?;
        let conflicts = program
            .get_memory()
            .is_some_and(|m| !m.intersect_range(base_addr, &end).is_empty());
        if conflicts && !is_overlay {
            return Err(CreateBlockError::Io(io::Error::other(format!(
                "Can't load {length} bytes at address {base_addr} since it conflicts with existing memory blocks!"
            ))));
        }
        memory_block_utils::create_initialized_block(
            program,
            is_overlay,
            block_name,
            base_addr,
            file_bytes,
            0,
            length,
            None,
            Some("Binary Loader"),
            true,
            !is_overlay,
            !is_overlay,
            log,
        )?;
        Ok(())
    }

    /// `clipToMemorySpace(long, MessageLog, Program)`.
    fn clip_to_memory_space(length: i64, log: &MessageLog, program: &dyn Program) -> i64 {
        let Some(space) = program.get_address_factory().and_then(|f| f.get_default_address_space()) else {
            return length;
        };
        let max_length = space.max_offset().wrapping_add(1);
        if max_length > 0 && length > max_length {
            log.append_msg("Clipped file to fit into memory space");
            return max_length;
        }
        length
    }
}

/// `"" + option.getValue()` for an error message.
fn render(option: &dyn Option) -> String {
    let value = option.get_value();
    if let Some(s) = value.downcast_ref::<String>() {
        s.clone()
    } else if let Some(b) = value.downcast_ref::<bool>() {
        b.to_string()
    } else if let Some(i) = value.downcast_ref::<i32>() {
        i.to_string()
    } else if let Some(h) = value.downcast_ref::<HexLong>() {
        h.to_string()
    } else {
        "null".to_string()
    }
}

/// The value of the named option, if present (Java's `get*(List<Option>)` getters loop to the last
/// match; options are unique by name in practice).
fn find<'a>(options: &'a [Box<dyn Option>], name: &str) -> std::option::Option<&'a dyn Option> {
    options.iter().rev().find(|o| o.get_name() == name).map(|o| o.as_ref())
}

impl AbstractProgramLoader for BinaryLoader {
    /// `loadProgramInto(Program, ImporterSettings)`: stores `length` bytes from `fileOffset` as
    /// file bytes and maps them at the base address (default: address 0 of the default space)
    /// in one block named after the option (default: the space name, or `ovN` for an overlay).
    fn load_program_into(
        &self,
        program: &dyn Program,
        provider: &dyn ByteProvider,
        options: &[Box<dyn Option>],
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), LoadIntoError> {
        let parse = |name: &str| -> Result<i64, LoadIntoError> {
            match find(options, name).map(parse_long) {
                None | Some(Ok(None)) => Ok(0),
                Some(Ok(Some(v))) => Ok(v),
                Some(Err(_)) => Err(io_error(format!("Invalid value for {name}"))),
            }
        };
        let mut length = parse(OPTION_NAME_LEN)?;
        let file_offset = parse(OPTION_NAME_FILE_OFFSET)?;
        let base_addr = find(options, OPTION_NAME_BASE_ADDR).and_then(base_addr_value).flatten();
        let block_name = find(options, OPTION_NAME_BLOCK_NAME)
            .and_then(|o| o.get_value().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let is_overlay = find(options, OPTION_NAME_IS_OVERLAY)
            .and_then(|o| o.get_value().downcast_ref::<bool>().copied())
            .unwrap_or(false);

        if length == 0 {
            length = provider.length() as i64;
        }

        length = Self::clip_to_memory_space(length, log, program);

        let file_bytes =
            memory_block_utils::create_file_bytes_range(program, provider, file_offset, length, monitor)
                .map_err(|e| match e {
                    CreateBlockError::Cancelled(c) => LoadIntoError::Cancelled(c),
                    CreateBlockError::Io(e) => LoadIntoError::Io(e),
                    other => io_error(other.to_string()),
                })?;
        let space = program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or_else(|| io_error("program has no default address space"))?;
        let base_addr = base_addr.unwrap_or_else(|| space.address(0));
        let block_name = if block_name.is_empty() {
            self.generate_block_name(program, is_overlay, base_addr.space())
        } else {
            block_name
        };
        match Self::create_block(program, is_overlay, &block_name, &base_addr, &file_bytes, length, log) {
            Ok(()) => Ok(()),
            Err(CreateBlockError::AddressOverflow(_)) => Err(LoadIntoError::Load(
                crate::app::util::opinion::load_exception::LoadException::new(format!(
                    "Invalid address range specified: start:{base_addr}, length:{length} - end address exceeds address space boundary!"
                )),
            )),
            Err(CreateBlockError::Io(e)) => Err(LoadIntoError::Io(e)),
            Err(other) => Err(io_error(other.to_string())),
        }
    }

    /// `shouldApplyProcessorLabelsByDefault()`: a raw binary has no format of its own to label,
    /// so the processor's labels are applied by default.
    fn should_apply_processor_labels_by_default(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
