//! Port of `ghidra.app.util.bin.format.macho.commands.LoadCommandFactory`.
//!
//! The Java class holds only static methods, so it is a module here: [`get_load_command`] creates
//! and parses one load command.

use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::opinion::dyld_cache_utils::SplitDyldCache;
use crate::format::macho::commands::segment_names;
use crate::format::macho::commands::build_version_command::BuildVersionCommand;
use crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand;
use crate::format::macho::commands::code_signature_command::CodeSignatureCommand;
use crate::format::macho::commands::corrupt_load_command::CorruptLoadCommand;
use crate::format::macho::commands::data_in_code_command::DataInCodeCommand;
use crate::format::macho::commands::dyld_exports_trie_command::DyldExportsTrieCommand;
use crate::format::macho::commands::dyld_info_command::DyldInfoCommand;
use crate::format::macho::commands::function_starts_command::FunctionStartsCommand;
use crate::format::macho::commands::link_edit_data_command::LinkEditDataCommand;
use crate::format::macho::commands::dynamic_symbol_table_command::DynamicSymbolTableCommand;
use crate::format::macho::commands::dynamic_library_command::DynamicLibraryCommand;
use crate::format::macho::commands::dynamic_linker_command::DynamicLinkerCommand;
use crate::format::macho::commands::encrypted_information_command::EncryptedInformationCommand;
use crate::format::macho::commands::entry_point_command::EntryPointCommand;
use crate::format::macho::commands::file_set_entry_command::FileSetEntryCommand;
use crate::format::macho::commands::fixed_virtual_memory_file_command::FixedVirtualMemoryFileCommand;
use crate::format::macho::commands::fixed_virtual_memory_shared_library_command::FixedVirtualMemorySharedLibraryCommand;
use crate::format::macho::commands::ident_command::IdentCommand;
use crate::format::macho::commands::linker_option_command::LinkerOptionCommand;
use crate::format::macho::commands::load_command_kind::LoadCommandKind;
use crate::format::macho::commands::load_command_types::*;
use crate::format::macho::commands::prebind_checksum_command::PrebindChecksumCommand;
use crate::format::macho::commands::prebound_dynamic_library_command::PreboundDynamicLibraryCommand;
use crate::format::macho::commands::routines_command::RoutinesCommand;
use crate::format::macho::commands::run_path_command::RunPathCommand;
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::commands::source_version_command::SourceVersionCommand;
use crate::format::macho::commands::sub_client_command::SubClientCommand;
use crate::format::macho::commands::sub_framework_command::SubFrameworkCommand;
use crate::format::macho::commands::sub_library_command::SubLibraryCommand;
use crate::format::macho::commands::sub_umbrella_command::SubUmbrellaCommand;
use crate::format::macho::commands::symbol_command::SymbolCommand;
use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
use crate::format::macho::commands::two_level_hints_command::TwoLevelHintsCommand;
use crate::format::macho::commands::unsupported_load_command::UnsupportedLoadCommand;
use crate::format::macho::commands::uuid_command::UuidCommand;
use crate::format::macho::commands::version_min_command::VersionMinCommand;
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::threadcommand::thread_command::ThreadCommand;

/// Java: `getLoadCommand(BinaryReader, MachHeader, SplitDyldCache)`. `split_dyld_cache` is the
/// split DYLD cache `header` resides in, or `None`.
///
/// Creates and parses the load command at `reader`'s position. Any failure while parsing the
/// command yields a [`CorruptLoadCommand`] carrying that failure instead, with the reader reset
/// to the command's start; only a failure to read even the corrupt command's header is returned
/// as an error.
///
/// Commands whose data lives in the `__LINKEDIT` segment require that the `__LINKEDIT`
/// [`SegmentCommand`] has already been parsed into `header`, so segments must be parsed first.
pub fn get_load_command(
    reader: &mut BinaryReader,
    header: &MachHeader,
    split_dyld_cache: Option<&SplitDyldCache>,
) -> Result<LoadCommandKind, MachException> {
    let orig_index = reader.get_pointer_index();
    match parse_load_command(reader, header, split_dyld_cache) {
        Ok(lc) => Ok(lc),
        Err(e) => {
            reader.set_pointer_index(orig_index);
            Ok(CorruptLoadCommand::new(reader, Arc::new(e))?.into())
        }
    }
}

/// The `try` body of Java's `getLoadCommand`.
fn parse_load_command(
    reader: &mut BinaryReader,
    header: &MachHeader,
    split: Option<&SplitDyldCache>,
) -> Result<LoadCommandKind, MachException> {
    let cmd_type = reader.peek_next_int()? as u32;
    let is32bit = header.is32bit();
    Ok(match cmd_type {
        LC_SEGMENT | LC_SEGMENT_64 => SegmentCommand::new(reader, is32bit)?.into(),
        LC_SYMTAB => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            SymbolTableCommand::new(reader, &mut linker_reader, header)?.into()
        }
        LC_THREAD | LC_UNIXTHREAD => ThreadCommand::new(reader, header)?.into(),
        LC_SYMSEG => SymbolCommand::new(reader)?.into(),
        LC_LOADFVMLIB | LC_IDFVMLIB => FixedVirtualMemorySharedLibraryCommand::new(reader)?.into(),
        LC_IDENT => IdentCommand::new(reader)?.into(),
        LC_FVMFILE => FixedVirtualMemoryFileCommand::new(reader)?.into(),
        LC_PREPAGE => UnsupportedLoadCommand::new(reader)?.into(),
        LC_DYSYMTAB => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            DynamicSymbolTableCommand::new(reader, &mut linker_reader, header)?.into()
        }
        LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_UPWARD_DYLIB | LC_LOAD_WEAK_DYLIB
        | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB => DynamicLibraryCommand::new(reader)?.into(),
        LC_LOAD_DYLINKER | LC_ID_DYLINKER | LC_DYLD_ENVIRONMENT => {
            DynamicLinkerCommand::new(reader)?.into()
        }
        LC_PREBOUND_DYLIB => PreboundDynamicLibraryCommand::new(reader)?.into(),
        LC_ROUTINES | LC_ROUTINES_64 => RoutinesCommand::new(reader, is32bit)?.into(),
        LC_SUB_FRAMEWORK => SubFrameworkCommand::new(reader)?.into(),
        LC_SUB_UMBRELLA => SubUmbrellaCommand::new(reader)?.into(),
        LC_SUB_CLIENT => SubClientCommand::new(reader)?.into(),
        LC_SUB_LIBRARY => SubLibraryCommand::new(reader)?.into(),
        LC_TWOLEVEL_HINTS => TwoLevelHintsCommand::new(reader)?.into(),
        LC_PREBIND_CKSUM => PrebindChecksumCommand::new(reader)?.into(),
        LC_UUID => UuidCommand::new(reader)?.into(),
        LC_RPATH => RunPathCommand::new(reader)?.into(),
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            EncryptedInformationCommand::new(reader, is32bit)?.into()
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            DyldInfoCommand::new(reader, &mut linker_reader, header)?.into()
        }
        LC_CODE_SIGNATURE => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            CodeSignatureCommand::new(reader, &mut linker_reader)?.into()
        }
        LC_SEGMENT_SPLIT_INFO | LC_OPTIMIZATION_HINT | LC_DYLIB_CODE_SIGN_DRS => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            LinkEditDataCommand::new(reader, &mut linker_reader)?.into()
        }
        LC_FUNCTION_STARTS => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            FunctionStartsCommand::new(reader, &mut linker_reader)?.into()
        }
        LC_DATA_IN_CODE => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            DataInCodeCommand::new(reader, &mut linker_reader)?.into()
        }
        LC_DYLD_EXPORTS_TRIE => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            DyldExportsTrieCommand::new(reader, &mut linker_reader)?.into()
        }
        LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_TVOS
        | LC_VERSION_MIN_WATCHOS => VersionMinCommand::new(reader)?.into(),
        LC_MAIN => EntryPointCommand::new(reader)?.into(),
        LC_SOURCE_VERSION => SourceVersionCommand::new(reader)?.into(),
        LC_LINKER_OPTIONS => LinkerOptionCommand::new(reader)?.into(),
        LC_BUILD_VERSION => BuildVersionCommand::new(reader)?.into(),
        LC_DYLD_CHAINED_FIXUPS => {
            let mut linker_reader = get_linker_load_command_reader(reader, header, split)?;
            DyldChainedFixupsCommand::new(reader, &mut linker_reader)?.into()
        }
        LC_FILESET_ENTRY => FileSetEntryCommand::new(reader)?.into(),
        _ => UnsupportedLoadCommand::new(reader)?.into(),
    })
}

/// Java: the private `getLinkerLoadCommandReader(BinaryReader, MachHeader, SplitDyldCache)`: a
/// reader for the data of commands used by the dynamic linker. Without a split DYLD cache that is
/// a clone of `reader`; with one, a little-endian reader over whichever cache file maps the
/// `__LINKEDIT` segment. Nothing should be assumed about where the returned reader points.
///
/// Requires the segment commands to have been parsed already.
fn get_linker_load_command_reader(
    reader: &BinaryReader,
    header: &MachHeader,
    split_dyld_cache: Option<&SplitDyldCache>,
) -> Result<BinaryReader, MachException> {
    let Some(split) = split_dyld_cache else {
        return Ok(reader.clone_reader());
    };
    if let Some(link_edit) = header.get_segment(segment_names::LINKEDIT) {
        for i in 0..split.size() {
            let mappings = split.get_dyld_cache_header(i).get_mapping_infos();
            if mappings.iter().any(|m| m.contains(link_edit.get_vm_address(), true)) {
                return Ok(BinaryReader::new(Rc::clone(split.get_provider(i)), true));
            }
        }
    }
    Err(MachException::new("__LINKEDIT segment not found in DYLD cache"))
}
