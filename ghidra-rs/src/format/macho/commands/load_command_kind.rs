//! The closed set of concrete Mach-O load commands.
//!
//! Java's `MachHeader` keeps a `List<LoadCommand>` of the abstract class and filters it by runtime
//! class (`getLoadCommands(Class<T>)`). Every load command is built by
//! [`load_command_factory`](super::load_command_factory), so the set of concrete types is closed:
//! this module stores them as the [`LoadCommandKind`] enum (one variant per concrete class) and
//! replaces the reflective filter with [`LoadCommandVariant`], which each concrete type implements
//! to pick itself out of a [`LoadCommandKind`]. There is no Java counterpart to this file.
//!
//! The obsolete commands (`SymbolCommand`, `IdentCommand`,
//! `FixedVirtualMemorySharedLibraryCommand`) have variants for completeness even though their
//! constructors always fail, exactly as Java's factory names them though it never yields them.

use std::ops::Deref;

use crate::format::macho::commands::build_version_command::BuildVersionCommand;
use crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand;
use crate::format::macho::commands::corrupt_load_command::CorruptLoadCommand;
use crate::format::macho::commands::dyld_info_command::DyldInfoCommand;
use crate::format::macho::commands::dynamic_library_command::DynamicLibraryCommand;
use crate::format::macho::commands::dynamic_linker_command::DynamicLinkerCommand;
use crate::format::macho::commands::encrypted_information_command::EncryptedInformationCommand;
use crate::format::macho::commands::entry_point_command::EntryPointCommand;
use crate::format::macho::commands::file_set_entry_command::FileSetEntryCommand;
use crate::format::macho::commands::fixed_virtual_memory_file_command::FixedVirtualMemoryFileCommand;
use crate::format::macho::commands::fixed_virtual_memory_shared_library_command::FixedVirtualMemorySharedLibraryCommand;
use crate::format::macho::commands::ident_command::IdentCommand;
use crate::format::macho::commands::linker_option_command::LinkerOptionCommand;
use crate::format::macho::commands::load_command::LoadCommand;
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
use crate::format::macho::threadcommand::thread_command::ThreadCommand;

/// A concrete load command type that can be picked out of a [`LoadCommandKind`].
///
/// Stands in for the `Class<T>` argument of Java's `MachHeader.getLoadCommands(Class<T>)` and
/// `getFirstLoadCommand(Class<T>)`.
pub trait LoadCommandVariant: LoadCommand + Sized {
    /// `Some` if `kind` holds a `Self` (Java: `classType.isAssignableFrom(command.getClass())`).
    fn from_kind(kind: &LoadCommandKind) -> Option<&Self>;

    /// Mutable counterpart of [`from_kind`](Self::from_kind).
    fn from_kind_mut(kind: &mut LoadCommandKind) -> Option<&mut Self>;
}

macro_rules! load_command_kinds {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        /// One parsed Mach-O load command, of any concrete type.
        pub enum LoadCommandKind {
            $(
                #[doc = concat!("A [`", stringify!($ty), "`].")]
                $variant($ty),
            )*
        }

        impl LoadCommandKind {
            /// This command as the abstract [`LoadCommand`].
            pub fn as_load_command(&self) -> &(dyn LoadCommand + 'static) {
                match self {
                    $(LoadCommandKind::$variant(c) => c,)*
                }
            }
        }

        $(
            impl LoadCommandVariant for $ty {
                fn from_kind(kind: &LoadCommandKind) -> Option<&Self> {
                    match kind {
                        LoadCommandKind::$variant(c) => Some(c),
                        #[allow(unreachable_patterns)]
                        _ => None,
                    }
                }

                fn from_kind_mut(kind: &mut LoadCommandKind) -> Option<&mut Self> {
                    match kind {
                        LoadCommandKind::$variant(c) => Some(c),
                        #[allow(unreachable_patterns)]
                        _ => None,
                    }
                }
            }

            impl From<$ty> for LoadCommandKind {
                fn from(c: $ty) -> Self {
                    LoadCommandKind::$variant(c)
                }
            }
        )*
    };
}

load_command_kinds! {
    Segment(SegmentCommand),
    SymbolTable(SymbolTableCommand),
    Symbol(SymbolCommand),
    Thread(ThreadCommand),
    FixedVirtualMemorySharedLibrary(FixedVirtualMemorySharedLibraryCommand),
    Ident(IdentCommand),
    DynamicLibrary(DynamicLibraryCommand),
    DynamicLinker(DynamicLinkerCommand),
    PreboundDynamicLibrary(PreboundDynamicLibraryCommand),
    Routines(RoutinesCommand),
    SubFramework(SubFrameworkCommand),
    SubUmbrella(SubUmbrellaCommand),
    SubClient(SubClientCommand),
    SubLibrary(SubLibraryCommand),
    TwoLevelHints(TwoLevelHintsCommand),
    PrebindChecksum(PrebindChecksumCommand),
    Uuid(UuidCommand),
    RunPath(RunPathCommand),
    EncryptedInformation(EncryptedInformationCommand),
    DyldInfo(DyldInfoCommand),
    VersionMin(VersionMinCommand),
    EntryPoint(EntryPointCommand),
    SourceVersion(SourceVersionCommand),
    LinkerOption(LinkerOptionCommand),
    BuildVersion(BuildVersionCommand),
    DyldChainedFixups(DyldChainedFixupsCommand),
    FileSetEntry(FileSetEntryCommand),
    FixedVirtualMemoryFile(FixedVirtualMemoryFileCommand),
    Unsupported(UnsupportedLoadCommand),
    Corrupt(CorruptLoadCommand),
}

impl std::fmt::Debug for LoadCommandKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadCommandKind")
            .field("name", &self.get_command_name())
            .field("start_index", &self.get_start_index())
            .finish()
    }
}

impl Deref for LoadCommandKind {
    type Target = dyn LoadCommand;

    fn deref(&self) -> &Self::Target {
        self.as_load_command()
    }
}
