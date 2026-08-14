//! Port of `ghidra.app.util.opinion.DyldCacheLoader`.
//!
//! A [`Loader`](crate::app::util::opinion::loader::Loader) for DYLD shared cache files.
//!
//! # Departures from the Java class
//!
//! * Java's `DyldCacheLoader extends AbstractProgramWrapperLoader`, which in turn extends
//!   `AbstractProgramLoader` -- neither is ported yet, and together they implement most of the
//!   `Loader` interface's machinery (constructing `Program`s, wrapping transactions, building
//!   `Loaded<Program>` results, etc). Porting that machinery is out of scope for this type, so
//!   [`DyldCacheLoader`] does not `impl Loader`; instead it exposes plain inherent methods
//!   mirroring exactly the members `DyldCacheLoader.java` itself declares
//!   (`findSupportedLoadSpecs`, `load`, `getDefaultOptions`, `getName`, plus the private
//!   `getDyldCacheOptions` helper). `getTier`/`getTierPriority` are inherited unchanged from
//!   `AbstractProgramWrapperLoader` in Java and are not overridden here either, for the same
//!   reason.
//! * `findSupportedLoadSpecs(ByteProvider)` and `getDefaultOptions(ByteProvider, ...)` take the
//!   real, already-ported [`ByteProvider`] trait (`crate::filesystem::ghidra::g_binary_reader`)
//!   directly, rather than the narrower `ByteProviderLike` marker the (not-implemented-here)
//!   `Loader` trait uses for the same Java type.
//! * `QueryOpinionService.query`'s static `languageService`/database singletons were already
//!   dropped when that class was ported (see its module docs); [`find_supported_load_specs`]
//!   threads the equivalent `&dyn Application`/`&dyn LanguageService` through explicitly, the same
//!   substitution `query_opinion_service::query` itself requires. Its `secondaryKey` argument is
//!   `null` in Java (`QueryOpinionService.query(getName(), architecture.getProcessor(), null)`),
//!   but the ported `query` takes a non-nullable `&str`; `""` is passed instead, since the
//!   opinion-file database is always empty in this crate today (`QueryOpinionServiceHandler` is a
//!   still-unported no-op stub -- see `query_opinion_service`'s module docs), so no query this
//!   loader makes can currently distinguish the two.
//! * `load(Program, ImporterSettings)` takes its `ImporterSettings` fields directly as separate
//!   parameters instead of the already-ported `Loader::ImporterSettings` struct: that struct's
//!   `provider` field is typed as the narrower `ByteProviderLike` marker and its `options` field
//!   as `Vec<Box<dyn OptionLike>>` (an opaque marker with no accessors), neither of which this
//!   method's body can work with (it needs real byte access and `Option::get_name`/`get_value` to
//!   read option values back out).
//! * `DyldCacheProgramBuilder.buildProgram`/`MemoryBlockUtils.createFileBytes` -- the two calls
//!   `load` makes -- are far larger unported subsystems (the former alone drives memory-block,
//!   symbol, export, and load-command-markup processing for the whole cache); both are stubbed as
//!   `unimplemented!()` placeholders in `seam_stubs` (see [`dyld_cache_program_builder`] and
//!   [`memory_block_utils`]) rather than guessed at, so [`load`](DyldCacheLoader::load) panics if
//!   actually called today. Since neither placeholder can yet report a cancellation, `load` no
//!   longer distinguishes Java's `catch (CancelledException) { return; }` from
//!   `catch (Exception e) { throw new IOException(...); }`; both collapse into a single
//!   `io::Result`.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::app::seam_stubs::{
    dyld_cache_program_builder, dyld_cache_utils, memory_block_utils, new_boolean, option_utils,
    DyldArchitecture, DyldCacheHeader, LoadSpec, MessageLog, Option, QueryResult,
};
use crate::app::util::opinion::dyld_cache_options::DyldCacheOptions;
use crate::app::util::opinion::loader::COMMAND_LINE_ARG_PREFIX;
use crate::app::util::opinion::query_opinion_service;
use crate::filesystem::ghidra::g_binary_reader::{ByteProvider, GBinaryReader};
use crate::framework::application::Application;
use crate::framework::model::DomainObject;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// `DyldCacheLoader.DYLD_CACHE_NAME`.
pub const DYLD_CACHE_NAME: &str = "DYLD Cache";

/// Loader option to fixup slide pointers.
const FIXUP_SLIDE_POINTERS_OPTION_NAME: &str = "Fixup slide pointers";
/// Default value for loader option to fixup slide pointers.
const FIXUP_SLIDE_POINTERS_OPTION_DEFAULT: bool = true;

/// Loader option to mark up slide pointers.
const MARKUP_SLIDE_POINTERS_OPTION_NAME: &str = "Markup slide pointers";
/// Default value for loader option to mark up slide pointers.
const MARKUP_SLIDE_POINTERS_OPTION_DEFAULT: bool = true;

/// Loader option to add slide pointers to relocation table.
const ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME: &str = "Add slide pointers to relocation table";
/// Default value for loader option to add slide pointers to relocation table.
const ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT: bool = false;

/// Loader option to process local symbols.
const PROCESS_LOCAL_SYMBOLS_OPTION_NAME: &str = "Process local symbols";
/// Default value for loader option to process local symbols.
const PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT: bool = true;

/// Loader option to mark up symbols.
const MARKUP_LOCAL_SYMBOLS_OPTION_NAME: &str = "Markup local symbol nlists";
/// Default value for loader option to mark up symbols.
const MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT: bool = false;

/// Loader option to process individual dylib's memory.
const PROCESS_DYLIB_MEMORY_OPTION_NAME: &str = "Process dylib memory";
/// Loader option to process individual dylib's memory.
const PROCESS_DYLIB_MEMORY_OPTION_DEFAULT: bool = true;

/// Loader option to process dylib symbols.
const PROCESS_DYLIB_SYMBOLS_OPTION_NAME: &str = "Process dylib symbols";
/// Default value for loader option to process dylib symbols.
const PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT: bool = true;

/// Loader option to process dylib exports.
const PROCESS_DYLIB_EXPORTS_OPTION_NAME: &str = "Process dylib exports";
/// Default value for loader option to process dylib exports.
const PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT: bool = true;

/// Loader option to mark up dylib load command data.
const MARKUP_DYLIB_LC_DATA_OPTION_NAME: &str = "Markup dylib load command data";
/// Default value for loader option to mark up dylib load command data.
const MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT: bool = false;

/// Loader option to process libobjc.
const PROCESS_DYLIB_LIBOBJC_OPTION_NAME: &str = "Process libobjc";
/// Default value for loader option to process libobjc.
const PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT: bool = true;

/// A [`Loader`](crate::app::util::opinion::loader::Loader) for DYLD shared cache files.
#[derive(Debug, Default, Clone, Copy)]
pub struct DyldCacheLoader;

impl DyldCacheLoader {
    /// Port of `DyldCacheLoader.getName()`.
    pub fn get_name(&self) -> String {
        DYLD_CACHE_NAME.to_string()
    }

    /// Port of `DyldCacheLoader.findSupportedLoadSpecs(ByteProvider)`.
    pub fn find_supported_load_specs(
        &self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        app: &dyn Application,
        language_service: &dyn LanguageService,
    ) -> io::Result<Vec<LoadSpec>> {
        let mut load_specs = Vec::new();

        if !dyld_cache_utils::is_dyld_cache(provider) {
            return Ok(load_specs);
        }

        // Mirrors Java's `catch (IOException e) { /* It's not what we expect */ }`: a parse
        // failure here just means no load specs come back, not a propagated error.
        let mut reader = GBinaryReader::new(Rc::clone(provider), true);
        let Ok(header) = DyldCacheHeader::new(&mut reader) else {
            return Ok(load_specs);
        };
        if header.is_subcache {
            return Ok(load_specs);
        }

        if let Some(architecture) = header.architecture {
            let results: Vec<QueryResult> = query_opinion_service::query(
                app,
                language_service,
                &self.get_name(),
                architecture.get_processor(),
                "",
            );
            for result in &results {
                load_specs.push(LoadSpec::from_query_result(header.base_address, result));
            }
            if load_specs.is_empty() {
                load_specs.push(LoadSpec::without_language_compiler_spec(header.base_address, true));
            }
        }

        Ok(load_specs)
    }

    /// Port of `DyldCacheLoader.load(Program, ImporterSettings)`. See the module docs for why the
    /// parameters differ from Java's `ImporterSettings` record, and why the two exception
    /// branches (`CancelledException` vs. any other `Exception`) collapse into one `io::Result`.
    pub fn load(
        &self,
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        options: &[Box<dyn Option>],
        log: &mut dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let dyld_cache_options = self.get_dyld_cache_options(options);
        let file_bytes = memory_block_utils::create_file_bytes(program, provider, monitor)?;
        dyld_cache_program_builder::build_program(
            program,
            provider,
            &file_bytes,
            dyld_cache_options,
            log,
            monitor,
        )
    }

    /// Port of `DyldCacheLoader.getDefaultOptions(ByteProvider, LoadSpec, DomainObject, boolean,
    /// boolean)`. Java's `super.getDefaultOptions(...)` (`AbstractProgramLoader`, not ported) is
    /// not modeled; this list starts empty rather than reproducing that unported base behavior
    /// (see module docs).
    pub fn get_default_options(
        &self,
        _provider: &Rc<RefCell<dyn ByteProvider>>,
        _load_spec: &LoadSpec,
        _domain_object: &dyn DomainObject,
        load_into_program: bool,
        _mirror_fs_layout: bool,
    ) -> Vec<Box<dyn Option>> {
        let mut list: Vec<Box<dyn Option>> = Vec::new();
        if !load_into_program {
            list.push(
                new_boolean(FIXUP_SLIDE_POINTERS_OPTION_NAME)
                    .value(Box::new(FIXUP_SLIDE_POINTERS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-fixupSlidePointers"))
                    .build(),
            );
            list.push(
                new_boolean(MARKUP_SLIDE_POINTERS_OPTION_NAME)
                    .value(Box::new(MARKUP_SLIDE_POINTERS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-markupSlidePointers"))
                    .build(),
            );
            list.push(
                new_boolean(ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME)
                    .value(Box::new(ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-addSlidePointerRelocations"))
                    .build(),
            );
            list.push(
                new_boolean(PROCESS_LOCAL_SYMBOLS_OPTION_NAME)
                    .value(Box::new(PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-processLocalSymbols"))
                    .build(),
            );
            list.push(
                new_boolean(MARKUP_LOCAL_SYMBOLS_OPTION_NAME)
                    .value(Box::new(MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-markupLocalSymbols"))
                    .build(),
            );
            list.push(
                new_boolean(PROCESS_DYLIB_MEMORY_OPTION_NAME)
                    .value(Box::new(PROCESS_DYLIB_MEMORY_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-processDylibMemory"))
                    .build(),
            );
            list.push(
                new_boolean(PROCESS_DYLIB_SYMBOLS_OPTION_NAME)
                    .value(Box::new(PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-processDylibSymbols"))
                    .build(),
            );
            list.push(
                new_boolean(PROCESS_DYLIB_EXPORTS_OPTION_NAME)
                    .value(Box::new(PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-processDylibExports"))
                    .build(),
            );
            list.push(
                new_boolean(MARKUP_DYLIB_LC_DATA_OPTION_NAME)
                    .value(Box::new(MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-markupDylibLoadCommandData"))
                    .build(),
            );
            list.push(
                new_boolean(PROCESS_DYLIB_LIBOBJC_OPTION_NAME)
                    .value(Box::new(PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT))
                    .command_line_argument(self.create_arg("-processLibobjc"))
                    .build(),
            );
        }
        list
    }

    /// Port of the private `DyldCacheLoader.getDyldCacheOptions(List<Option>)`.
    fn get_dyld_cache_options(&self, options: &[Box<dyn Option>]) -> DyldCacheOptions {
        let fixup_slide_pointers = option_utils::get_bool_option(
            FIXUP_SLIDE_POINTERS_OPTION_NAME,
            options,
            FIXUP_SLIDE_POINTERS_OPTION_DEFAULT,
        );
        let markup_slide_pointers = option_utils::get_bool_option(
            MARKUP_SLIDE_POINTERS_OPTION_NAME,
            options,
            MARKUP_SLIDE_POINTERS_OPTION_DEFAULT,
        );
        let add_slide_pointer_relocations = option_utils::get_bool_option(
            ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME,
            options,
            ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT,
        );
        let process_local_symbols = option_utils::get_bool_option(
            PROCESS_LOCAL_SYMBOLS_OPTION_NAME,
            options,
            PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT,
        );
        let markup_local_symbols = option_utils::get_bool_option(
            MARKUP_LOCAL_SYMBOLS_OPTION_NAME,
            options,
            MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT,
        );
        let process_dylib_memory = option_utils::get_bool_option(
            PROCESS_DYLIB_MEMORY_OPTION_NAME,
            options,
            PROCESS_DYLIB_MEMORY_OPTION_DEFAULT,
        );
        let process_dylib_symbols = option_utils::get_bool_option(
            PROCESS_DYLIB_SYMBOLS_OPTION_NAME,
            options,
            PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT,
        );
        let process_dylib_exports = option_utils::get_bool_option(
            PROCESS_DYLIB_EXPORTS_OPTION_NAME,
            options,
            PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT,
        );
        let markup_dylib_load_command_data = option_utils::get_bool_option(
            MARKUP_DYLIB_LC_DATA_OPTION_NAME,
            options,
            MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT,
        );
        let process_libobjc = option_utils::get_bool_option(
            PROCESS_DYLIB_LIBOBJC_OPTION_NAME,
            options,
            PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT,
        );

        DyldCacheOptions::new(
            fixup_slide_pointers,
            markup_slide_pointers,
            add_slide_pointer_relocations,
            process_local_symbols,
            markup_local_symbols,
            process_dylib_memory,
            process_dylib_symbols,
            process_dylib_exports,
            markup_dylib_load_command_data,
            process_libobjc,
        )
    }

    /// Port of `Loader.createArg(String)`, which `AbstractProgramWrapperLoader` inherits
    /// unmodified. Reuses [`Loader`](crate::app::util::opinion::loader::Loader)'s
    /// [`COMMAND_LINE_ARG_PREFIX`] constant directly since this type doesn't implement that trait
    /// (see module docs).
    fn create_arg(&self, arg: &str) -> String {
        format!("{COMMAND_LINE_ARG_PREFIX}{arg}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::application_properties::ApplicationProperties;
    use crate::framework::platform::Platform;
    use crate::framework::seam_stubs::ApplicationLayoutLike;
    use crate::generic::jar::ResourceFile;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::seam_stubs::LanguageCompilerSpecPair;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::LanguageNotFoundException;
    use crate::program::seam_stubs::Processor as ProcessorTrait;
    use crate::util::task::DummyMonitor;

    /// In-memory [`ByteProvider`], mirroring the same helper other reader tests in this crate
    /// define locally (e.g. `g_binary_reader`'s own `VecProvider`).
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            let idx = index as usize;
            if idx >= self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.0[idx] = value;
            Ok(())
        }
        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start + values.len();
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "write past end"));
            }
            self.0[start..end].copy_from_slice(values);
            Ok(())
        }
    }

    fn provider(bytes: &[u8]) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::new(RefCell::new(VecProvider(bytes.to_vec())))
    }

    /// An `Application` whose `find_files_by_extension_in_application` (via the trait's default,
    /// which walks `application_layout().modules()`) always reports zero files, since
    /// `ApplicationLayoutLike::modules` itself defaults to empty. Every other member is
    /// unreachable through that path and left `unimplemented!()`.
    struct EmptyApplication;

    impl ApplicationLayoutLike for EmptyApplication {
        fn application_properties(&self) -> &dyn ApplicationProperties {
            unimplemented!("not exercised by this smoke test")
        }
        fn application_installation_dir(&self) -> std::option::Option<&ResourceFile> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl Application for EmptyApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            Box::new(EmptyApplication)
        }
        fn current_platform(&self) -> Box<dyn Platform> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A `LanguageService` never actually called: with zero `.opinion` files found, the opinion
    /// database this loader queries is always empty (see module docs), so `query_opinion_service`
    /// never has a language/compiler-spec pair to expand a query against.
    struct UnusedLanguageService;

    impl LanguageService for UnusedLanguageService {
        fn get_language(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_language(
            &self,
            _processor: &dyn ProcessorTrait,
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
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn ProcessorTrait,
            _endianness: std::option::Option<crate::program::model::lang::endian::Endian>,
            _size: std::option::Option<i32>,
            _variant: std::option::Option<&str>,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            Vec::new()
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
            Vec::new()
        }
        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn ProcessorTrait,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            Vec::new()
        }
    }

    // --- DyldArchitecture / DyldCacheHeader / DyldCacheUtils (seam_stubs) ---

    #[test]
    fn architecture_lookup_matches_known_signature() {
        let arch = DyldArchitecture::get_architecture("dyld_v1  arm64e").unwrap();
        assert_eq!(arch.get_processor(), "AARCH64");
    }

    #[test]
    fn architecture_lookup_rejects_unknown_signature() {
        assert!(DyldArchitecture::get_architecture("not a dyld cache").is_none());
    }

    #[test]
    fn is_dyld_cache_true_for_known_signature() {
        let p = provider(b"dyld_v1  arm64e ");
        assert!(dyld_cache_utils::is_dyld_cache(&p));
    }

    #[test]
    fn is_dyld_cache_false_for_garbage() {
        let p = provider(b"not a dyld cache");
        assert!(!dyld_cache_utils::is_dyld_cache(&p));
    }

    #[test]
    fn is_dyld_cache_false_for_too_short_provider() {
        let p = provider(b"short");
        assert!(!dyld_cache_utils::is_dyld_cache(&p));
    }

    #[test]
    fn header_parses_architecture_from_magic() {
        let p = provider(b"dyld_v1   arm64 ");
        let mut reader = GBinaryReader::new(p, true);
        let header = DyldCacheHeader::new(&mut reader).unwrap();
        assert_eq!(header.architecture.unwrap().get_processor(), "AARCH64");
        assert!(!header.is_subcache);
        assert_eq!(header.base_address, 0);
    }

    #[test]
    fn header_parse_fails_on_truncated_input() {
        let p = provider(b"short");
        let mut reader = GBinaryReader::new(p, true);
        assert!(DyldCacheHeader::new(&mut reader).is_err());
    }

    // --- LoadSpec derivation ---

    fn pair() -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new(
            LanguageID::new("AARCH64:LE:64:v8A").unwrap(),
            CompilerSpecID::new(Some("default")),
        )
    }

    #[test]
    fn load_spec_from_preferred_query_result_is_complete() {
        let result = QueryResult::new(pair(), true);
        let spec = LoadSpec::from_query_result(0x1000, &result);
        assert_eq!(spec.desired_image_base, 0x1000);
        assert!(spec.preferred);
        assert!(spec.requires_language_compiler_spec);
        assert!(spec.is_complete());
        assert_eq!(spec.language_compiler_spec, Some(pair()));
    }

    #[test]
    fn load_spec_without_language_compiler_spec_is_incomplete_when_required() {
        let spec = LoadSpec::without_language_compiler_spec(0x2000, true);
        assert_eq!(spec.desired_image_base, 0x2000);
        assert!(!spec.preferred);
        assert!(spec.requires_language_compiler_spec);
        assert!(spec.language_compiler_spec.is_none());
        // Mirrors `isComplete()`: requires a language/compiler but doesn't have one yet.
        assert!(!spec.is_complete());
    }

    #[test]
    fn load_spec_not_requiring_language_compiler_spec_is_complete() {
        let spec = LoadSpec::without_language_compiler_spec(0, false);
        assert!(!spec.requires_language_compiler_spec);
        assert!(spec.is_complete());
    }

    // --- DyldCacheLoader ---

    #[test]
    fn get_name_matches_dyld_cache_name_constant() {
        assert_eq!(DyldCacheLoader.get_name(), DYLD_CACHE_NAME);
        assert_eq!(DYLD_CACHE_NAME, "DYLD Cache");
    }

    #[test]
    fn find_supported_load_specs_empty_for_non_dyld_cache() {
        let loader = DyldCacheLoader;
        let p = provider(b"not a dyld cache");
        let specs = loader
            .find_supported_load_specs(&p, &EmptyApplication, &UnusedLanguageService)
            .unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn find_supported_load_specs_falls_back_to_preferred_only_spec() {
        // With no `.opinion` files registered (see `UnusedLanguageService`'s docs),
        // `QueryOpinionService.query` always returns no results, so this exercises Java's
        // `if (loadSpecs.isEmpty()) { loadSpecs.add(new LoadSpec(this, ..., true)); }` fallback.
        let loader = DyldCacheLoader;
        let p = provider(b"dyld_v1  arm64e ");
        let specs = loader
            .find_supported_load_specs(&p, &EmptyApplication, &UnusedLanguageService)
            .unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].desired_image_base, 0);
        assert!(specs[0].requires_language_compiler_spec);
        assert!(!specs[0].preferred);
        assert!(specs[0].language_compiler_spec.is_none());
    }

    #[test]
    fn get_default_options_adds_ten_options_when_not_loading_into_program() {
        let loader = DyldCacheLoader;
        let p = provider(b"");
        let load_spec = LoadSpec::without_language_compiler_spec(0, true);
        struct MockDomainObject;
        impl DomainObject for MockDomainObject {}

        let opts = loader.get_default_options(&p, &load_spec, &MockDomainObject, false, false);
        assert_eq!(opts.len(), 10);
        assert_eq!(opts[0].get_name(), FIXUP_SLIDE_POINTERS_OPTION_NAME);
        assert_eq!(
            *opts[0].get_value().downcast_ref::<bool>().unwrap(),
            FIXUP_SLIDE_POINTERS_OPTION_DEFAULT
        );
        assert_eq!(opts[2].get_name(), ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME);
        assert_eq!(
            *opts[2].get_value().downcast_ref::<bool>().unwrap(),
            ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT
        );
        assert_eq!(opts[9].get_name(), PROCESS_DYLIB_LIBOBJC_OPTION_NAME);
    }

    #[test]
    fn get_default_options_empty_when_loading_into_program() {
        let loader = DyldCacheLoader;
        let p = provider(b"");
        let load_spec = LoadSpec::without_language_compiler_spec(0, true);
        struct MockDomainObject;
        impl DomainObject for MockDomainObject {}

        let opts = loader.get_default_options(&p, &load_spec, &MockDomainObject, true, false);
        assert!(opts.is_empty());
    }

    #[test]
    fn get_dyld_cache_options_uses_defaults_when_no_options_given() {
        let loader = DyldCacheLoader;
        let dyld_options = loader.get_dyld_cache_options(&[]);
        assert_eq!(dyld_options.fixup_slide_pointers, FIXUP_SLIDE_POINTERS_OPTION_DEFAULT);
        assert_eq!(dyld_options.markup_slide_pointers, MARKUP_SLIDE_POINTERS_OPTION_DEFAULT);
        assert_eq!(
            dyld_options.add_slide_pointer_relocations,
            ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT
        );
        assert_eq!(dyld_options.process_local_symbols, PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT);
        assert_eq!(dyld_options.markup_local_symbols, MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT);
        assert_eq!(dyld_options.process_dylib_memory, PROCESS_DYLIB_MEMORY_OPTION_DEFAULT);
        assert_eq!(dyld_options.process_dylib_symbols, PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT);
        assert_eq!(dyld_options.process_dylib_exports, PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT);
        assert_eq!(
            dyld_options.markup_dylib_load_command_data,
            MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT
        );
        assert_eq!(dyld_options.process_libobjc, PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT);
    }

    #[test]
    fn get_dyld_cache_options_honors_overrides() {
        let loader = DyldCacheLoader;
        let options: Vec<Box<dyn Option>> = vec![
            new_boolean(FIXUP_SLIDE_POINTERS_OPTION_NAME)
                .value(Box::new(false))
                .command_line_argument(String::new())
                .build(),
            new_boolean(PROCESS_DYLIB_LIBOBJC_OPTION_NAME)
                .value(Box::new(false))
                .command_line_argument(String::new())
                .build(),
        ];
        let dyld_options = loader.get_dyld_cache_options(&options);
        assert!(!dyld_options.fixup_slide_pointers);
        assert!(!dyld_options.process_libobjc);
        // Unspecified options still take their defaults.
        assert_eq!(dyld_options.markup_slide_pointers, MARKUP_SLIDE_POINTERS_OPTION_DEFAULT);
    }

    #[test]
    fn load_reports_io_error_from_create_file_bytes_stub() {
        // `memory_block_utils::create_file_bytes`/`dyld_cache_program_builder::build_program` are
        // unimplemented placeholders (see module docs) pending the real (much larger) ports, so
        // this only smoke-tests that `DyldCacheLoader::load` is reachable and panics rather than
        // silently misbehaving.
        let loader = DyldCacheLoader;
        let p = provider(b"dyld_v1  arm64e ");
        struct MockProgram;
        impl DomainObject for MockProgram {}
        impl Program for MockProgram {
            fn get_name(&self) -> String {
                "mock.program".to_string()
            }
            fn get_language_id(&self) -> String {
                "AARCH64:LE:64:v8A".to_string()
            }
        }
        struct MockLog;
        impl MessageLog for MockLog {}

        let mut program = MockProgram;
        let mut log = MockLog;
        let monitor = DummyMonitor;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            loader.load(&mut program, &p, &[], &mut log, &monitor)
        }));
        assert!(result.is_err());
    }
}
