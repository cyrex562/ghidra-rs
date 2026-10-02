//! Port of `ghidra.app.util.opinion.ElfLoader`.
//!
//! A [`Loader`](crate::app::util::opinion::loader::Loader) for processing Executable and Linking
//! Format (ELF) files.
//!
//! # Departures from the Java class
//!
//! * `ElfLoader extends AbstractLibrarySupportLoader` (in turn `AbstractProgramLoader`), which
//!   implement the bulk of the `Loader` interface (program creation, transaction management,
//!   language/compiler-spec matching for load-into, `getTier()`/`getTierPriority()`, ...) and are
//!   not ported. `ElfLoader.java` itself only overrides `getDefaultOptions`, `validateOptions`,
//!   `findSupportedLoadSpecs`, `load`, `postLoadProgramFixups`, and `getName`, so -- like
//!   [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) and
//!   [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) -- this port models just that
//!   overridden surface as inherent methods on a standalone struct, rather than implementing the
//!   [`Loader`](crate::app::util::opinion::loader::Loader) trait (which would additionally
//!   require the inherited machinery this class never defines). `super.getDefaultOptions(..)`'s
//!   return value becomes an explicit `base_options` parameter to
//!   [`get_default_options`](ElfLoader::get_default_options); `super.validateOptions(..)` is not
//!   modeled at all (see that method's docs).
//! * [`get_default_options`](ElfLoader::get_default_options) constructs the [`ElfHeader`] from
//!   the provider itself and hands it to
//!   [`elf_loader_options_factory::add_options`] (Java constructs it inside `addOptions`); an
//!   `ElfException` is logged and ignored either way, exactly as Java's catch-all does.
//! * [`load`](ElfLoader::load) takes the log as a shared `Arc<MessageLog>` so the header's error
//!   consumer (`msg -> settings.log().appendMsg(msg)`) can own a handle to it.
//! * `QueryOpinionService.query(String, String, String)` and
//!   `LanguageCompilerSpecPair.getLanguageDescription()` both resolve process-wide singletons
//!   (`Application`/`DefaultLanguageService`) that were dropped when those classes were ported
//!   (see [`query_opinion_service`](crate::app::util::opinion::query_opinion_service)'s and
//!   [`LoadSpec::get_language`](crate::app::seam_stubs::LoadSpec::get_language)'s docs), so
//!   [`find_supported_load_specs`](ElfLoader::find_supported_load_specs) takes explicit
//!   `&dyn Application`/`&dyn LanguageService` parameters instead.
//! * `ElfProgramBuilder.loadElf(..)`, the sole call `ElfLoader.load` makes, is
//!   [`elf_program_builder::load_elf`](crate::app::util::opinion::elf_program_builder::load_elf);
//!   it builds the program's memory so far (symbols, relocations and markup are its phase 2 --
//!   see its docs). It takes the program as an `Arc<dyn Program>` because the
//!   `ElfLoadHelper` it implements hands the program out that way.
//! * `postLoadProgramFixups`'s `ImporterSettings settings` parameter belongs to the [`Loader`]
//!   trait this port doesn't implement (see above), so it is unpacked into the individual pieces
//!   Java actually reads from it (`project`, `log`, `monitor`). `ExternalSymbolResolver` is a
//!   large unported subsystem in its own right; see
//!   [`crate::app::seam_stubs::ExternalSymbolResolver`]'s docs for what is and is not modeled.

use std::collections::HashSet;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::importer::message_log::MessageLog;
use crate::app::seam_stubs::{ExternalSymbolResolver, LoadSpec, Option, QueryResult};
use crate::app::util::opinion::elf_program_builder;
use crate::app::util::opinion::elf_loader_options_factory;
use crate::app::util::opinion::loaded::Loaded;
use crate::app::util::opinion::query_opinion_service;
use crate::format::golang::go_constants::GOLANG_CSPEC_NAME;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::format::elf::elf_header::ElfHeader;
use crate::framework::application::Application;
use crate::framework::model::Project;
use crate::framework::options::Options;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::program::seam_stubs::LanguageNotFoundException;
use crate::util::msg::Msg;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::task::TaskMonitor;

/// `ElfLoader.ELF_NAME`.
pub const ELF_NAME: &str = "Executable and Linking Format (ELF)";

/// `ElfLoader.ELF_ENTRY_FUNCTION_NAME`.
pub const ELF_ENTRY_FUNCTION_NAME: &str = "entry";

/// `ElfLoader.ELF_FILE_TYPE_PROPERTY`.
pub const ELF_FILE_TYPE_PROPERTY: &str = "ELF File Type";
/// `ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY`.
pub const ELF_ORIGINAL_IMAGE_BASE_PROPERTY: &str = "ELF Original Image Base";
/// `ElfLoader.ELF_PRELINKED_PROPERTY`.
pub const ELF_PRELINKED_PROPERTY: &str = "ELF Prelinked";

/// `ElfLoader.ELF_SOURCE_FILE_PROPERTY_PREFIX` (followed by `"#]"`).
pub const ELF_SOURCE_FILE_PROPERTY_PREFIX: &str = "ELF Source File [";

/// Loader for processing Executable and Linking Format (ELF) files.
///
/// Port of `ghidra.app.util.opinion.ElfLoader`.
pub struct ElfLoader;

impl Default for ElfLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfLoader {
    pub fn new() -> Self {
        ElfLoader
    }

    /// `ElfLoader.getElfOriginalImageBase(Program)`.
    ///
    /// # Panics
    /// Panics if the [`ELF_ORIGINAL_IMAGE_BASE_PROPERTY`] property is present but not valid hex,
    /// mirroring Java's uncaught `NumberFormatException` out of `NumericUtilities.parseHexLong`.
    pub fn get_elf_original_image_base(program: &dyn Program) -> std::option::Option<i64> {
        let props = program.get_options(PROGRAM_INFO);
        props.get_value_as_string(ELF_ORIGINAL_IMAGE_BASE_PROPERTY).map(|oib_str| {
            NumericUtilities::parse_hex_long(&oib_str)
                .expect("ELF Original Image Base property must be valid hex")
        })
    }

    /// `ElfLoader.isElf(Program)`.
    pub fn is_elf_program(program: &dyn Program) -> bool {
        Self::is_elf(&program.get_executable_format())
    }

    /// `ElfLoader.isElf(String)`.
    pub fn is_elf(executable_format_string: &str) -> bool {
        executable_format_string == ELF_NAME
    }

    /// `ElfLoader.getDefaultOptions(ByteProvider, LoadSpec, DomainObject, boolean, boolean)`. See
    /// the module docs for why `base_options` stands in for `super.getDefaultOptions(..)`'s
    /// return value.
    ///
    /// NOTE: add-to-program is not supported.
    pub fn get_default_options(
        &self,
        base_options: Vec<Box<dyn Option>>,
        provider: Rc<dyn ByteProvider>,
        load_spec: &LoadSpec,
        language_service: &dyn LanguageService,
    ) -> Vec<Box<dyn Option>> {
        let mut options = base_options;
        let result = ElfHeader::new(provider, None)
            .map_err(|e| e.to_string())
            .and_then(|elf| {
                elf_loader_options_factory::add_options(
                    &mut options,
                    &elf,
                    load_spec,
                    language_service,
                )
                .map_err(|e| e.to_string())
            });
        if let Err(e) = result {
            Msg::error_with_error(
                "ElfLoader",
                &"Error while generating Elf import options",
                &io::Error::new(io::ErrorKind::InvalidData, e),
            );
            // ignore here, will catch later
        }
        options
    }

    /// `ElfLoader.validateOptions(ByteProvider, LoadSpec, List<Option>, Program)`.
    ///
    /// `super.validateOptions(..)` (on the unported `AbstractLibrarySupportLoader`) is not
    /// modeled: see the module docs.
    pub fn validate_options(
        &self,
        options: &[Box<dyn Option>],
        load_spec: &LoadSpec,
        language_service: &dyn LanguageService,
    ) -> std::option::Option<String> {
        elf_loader_options_factory::validate_options(load_spec, options, language_service)
    }

    /// `ElfLoader.findSupportedLoadSpecs(ByteProvider)`. See the module docs for why
    /// `app`/`language_service` are explicit parameters. A provider that is not an ELF image
    /// (an `ElfException`) yields no load specs.
    ///
    /// # Errors
    /// Returns `Err` if `elf.parseSectionHeaders()`'s IO failed, or if a query result's
    /// language/compiler pair could not be resolved to a
    /// [`LanguageDescription`](crate::program::model::lang::language_description::LanguageDescription),
    /// mirroring Java's `throws IOException` (which `LanguageNotFoundException`, thrown
    /// uncaught by `LanguageCompilerSpecPair.getLanguageDescription()`, is itself a subclass of).
    pub fn find_supported_load_specs(
        &self,
        provider: Rc<dyn ByteProvider>,
        app: &dyn Application,
        language_service: &dyn LanguageService,
    ) -> io::Result<Vec<LoadSpec>> {
        let mut load_specs = Vec::new();

        let mut elf = match ElfHeader::new(provider, None) {
            Ok(elf) => elf,
            // not a problem, it's not an elf
            Err(_) => return Ok(load_specs),
        };

        let machine = elf.get_machine_name();
        let compiler = Self::detect_compiler_name(&mut elf)?;

        let mut results: HashSet<QueryResult> = HashSet::new();
        if let Some(compiler) = compiler {
            results.extend(query_opinion_service::query(
                app,
                language_service,
                ELF_NAME,
                &machine,
                &compiler,
            ));
        }
        results.extend(query_opinion_service::query(
            app,
            language_service,
            ELF_NAME,
            &machine,
            &elf.get_flags(),
        ));

        for result in results {
            let mut add = true;
            let description = language_service
                .get_language_description(result.pair.get_language_id())
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
            if elf.is32_bit() && description.get_size() > 32 {
                add = false;
            }
            if elf.is64_bit() && description.get_size() <= 32 {
                add = false;
            }
            if elf.is_little_endian() && description.get_endian() != Endian::Little {
                add = false;
            }
            if elf.is_big_endian() && description.get_endian() != Endian::Big {
                add = false;
            }
            if add {
                load_specs.push(LoadSpec::from_query_result(0, &result));
            }
        }

        if load_specs.is_empty() {
            load_specs.push(LoadSpec::without_language_compiler_spec(0, true));
        }

        Ok(load_specs)
    }

    /// `ElfLoader.load(Program, ImporterSettings)`. The individual `ImporterSettings` fields Java
    /// reads are explicit parameters; the header's error messages go to `log`.
    ///
    /// # Errors
    /// An `ElfException` (not an ELF, or a malformed one) becomes an `io::Error` carrying its
    /// message, as in Java.
    pub fn load(
        &self,
        provider: Rc<dyn ByteProvider>,
        program: &Arc<dyn Program>,
        options: &[Box<dyn Option>],
        log: &Arc<MessageLog>,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let sink = Arc::clone(log);
        let elf = ElfHeader::new(provider, Some(Box::new(move |msg: &str| sink.append_msg(msg))))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        elf_program_builder::load_elf(elf, Arc::clone(program), options, log, monitor).map_err(|e| match e {
            elf_program_builder::ElfLoadError::Io(e) => e,
            cancelled => io::Error::new(io::ErrorKind::Interrupted, cancelled.to_string()),
        })
    }

    /// `ElfLoader.postLoadProgramFixups(List<Loaded<Program>>, ImporterSettings)`. See the module
    /// docs for why `settings` is unpacked into `project`/`log`/`monitor`.
    ///
    /// `super.postLoadProgramFixups(..)` (on the unported `AbstractProgramLoader`) is documented
    /// as doing nothing by default, so nothing is called before the ELF-specific external-symbol
    /// fixup below.
    pub fn post_load_program_fixups(
        &self,
        loaded_programs: &[Box<dyn Loaded>],
        project: std::option::Option<&dyn Project>,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) {
        let project_data = project.map(|p| p.get_project_data());
        let mut esr = ExternalSymbolResolver::new(project_data, monitor);
        for loaded in loaded_programs {
            esr.add_program_to_fixup(loaded.as_ref());
        }
        // Java's `esr.fixUnresolvedExternalSymbols()` declares `throws CancelledException`, which
        // `postLoadProgramFixups` also declares; propagating it would change this method's
        // signature for a path this stub never actually takes (see
        // `ExternalSymbolResolver::fix_unresolved_external_symbols`'s docs), so it is unwrapped.
        esr.fix_unresolved_external_symbols()
            .expect("fix_unresolved_external_symbols placeholder never returns Err");
        esr.log_info(&mut |msg| log.append_msg(msg), true);
    }

    /// `ElfLoader.getName()`.
    pub fn get_name(&self) -> &'static str {
        ELF_NAME
    }

    /// `ElfLoader.detectCompilerName(ElfHeader)`.
    fn detect_compiler_name(elf: &mut ElfHeader) -> io::Result<std::option::Option<String>> {
        elf.parse_section_headers()?;
        let section_names: Vec<String> =
            elf.get_sections().iter().map(|s| s.get_name_as_string()).collect();
        if has_golang_sections(&section_names) {
            return Ok(Some(GOLANG_CSPEC_NAME.to_string()));
        }
        Ok(None)
    }
}

use crate::format::golang::rtti::go_rtti_mapper::has_golang_sections;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::elf::elf_test_image::{provider, ElfImage};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::{LanguageCompilerSpecPair, LanguageCompilerSpecQuery, Processor};
    use std::sync::Arc;

    #[test]
    fn constants_match_java() {
        assert_eq!(ELF_NAME, "Executable and Linking Format (ELF)");
        assert_eq!(ELF_ENTRY_FUNCTION_NAME, "entry");
        assert_eq!(ELF_FILE_TYPE_PROPERTY, "ELF File Type");
        assert_eq!(ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "ELF Original Image Base");
        assert_eq!(ELF_PRELINKED_PROPERTY, "ELF Prelinked");
        assert_eq!(ELF_SOURCE_FILE_PROPERTY_PREFIX, "ELF Source File [");
    }

    #[test]
    fn get_name_returns_elf_name() {
        let loader = ElfLoader::new();
        assert_eq!(loader.get_name(), ELF_NAME);
    }

    #[test]
    fn is_elf_matches_only_the_elf_name() {
        assert!(ElfLoader::is_elf(ELF_NAME));
        assert!(!ElfLoader::is_elf("Portable Executable (PE)"));
    }

    #[test]
    fn has_golang_sections_matches_known_names() {
        assert!(has_golang_sections(&[".gopclntab".to_string()]));
        assert!(has_golang_sections(&["go.buildinfo".to_string()]));
        assert!(has_golang_sections(&["go_buildinfo".to_string()]));
        assert!(!has_golang_sections(&[".text".to_string(), ".data".to_string()]));
    }

    /// A synthetic ELF image (`e_machine` 3, `e_flags` 0) with the named sections.
    fn image(is_64_bit: bool, is_little_endian: bool, sections: &[&str]) -> Vec<u8> {
        let mut img = ElfImage::new(is_64_bit, is_little_endian);
        img.e_machine = 3;
        for name in sections {
            img.add_section(name, 1, 0, 0, &[0u8; 4]);
        }
        img.build()
    }

    fn header(is_64_bit: bool, is_little_endian: bool, sections: &[&str]) -> ElfHeader {
        ElfHeader::new(provider(image(is_64_bit, is_little_endian, sections)), None).unwrap()
    }

    /// A `LanguageService` over a single fixed `(language, size, endian)` catalog entry, matching
    /// [`query_opinion_service`](crate::app::util::opinion::query_opinion_service)'s test-mock
    /// conventions.
    struct MockLanguageService {
        language_id: LanguageID,
        size: i32,
        endian: Endian,
    }

    struct MockLanguageDescription {
        language_id: LanguageID,
        size: i32,
        endian: Endian,
    }

    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            self.language_id.clone()
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_endian(&self) -> Endian {
            self.endian
        }

        fn get_instruction_endian(&self) -> Endian {
            self.endian
        }

        fn get_size(&self) -> i32 {
            self.size
        }

        fn get_variant(&self) -> String {
            "default".to_string()
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_description(&self) -> String {
            self.language_id.get_id_as_string().to_string()
        }

        fn is_deprecated(&self) -> bool {
            false
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.language_id, compiler_spec_id))
        }

        fn get_external_names(&self, _external_tool: &str) -> std::option::Option<Vec<String>> {
            None
        }
    }

    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn crate::program::model::lang::language::Language>, LanguageNotFoundException>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_language(
            &self,
            _processor: &dyn Processor,
        ) -> Result<Box<dyn crate::program::model::lang::language::Language>, LanguageNotFoundException>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_description(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            if *language_id == self.language_id {
                Ok(Box::new(MockLanguageDescription {
                    language_id: self.language_id.clone(),
                    size: self.size,
                    endian: self.endian,
                }))
            } else {
                Err(LanguageNotFoundException(format!("no such language: {language_id}")))
            }
        }

        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }

        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: std::option::Option<Endian>,
            _size: std::option::Option<i32>,
            _variant: std::option::Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }

        fn get_language_compiler_spec_pairs(
            &self,
            _query: &LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            vec![LanguageCompilerSpecPair::new(
                self.language_id.clone(),
                CompilerSpecID::new(Some("default")),
            )]
        }

        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &crate::program::seam_stubs::ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }

        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn Processor,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
    }

    /// `Application` with no `.opinion` files, so `find_supported_load_specs` always exercises
    /// the "no matches" fallback branch. Mirrors the identical mock in
    /// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader)'s tests.
    struct MockApplication;

    impl crate::framework::seam_stubs::ApplicationLayoutLike for MockApplication {
        fn application_properties(&self) -> &dyn crate::framework::application_properties::ApplicationProperties {
            unimplemented!("not exercised by this smoke test")
        }
        fn application_installation_dir(&self) -> std::option::Option<&crate::generic::jar::ResourceFile> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl Application for MockApplication {
        fn application_layout(&self) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
            Box::new(MockApplication)
        }
        fn current_platform(&self) -> Box<dyn crate::framework::platform::Platform> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn find_supported_load_specs_falls_back_when_query_matches_nothing() {
        let loader = ElfLoader::new();
        let elf = provider(image(false, true, &[]));
        let app = MockApplication;
        let language_service = MockLanguageService {
            language_id: LanguageID::new("x86:LE:32:default").unwrap(),
            size: 32,
            endian: Endian::Little,
        };

        // No `.opinion` files are registered in this crate's `QueryOpinionService` yet (its
        // database is populated by parsing them, which is itself unported -- see that module's
        // docs), so `query` always returns empty results and this always takes the "no matches"
        // fallback branch.
        let specs = loader.find_supported_load_specs(elf, &app, &language_service).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(specs[0].language_compiler_spec.is_none());
        assert!(specs[0].requires_language_compiler_spec);
    }

    #[test]
    fn detect_compiler_name_recognizes_golang_sections() {
        let mut elf = header(true, true, &[".text", ".gopclntab"]);
        assert_eq!(
            ElfLoader::detect_compiler_name(&mut elf).unwrap(),
            Some(GOLANG_CSPEC_NAME.to_string())
        );
    }

    #[test]
    fn detect_compiler_name_none_without_golang_sections() {
        let mut elf = header(true, true, &[".text"]);
        assert_eq!(ElfLoader::detect_compiler_name(&mut elf).unwrap(), None);
    }

    #[test]
    fn find_supported_load_specs_is_empty_for_a_non_elf() {
        let loader = ElfLoader::new();
        let language_service = MockLanguageService {
            language_id: LanguageID::new("x86:LE:32:default").unwrap(),
            size: 32,
            endian: Endian::Little,
        };
        let specs = loader
            .find_supported_load_specs(provider(b"MZ not an elf at all, really".to_vec()), &MockApplication, &language_service)
            .unwrap();
        assert!(specs.is_empty());
    }

    /// `ElfLoader.load` end to end on a real language: `/bin/ls` into a fresh `ProgramDB` built
    /// on the local Ghidra distribution's `x86-64.sla` (skipped when either is absent).
    #[test]
    fn load_bin_ls_into_program_db_with_real_language() {
        use crate::app::seam_stubs::new_string;
        use crate::app::util::opinion::elf_loader_options_factory::IMAGE_BASE_OPTION_NAME;
        use crate::pcode::utils::sla_format::{build_decoder, tests::dist_sla};
        use crate::program::database::program_db::ProgramDB;
        use crate::program::model::address::DefaultAddressFactory;
        use crate::program::model::lang::sleigh::SleighLanguage;
        use crate::util::task::DummyMonitor;

        let Some(sla) = dist_sla("x86", "x86-64.sla") else {
            return;
        };
        let Ok(bytes) = std::fs::read("/bin/ls") else {
            return;
        };
        if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[18] != 62 {
            return;
        }
        let decoder = build_decoder(&sla, Arc::new(DefaultAddressFactory::new(vec![]))).unwrap();
        let language =
            Arc::new(SleighLanguage::decode(&decoder, "x86:LE:64:default".to_string()).unwrap());
        let program: Arc<dyn Program> = Arc::new(ProgramDB::new("ls".into(), language).unwrap());
        let options: Vec<Box<dyn Option>> = vec![new_string(IMAGE_BASE_OPTION_NAME)
            .value(Box::new("100000".to_string()))
            .build()];
        let log = Arc::new(MessageLog::new());
        ElfLoader::new()
            .load(provider(bytes), &program, &options, &log, &DummyMonitor)
            .unwrap();
        let memory = program.get_memory().unwrap();
        assert!(!memory.is_empty());
        assert_eq!(program.get_image_base().unwrap().offset(), 0x100000);
        let text = memory
            .get_block_handles()
            .into_iter()
            .find(|b| b.read().unwrap().get_name() == ".text")
            .expect(".text block");
        assert!(text.read().unwrap().is_execute());
        assert!(text.read().unwrap().get_start().offset() >= 0x100000);
    }
}
