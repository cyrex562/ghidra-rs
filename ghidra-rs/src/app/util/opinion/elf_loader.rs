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
//! * `ElfHeader`'s `new ElfHeader(ByteProvider, ErrorConsumer)` constructor is not part of the
//!   ported [`ElfHeader`](crate::format::seam_stubs::ElfHeader) placeholder trait (which has no
//!   way to parse bytes). Every method that Java calls `new ElfHeader(..)` from -- and whose
//!   `catch (ElfException e)` handles the "not actually an ELF" case -- instead takes an
//!   already-parsed `elf: &dyn ElfHeader`, mirroring the same substitution already made in
//!   [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) (see
//!   its module docs): "the (unported) `ElfLoader` caller is expected to have parsed one
//!   already." Concretely, [`find_supported_load_specs`](ElfLoader::find_supported_load_specs)
//!   and [`load`](ElfLoader::load) both drop their `ByteProvider` parameter for a pre-parsed
//!   `ElfHeader`, and the `ElfException`-means-"not an ELF" behavior becomes the caller's problem
//!   to detect before calling in.
//! * `QueryOpinionService.query(String, String, String)` and
//!   `LanguageCompilerSpecPair.getLanguageDescription()` both resolve process-wide singletons
//!   (`Application`/`DefaultLanguageService`) that were dropped when those classes were ported
//!   (see [`query_opinion_service`](crate::app::util::opinion::query_opinion_service)'s and
//!   [`LoadSpec::get_language`](crate::app::seam_stubs::LoadSpec::get_language)'s docs), so
//!   [`find_supported_load_specs`](ElfLoader::find_supported_load_specs) takes explicit
//!   `&dyn Application`/`&dyn LanguageService` parameters instead.
//! * `ElfProgramBuilder.loadElf(..)`, the sole call `ElfLoader.load` makes, is a large unported
//!   subsystem (ELF-to-`Program` construction: memory blocks, symbols, relocations, ...). It is
//!   modeled as the free function
//!   [`elf_program_builder::load_elf`](crate::app::seam_stubs::elf_program_builder::load_elf),
//!   which panics until that subsystem lands; see its docs.
//! * `postLoadProgramFixups`'s `ImporterSettings settings` parameter belongs to the [`Loader`]
//!   trait this port doesn't implement (see above), so it is unpacked into the individual pieces
//!   Java actually reads from it (`project`, `log`, `monitor`). `ExternalSymbolResolver` is a
//!   large unported subsystem in its own right; see
//!   [`crate::app::seam_stubs::ExternalSymbolResolver`]'s docs for what is and is not modeled.

use std::collections::HashSet;
use std::io;

use crate::app::seam_stubs::{
    elf_program_builder, ExternalSymbolResolver, LoadSpec, MessageLog, Option, QueryResult,
};
use crate::app::util::opinion::elf_loader_options_factory;
use crate::app::util::opinion::loaded::Loaded;
use crate::app::util::opinion::query_opinion_service;
use crate::format::golang::go_constants::GOLANG_CSPEC_NAME;
use crate::format::seam_stubs::ElfHeader;
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

/// Stands in for the unported static `GoBuildInfo.SECTION_NAME`/`GoBuildInfo.MACHO_SECTION_NAME`
/// constants, used only by [`has_golang_sections`] below.
const GO_BUILDINFO_SECTION_NAME: &str = "go.buildinfo";
const GO_BUILDINFO_MACHO_SECTION_NAME: &str = "go_buildinfo";

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
    /// return value and `elf` for the `ByteProvider` parameter.
    ///
    /// NOTE: add-to-program is not supported.
    pub fn get_default_options(
        &self,
        base_options: Vec<Box<dyn Option>>,
        elf: &dyn ElfHeader,
        load_spec: &LoadSpec,
        language_service: &dyn LanguageService,
    ) -> Vec<Box<dyn Option>> {
        let mut options = base_options;
        if let Err(e) =
            elf_loader_options_factory::add_options(&mut options, elf, load_spec, language_service)
        {
            Msg::error_with_error(
                "ElfLoader",
                &"Error while generating Elf import options",
                &e,
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

    /// `ElfLoader.findSupportedLoadSpecs(ByteProvider)`. See the module docs for why `elf` is
    /// taken pre-parsed, and `app`/`language_service` are explicit parameters.
    ///
    /// # Errors
    /// Returns `Err` if `elf.parseSectionHeaders()`'s IO failed, or if a query result's
    /// language/compiler pair could not be resolved to a
    /// [`LanguageDescription`](crate::program::model::lang::language_description::LanguageDescription),
    /// mirroring Java's `throws IOException` (which `LanguageNotFoundException`, thrown
    /// uncaught by `LanguageCompilerSpecPair.getLanguageDescription()`, is itself a subclass of).
    pub fn find_supported_load_specs(
        &self,
        elf: &dyn ElfHeader,
        app: &dyn Application,
        language_service: &dyn LanguageService,
    ) -> io::Result<Vec<LoadSpec>> {
        let mut load_specs = Vec::new();

        let machine = elf.get_machine_name();
        let compiler = Self::detect_compiler_name(elf)?;

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

    /// `ElfLoader.load(Program, ImporterSettings)`. See the module docs for why `elf` is taken
    /// pre-parsed and the individual `ImporterSettings` fields Java reads are explicit
    /// parameters.
    pub fn load(
        &self,
        elf: &dyn ElfHeader,
        program: &mut dyn Program,
        options: &[Box<dyn Option>],
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        elf_program_builder::load_elf(elf, program, options, log, monitor)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
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
        log: &dyn MessageLog,
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
    fn detect_compiler_name(elf: &dyn ElfHeader) -> io::Result<std::option::Option<String>> {
        elf.parse_section_headers()?;
        let section_names: Vec<String> =
            elf.get_sections().iter().map(|s| s.get_name_as_string()).collect();
        if has_golang_sections(&section_names) {
            return Ok(Some(GOLANG_CSPEC_NAME.to_string()));
        }
        Ok(None)
    }
}

/// Stands in for the unported static `GoRttiMapper.hasGolangSections(List<String>)`: a pure
/// predicate over three substrings, so it's ported directly here rather than added to the
/// [`GoRttiMapper`](crate::format::seam_stubs::GoRttiMapper) trait stub (whose members are all
/// instance methods).
fn has_golang_sections(section_names: &[String]) -> bool {
    section_names.iter().any(|name| {
        name.contains("gopclntab")
            || name.contains(GO_BUILDINFO_MACHO_SECTION_NAME)
            || name.contains(GO_BUILDINFO_SECTION_NAME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::ElfSectionHeader;
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

    struct MockElfSectionHeader {
        name: &'static str,
    }

    impl ElfSectionHeader for MockElfSectionHeader {
        fn get_name_as_string(&self) -> String {
            self.name.to_string()
        }

        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            unimplemented!("not exercised by this smoke test")
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

    struct MockElfHeader {
        is_64_bit: bool,
        is_little_endian: bool,
        sections: Vec<&'static str>,
    }

    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            !self.is_64_bit
        }

        fn is_relocatable(&self) -> bool {
            false
        }

        fn is_big_endian(&self) -> bool {
            !self.is_little_endian
        }

        fn is_little_endian(&self) -> bool {
            self.is_little_endian
        }

        fn get_machine_name(&self) -> String {
            "3".to_string()
        }

        fn get_flags(&self) -> String {
            "0".to_string()
        }

        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
            self.sections
                .iter()
                .map(|&name| Box::new(MockElfSectionHeader { name }) as Box<dyn ElfSectionHeader>)
                .collect()
        }
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
        let elf = MockElfHeader { is_64_bit: false, is_little_endian: true, sections: vec![] };
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
        let specs = loader.find_supported_load_specs(&elf, &app, &language_service).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(specs[0].language_compiler_spec.is_none());
        assert!(specs[0].requires_language_compiler_spec);
    }

    #[test]
    fn detect_compiler_name_recognizes_golang_sections() {
        let elf = MockElfHeader {
            is_64_bit: true,
            is_little_endian: true,
            sections: vec![".text", ".gopclntab"],
        };
        assert_eq!(
            ElfLoader::detect_compiler_name(&elf).unwrap(),
            Some(GOLANG_CSPEC_NAME.to_string())
        );
    }

    #[test]
    fn detect_compiler_name_none_without_golang_sections() {
        let elf =
            MockElfHeader { is_64_bit: true, is_little_endian: true, sections: vec![".text"] };
        assert_eq!(ElfLoader::detect_compiler_name(&elf).unwrap(), None);
    }
}
