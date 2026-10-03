//! Port of `ghidra.program.util.DefaultLanguageService`.
//!
//! Gathers the language descriptions of one or more [`LanguageProvider`]s and answers
//! [`LanguageService`] queries over them, loading a language from its provider on request.
//!
//! # Differences from Java
//! * There is no process-wide singleton (`getLanguageService()`, seeded from the
//!   `SleighLanguageProvider` singleton): build a service over the provider(s) you want, e.g.
//!   [`DefaultLanguageService::from_sleigh_provider`], and share it through an `Arc`.
//!   `getDefinedExternalToolNames`, a `static` method that read the singleton, is therefore an
//!   instance method.
//! * Java loads a not-yet-loaded language inside a modal task dialog; here it loads on the
//!   calling thread (still one load at a time per language).
//! * [`DefaultLanguageService::get_sleigh_language`] is the typed form of `getLanguage` that
//!   Java callers get by casting to `SleighLanguage` (e.g. to create a `ProgramDB`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_provider::LanguageProvider;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::seam_stubs::{
    ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
    LanguageNotFoundException, Processor,
};
use crate::util::task::DummyMonitor;

/// A language provider shareable by a service used from several threads.
pub type SharedLanguageProvider = Arc<dyn LanguageProvider + Send + Sync>;

/// One language: its description and the provider that loads it. Port of the private
/// `LanguageInfo`.
struct LanguageInfo {
    provider: SharedLanguageProvider,
    description: Arc<dyn LanguageDescription>,
    /// Java's `synchronized getLanguage()`: one load of a language at a time.
    load_lock: Mutex<()>,
}

impl LanguageInfo {
    /// Port of `LanguageInfo.getLanguage()`.
    fn get_language(&self) -> Result<Box<dyn Language>, LanguageNotFoundException> {
        let _guard = self.load_lock.lock().unwrap_or_else(PoisonError::into_inner);
        let id = self.description.get_language_id();
        self.provider
            .get_language_with_monitor(&id, &DummyMonitor)?
            .ok_or_else(|| language_not_found(&id))
    }
}

fn language_not_found(language_id: &LanguageID) -> LanguageNotFoundException {
    LanguageNotFoundException(format!("Language not found for '{language_id}'"))
}

/// Java compares `Processor`s by name (`Processor.equals`).
fn same_processor(a: &dyn Processor, b: &dyn Processor) -> bool {
    a.name() == b.name()
}

/// The default [`LanguageService`]: every language of its providers. See the module docs.
pub struct DefaultLanguageService {
    /// `languageInfos`, in provider order.
    language_infos: Vec<LanguageInfo>,
    /// `languageMap`: language id -> index into `language_infos`.
    language_map: HashMap<LanguageID, usize>,
}

impl DefaultLanguageService {
    /// A service over `provider`'s languages. Port of the private
    /// `DefaultLanguageService(LanguageProvider)` constructor.
    pub fn new(provider: SharedLanguageProvider) -> Self {
        Self::with_providers([provider])
    }

    /// A service over the languages of every one of `providers`; a language id already added by
    /// an earlier provider is skipped (Java's `addLanguages`).
    pub fn with_providers(providers: impl IntoIterator<Item = SharedLanguageProvider>) -> Self {
        let mut service = Self { language_infos: Vec::new(), language_map: HashMap::new() };
        for provider in providers {
            service.add_languages(provider);
        }
        service
    }

    /// A service over a [`SleighLanguageProvider`]'s languages: the Java singleton's setup.
    pub fn from_sleigh_provider(provider: SleighLanguageProvider) -> Self {
        Self::new(Arc::new(provider))
    }

    /// Port of the private `addLanguages(LanguageProvider)`. Java's `IllegalStateException` for
    /// a duplicate id cannot happen: a duplicate is skipped by the `contains` check before it.
    fn add_languages(&mut self, provider: SharedLanguageProvider) {
        for description in provider.get_language_descriptions() {
            let id = description.get_language_id();
            if self.language_map.contains_key(&id) {
                // Skip a language previously added.
                continue;
            }
            self.language_map.insert(id, self.language_infos.len());
            self.language_infos.push(LanguageInfo {
                provider: Arc::clone(&provider),
                description: Arc::from(description),
                load_lock: Mutex::new(()),
            });
        }
    }

    fn info(&self, language_id: &LanguageID) -> Result<&LanguageInfo, LanguageNotFoundException> {
        self.language_map
            .get(language_id)
            .map(|&i| &self.language_infos[i])
            .ok_or_else(|| language_not_found(language_id))
    }

    fn boxed(description: &Arc<dyn LanguageDescription>) -> Box<dyn LanguageDescription> {
        Box::new(Arc::clone(description))
    }

    /// The language `language_id` as the shared [`SleighLanguage`] it is, as Java callers get
    /// by casting `getLanguage`'s result -- what `ProgramDB::new` takes.
    ///
    /// # Errors
    /// [`LanguageNotFoundException`] if the language is unknown, fails to load, or is not a
    /// shared Sleigh language.
    pub fn get_sleigh_language(&self, language_id: &LanguageID) -> Result<Arc<SleighLanguage>, LanguageNotFoundException> {
        crate::program::model::lang::language_service::get_sleigh_language(self, language_id)
    }

    /// The descriptions matching every non-`None` criterion. Port of the four-argument
    /// `getLanguageDescriptions(Processor, Endian, Integer, String)` with Java's `null`
    /// processor allowed (as `getLanguageCompilerSpecPairs` passes it).
    fn matching_descriptions(
        &self,
        processor: Option<&dyn Processor>,
        endianness: Option<Endian>,
        size: Option<i32>,
        variant: Option<&str>,
    ) -> Vec<&Arc<dyn LanguageDescription>> {
        self.language_infos
            .iter()
            .map(|info| &info.description)
            .filter(|d| processor.is_none_or(|p| same_processor(p, d.get_processor().as_ref())))
            .filter(|d| endianness.is_none_or(|e| e == d.get_endian()))
            .filter(|d| size.is_none_or(|s| s == d.get_size()))
            .filter(|d| variant.is_none_or(|v| v == d.get_variant()))
            .collect()
    }

    fn external_descriptions(
        &self,
        external_processor_name: Option<&str>,
        external_tool: Option<&str>,
        endianness: Option<Endian>,
        size: Option<i32>,
    ) -> Vec<&Arc<dyn LanguageDescription>> {
        self.language_infos
            .iter()
            .map(|info| &info.description)
            .filter(|d| language_matches_external_processor(d.as_ref(), external_processor_name, external_tool))
            .filter(|d| endianness.is_none_or(|e| e == d.get_endian()))
            .filter(|d| size.is_none_or(|s| s == d.get_size()))
            .collect()
    }

    /// Returns the descriptions of languages known to other tools by `external_processor_name`
    /// (e.g. x86 languages are "metapc" to IDA-PRO) that match the given criteria. A `None`
    /// criterion is a don't-care wildcard, except that a `Some` processor name requires
    /// `external_tool` to be `Some` and to name it (case-insensitively). Port of
    /// `getExternalLanguageDescriptions(String, String, Endian, Integer)`.
    pub fn get_external_language_descriptions(
        &self,
        external_processor_name: Option<&str>,
        external_tool: Option<&str>,
        endianness: Option<Endian>,
        size: Option<i32>,
    ) -> Vec<Box<dyn LanguageDescription>> {
        self.external_descriptions(external_processor_name, external_tool, endianness, size)
            .into_iter()
            .map(Self::boxed)
            .collect()
    }

    /// Returns the external names `tool` uses for the language `language_id`, or `None` if
    /// `language_id`/`tool` is empty or no such names are registered. Port of the `static`
    /// `getDefinedExternalToolNames(String, String, boolean)`, which read the singleton service.
    pub fn get_defined_external_tool_names(
        &self,
        language_id: &str,
        tool: &str,
        include_deprecated: bool,
    ) -> Option<Vec<String>> {
        if language_id.is_empty() || tool.is_empty() {
            return None;
        }
        self.get_language_descriptions(include_deprecated)
            .into_iter()
            .filter(|d| d.get_language_id().get_id_as_string() == language_id)
            .find_map(|d| d.get_external_names(tool))
    }

    /// Port of the private `addLanguageCompilerSpecPairs`: the pair for the preferred compiler
    /// spec if the language has it, otherwise a pair for every compiler spec.
    fn add_language_compiler_spec_pairs(
        description: &dyn LanguageDescription,
        preferred_compiler_spec_id: Option<&CompilerSpecID>,
        result: &mut Vec<LanguageCompilerSpecPair>,
    ) {
        let specs = description.get_compatible_compiler_spec_descriptions();
        let id = description.get_language_id();
        if let Some(preferred) = preferred_compiler_spec_id {
            if let Some(spec) = specs.iter().find(|s| &s.get_compiler_spec_id() == preferred) {
                result.push(LanguageCompilerSpecPair::new(id, spec.get_compiler_spec_id()));
                return;
            }
        }
        for spec in specs {
            result.push(LanguageCompilerSpecPair::new(id.clone(), spec.get_compiler_spec_id()));
        }
    }
}

/// Port of the private static `languageMatchesExternalProcessor`.
fn language_matches_external_processor(
    description: &dyn LanguageDescription,
    external_processor_name: Option<&str>,
    external_tool: Option<&str>,
) -> bool {
    let Some(external_processor_name) = external_processor_name else {
        return true;
    };
    let Some(external_tool) = external_tool else {
        return false;
    };
    description
        .get_external_names(external_tool)
        .is_some_and(|names| names.iter().any(|n| external_processor_name.eq_ignore_ascii_case(n)))
}

impl LanguageService for DefaultLanguageService {
    fn get_language(&self, language_id: &LanguageID) -> Result<Box<dyn Language>, LanguageNotFoundException> {
        self.info(language_id)?.get_language()
    }

    /// Port of `getDefaultLanguage(Processor)`: the first language of `processor`.
    fn get_default_language(&self, processor: &dyn Processor) -> Result<Box<dyn Language>, LanguageNotFoundException> {
        self.language_infos
            .iter()
            .find(|info| same_processor(processor, info.description.get_processor().as_ref()))
            .ok_or_else(|| LanguageNotFoundException(format!("Language not found for processor: {}", processor.name())))?
            .get_language()
    }

    fn get_language_description(
        &self,
        language_id: &LanguageID,
    ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
        Ok(Self::boxed(&self.info(language_id)?.description))
    }

    fn get_language_descriptions(&self, include_deprecated_languages: bool) -> Vec<Box<dyn LanguageDescription>> {
        self.language_infos
            .iter()
            .filter(|info| include_deprecated_languages || !info.description.is_deprecated())
            .map(|info| Self::boxed(&info.description))
            .collect()
    }

    fn get_language_descriptions_matching(
        &self,
        processor: &dyn Processor,
        endianness: Option<Endian>,
        size: Option<i32>,
        variant: Option<&str>,
    ) -> Vec<Box<dyn LanguageDescription>> {
        self.matching_descriptions(Some(processor), endianness, size, variant)
            .into_iter()
            .map(Self::boxed)
            .collect()
    }

    /// Port of `getLanguageCompilerSpecPairs(LanguageCompilerSpecQuery)`; omits deprecated
    /// languages.
    fn get_language_compiler_spec_pairs(&self, query: &LanguageCompilerSpecQuery) -> Vec<LanguageCompilerSpecPair> {
        let mut result = Vec::new();
        let descriptions = self.matching_descriptions(
            query.processor.as_deref(),
            query.endian,
            query.size,
            query.variant.as_deref(),
        );
        for description in descriptions.into_iter().filter(|d| !d.is_deprecated()) {
            for spec in description.get_compatible_compiler_spec_descriptions() {
                let spec_id = spec.get_compiler_spec_id();
                if query.compiler_spec_id.as_ref().is_none_or(|q| q == &spec_id) {
                    result.push(LanguageCompilerSpecPair::new(description.get_language_id(), spec_id));
                }
            }
        }
        result
    }

    /// Port of `getLanguageCompilerSpecPairs(ExternalLanguageCompilerSpecQuery)`; omits deprecated
    /// languages.
    fn get_language_compiler_spec_pairs_external(
        &self,
        query: &ExternalLanguageCompilerSpecQuery,
    ) -> Vec<LanguageCompilerSpecPair> {
        let mut result = Vec::new();
        let descriptions = self.external_descriptions(
            query.external_processor_name.as_deref(),
            query.external_tool.as_deref(),
            query.endian,
            query.size,
        );
        for description in descriptions.into_iter().filter(|d| !d.is_deprecated()) {
            Self::add_language_compiler_spec_pairs(description.as_ref(), query.compiler_spec_id.as_ref(), &mut result);
        }
        result
    }

    fn get_language_descriptions_for_processor(&self, processor: &dyn Processor) -> Vec<Box<dyn LanguageDescription>> {
        self.language_infos
            .iter()
            .filter(|info| same_processor(processor, info.description.get_processor().as_ref()))
            .map(|info| Self::boxed(&info.description))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::basic_compiler_spec_description::BasicCompilerSpecDescription;
    use crate::program::model::lang::basic_language_description::{BasicLanguageDescription, ExternalNames};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::processor::Processor as RealProcessor;
    use crate::util::task::TaskMonitor;

    fn description(id: &str, endian: Endian, size: i32, deprecated: bool, specs: &[&str], ida: Option<&str>) -> BasicLanguageDescription {
        let processor = RealProcessor::find_or_possibly_create_processor(id.split(':').next().unwrap());
        let specs: Vec<Arc<dyn CompilerSpecDescription>> = specs
            .iter()
            .map(|s| Arc::new(BasicCompilerSpecDescription::new(CompilerSpecID::new(Some(s)), *s)) as Arc<dyn CompilerSpecDescription>)
            .collect();
        let names = ida.map(|n| ExternalNames::from([("IDA-PRO".to_string(), vec![n.to_string()])]));
        BasicLanguageDescription::new(
            LanguageID::new(id).unwrap(),
            processor,
            endian,
            endian,
            size,
            "default",
            id,
            1,
            0,
            deprecated,
            specs,
            names,
        )
    }

    /// A provider of fixed descriptions whose languages never load.
    struct DescriptionsOnly(Vec<BasicLanguageDescription>);

    impl LanguageProvider for DescriptionsOnly {
        fn get_language_with_monitor(
            &self,
            _language_id: &LanguageID,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException> {
            Ok(None)
        }
        fn get_language_descriptions(&self) -> Vec<Box<dyn LanguageDescription>> {
            self.0.iter().map(|d| Box::new(d.clone()) as Box<dyn LanguageDescription>).collect()
        }
        fn had_load_failure(&self) -> bool {
            false
        }
        fn is_language_loaded(&self, _language_id: &LanguageID) -> bool {
            false
        }
    }

    fn service() -> DefaultLanguageService {
        DefaultLanguageService::new(Arc::new(DescriptionsOnly(vec![
            description("x86:LE:32:default", Endian::Little, 32, false, &["windows", "gcc"], Some("metapc")),
            description("x86:LE:64:default", Endian::Little, 64, false, &["windows", "gcc"], Some("metapc")),
            description("8051:BE:16:default", Endian::Big, 16, false, &["default"], None),
            description("8051:BE:16:old", Endian::Big, 16, true, &["default"], None),
        ])))
    }

    fn ids(descriptions: &[Box<dyn LanguageDescription>]) -> Vec<String> {
        descriptions.iter().map(|d| d.get_language_id().get_id_as_string().to_string()).collect()
    }

    fn pair_ids(pairs: &[LanguageCompilerSpecPair]) -> Vec<String> {
        pairs.iter().map(|p| format!("{}/{}", p.get_language_id(), p.get_compiler_spec_id())).collect()
    }

    #[test]
    fn service_and_sleigh_provider_are_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DefaultLanguageService>();
        assert_send_sync::<SleighLanguageProvider>();
    }

    #[test]
    fn descriptions_by_id_and_deprecation() {
        let s = service();
        let x86 = LanguageID::new("x86:LE:64:default").unwrap();
        assert_eq!(s.get_language_description(&x86).unwrap().get_size(), 64);
        assert!(s.get_language_description(&LanguageID::new("ARM:LE:32:v8").unwrap()).is_err());
        assert_eq!(s.get_language_descriptions(true).len(), 4);
        assert_eq!(
            ids(&s.get_language_descriptions(false)),
            ["x86:LE:32:default", "x86:LE:64:default", "8051:BE:16:default"]
        );
    }

    #[test]
    fn descriptions_for_processor_and_matching_criteria() {
        let s = service();
        let x86 = RealProcessor::find_or_possibly_create_processor("x86");
        assert_eq!(s.get_language_descriptions_for_processor(&x86).len(), 2);
        #[allow(deprecated)]
        let matching = s.get_language_descriptions_matching(&x86, Some(Endian::Little), Some(64), Some("default"));
        assert_eq!(ids(&matching), ["x86:LE:64:default"]);
    }

    #[test]
    fn compiler_spec_pairs_omit_deprecated_and_filter_by_spec() {
        let s = service();
        let all = s.get_language_compiler_spec_pairs(&LanguageCompilerSpecQuery::new(None, Some(Endian::Big), None, None, None));
        assert_eq!(pair_ids(&all), ["8051:BE:16:default/default"]);
        let gcc = s.get_language_compiler_spec_pairs(&LanguageCompilerSpecQuery::new(
            Some(Box::new(RealProcessor::find_or_possibly_create_processor("x86"))),
            None,
            None,
            None,
            Some(CompilerSpecID::new(Some("gcc"))),
        ));
        assert_eq!(pair_ids(&gcc), ["x86:LE:32:default/gcc", "x86:LE:64:default/gcc"]);
    }

    #[test]
    fn external_pairs_prefer_the_requested_spec_else_offer_all() {
        let s = service();
        let query = |spec: Option<&str>| {
            ExternalLanguageCompilerSpecQuery::new(
                Some("METAPC".to_string()),
                Some("IDA-PRO".to_string()),
                None,
                Some(64),
                spec.map(|x| CompilerSpecID::new(Some(x))),
            )
        };
        assert_eq!(pair_ids(&s.get_language_compiler_spec_pairs_external(&query(Some("gcc")))), ["x86:LE:64:default/gcc"]);
        assert_eq!(
            pair_ids(&s.get_language_compiler_spec_pairs_external(&query(Some("clang")))),
            ["x86:LE:64:default/windows", "x86:LE:64:default/gcc"]
        );
    }

    #[test]
    fn external_language_descriptions() {
        let s = service();
        assert_eq!(s.get_external_language_descriptions(Some("METAPC"), Some("IDA-PRO"), None, Some(32)).len(), 1);
        // A processor name needs a tool.
        assert!(s.get_external_language_descriptions(Some("metapc"), None, None, None).is_empty());
        assert_eq!(
            ids(&s.get_external_language_descriptions(None, None, Some(Endian::Big), Some(16))),
            ["8051:BE:16:default", "8051:BE:16:old"]
        );
    }

    #[test]
    fn defined_external_tool_names() {
        let s = service();
        assert_eq!(s.get_defined_external_tool_names("x86:LE:32:default", "IDA-PRO", true), Some(vec!["metapc".to_string()]));
        assert!(s.get_defined_external_tool_names("8051:BE:16:default", "IDA-PRO", true).is_none());
        assert!(s.get_defined_external_tool_names("", "IDA-PRO", true).is_none());
        assert!(s.get_defined_external_tool_names("x86:LE:32:default", "", true).is_none());
    }

    #[test]
    fn later_providers_do_not_replace_earlier_languages() {
        let first: SharedLanguageProvider =
            Arc::new(DescriptionsOnly(vec![description("x86:LE:32:default", Endian::Little, 32, false, &["gcc"], None)]));
        let second: SharedLanguageProvider = Arc::new(DescriptionsOnly(vec![
            description("x86:LE:32:default", Endian::Little, 99, false, &["gcc"], None),
            description("ARM:LE:32:v8", Endian::Little, 32, false, &["default"], None),
        ]));
        let s = DefaultLanguageService::with_providers([first, second]);
        assert_eq!(ids(&s.get_language_descriptions(true)), ["x86:LE:32:default", "ARM:LE:32:v8"]);
        assert_eq!(s.get_language_description(&LanguageID::new("x86:LE:32:default").unwrap()).unwrap().get_size(), 32);
    }

    /// A provider of one language (the generated x86-64 test language), handed out either as
    /// the shared language or as an unshared copy (which cannot be recovered as an `Arc`).
    struct OneLanguage {
        description: BasicLanguageDescription,
        shared: bool,
    }

    impl LanguageProvider for OneLanguage {
        fn get_language_with_monitor(
            &self,
            _language_id: &LanguageID,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException> {
            let language = crate::program::model::lang::cspec_test_support::sleigh_x86_64_language(None);
            if self.shared {
                return Ok(Some(Box::new(language)));
            }
            let unshared = Arc::try_unwrap(language).ok().expect("only reference");
            Ok(Some(Box::new(unshared)))
        }
        fn get_language_descriptions(&self) -> Vec<Box<dyn LanguageDescription>> {
            vec![Box::new(self.description.clone())]
        }
        fn had_load_failure(&self) -> bool {
            false
        }
        fn is_language_loaded(&self, _language_id: &LanguageID) -> bool {
            true
        }
    }

    #[test]
    fn get_sleigh_language_recovers_the_shared_sleigh_language_only() {
        let id = LanguageID::new("x86:LE:64:default").unwrap();
        let description = description("x86:LE:64:default", Endian::Little, 64, false, &["gcc"], None);
        let shared = DefaultLanguageService::new(Arc::new(OneLanguage { description: description.clone(), shared: true }));
        let language = shared.get_sleigh_language(&id).unwrap();
        assert!(language.get_register_by_name("RAX").is_some());
        let unshared = DefaultLanguageService::new(Arc::new(OneLanguage { description, shared: false }));
        let err = unshared.get_sleigh_language(&id).err().unwrap();
        assert!(err.0.contains("not a shared Sleigh language"), "{}", err.0);
    }

    #[test]
    fn unloadable_or_unknown_languages_are_not_found() {
        let s = service();
        let x86 = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(s.get_language(&x86).is_err());
        assert!(s.get_sleigh_language(&x86).is_err());
        assert!(s.get_language(&LanguageID::new("ARM:LE:32:v8").unwrap()).is_err());
        let z80 = RealProcessor::find_or_possibly_create_processor("Z80");
        assert!(s.get_default_language(&z80).is_err());
    }

    /// The acceptance path: a language id -> the Sleigh language from the local Ghidra
    /// distribution -> a `ProgramDB` -> `/bin/ls` loaded through the ELF loader. Skipped when the
    /// distribution or an x86-64 `/bin/ls` is absent.
    #[test]
    fn x86_64_from_the_service_creates_a_program_db_that_loads_bin_ls() {
        use crate::app::plugin::processors::sleigh::sleigh_language_provider::tests::ghidra_dist;
        use crate::app::seam_stubs::new_string;
        use crate::app::util::opinion::elf_loader::ElfLoader;
        use crate::app::util::opinion::elf_loader_options_factory::IMAGE_BASE_OPTION_NAME;
        use crate::format::elf::elf_test_image::provider;
        use crate::program::database::program_db::ProgramDB;
        use crate::program::model::listing::Program;

        let Some(dist) = ghidra_dist() else {
            return;
        };
        let Ok(bytes) = std::fs::read("/bin/ls") else {
            return;
        };
        if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[18] != 62 {
            return;
        }
        let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(&dist));
        let language = service.get_sleigh_language(&LanguageID::new("x86:LE:64:default").unwrap()).unwrap();
        assert_eq!(language.get_language_description().get_size(), 64);
        // Asking again hands out the same, cached language.
        let again = service.get_sleigh_language(&LanguageID::new("x86:LE:64:default").unwrap()).unwrap();
        assert!(Arc::ptr_eq(&language, &again));
        // Loaders get a `&dyn LanguageService`; the free helper gives them the same language.
        let as_dyn: &dyn LanguageService = &service;
        let via_dyn = crate::program::model::lang::language_service::get_sleigh_language(
            as_dyn,
            &LanguageID::new("x86:LE:64:default").unwrap(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&language, &via_dyn));

        let program: Arc<dyn Program> = Arc::new(ProgramDB::new("ls".into(), language).unwrap());
        let options: Vec<Box<dyn crate::app::seam_stubs::Option>> =
            vec![new_string(IMAGE_BASE_OPTION_NAME).value(Box::new("100000".to_string())).build()];
        let log = Arc::new(crate::app::util::importer::message_log::MessageLog::new());
        ElfLoader::new().load(provider(bytes), &program, &options, &log, &DummyMonitor).unwrap();
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

    /// Every language id the task names comes out of the distribution as a loadable Sleigh
    /// language.
    #[test]
    fn aarch64_from_the_service() {
        use crate::app::plugin::processors::sleigh::sleigh_language_provider::tests::ghidra_dist;
        let Some(dist) = ghidra_dist() else {
            return;
        };
        let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(&dist));
        let language = service.get_sleigh_language(&LanguageID::new("AARCH64:LE:64:v8A").unwrap()).unwrap();
        assert!(language.get_register_by_name("x0").is_some());
        assert_eq!(language.get_default_compiler_spec().get_compiler_spec_id(), CompilerSpecID::new(Some("default")));
        let aarch64 = RealProcessor::find_or_possibly_create_processor("AARCH64");
        assert!(service.get_default_language(&aarch64).is_ok());
    }
}
