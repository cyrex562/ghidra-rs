//! Port of `ghidra.app.util.opinion.XmlLoader`.
//!
//! Loads a Ghidra program XML file (see `PROGRAM.DTD`). The load specs it offers come from the
//! `LANGUAGE`/`INFO_SOURCE` tags at the head of the document: an explicit language ID wins, an
//! external processor name is resolved through a language-service query, and if neither matches
//! anything the loader falls back to offering every non-deprecated language of the right
//! endianness. The import itself is delegated to `ProgramXmlMgr`, run inside an analysis-suspended
//! worker when the program already has an analysis manager.
//!
//! # Departures from the Java class
//!
//! * `XmlLoader extends AbstractProgramLoader`, which implements the bulk of the `Loader`
//!   interface (program creation, transaction handling, `Loaded` bookkeeping, ...) and is not
//!   ported. Like [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader), this port
//!   models just the overridden surface as inherent methods on a standalone struct rather than
//!   implementing the [`Loader`](crate::app::util::opinion::loader::Loader) trait, which would
//!   additionally require the inherited machinery this class never defines. The one inherited
//!   helper `loadProgram` calls, `createDefaultMemoryBlocks`, is a placeholder in
//!   [`abstract_program_loader`](crate::app::seam_stubs::abstract_program_loader).
//! * `getLanguageService()` (an `AbstractProgramLoader` helper wrapping the
//!   `DefaultLanguageService` singleton, which was dropped when that class was ported) becomes an
//!   explicit [`LanguageService`] parameter, mirroring the substitution already established in
//!   [`LoadSpec::get_language`]. That also removes the bare `getLanguageService()` call at the top
//!   of `findSupportedLoadSpecs`, which Java makes purely to force the `Processor` name registry
//!   to be populated before parsing -- passing a live service in has already had that effect.
//! * `loadProgram(ImporterSettings)` returns `List<Loaded<Program>>`, built by the inherited
//!   `createProgram(imageBase, settings)`. There is no concrete
//!   [`Loaded`](crate::app::util::opinion::loaded::Loaded) implementer in the crate, and no
//!   ported `createProgram`, so [`XmlLoader::load_program`] takes a `create_program` closure --
//!   handed the parsed image base exactly as Java hands it to `createProgram` -- and returns the
//!   resulting `Program` directly: `None` for Java's empty list (nothing parsed), `Some` for its
//!   one-element list. Java's `finally { loadedList.forEach(Loaded::close); }` on failure becomes
//!   the program being dropped on the error paths.
//! * `ProgramXmlMgr`, `XmlProgramOptions`, `AutoAnalysisManager` and `MessageLog` are not ported;
//!   they are placeholders in [`app::seam_stubs`](crate::app::seam_stubs). Everything that
//!   bottoms out in one of them (`parse`, `doImportWork`, `getDefaultOptions`, `validateOptions`)
//!   is ported in full but panics on the placeholder if actually run today; the loader's own
//!   logic -- load-spec selection, address-model size extraction, file-name preferences,
//!   transaction/worker choreography, failure-message selection -- is ported in full.
//! * `parse` catches `Throwable` so that a speculative load of a non-XML file yields an empty
//!   result. Here it maps the `Err` out of
//!   [`ProgramXmlMgr::get_program_info`](crate::app::seam_stubs::ProgramXmlMgr::get_program_info)
//!   the same way. (It cannot also catch the placeholder's `unimplemented!()` panic; once the
//!   real `ProgramXmlMgr` reports parse failures as errors, the behavior matches Java's.)
//! * Java's `findSupportedLoadSpecs` is one method; the half that reasons about an already-parsed
//!   `ProgramInfo` is split out here as [`XmlLoader::load_specs_for_info`], so it can be exercised
//!   without a real `ProgramXmlMgr`.
//! * `doImport` reports cancellation, an `InvocationTargetException`'s `IOException` cause, and
//!   `InterruptedException` through the three exception arms of Java's `scheduleWorker` call. The
//!   ported [`AnalysisWorker`] callback may only fail with `CancelledException`, so the
//!   `LoadException` `doImportWork` raises is stashed on the worker and re-raised by `doImport`
//!   after `scheduleWorker` returns, which is where Java surfaces it too.
//! * `ByteProvider.getName()` is not on the ported [`ByteProvider`] trait (only `get_fsrl`/
//!   `get_file` are). This port derives the same display name from those two instead, exactly as
//!   [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) does.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use regex::Regex;

use crate::app::plugin::core::analysis::analysis_worker::AnalysisWorker;
use crate::app::seam_stubs::{
    abstract_program_loader, auto_analysis_manager, LoadSpec, MessageLog, Option as LoaderOption,
    ProgramXmlMgr, XmlProgramOptions,
};
use crate::app::util::opinion::load_exception::LoadException;
use crate::app::util::opinion::loader_tier::LoaderTier;
use crate::app::util::xml::program_info::ProgramInfo;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::model::address::Address;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::Program;
use crate::program::seam_stubs::{
    ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageNotFoundException,
};
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// `XmlLoader.FILE_EXTENSION`.
const FILE_EXTENSION: &str = ".xml";

/// `XmlLoader.XML_SRC_NAME`.
pub const XML_SRC_NAME: &str = "XML Input Format";

/// `XmlLoader.ADDRESS_MODEL_PATTERN`.
fn address_model_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(\d+)-bit").expect("valid address model pattern"))
}

/// Everything [`XmlLoader::load_program`]/[`XmlLoader::load_program_into`] can fail with.
///
/// Java declares `IOException, LoadException, CancelledException` on both; `LoadException` is a
/// subclass of `IOException` there, and the only cancellation path (`doImport`'s
/// `catch (CancelledException e) { return false; }`) is swallowed rather than propagated, so only
/// the first two are modeled. [`XmlImportError::LanguageNotFound`] additionally covers the
/// language lookup `loadProgram` performs, which Java reaches through the unchecked-throwing
/// `getLanguageService().getLanguage(..)`.
#[derive(Debug, thiserror::Error)]
pub enum XmlImportError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Load(#[from] LoadException),
    #[error(transparent)]
    LanguageNotFound(#[from] LanguageNotFoundException),
}

/// `XmlLoader.ParseResult`. Java's two fields are either both set or both `null`.
struct ParseResult {
    last_xml_mgr: Option<ProgramXmlMgr>,
    last_info: Option<ProgramInfo>,
}

impl ParseResult {
    /// `new ParseResult(null, null)`, the result Java's `catch (Throwable e)` arm returns.
    fn empty() -> Self {
        ParseResult { last_xml_mgr: None, last_info: None }
    }
}

/// The anonymous `AnalysisWorker` `XmlLoader.doImport` schedules.
///
/// `failure` carries the `LoadException` `doImportWork` raises back out to `doImport`; see the
/// module docs for why it cannot travel through the callback's return type.
struct XmlImportWorker<'a> {
    mgr: &'a ProgramXmlMgr,
    options: &'a [Box<dyn LoaderOption>],
    log: &'a dyn MessageLog,
    is_add_to_program: bool,
    failure: Mutex<Option<LoadException>>,
}

impl AnalysisWorker for XmlImportWorker<'_> {
    fn analysis_worker_callback(
        &self,
        program: &dyn Program,
        _worker_context: &dyn std::any::Any,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledException> {
        match XmlLoader::do_import_work(
            self.mgr,
            self.options,
            self.log,
            program,
            monitor,
            self.is_add_to_program,
        ) {
            Ok(success) => Ok(success),
            Err(e) => {
                *self.failure.lock().expect("XmlImportWorker failure slot poisoned") = Some(e);
                Ok(false)
            }
        }
    }

    fn get_worker_name(&self) -> String {
        "XML Importer".to_string()
    }
}

/// Loader for Ghidra program XML files.
///
/// Port of `ghidra.app.util.opinion.XmlLoader`.
pub struct XmlLoader;

impl Default for XmlLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl XmlLoader {
    pub fn new() -> Self {
        XmlLoader
    }

    /// `XmlLoader.getTier()`.
    pub fn get_tier(&self) -> LoaderTier {
        LoaderTier::SpecializedTargetLoader
    }

    /// `XmlLoader.getTierPriority()`.
    pub fn get_tier_priority(&self) -> i32 {
        50
    }

    /// `XmlLoader.supportsLoadIntoProgram()`.
    pub fn supports_load_into_program(&self) -> bool {
        true
    }

    /// `XmlLoader.getName()`.
    pub fn get_name(&self) -> &'static str {
        XML_SRC_NAME
    }

    /// `XmlLoader.findSupportedLoadSpecs(ByteProvider)`. See the module docs for why the language
    /// service is passed in.
    pub fn find_supported_load_specs(
        &self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        language_service: &dyn LanguageService,
    ) -> io::Result<Vec<LoadSpec>> {
        let result = Self::parse(provider);
        let Some(info) = result.last_info.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(self.load_specs_for_info(info, language_service))
    }

    /// The body of `findSupportedLoadSpecs` past its `info == null` guard: everything that
    /// reasons about an already-parsed `ProgramInfo`. Split out so it can be exercised without a
    /// real `ProgramXmlMgr`; see the module docs.
    #[allow(deprecated)]
    fn load_specs_for_info(
        &self,
        info: &ProgramInfo,
        language_service: &dyn LanguageService,
    ) -> Vec<LoadSpec> {
        let mut load_specs = Vec::new();

        if let Some(language_id) = info.language_id.as_ref() {
            // Non-external language: got a language ID, good...
            if let Ok(language_description) = language_service.get_language_description(language_id)
            {
                match info.compiler_spec_id.as_ref() {
                    None => {
                        // No compiler spec ID, try to pick "default" (embedded magic string!!! BAD)
                        for csd in language_description.get_compatible_compiler_spec_descriptions() {
                            let pair = LanguageCompilerSpecPair::new(
                                language_description.get_language_id(),
                                csd.get_compiler_spec_id(),
                            );
                            load_specs.push(LoadSpec::with_language_compiler_spec(0, pair, false));
                        }
                    }
                    Some(compiler_spec_id) => {
                        // Test existence; a failure leaves `loadSpecs` empty, falling through to
                        // the catch-all below.
                        if language_description
                            .get_compiler_spec_description_by_id(compiler_spec_id)
                            .is_ok()
                        {
                            // Good, we know exactly what this is (make it preferred).
                            let pair = LanguageCompilerSpecPair::new(
                                language_id.clone(),
                                compiler_spec_id.clone(),
                            );
                            load_specs.push(LoadSpec::with_language_compiler_spec(0, pair, true));
                        }
                    }
                }
            }
        } else if info.processor_name.is_some() {
            // External language: no ID, look by processor/possibly endian.
            let size = Self::extract_size(info.address_model.as_deref());
            let endian = info.endian.as_deref().and_then(Endian::to_endian);
            let broad_query = ExternalLanguageCompilerSpecQuery::new(
                info.processor_name.clone(),
                info.normalized_external_tool_name().map(str::to_string),
                endian,
                size,
                info.compiler_spec_id.clone(),
            );
            let pairs = language_service.get_language_compiler_spec_pairs_external(&broad_query);

            if !pairs.is_empty() {
                let preferred = pairs.len() == 1;
                for pair in pairs {
                    load_specs.push(LoadSpec::with_language_compiler_spec(0, pair, preferred));
                }
            }
        }

        if load_specs.is_empty() {
            // Just put 'em all in (give endianness preference).
            let endian = info.endian.as_deref().and_then(Endian::to_endian);
            for language_description in language_service.get_language_descriptions(false) {
                if let Some(endian) = endian {
                    if language_description.get_endian() != endian {
                        continue;
                    }
                }
                for compiler_spec_description in
                    language_description.get_compatible_compiler_spec_descriptions()
                {
                    let pair = LanguageCompilerSpecPair::new(
                        language_description.get_language_id(),
                        compiler_spec_description.get_compiler_spec_id(),
                    );
                    load_specs.push(LoadSpec::with_language_compiler_spec(0, pair, false));
                }
            }
        }

        load_specs
    }

    /// `XmlLoader.getPreferredFileName(ByteProvider)`.
    pub fn get_preferred_file_name(&self, provider: &Rc<RefCell<dyn ByteProvider>>) -> String {
        let name = Self::provider_name(provider);
        if name.to_lowercase().ends_with(FILE_EXTENSION) {
            return name[..name.len() - FILE_EXTENSION.len()].to_string();
        }
        name
    }

    /// `XmlLoader.extractSize(String)`.
    fn extract_size(address_model: Option<&str>) -> Option<i32> {
        let address_model = address_model?;
        let captures = address_model_pattern().captures(address_model)?;
        captures.get(1)?.as_str().parse().ok()
    }

    /// `XmlLoader.getDefaultOptions(ByteProvider, LoadSpec, DomainObject, boolean, boolean)`.
    /// Java reads none of the first three parameters nor `mirrorFsLayout`, so they are dropped.
    pub fn get_default_options(&self, load_into_program: bool) -> Vec<Box<dyn LoaderOption>> {
        XmlProgramOptions::new().get_options(load_into_program)
    }

    /// `XmlLoader.validateOptions(ByteProvider, LoadSpec, List<Option>, Program)`, returning
    /// `None` where Java returns `null` (all options valid). Java reads neither the provider, the
    /// load spec, nor the program, so they are dropped.
    pub fn validate_options(&self, options: &[Box<dyn LoaderOption>]) -> Option<String> {
        match XmlProgramOptions::new().set_options(options) {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        }
    }

    /// `XmlLoader.loadProgram(ImporterSettings)`. `create_program` stands in for the inherited
    /// `createProgram(imageBase, settings)`; `Ok(None)` is Java's empty result list. See the
    /// module docs.
    #[allow(clippy::too_many_arguments)]
    pub fn load_program(
        &self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        load_spec: &LoadSpec,
        language_service: &dyn LanguageService,
        create_program: impl FnOnce(Option<Address>) -> Box<dyn Program>,
        options: &[Box<dyn LoaderOption>],
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn Program>>, XmlImportError> {
        let importer_language = load_spec.get_language(language_service)?;

        let result = Self::parse(provider);
        let (Some(info), Some(mgr)) = (result.last_info, result.last_xml_mgr) else {
            return Ok(None);
        };

        let image_base = info
            .image_base
            .as_deref()
            .and_then(|base| importer_language.get_address_factory().get_address(base));

        let mut prog = create_program(image_base);
        match self.do_import(&mgr, options, log, prog.as_mut(), monitor, false) {
            Ok(true) => {
                abstract_program_loader::create_default_memory_blocks(prog.as_mut(), log, monitor);
                Ok(Some(prog))
            }
            // Java's `finally` closes the (unreturned) `Loaded`; dropping `prog` does the same.
            Ok(false) => Err(LoadException::new("Failed to load").into()),
            Err(e) => Err(e),
        }
    }

    /// `XmlLoader.loadProgramInto(Program, ImporterSettings)`.
    pub fn load_program_into(
        &self,
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        options: &[Box<dyn LoaderOption>],
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), XmlImportError> {
        // Java hands `settings.provider().getFile()` straight to `new ProgramXmlMgr(File)`, which
        // NPEs on a provider with no backing file; this port reports that as an error instead.
        let file = provider.borrow().get_file().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "byte provider has no backing file")
        })?;
        self.do_import(&ProgramXmlMgr::from_file(file), options, log, program, monitor, true)?;
        Ok(())
    }

    /// `XmlLoader.doImportWork(ProgramXmlMgr, List<Option>, MessageLog, Program, TaskMonitor,
    /// boolean)`.
    fn do_import_work(
        mgr: &ProgramXmlMgr,
        options: &[Box<dyn LoaderOption>],
        log: &dyn MessageLog,
        prog: &dyn Program,
        monitor: &dyn TaskMonitor,
        is_add_to_program: bool,
    ) -> Result<bool, LoadException> {
        let mut mgr_log: Option<Box<dyn MessageLog>> = None;

        // Java wraps the whole body in one `catch (Exception e)`; both statements that can throw
        // are funneled into `failure` here.
        let mut xml_options = XmlProgramOptions::new();
        let failure: Option<Box<dyn std::error::Error>> = match xml_options.set_options(options) {
            Err(e) => Some(Box::new(e)),
            Ok(()) => {
                xml_options.set_add_to_program(is_add_to_program);
                match mgr.read(prog, monitor, &xml_options) {
                    Ok(read_log) => {
                        log.copy_from(read_log.as_ref());
                        mgr_log = Some(read_log);
                        None
                    }
                    Err(e) => Some(Box::new(e)),
                }
            }
        };

        let Some(error) = failure else {
            return Ok(true);
        };

        let mut message = "(empty)".to_string();
        if let Some(mgr_log) = mgr_log.as_deref() {
            let mgr_message = mgr_log.to_display_string();
            if !mgr_message.is_empty() {
                message = mgr_message;
            }
        }
        let log_message = log.to_display_string();
        if !log_message.is_empty() {
            message = log_message;
        }
        Msg::warn_with_error(
            "XmlLoader",
            &format!("XML import exception, log: {message}"),
            error.as_ref(),
        );
        Err(LoadException::new(error.to_string()))
    }

    /// `XmlLoader.doImport(ProgramXmlMgr, List<Option>, MessageLog, Program, TaskMonitor,
    /// boolean)`.
    fn do_import(
        &self,
        mgr: &ProgramXmlMgr,
        options: &[Box<dyn LoaderOption>],
        log: &dyn MessageLog,
        prog: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        is_add_to_program: bool,
    ) -> Result<bool, XmlImportError> {
        if !auto_analysis_manager::has_auto_analysis_manager(prog) {
            let tx_id = prog.start_transaction("XML Import");
            let result = Self::do_import_work(mgr, options, log, prog, monitor, is_add_to_program);
            prog.end_transaction(tx_id, true);
            return Ok(result?);
        }

        let analysis_mgr = auto_analysis_manager::get_analysis_manager(prog);
        let worker = XmlImportWorker {
            mgr,
            options,
            log,
            is_add_to_program,
            failure: Mutex::new(None),
        };
        // `&()` stands in for the `null` worker context Java passes.
        let scheduled = analysis_mgr.schedule_worker(&worker, &(), false, monitor)?;
        if let Some(failure) =
            worker.failure.into_inner().expect("XmlImportWorker failure slot poisoned")
        {
            return Err(failure.into());
        }
        Ok(scheduled)
    }

    /// `XmlLoader.parse(ByteProvider)`.
    fn parse(provider: &Rc<RefCell<dyn ByteProvider>>) -> ParseResult {
        let last_xml_mgr = ProgramXmlMgr::from_provider(provider);
        match last_xml_mgr.get_program_info() {
            Ok(Some(last_info)) => {
                ParseResult { last_xml_mgr: Some(last_xml_mgr), last_info: Some(last_info) }
            }
            // Java keeps the manager and a null info here; `findSupportedLoadSpecs`/`loadProgram`
            // both bail on the null info before touching the manager, so the two are equivalent.
            Ok(None) => ParseResult { last_xml_mgr: Some(last_xml_mgr), last_info: None },
            Err(e) => {
                // This can happen during the import process when this loader attempts to load a
                // non-xml file (there really should be 2 methods, a speculative version and a
                // version that expects no exception).
                Msg::trace_with_error(
                    "XmlLoader",
                    &format!("Unable to parse XML for {}", Self::provider_name(provider)),
                    &e,
                );
                ParseResult::empty()
            }
        }
    }

    /// Stands in for `provider.getName()`, which is not on the ported [`ByteProvider`] trait. See
    /// the module docs.
    fn provider_name(provider: &Rc<RefCell<dyn ByteProvider>>) -> String {
        let borrowed = provider.borrow();
        if let Some(name) = borrowed.get_fsrl().and_then(|f| f.name()) {
            return name;
        }
        if let Some(path) = borrowed.get_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                return name.to_string();
            }
        }
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::{LanguageCompilerSpecQuery, Processor};
    use std::path::PathBuf;

    /// A `ByteProvider` that knows nothing but its backing file, which is all
    /// [`XmlLoader::provider_name`] and [`XmlLoader::load_program_into`] read.
    struct FileOnlyProvider {
        file: Option<PathBuf>,
    }

    impl ByteProvider for FileOnlyProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(0)
        }

        fn is_valid_index(&mut self, _index: u64) -> bool {
            false
        }

        fn read_byte(&mut self, _index: u64) -> io::Result<u8> {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty"))
        }

        fn read_bytes(&mut self, _index: u64, _length: usize) -> io::Result<Vec<u8>> {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty"))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Ok(())
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn get_file(&self) -> Option<PathBuf> {
            self.file.clone()
        }
    }

    fn provider_named(name: &str) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::new(RefCell::new(FileOnlyProvider { file: Some(PathBuf::from(name)) }))
    }

    struct FakeCompilerSpecDescription {
        id: CompilerSpecID,
    }

    impl CompilerSpecDescription for FakeCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.id.clone()
        }

        fn get_compiler_spec_name(&self) -> String {
            self.id.get_id_as_string().to_string()
        }

        fn get_source(&self) -> String {
            "test".to_string()
        }
    }

    struct FakeLanguageDescription {
        id: LanguageID,
        endian: Endian,
        compiler_spec_ids: Vec<&'static str>,
    }

    impl LanguageDescription for FakeLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            self.id.clone()
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised")
        }

        fn get_endian(&self) -> Endian {
            self.endian
        }

        fn get_instruction_endian(&self) -> Endian {
            self.endian
        }

        fn get_size(&self) -> i32 {
            32
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
            self.id.get_id_as_string().to_string()
        }

        fn is_deprecated(&self) -> bool {
            false
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            self.compiler_spec_ids
                .iter()
                .map(|id| {
                    Box::new(FakeCompilerSpecDescription {
                        id: CompilerSpecID::new(Some(id)),
                    }) as Box<dyn CompilerSpecDescription>
                })
                .collect()
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            if self.compiler_spec_ids.contains(&compiler_spec_id.get_id_as_string()) {
                Ok(Box::new(FakeCompilerSpecDescription { id: compiler_spec_id.clone() }))
            } else {
                Err(CompilerSpecNotFoundException::new(&self.id, compiler_spec_id))
            }
        }

        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    /// A `LanguageService` over a fixed catalog, plus a canned answer for the external query.
    struct FakeLanguageService {
        descriptions: Vec<(LanguageID, Endian, Vec<&'static str>)>,
        external_pairs: Vec<LanguageCompilerSpecPair>,
    }

    impl FakeLanguageService {
        fn describe(&self, index: usize) -> Box<dyn LanguageDescription> {
            let (id, endian, compiler_spec_ids) = &self.descriptions[index];
            Box::new(FakeLanguageDescription {
                id: id.clone(),
                endian: *endian,
                compiler_spec_ids: compiler_spec_ids.clone(),
            })
        }
    }

    #[allow(deprecated)]
    impl LanguageService for FakeLanguageService {
        fn get_language(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised")
        }

        fn get_default_language(
            &self,
            _processor: &dyn Processor,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised")
        }

        fn get_language_description(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            match self.descriptions.iter().position(|(id, _, _)| id == language_id) {
                Some(index) => Ok(self.describe(index)),
                None => Err(LanguageNotFoundException(format!(
                    "language not found: {}",
                    language_id.get_id_as_string()
                ))),
            }
        }

        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn LanguageDescription>> {
            (0..self.descriptions.len()).map(|i| self.describe(i)).collect()
        }

        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: Option<Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }

        fn get_language_compiler_spec_pairs(
            &self,
            _query: &LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }

        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            self.external_pairs.clone()
        }

        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn Processor,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
    }

    fn language_id(id: &str) -> LanguageID {
        LanguageID::new(id).expect("non-empty language id")
    }

    fn catalog() -> FakeLanguageService {
        FakeLanguageService {
            descriptions: vec![
                (language_id("x86:LE:32:default"), Endian::Little, vec!["gcc", "windows"]),
                (language_id("PowerPC:BE:32:default"), Endian::Big, vec!["default"]),
            ],
            external_pairs: Vec::new(),
        }
    }

    fn spec_ids(specs: &[LoadSpec]) -> Vec<(String, String, bool)> {
        specs
            .iter()
            .map(|spec| {
                let pair = spec.language_compiler_spec.as_ref().expect("pair present");
                (
                    pair.get_language_id().get_id_as_string().to_string(),
                    pair.get_compiler_spec_id().get_id_as_string().to_string(),
                    spec.preferred,
                )
            })
            .collect()
    }

    #[test]
    fn constants_and_tier_match_java() {
        let loader = XmlLoader::new();
        assert_eq!(XML_SRC_NAME, "XML Input Format");
        assert_eq!(FILE_EXTENSION, ".xml");
        assert_eq!(loader.get_name(), "XML Input Format");
        assert_eq!(loader.get_tier(), LoaderTier::SpecializedTargetLoader);
        assert_eq!(loader.get_tier_priority(), 50);
        assert!(loader.supports_load_into_program());
    }

    #[test]
    fn extract_size_reads_the_bit_count() {
        // `ADDRESS_MODEL_PATTERN` is "(\d+)-bit", matched with find(), so it also hits mid-string.
        assert_eq!(XmlLoader::extract_size(Some("32-bit")), Some(32));
        assert_eq!(XmlLoader::extract_size(Some("a 64-bit model")), Some(64));
        // No hyphen -> no match, which is why an IDA-style "32 bit" yields null in Java too.
        assert_eq!(XmlLoader::extract_size(Some("32 bit")), None);
        assert_eq!(XmlLoader::extract_size(Some("")), None);
        assert_eq!(XmlLoader::extract_size(None), None);
    }

    #[test]
    fn preferred_file_name_strips_xml_extension_case_insensitively() {
        let loader = XmlLoader::new();
        assert_eq!(loader.get_preferred_file_name(&provider_named("hello.xml")), "hello");
        assert_eq!(loader.get_preferred_file_name(&provider_named("hello.XML")), "hello");
        // Not an .xml file: the name comes back unchanged.
        assert_eq!(loader.get_preferred_file_name(&provider_named("hello.exe")), "hello.exe");
        // The extension is only stripped from the end.
        assert_eq!(loader.get_preferred_file_name(&provider_named("a.xml.gz")), "a.xml.gz");
    }

    #[test]
    fn known_language_and_compiler_spec_yields_one_preferred_spec() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.language_id = Some(language_id("x86:LE:32:default"));
        info.set_compiler_spec_id(Some("gcc"));

        let specs = loader.load_specs_for_info(&info, &catalog());
        assert_eq!(spec_ids(&specs), vec![("x86:LE:32:default".into(), "gcc".into(), true)]);
    }

    #[test]
    fn known_language_without_compiler_spec_yields_every_compatible_spec_unpreferred() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.language_id = Some(language_id("x86:LE:32:default"));

        let specs = loader.load_specs_for_info(&info, &catalog());
        assert_eq!(
            spec_ids(&specs),
            vec![
                ("x86:LE:32:default".into(), "gcc".into(), false),
                ("x86:LE:32:default".into(), "windows".into(), false),
            ]
        );
    }

    #[test]
    fn unknown_compiler_spec_falls_back_to_every_language_of_that_endianness() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.language_id = Some(language_id("x86:LE:32:default"));
        info.set_compiler_spec_id(Some("nosuchspec"));
        info.endian = Some("big".to_string());

        // `getCompilerSpecDescriptionByID` throws, leaving loadSpecs empty, so the catch-all runs
        // and the big-endian filter keeps only PowerPC.
        let specs = loader.load_specs_for_info(&info, &catalog());
        assert_eq!(
            spec_ids(&specs),
            vec![("PowerPC:BE:32:default".into(), "default".into(), false)]
        );
    }

    #[test]
    fn unknown_language_id_falls_back_to_every_language_when_endian_is_unset() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.language_id = Some(language_id("nosuch:LE:32:default"));

        let specs = loader.load_specs_for_info(&info, &catalog());
        assert_eq!(
            spec_ids(&specs),
            vec![
                ("x86:LE:32:default".into(), "gcc".into(), false),
                ("x86:LE:32:default".into(), "windows".into(), false),
                ("PowerPC:BE:32:default".into(), "default".into(), false),
            ]
        );
    }

    #[test]
    fn external_processor_with_one_match_is_preferred() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.processor_name = Some("metapc".to_string());
        info.set_tool(Some("IDA-PRO 7.0".to_string()));

        let mut service = catalog();
        service.external_pairs = vec![LanguageCompilerSpecPair::new(
            language_id("x86:LE:32:default"),
            CompilerSpecID::new(Some("windows")),
        )];

        let specs = loader.load_specs_for_info(&info, &service);
        assert_eq!(spec_ids(&specs), vec![("x86:LE:32:default".into(), "windows".into(), true)]);
    }

    #[test]
    fn external_processor_with_several_matches_is_not_preferred() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.processor_name = Some("metapc".to_string());

        let mut service = catalog();
        service.external_pairs = vec![
            LanguageCompilerSpecPair::new(
                language_id("x86:LE:32:default"),
                CompilerSpecID::new(Some("gcc")),
            ),
            LanguageCompilerSpecPair::new(
                language_id("x86:LE:32:default"),
                CompilerSpecID::new(Some("windows")),
            ),
        ];

        let specs = loader.load_specs_for_info(&info, &service);
        assert_eq!(
            spec_ids(&specs),
            vec![
                ("x86:LE:32:default".into(), "gcc".into(), false),
                ("x86:LE:32:default".into(), "windows".into(), false),
            ]
        );
    }

    #[test]
    fn external_processor_with_no_matches_falls_back_to_the_whole_catalog() {
        let loader = XmlLoader::new();
        let mut info = ProgramInfo::new();
        info.processor_name = Some("nosuchprocessor".to_string());
        info.endian = Some("little".to_string());

        let specs = loader.load_specs_for_info(&info, &catalog());
        assert_eq!(
            spec_ids(&specs),
            vec![
                ("x86:LE:32:default".into(), "gcc".into(), false),
                ("x86:LE:32:default".into(), "windows".into(), false),
            ]
        );
    }
}
