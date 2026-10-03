//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageProvider`.
//!
//! Reads `.ldefs` language definition files into [`SleighLanguageDescription`]s and loads the
//! [`SleighLanguage`] each describes on first request, caching it (Java's `LanguageRec`).
//!
//! # Differences from Java
//! * **Discovery.** Java's singleton constructor scans the whole application
//!   (`Application.findFilesByExtensionInApplication(".ldefs")`). Here the caller chooses the
//!   `.ldefs` files: [`SleighLanguageProvider::from_application`] does the Java scan,
//!   [`SleighLanguageProvider::from_language_roots`] scans directories, and
//!   [`SleighLanguageProvider::from_ghidra_installation`] scans a Ghidra installation's
//!   `Ghidra/Processors/*/data/languages` directories. There is no process-wide singleton
//!   (`getSleighLanguageProvider()`); share one provider through an `Arc`.
//! * **Compiling.** The SLEIGH compiler is not ported, so languages load from the compiled `.sla`
//!   files as they are (see
//!   [`LocatedSleighLanguageFile`](super::sleigh_language_file::LocatedSleighLanguageFile)):
//!   Java's behaviour for a language directory it cannot lock.
//! * **Resource lookup.** `.pspec`/`.cspec`/`.slaspec`/`.idx` files must be found relative to their
//!   `.ldefs` file (Java falls back to an application-wide search by file name).
//! * **Errors.** Java's `Msg.showError` dialogs are logged through [`Msg`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::framework::application::Application;
use crate::generic::jar::resource_file::ResourceFile;
use crate::pcode::utils::sla_format::build_decoder;
use crate::program::model::address::DefaultAddressFactory;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_provider::LanguageProvider;
use crate::program::model::lang::processor::Processor;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::seam_stubs::LanguageNotFoundException;
use crate::util::msg::Msg;
use crate::util::system_utilities::SystemUtilities;
use crate::util::task::TaskMonitor;
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use crate::util::xml::xml_pull_parser_factory;

use super::sleigh_compiler_spec_description::SleighCompilerSpecDescription;
use super::sleigh_exception::SleighException;
use super::sleigh_language_description::SleighLanguageDescription;
use super::sleigh_language_file::{from_sla_filename, get_language_resource_file};
use super::sleigh_language_validator::SleighLanguageValidator;

const ORIGINATOR: &str = "SleighLanguageProvider";

/// System property that overrides [`language_lock_timeout`]'s duration, in milliseconds. Port of
/// `SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT_PROPNAME`.
pub const LANGUAGE_LOCK_TIMEOUT_PROPNAME: &str =
    "ghidra.app.plugin.processors.sleigh.SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT_MS";

const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 60;

/// Timeout used when trying to acquire the sla file lock (default 60 seconds, overridable via
/// [`LANGUAGE_LOCK_TIMEOUT_PROPNAME`]). Port of `SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT`,
/// turned into a function since Rust has no direct equivalent of a JVM-startup-time-evaluated
/// `static final` reading `System.getProperty`.
pub fn language_lock_timeout() -> Duration {
    if let Ok(override_ms) = std::env::var(LANGUAGE_LOCK_TIMEOUT_PROPNAME) {
        if let Ok(ms) = override_ms.parse::<u64>() {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS)
}

/// Environment variable naming a Ghidra installation directory (the one holding `Ghidra/`), for
/// [`SleighLanguageProvider::from_environment`].
pub const GHIDRA_DIST_ENV: &str = "GHIDRA_RS_GHIDRA_DIST";

/// The load state of one language. Port of the private `LanguageRec`.
struct LanguageState {
    /// `lang`: the loaded language, once loaded.
    lang: Option<Arc<SleighLanguage>>,
    /// `badSlaspecTS`: the `.slaspec` timestamp when loading last failed.
    bad_slaspec_ts: Option<u64>,
    /// `th`: why loading last failed.
    failure: Option<String>,
}

struct LanguageRec {
    description: Arc<SleighLanguageDescription>,
    state: Mutex<LanguageState>,
}

impl LanguageRec {
    fn new(description: SleighLanguageDescription) -> Self {
        Self {
            description: Arc::new(description),
            state: Mutex::new(LanguageState { lang: None, bad_slaspec_ts: None, failure: None }),
        }
    }

    /// A panic while the state was held cannot leave it half-updated in a way that matters (each
    /// field is replaced whole), so a poisoned lock is recovered.
    fn state(&self) -> MutexGuard<'_, LanguageState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slaspec_last_modified(&self) -> u64 {
        self.description
            .get_language_file()
            .map_or(0, |f| f.sla_spec_file().last_modified())
    }

    /// Port of `isRepeatFailedLangFile()`: loading failed before, and the `.slaspec` has not
    /// changed since (there are no lock-timeout failures to retry, as nothing is locked).
    fn is_repeat_failed_lang_file(&self, state: &mut LanguageState) -> bool {
        if let Some(bad_ts) = state.bad_slaspec_ts {
            if self.slaspec_last_modified() != bad_ts {
                state.bad_slaspec_ts = None;
            }
        }
        state.bad_slaspec_ts.is_some()
    }

    /// Port of `loadLanguage(TaskMonitor)`.
    fn load_language(&self, state: &mut LanguageState) -> Result<(), LanguageNotFoundException> {
        match load_sleigh_language(&self.description) {
            Ok(lang) => {
                state.lang = Some(lang);
                state.bad_slaspec_ts = None;
                state.failure = None;
                Ok(())
            }
            Err(e) => {
                state.bad_slaspec_ts = Some(self.slaspec_last_modified());
                state.failure = Some(e.to_string());
                Msg::error(
                    ORIGINATOR,
                    &format!(
                        "Failed to read language {}: {e}",
                        self.description.get_language_id()
                    ),
                );
                Err(not_found(&self.description.get_language_id(), &e.to_string()))
            }
        }
    }
}

fn not_found(language_id: &LanguageID, cause: &str) -> LanguageNotFoundException {
    LanguageNotFoundException(format!("Language not found for '{language_id}': {cause}"))
}

/// Java's `new SleighLanguage(description, monitor)`: the `.slaspec` must exist, then the `.sla`
/// is decoded (no recompilation, see the module docs) together with the `.pspec`.
fn load_sleigh_language(
    description: &Arc<SleighLanguageDescription>,
) -> Result<Arc<SleighLanguage>, SleighException> {
    let lang_file = description.get_language_file().ok_or_else(|| {
        SleighException::with_message(format!(
            "No .sla file for language {}",
            description.get_language_id()
        ))
    })?;
    if !lang_file.sla_spec_file().exists() {
        return Err(SleighException::with_message(format!(
            "Missing slaspec: {}",
            lang_file.sla_spec_file().absolute_path()
        )));
    }
    let sla_path = PathBuf::from(lang_file.sla_file().absolute_path());
    let decoder = build_decoder(&sla_path, Arc::new(DefaultAddressFactory::new(vec![])))
        .map_err(|e| SleighException::with_message(format!("Error decoding {}: {e}", sla_path.display())))?;
    let language = SleighLanguage::decode_with_description(&decoder, Arc::clone(description))
        .map_err(|e| SleighException::with_message(format!("Error decoding {}: {e}", sla_path.display())))?;
    Ok(language.into_shared())
}

/// Searches `.ldefs` files for Sleigh language definitions and provides their descriptions and
/// (loaded on demand, then cached) languages. See the module docs.
pub struct SleighLanguageProvider {
    /// `languages`: a `LinkedHashMap` in Java, preserving load order.
    languages: Vec<LanguageRec>,
    index: HashMap<LanguageID, usize>,
    /// `failureCount`, kept as the failure messages: `.ldefs` files that failed to validate or
    /// parse.
    failures: Vec<String>,
    /// Where a referenced file not next to its `.ldefs` is searched for by name (Java searches
    /// the whole application).
    search_roots: Vec<PathBuf>,
}

impl SleighLanguageProvider {
    fn empty() -> Self {
        Self { languages: Vec::new(), index: HashMap::new(), failures: Vec::new(), search_roots: Vec::new() }
    }

    /// The languages defined by one `.ldefs` file. Port of the (test-only in Java)
    /// `SleighLanguageProvider(ResourceFile ldefsFile)` constructor; a file that fails to
    /// validate or parse is reported through [`LanguageProvider::had_load_failure`].
    pub fn from_ldefs_file(ldefs_file: &ResourceFile) -> Self {
        Self::from_ldefs_files([ldefs_file.clone()])
    }

    /// The languages defined by every one of `ldefs_files`, in order.
    pub fn from_ldefs_files(ldefs_files: impl IntoIterator<Item = ResourceFile>) -> Self {
        Self::from_ldefs_files_searching(ldefs_files, Vec::new())
    }

    /// [`Self::from_ldefs_files`], resolving a referenced file that is not next to its `.ldefs`
    /// by searching `search_roots` for it by name (Java searches the whole application).
    pub fn from_ldefs_files_searching(
        ldefs_files: impl IntoIterator<Item = ResourceFile>,
        search_roots: Vec<PathBuf>,
    ) -> Self {
        let mut provider = Self::empty();
        provider.search_roots = search_roots;
        for file in ldefs_files {
            provider.create_languages(&file);
        }
        provider
    }

    /// The languages of every `.ldefs` file in the application's modules. Port of the singleton
    /// constructor's `createLanguages()`.
    pub fn from_application(application: &dyn Application) -> Self {
        Self::from_ldefs_files(application.find_files_by_extension_in_application(".ldefs"))
    }

    /// The languages of every `.ldefs` file found (recursively, in sorted path order) under each
    /// of `roots`; referenced files are also searched for by name under `roots`.
    pub fn from_language_roots(roots: &[PathBuf]) -> Self {
        let mut files = Vec::new();
        for root in roots {
            collect_ldefs(root, &mut files);
        }
        Self::from_ldefs_files_searching(files.into_iter().map(ResourceFile::new), roots.to_vec())
    }

    /// The languages of a Ghidra installation (the directory holding `Ghidra/`): every
    /// `Ghidra/Processors/*/data/languages` directory, in processor name order.
    pub fn from_ghidra_installation(install_dir: &Path) -> Self {
        Self::from_language_roots(&ghidra_installation_language_roots(install_dir))
    }

    /// [`Self::from_ghidra_installation`] for the installation named by [`GHIDRA_DIST_ENV`], or
    /// `None` when that variable is unset.
    pub fn from_environment() -> Option<Self> {
        let dir = std::env::var_os(GHIDRA_DIST_ENV)?;
        Some(Self::from_ghidra_installation(Path::new(&dir)))
    }

    /// Port of `createLanguages(ResourceFile)`: validates and reads one `.ldefs` file, counting
    /// a failure instead of propagating it.
    fn create_languages(&mut self, file: &ResourceFile) {
        let result = SleighLanguageValidator::validate_ldefs_file(file)
            .and_then(|()| self.create_language_descriptions(file));
        if let Err(e) = result {
            Msg::show_error(ORIGINATOR, &format!("Problem loading {}", file.name()), &e);
            self.failures.push(format!("{}: {e}", file.absolute_path()));
        }
    }

    /// Port of `createLanguageDescriptions(ResourceFile)`.
    fn create_language_descriptions(&mut self, spec_file: &ResourceFile) -> Result<(), SleighException> {
        let mut parser = xml_pull_parser_factory::create_from_resource_file(spec_file, None, false)
            .map_err(|e| SleighException::with_message(format!("Error parsing {}: {e}", spec_file.name())))?;
        let parent = spec_file.get_parent_file().ok_or_else(|| {
            SleighException::with_message(format!("{} has no parent directory", spec_file.absolute_path()))
        })?;
        let result = self.read(&mut parser, &parent, &spec_file.name());
        parser.dispose();
        result
    }

    /// Port of `read(XmlPullParser, ResourceFile, String)`.
    fn read<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        parent_directory: &ResourceFile,
        ldefs: &str,
    ) -> Result<(), SleighException> {
        let xml = |e: &dyn std::fmt::Display| SleighException::with_message(format!("{ldefs}: {e}"));
        let start = parser.start(&["language_definitions"]).map_err(|e| xml(&e))?;
        while let Some(language_enter) = parser.soft_start(&["language"]) {
            let attr = |name: &str| language_enter.get_attribute(name);
            let hidden = decode_boolean(&attr("hidden").unwrap_or_default());
            if hidden && !SystemUtilities::is_in_development_mode() {
                parser.discard_sub_tree_element(&language_enter);
                continue;
            }

            let id_text = attr("id").unwrap_or_default();
            let id = LanguageID::new(id_text.clone()).map_err(|e| xml(&format!("bad language id '{id_text}': {e}")))?;
            let processor_name = attr("processor").unwrap_or_default();
            let endian = parse_endian(&attr("endian").unwrap_or_default()).map_err(|e| xml(&e))?;
            let instruction_endian = match attr("instructionEndian") {
                Some(text) => parse_endian(&text).map_err(|e| xml(&e))?,
                None => endian,
            };
            let size = decode_int(attr("size").as_deref());
            let variant = attr("variant").unwrap_or_default();
            let (version, minor_version) = parse_version(&attr("version").unwrap_or_default())?;
            let deprecated = decode_boolean(&attr("deprecated").unwrap_or_default());
            let sla_filename = attr("slafile").unwrap_or_default();
            let manual_index_file = attr("manualindexfile");
            let pspec = attr("processorspec").unwrap_or_default();

            while parser.has_next() && parser.peek().get_name() != "description" {
                parser.discard_sub_tree();
            }
            let description_start = parser.start(&[]).map_err(|e| xml(&e))?;
            let description_end = parser.end_matching(&description_start).map_err(|e| xml(&e))?;
            let description_text = description_end.get_text().to_string();

            let mut truncated_space_map: Option<HashMap<String, i32>> = None;
            while let Some(element) = parser.soft_start(&["truncate_space"]) {
                let space_name = element.get_attribute("space").unwrap_or_default();
                let truncated_size = decode_int(element.get_attribute("size").as_deref());
                let map = truncated_space_map.get_or_insert_with(HashMap::new);
                if map.insert(space_name.clone(), truncated_size).is_some() {
                    return Err(SleighException::with_message(format!(
                        "truncated space '{space_name}' alread specified"
                    )));
                }
                parser.end_matching(&element).map_err(|e| xml(&e))?;
            }

            let mut compiler_specs: Vec<Arc<dyn CompilerSpecDescription>> = Vec::new();
            while let Some(compiler) = parser.soft_start(&["compiler"]) {
                let compiler_id = compiler.get_attribute("id");
                let compiler_spec_name = compiler.get_attribute("name").unwrap_or_default();
                let filename = compiler.get_attribute("spec").unwrap_or_default();
                let file = get_language_resource_file(parent_directory, &filename, ".cspec", &self.search_roots)
                    .map_err(|e| SleighException::with_message(e.message()))?;
                compiler_specs.push(Arc::new(SleighCompilerSpecDescription::new(
                    CompilerSpecID::new(compiler_id.as_deref()),
                    compiler_spec_name,
                    file,
                )));
                parser.end_matching(&compiler).map_err(|e| xml(&e))?;
            }

            let mut external_names: HashMap<String, Vec<String>> = HashMap::new();
            while let Some(external_name) = parser.soft_start(&["external_name"]) {
                let tool = external_name.get_attribute("tool").unwrap_or_default();
                let name = external_name.get_attribute("name").unwrap_or_default();
                if !tool.is_empty() && !name.is_empty() {
                    external_names.entry(tool).or_default().push(name);
                }
                parser.end_matching(&external_name).map_err(|e| xml(&e))?;
            }

            // Skip any deprecated-spec tags, or anything else for that matter.
            while parser.has_next() && !parser.peek().is_end() {
                parser.discard_sub_tree();
            }
            parser.end_matching(&language_enter).map_err(|e| xml(&e))?;

            let mut description = SleighLanguageDescription::new(
                id.clone(),
                description_text,
                Processor::find_or_possibly_create_processor(&processor_name),
                endian,
                instruction_endian,
                size,
                variant,
                version,
                minor_version,
                deprecated,
                truncated_space_map,
                compiler_specs,
                Some(external_names),
            );
            let defs_file = parent_directory.join(ldefs);
            let result = crate::program::model::lang::sleigh::manual::exists_and_is_case_dependent(&defs_file);
            if !result.is_ok() {
                return Err(SleighException::with_message(format!(
                    "ldefs file {} is not properly case dependent: {}",
                    defs_file.absolute_path(),
                    result.message()
                )));
            }
            description.set_defs_file(Some(defs_file.clone()));

            let spec_file = get_language_resource_file(parent_directory, &pspec, ".pspec", &self.search_roots)
                .map_err(|e| SleighException::with_message(e.message()))?;
            description.set_spec_file(Some(spec_file));

            let lang_file = from_sla_filename(parent_directory, &sla_filename, &self.search_roots)
                .map_err(|e| SleighException::with_message(e.message()))?;
            description.set_language_file(Some(Box::new(lang_file)));

            if let Some(manual_index_file) = manual_index_file {
                // An error with the manual shouldn't prevent the language from loading.
                match get_language_resource_file(parent_directory, &manual_index_file, ".idx", &self.search_roots) {
                    Ok(file) => description.set_manual_index_file(Some(file)),
                    Err(e) => Msg::error(ORIGINATOR, &e.message()),
                }
            }

            let rec = LanguageRec::new(description);
            match self.index.get(&id) {
                Some(&i) => {
                    Msg::show_error(
                        ORIGINATOR,
                        "Duplicate Sleigh Language ID",
                        &format!("Language {id} previously defined: {}", defs_file.absolute_path()),
                    );
                    // Java's `LinkedHashMap.put` replaces the value in place.
                    self.languages[i] = rec;
                }
                None => {
                    self.index.insert(id, self.languages.len());
                    self.languages.push(rec);
                }
            }
        }
        parser.end_matching(&start).map_err(|e| xml(&e))?;
        Ok(())
    }

    /// Why each `.ldefs` file that failed to load failed (empty when
    /// [`LanguageProvider::had_load_failure`] is `false`).
    pub fn load_failures(&self) -> &[String] {
        &self.failures
    }

    fn rec(&self, language_id: &LanguageID) -> Option<&LanguageRec> {
        self.index.get(language_id).map(|&i| &self.languages[i])
    }

    /// The language `language_id`, loading (and caching) it on first request; `None` if this
    /// provider does not define it. Port of the covariant `getLanguage(LanguageID, TaskMonitor)`,
    /// which returns `SleighLanguage`.
    ///
    /// # Errors
    /// [`LanguageNotFoundException`] if the language failed to load (now, or before with its
    /// `.slaspec` unchanged since).
    pub fn get_sleigh_language(
        &self,
        language_id: &LanguageID,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Option<Arc<SleighLanguage>>, LanguageNotFoundException> {
        let Some(rec) = self.rec(language_id) else {
            return Ok(None);
        };
        let mut state = rec.state();
        if state.lang.is_none() {
            if rec.is_repeat_failed_lang_file(&mut state) {
                let cause = state.failure.clone().unwrap_or_default();
                return Err(not_found(language_id, &cause));
            }
            rec.load_language(&mut state)?;
        }
        Ok(state.lang.clone())
    }

    /// The description of `language_id`, or `None`. Port of
    /// `getLanguageDescription(LanguageID)`.
    pub fn get_language_description(&self, language_id: &LanguageID) -> Option<Arc<SleighLanguageDescription>> {
        self.rec(language_id).map(|rec| Arc::clone(&rec.description))
    }

    /// Every description, in load order, shared. The typed form of
    /// [`LanguageProvider::get_language_descriptions`].
    pub fn get_sleigh_language_descriptions(&self) -> Vec<Arc<SleighLanguageDescription>> {
        self.languages.iter().map(|rec| Arc::clone(&rec.description)).collect()
    }

    /// Forgets the loaded language (and any load failure), so it is re-read on the next request.
    /// Port of the package-private `unloadLanguage(LanguageID)`.
    pub fn unload_language(&self, language_id: &LanguageID) {
        if let Some(rec) = self.rec(language_id) {
            let mut state = rec.state();
            state.lang = None;
            state.bad_slaspec_ts = None;
            state.failure = None;
        }
    }
}

impl LanguageProvider for SleighLanguageProvider {
    fn get_language_with_monitor(
        &self,
        language_id: &LanguageID,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException> {
        Ok(self
            .get_sleigh_language(language_id, monitor)?
            .map(|lang| Box::new(lang) as Box<dyn Language>))
    }

    fn get_language_descriptions(&self) -> Vec<Box<dyn LanguageDescription>> {
        self.languages
            .iter()
            .map(|rec| Box::new(Arc::clone(&rec.description)) as Box<dyn LanguageDescription>)
            .collect()
    }

    fn had_load_failure(&self) -> bool {
        !self.failures.is_empty()
    }

    fn is_language_loaded(&self, language_id: &LanguageID) -> bool {
        self.rec(language_id).is_some_and(|rec| rec.state().lang.is_some())
    }
}

/// Java's `Endian.valueOf(text.toUpperCase())`.
fn parse_endian(text: &str) -> Result<Endian, String> {
    match text.to_ascii_uppercase().as_str() {
        "BIG" => Ok(Endian::Big),
        "LITTLE" => Ok(Endian::Little),
        _ => Err(format!("invalid endian '{text}'")),
    }
}

/// The `version="<major>[.<minor>]"` attribute.
fn parse_version(text: &str) -> Result<(i32, i32), SleighException> {
    let bad = || {
        SleighException::with_message(format!(
            "Version tag must specify address <major>[.<minor>] version numbers (got '{text}')"
        ))
    };
    let mut pieces = text.split('.');
    // Java's `SpecXmlUtils.decodeInt`, whose `NumberFormatException` becomes the error above.
    let parse = |piece: &str| -> Result<i32, SleighException> {
        let (digits, radix) = if let Some(hex) = piece.strip_prefix("0x") {
            (hex, 16)
        } else if piece.len() > 1 && piece.starts_with('0') {
            (&piece[1..], 8)
        } else {
            (piece, 10)
        };
        i64::from_str_radix(digits, radix).map(|v| v as i32).map_err(|_| bad())
    };
    let major = parse(pieces.next().unwrap_or_default())?;
    let minor = match pieces.next() {
        Some(piece) => parse(piece)?,
        None => 0,
    };
    Ok((major, minor))
}

/// Every `*.ldefs` file under `dir`, recursively, in sorted path order.
fn collect_ldefs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_ldefs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "ldefs") {
            out.push(path);
        }
    }
}

/// `<install_dir>/Ghidra/Processors/*/data/languages`, in processor name order.
pub fn ghidra_installation_language_roots(install_dir: &Path) -> Vec<PathBuf> {
    let processors = install_dir.join("Ghidra").join("Processors");
    let Ok(entries) = std::fs::read_dir(&processors) else {
        return Vec::new();
    };
    let mut roots: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path().join("data").join("languages")))
        .filter(|p| p.is_dir())
        .collect();
    roots.sort();
    roots
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    /// The local Ghidra 12.1.2 distribution (`$GHIDRA_RS_GHIDRA_DIST`, else the gitignored
    /// `tools/ghidra-dist/ghidra_12.1.2_PUBLIC`), if present.
    pub(crate) fn ghidra_dist() -> Option<PathBuf> {
        let dir = std::env::var_os(GHIDRA_DIST_ENV).map(PathBuf::from).unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/ghidra-dist/ghidra_12.1.2_PUBLIC")
        });
        dir.join("Ghidra/Processors").is_dir().then_some(dir)
    }

    const LDEFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="toy"
            endian="big"
            size="32"
            variant="default"
            version="1.3"
            slafile="toy.sla"
            processorspec="toy.pspec"
            manualindexfile="toy.idx"
            id="toy:BE:32:default">
    <description>Toy processor
    32-bit big endian</description>
    <compiler name="default" spec="toy.cspec" id="default"/>
    <compiler name="gcc" spec="toy-gcc.cspec" id="gcc"/>
    <external_name tool="gnu" name="toy"/>
    <external_name tool="gnu" name="toy32"/>
    <external_name tool="IDA-PRO" name=""/>
  </language>
  <language processor="toy"
            endian="little"
            instructionEndian="big"
            size="64"
            variant="wide"
            version="2"
            slafile="toy64"
            processorspec="toy.pspec"
            deprecated="true"
            id="toy:LE:64:wide">
    <description>Toy wide</description>
    <truncate_space space="ram" size="4"/>
    <compiler name="default" spec="toy.cspec" id="default"/>
  </language>
  <language processor="toy"
            endian="big"
            size="16"
            variant="secret"
            version="1"
            slafile="toy.sla"
            processorspec="toy.pspec"
            hidden="true"
            id="toy:BE:16:secret">
    <description>Hidden</description>
    <compiler name="default" spec="toy.cspec" id="default"/>
  </language>
</language_definitions>
"#;

    /// A language directory holding [`LDEFS`] and the (empty) files it names.
    fn toy_dir(ldefs: &str) -> (tempfile::TempDir, ResourceFile) {
        let dir = tempfile::tempdir().unwrap();
        for f in ["toy.slaspec", "toy.sla", "toy64.slaspec", "toy.pspec", "toy.cspec", "toy-gcc.cspec", "toy.idx"] {
            std::fs::write(dir.path().join(f), b"").unwrap();
        }
        let path = dir.path().join("toy.ldefs");
        std::fs::write(&path, ldefs).unwrap();
        (dir, ResourceFile::new(path))
    }

    fn id(s: &str) -> LanguageID {
        LanguageID::new(s).unwrap()
    }

    #[test]
    fn reads_every_language_attribute_and_child() {
        let (dir, ldefs) = toy_dir(LDEFS);
        let provider = SleighLanguageProvider::from_ldefs_file(&ldefs);
        assert!(!provider.had_load_failure());

        let d = provider.get_language_description(&id("toy:BE:32:default")).unwrap();
        assert_eq!(d.get_processor().name(), "toy");
        assert_eq!(d.get_endian(), Endian::Big);
        assert_eq!(d.get_instruction_endian(), Endian::Big);
        assert_eq!(d.get_size(), 32);
        assert_eq!(d.get_variant(), "default");
        assert_eq!((d.get_version(), d.get_minor_version()), (1, 3));
        assert!(!d.is_deprecated());
        assert_eq!(d.get_description(), "Toy processor\n    32-bit big endian");
        let specs: Vec<_> = d
            .get_compatible_compiler_spec_descriptions()
            .iter()
            .map(|s| (s.get_compiler_spec_id().to_string(), s.get_compiler_spec_name()))
            .collect();
        assert_eq!(specs, vec![("default".into(), "default".into()), ("gcc".into(), "gcc".into())]);
        let gcc = d.get_compiler_spec_description_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        let gcc_file = gcc.as_sleigh_compiler_spec_description().unwrap().get_file().name();
        assert_eq!(gcc_file, "toy-gcc.cspec");
        assert_eq!(d.get_external_names("gnu"), Some(vec!["toy".to_string(), "toy32".to_string()]));
        // Empty external names are dropped.
        assert_eq!(d.get_external_names("IDA-PRO"), None);
        assert!(d.get_truncated_space_names().is_empty());
        assert_eq!(d.get_defs_file().unwrap().name(), "toy.ldefs");
        assert_eq!(d.get_spec_file().unwrap().name(), "toy.pspec");
        assert_eq!(d.get_manual_index_file().unwrap().name(), "toy.idx");
        let lang_file = d.get_language_file().unwrap();
        assert_eq!(lang_file.sla_file().name(), "toy.sla");
        assert_eq!(lang_file.sla_spec_file().name(), "toy.slaspec");
        drop(dir);
    }

    #[test]
    fn reads_instruction_endian_truncations_deprecation_and_sla_without_extension() {
        let (_dir, ldefs) = toy_dir(LDEFS);
        let provider = SleighLanguageProvider::from_ldefs_file(&ldefs);
        let d = provider.get_language_description(&id("toy:LE:64:wide")).unwrap();
        assert_eq!(d.get_endian(), Endian::Little);
        assert_eq!(d.get_instruction_endian(), Endian::Big);
        assert_eq!((d.get_version(), d.get_minor_version()), (2, 0));
        assert!(d.is_deprecated());
        assert_eq!(d.get_truncated_space_size("ram"), Some(4));
        assert!(d.get_manual_index_file().is_none());
        // `slafile="toy64"`: the .sla is next to toy64.slaspec even though it does not exist.
        assert_eq!(d.get_language_file().unwrap().sla_file().name(), "toy64.sla");
        assert_eq!(d.get_compatible_compiler_spec_descriptions().len(), 1);
    }

    #[test]
    fn descriptions_keep_ldefs_order_and_hidden_languages_follow_development_mode() {
        let (_dir, ldefs) = toy_dir(LDEFS);
        let provider = SleighLanguageProvider::from_ldefs_file(&ldefs);
        let ids: Vec<String> = provider
            .get_language_descriptions()
            .iter()
            .map(|d| d.get_language_id().get_id_as_string().to_string())
            .collect();
        let mut expected = vec!["toy:BE:32:default".to_string(), "toy:LE:64:wide".to_string()];
        if SystemUtilities::is_in_development_mode() {
            expected.push("toy:BE:16:secret".to_string());
        }
        assert_eq!(ids, expected);
        assert!(provider.get_language_description(&id("x86:LE:32:default")).is_none());
    }

    #[test]
    fn missing_referenced_file_fails_the_ldefs_file() {
        let (dir, ldefs) = toy_dir(LDEFS);
        std::fs::remove_file(dir.path().join("toy-gcc.cspec")).unwrap();
        let provider = SleighLanguageProvider::from_ldefs_file(&ldefs);
        assert!(provider.had_load_failure());
        assert!(provider.get_language_description(&id("toy:BE:32:default")).is_none());
    }

    #[test]
    fn invalid_ldefs_is_a_load_failure_not_a_panic() {
        let (_dir, ldefs) = toy_dir("<language_definitions><language/></language_definitions>");
        let provider = SleighLanguageProvider::from_ldefs_file(&ldefs);
        assert!(provider.had_load_failure());
        assert!(provider.get_language_descriptions().is_empty());
    }

    #[test]
    fn duplicate_truncated_space_is_rejected() {
        let ldefs = LDEFS.replace(
            r#"<truncate_space space="ram" size="4"/>"#,
            r#"<truncate_space space="ram" size="4"/><truncate_space space="ram" size="2"/>"#,
        );
        let (_dir, ldefs) = toy_dir(&ldefs);
        assert!(SleighLanguageProvider::from_ldefs_file(&ldefs).had_load_failure());
    }

    #[test]
    fn unknown_language_is_none_and_unloadable_language_is_not_found_until_it_changes() {
        let (_dir, ldefs) = toy_dir(LDEFS);
        let provider = SleighLanguageProvider::from_ldefs_file(&ldefs);
        assert!(provider.get_sleigh_language(&id("x86:LE:32:default"), &DummyMonitor).unwrap().is_none());
        // toy.sla is empty: not a valid .sla.
        let toy = id("toy:BE:32:default");
        let first = provider.get_sleigh_language(&toy, &DummyMonitor).err().unwrap();
        assert!(first.0.contains("toy:BE:32:default"), "{}", first.0);
        assert!(!provider.is_language_loaded(&toy));
        // The failure is remembered (the .slaspec has not changed).
        let again = provider.get_sleigh_language(&toy, &DummyMonitor).err().unwrap();
        assert_eq!(again.0, first.0);
        provider.unload_language(&toy);
        assert!(provider.get_language(&toy).is_err());
    }

    #[test]
    fn parse_version_accepts_major_and_optional_minor() {
        assert_eq!(parse_version("1").unwrap(), (1, 0));
        assert_eq!(parse_version("3.12").unwrap(), (3, 12));
        assert!(parse_version("").is_err());
        assert!(parse_version("one").is_err());
        assert!(parse_version("e").is_err());
        assert!(parse_version("1.").is_err());
    }

    #[test]
    fn language_lock_timeout_defaults_to_sixty_seconds() {
        // Does not exercise the override path: that would mutate process-global env state shared
        // with other tests in this binary.
        std::env::remove_var(LANGUAGE_LOCK_TIMEOUT_PROPNAME);
        assert_eq!(language_lock_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn ghidra_distribution_languages_are_described_and_x86_64_loads_once() {
        let Some(dist) = ghidra_dist() else {
            return;
        };
        let provider = SleighLanguageProvider::from_ghidra_installation(&dist);
        assert!(!provider.had_load_failure(), "{:#?}", provider.load_failures());
        let x86_64 = id("x86:LE:64:default");
        let d = provider.get_language_description(&x86_64).unwrap();
        assert_eq!(d.get_size(), 64);
        assert!(d.get_compiler_spec_description_by_id(&CompilerSpecID::new(Some("gcc"))).is_ok());
        assert!(provider.get_language_description(&id("AARCH64:LE:64:v8A")).is_some());

        assert!(!provider.is_language_loaded(&x86_64));
        let lang = provider.get_sleigh_language(&x86_64, &DummyMonitor).unwrap().unwrap();
        assert!(provider.is_language_loaded(&x86_64));
        assert_eq!(lang.get_language_id(), x86_64);
        assert!(lang.get_register_by_name("RAX").is_some());
        assert_eq!(lang.get_program_counter().unwrap().name(), "RIP");
        let again = provider.get_sleigh_language(&x86_64, &DummyMonitor).unwrap().unwrap();
        assert!(Arc::ptr_eq(&lang, &again));
        // The first compiler spec in x86.ldefs is the default; the .cspec loads.
        assert_eq!(
            lang.get_default_compiler_spec().get_compiler_spec_id(),
            CompilerSpecID::new(Some("windows"))
        );
        let gcc = lang.get_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        assert!(gcc.get_default_calling_convention().is_some());
    }
}
