//! Port of `ghidra.app.util.opinion.LibraryLookupTable`.
//!
//! Locates (and creates) the `.exports`/`.ord` symbol files Ghidra keeps for Windows libraries,
//! under either the user's settings directory or the `Base` module's data directory, and caches
//! the parsed [`LibrarySymbolTable`]s keyed by library name and architecture size.
//!
//! Java's version is a class of nothing but `static` members (five static fields, twenty-one
//! static methods, no instance state), so -- as with
//! [`query_opinion_service`](crate::app::util::opinion::query_opinion_service) and
//! [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) in this
//! same package -- it is ported as a plain module of consts and free functions rather than a
//! zero-instance struct.
//!
//! # Departures from the Java class
//!
//! * `Application.getUserSettingsDirectory()` and `Application.getModuleDataSubDirectory(String)`
//!   resolve a process-wide singleton that was dropped when `Application` was ported, so every
//!   function that needs them takes an explicit `&dyn Application` parameter, the same
//!   substitution `query_opinion_service` and `elf_loader` already make. The single-argument
//!   `getModuleDataSubDirectory` additionally resolves *the calling class's* module, which for
//!   `LibraryLookupTable` is `Ghidra/Features/Base`; that becomes an explicit
//!   [`BASE_MODULE_NAME`] argument to the ported two-argument form.
//! * Java's `synchronized static` methods all share the class monitor. Here the two pieces of
//!   mutable static state get one `Mutex` each ([`CACHE_MAP`] and [`FILES_TO_DELETE`]), each held
//!   only for the statement that touches it -- the Java monitor is reentrant and these functions
//!   call each other, so a single module-wide lock would deadlock.
//! * The static `cacheMap` field is a `FixedSizeHashMap`, which this crate ported as a trait with
//!   no concrete implementation yet, so [`SymbolTableCache`] below is a private implementation of
//!   that trait. Its values are `Arc<LibrarySymbolTable>` because Java's cache hands out the same
//!   instance to every caller.
//! * `createFile` caches the new symbol table *before* setting its version and folding in the
//!   `.ord` file; here the cache insert moves after those two mutations, so that the `Arc` handed
//!   out is never observed half-initialized. Nothing between the two points reads the cache, so
//!   the only visible difference is on the `checkCancelled` path, where Java would leave a
//!   version-less table cached.
//! * `LibrarySymbolTable`, `PeLoader` and `ResourceDataDirectory` are not ported yet;
//!   `LibrarySymbolTable` in particular forms a dependency cycle back into this module (its
//!   `getCacheKey(String, int)` calls [`strip_possible_extension_from_filename`]), which is why
//!   it is stubbed rather than ported alongside. See [`crate::app::seam_stubs`],
//!   [`crate::format::seam_stubs`] and `STUBS.tsv`.
//! * `ResourceFile` was ported without `listFiles()` or `delete()`, so [`list_files`] and
//!   [`delete_file`] below reach through its `get_file` to `std::fs` rather than growing the
//!   already-ported type.
//! * Java's `getNewExtensionedFile`/`getNewSystemExtensionedFile` pass a possibly-`null` base
//!   directory straight into `new ResourceFile(baseDir, name)`, which NPEs. The ported forms
//!   return `Option<ResourceFile>` and [`create_file_in`] turns `None` into an `io::Error`.
//! * `getFiles` dereferences the `.ord` file's timestamp without a null check (NPE whenever a
//!   library has an `.exports` file but no `.ord` file). Here a missing `.ord` file simply means
//!   "no newer definition to rebuild from", which is what the comparison is asking.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::app::seam_stubs::{LibrarySymbolTable, MessageLog, PeLoader};
use crate::format::seam_stubs::resource_data_directory;
use crate::framework::application::Application;
use crate::framework::options::Options;
use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::util::datastruct::fixed_size_hash_map::FixedSizeHashMap;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// `LibraryLookupTable.EXPORTS_FILE_EXTENSION`.
pub const EXPORTS_FILE_EXTENSION: &str = ".exports";

/// `LibraryLookupTable.ORDINAL_MAPPING_FILE_EXTENSION`.
pub const ORDINAL_MAPPING_FILE_EXTENSION: &str = ".ord";

/// `LibraryLookupTable.MAX_CACHE_ITEMS`.
const MAX_CACHE_ITEMS: usize = 10;

/// Originator passed to [`Msg`], standing in for Java's `LibraryLookupTable.class`.
const ORIGINATOR: &str = "LibraryLookupTable";

/// The module whose `data/symbols` directory holds the shipped `.exports` files. Java's
/// `Application.getModuleDataSubDirectory(String)` derives this from the calling class; see the
/// module docs.
pub const BASE_MODULE_NAME: &str = "Base";

/// The static `cacheMap` field: a `FixedSizeHashMap<String, LibrarySymbolTable>` of at most
/// [`MAX_CACHE_ITEMS`] entries, keyed by `LibrarySymbolTable.getCacheKey()`.
static CACHE_MAP: OnceLock<Mutex<SymbolTableCache>> = OnceLock::new();

/// The static `filesToDeleteList` field, drained by [`cleanup`].
static FILES_TO_DELETE: OnceLock<Mutex<Vec<ResourceFile>>> = OnceLock::new();

/// The concrete LRU map backing [`CACHE_MAP`]. Java gets this from `FixedSizeHashMap`, which this
/// crate ported as a trait (to cut a dependency cycle) with no concrete implementation, so the
/// eviction bookkeeping lives here.
struct SymbolTableCache {
    max_size: usize,
    /// Keys least-recently-used first.
    order: Vec<String>,
    store: HashMap<String, Arc<LibrarySymbolTable>>,
}

impl SymbolTableCache {
    fn new(max_size: usize) -> Self {
        SymbolTableCache { max_size, order: Vec::new(), store: HashMap::new() }
    }

    /// Moves `key` to the most-recently-used end of [`Self::order`].
    fn touch(&mut self, key: &str) {
        self.order.retain(|k| k != key);
        self.order.push(key.to_string());
    }
}

impl FixedSizeHashMap<String, Arc<LibrarySymbolTable>> for SymbolTableCache {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn len(&self) -> usize {
        self.store.len()
    }

    fn get(&mut self, key: &String) -> Option<&Arc<LibrarySymbolTable>> {
        if self.store.contains_key(key) {
            self.touch(key);
        }
        self.store.get(key)
    }

    fn contains_key(&self, key: &String) -> bool {
        self.store.contains_key(key)
    }

    fn put(
        &mut self,
        key: String,
        value: Arc<LibrarySymbolTable>,
    ) -> Option<Arc<LibrarySymbolTable>> {
        self.touch(&key);
        let previous = self.store.insert(key, value);
        if self.store.len() > self.max_size {
            let oldest = self.order.remove(0);
            self.store.remove(&oldest);
        }
        previous
    }

    fn remove(&mut self, key: &String) -> Option<Arc<LibrarySymbolTable>> {
        self.order.retain(|k| k != key);
        self.store.remove(key)
    }

    fn clear(&mut self) {
        self.order.clear();
        self.store.clear();
    }
}

fn cache_map() -> MutexGuard<'static, SymbolTableCache> {
    CACHE_MAP
        .get_or_init(|| Mutex::new(SymbolTableCache::new(MAX_CACHE_ITEMS)))
        .lock()
        .expect("LibraryLookupTable symbol-table cache mutex poisoned")
}

fn files_to_delete() -> MutexGuard<'static, Vec<ResourceFile>> {
    FILES_TO_DELETE
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("LibraryLookupTable pending-deletion list mutex poisoned")
}

/// `LibraryLookupTable.getMemorySizePath(int)`.
fn get_memory_size_path(size: i32) -> &'static str {
    match size {
        64 => "win64",
        32 => "win32",
        16 => "win16",
        _ => "win_unsupported",
    }
}

/// Stands in for `ResourceFile.listFiles()`, which this crate's `ResourceFile` does not have.
/// `None` mirrors the `null` Java returns for a non-directory or unreadable directory.
fn list_files(dir: &ResourceFile) -> Option<Vec<ResourceFile>> {
    let path = dir.get_file(false)?;
    let entries = fs::read_dir(path).ok()?;
    Some(entries.flatten().map(|entry| ResourceFile::new(entry.path())).collect())
}

/// Stands in for `ResourceFile.delete()`, which this crate's `ResourceFile` does not have.
fn delete_file(file: &ResourceFile) -> bool {
    file.get_file(false).is_some_and(|path| fs::remove_file(path).is_ok())
}

/// `new File(path).getName()`. Both separators are accepted because the paths this is applied to
/// are recorded executable paths, which may well be Windows-style on a non-Windows host (the same
/// allowance [`crate::app::util::opinion::loader`] makes for import paths).
pub(crate) fn file_name_of(path: &str) -> String {
    match path.rfind(['/', '\\']) {
        Some(index) => path[index + 1..].to_string(),
        None => path.to_string(),
    }
}

/// `LibraryLookupTable.createUserResourceDir(int)`: `<user settings>/symbols/win<size>`, creating
/// both levels if needed. `None` mirrors Java's `null` return when a directory cannot be created
/// (and additionally covers an `Application` with no user settings directory at all, which Java
/// would have NPEd on).
fn create_user_resource_dir(app: &dyn Application, size: i32) -> Option<ResourceFile> {
    let symbols = app.user_settings_directory()?.join("symbols");
    if !symbols.is_dir() && fs::create_dir(&symbols).is_err() {
        Msg::error(ORIGINATOR, &"couldn't create symbols directory in user's home directory");
        return None;
    }

    let win = symbols.join(get_memory_size_path(size));
    if !win.is_dir() && fs::create_dir(&win).is_err() {
        Msg::error(ORIGINATOR, &"couldn't create symbols/win directory in user's home directory");
        return None;
    }

    Some(ResourceFile::new(win))
}

/// `LibraryLookupTable.getSystemResourceDir(int)`: the `Base` module's `data/symbols/win<size>`.
fn get_system_resource_dir(app: &dyn Application, size: i32) -> Option<ResourceFile> {
    let relative_path = format!("symbols/{}", get_memory_size_path(size));
    match app.get_module_data_sub_directory(BASE_MODULE_NAME, &relative_path) {
        Ok(dir) => Some(dir),
        Err(e) => {
            Msg::warn(
                ORIGINATOR,
                &format!("Couldn't find symbols/win directory in module data directory.{e}"),
            );
            None
        }
    }
}

/// `LibraryLookupTable.getFiles(String, int, Set, Set)`: partitions `dllname` and everything it
/// forwards to into the libraries that do and do not have usable symbol files.
pub fn get_files(
    app: &dyn Application,
    dllname: &str,
    size: i32,
    unresolved_libs: &mut HashSet<String>,
    resolved_libs: &mut HashSet<String>,
) {
    if unresolved_libs.contains(dllname) || resolved_libs.contains(dllname) {
        return;
    }

    let Some(file) = get_existing_exports_file(app, dllname, size) else {
        unresolved_libs.insert(dllname.to_string());
        return;
    };

    // Check if it should be re-created. Java reads the `.ord` file's timestamp unconditionally;
    // see the module docs for why a missing one is treated as "nothing newer" here.
    let last_export = file.last_modified();
    if let Some(def_file) = get_existing_ordinal_file(app, dllname, size) {
        if def_file.last_modified() > last_export {
            unresolved_libs.insert(dllname.to_string());
        }
    }

    let Some(table) = get_symbol_table(app, dllname, size) else {
        unresolved_libs.insert(dllname.to_string());
        return;
    };
    resolved_libs.insert(dllname.to_string());

    for forward in table.get_forwards() {
        get_files(app, forward, size, unresolved_libs, resolved_libs);
    }
}

/// `LibraryLookupTable.cleanup()`: deletes every file queued by [`create_file_in`] as not worth
/// keeping.
pub fn cleanup() {
    let mut files = files_to_delete();
    for file in files.iter() {
        delete_file(file);
    }
    files.clear();
}

/// Combines the checked exceptions declared on `LibraryLookupTable.createFile`: `IOException` and
/// `CancelledException`.
#[derive(Debug, thiserror::Error)]
pub enum CreateFileError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// `LibraryLookupTable.createFile(Program, boolean, TaskMonitor)`: writes `program`'s exports
/// into the user's symbol directory.
pub fn create_file(
    app: &dyn Application,
    program: &dyn Program,
    overwrite: bool,
    monitor: &dyn TaskMonitor,
) -> Result<ResourceFile, CreateFileError> {
    create_file_in(app, program, overwrite, false, monitor)
}

/// `LibraryLookupTable.createFile(Program, boolean, boolean, TaskMonitor)`. With `in_system` the
/// exports file is written into the `Base` module's data directory (named after the program's
/// executable) rather than the user's settings directory (named after the program).
///
/// # Panics
/// Panics if `program` has no language, mirroring Java's uncaught `NullPointerException` out of
/// `program.getLanguage().getLanguageDescription()`.
pub fn create_file_in(
    app: &dyn Application,
    program: &dyn Program,
    overwrite: bool,
    in_system: bool,
    monitor: &dyn TaskMonitor,
) -> Result<ResourceFile, CreateFileError> {
    let language: Arc<dyn Language> =
        program.get_language().expect("program must have a language to create a symbol file");
    let size = language.get_language_description().get_size();

    let file = if in_system {
        get_new_system_exports_file(app, &file_name_of(&program.get_executable_path()), size)
    } else {
        get_new_exports_file(app, &Program::get_name(program), size)
    };
    let file = file.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no symbols/{} directory available to write to", get_memory_size_path(size)),
        )
    })?;

    if file.exists() && !overwrite {
        return Ok(file);
    }

    monitor.set_message(&format!("[{}]: creating symbol file...", Program::get_name(program)));
    let mut sym_tab = LibrarySymbolTable::from_program(program, monitor)?;

    let props = program.get_options(PROGRAM_INFO);
    let format = program.get_executable_format();
    let company =
        props.get_string(&resource_data_directory::get_pe_resource_property("CompanyName"), "");
    let version =
        props.get_string(&resource_data_directory::get_pe_resource_property("FileVersion"), "");

    let save = format != PeLoader::PE_NAME || company.to_lowercase().contains("microsoft");
    if save {
        sym_tab.set_version(&version);
    } else {
        files_to_delete().push(file.clone());
    }

    // Apply any name definition files.
    if let Some(existing_def_file) =
        get_existing_ordinal_file(app, &Program::get_name(program), size)
    {
        sym_tab.apply_ordinal_file(&existing_def_file, false);
    }

    // Java caches the table before the two mutations above; see the module docs.
    let sym_tab = Arc::new(sym_tab);
    cache_map().put(sym_tab.get_cache_key(), Arc::clone(&sym_tab));

    monitor.check_cancelled()?;

    match file.get_file(true) {
        None => Msg::warn(ORIGINATOR, &"Can't write to installation directory"),
        Some(output) => {
            sym_tab.write(&output, Path::new(&program.get_executable_path()), &version)?
        }
    }

    Ok(file)
}

/// `LibraryLookupTable.getSymbolTable(String, int)`: the symbol table associated with `dll_name`,
/// of the given architecture size (e.g. 32 or 64).
///
/// See [`get_symbol_table_with_log`] for where the table comes from.
pub fn get_symbol_table(
    app: &dyn Application,
    dll_name: &str,
    size: i32,
) -> Option<Arc<LibrarySymbolTable>> {
    get_symbol_table_with_log(app, dll_name, size, None)
}

/// `LibraryLookupTable.getSymbolTable(String, int, MessageLog)`: the symbol table associated with
/// `dll_name`.
///
/// If one was not previously generated for `dll_name` it is constructed from a `.exports` file
/// found within the `symbols` resource area; failing that, from a similarly named `.ord` file.
/// The `.exports` file is a Ghidra XML file, while the `.ord` file is produced by the Visual
/// Studio `DUMPBIN /EXPORTS` command. The default resource area is
/// `Ghidra/Features/Base/data/symbols/[win32|win64]`; alternatively a user-specific resource
/// directory at `<user settings>/symbols/[win32|win64]` may be used.
///
/// [`CACHE_MAP`] is a static cache which always returns the same instance for a given DLL name.
pub fn get_symbol_table_with_log(
    app: &dyn Application,
    dll_name: &str,
    size: i32,
    log: Option<&dyn MessageLog>,
) -> Option<Arc<LibrarySymbolTable>> {
    let cache_key = LibrarySymbolTable::cache_key_for(dll_name, size);
    if let Some(sym_tab) = cache_map().get(&cache_key).cloned() {
        if let Some(log) = log {
            log.append_msg(&format!("Applying cached symbols from {dll_name}"));
        }
        return Some(sym_tab);
    }

    // Look in resources of pre-parsed .dll's.
    let file = get_existing_exports_file(app, dll_name, size);
    if let Some(file) = &file {
        if let Some(log) = log {
            log.append_msg(&format!("Applying {}", file.absolute_path()));
        }
        match LibrarySymbolTable::from_exports_file(file, size) {
            Ok(sym_tab) => {
                let sym_tab = Arc::new(sym_tab);
                cache_map().put(sym_tab.get_cache_key(), Arc::clone(&sym_tab));
                return Some(sym_tab);
            }
            Err(e) => Msg::error(
                ORIGINATOR,
                &format!("Error reading {}: {e}", file.absolute_path()),
            ),
        }
    }

    if let Some(existing_ordinal_file) = get_existing_ordinal_file(app, dll_name, size) {
        if let Some(log) = log {
            // Java logs the *exports* file here, which is `null` unless reading it just failed.
            // Reproduced rather than corrected so the log reads the same.
            let applied = file.map_or_else(|| "null".to_string(), |f| f.absolute_path());
            log.append_msg(&format!("Applying {applied}"));
        }
        let mut sym_tab = LibrarySymbolTable::new(dll_name, size);
        sym_tab.apply_ordinal_file(&existing_ordinal_file, true);
        let sym_tab = Arc::new(sym_tab);
        cache_map().put(sym_tab.get_cache_key(), Arc::clone(&sym_tab));
        return Some(sym_tab);
    }

    None
}

/// `LibraryLookupTable.libraryLookupTableFileExists(String, int)`.
pub fn library_lookup_table_file_exists(app: &dyn Application, dllname: &str, size: i32) -> bool {
    get_existing_exports_file(app, dllname, size).is_some()
}

/// `LibraryLookupTable.getExistingExportsFile(String, int)`.
pub fn get_existing_exports_file(
    app: &dyn Application,
    dll_name: &str,
    size: i32,
) -> Option<ResourceFile> {
    get_existing_extensioned_file(app, dll_name, EXPORTS_FILE_EXTENSION, size)
}

/// `LibraryLookupTable.getNewExportsFile(String, int)`.
pub fn get_new_exports_file(
    app: &dyn Application,
    dll_name: &str,
    size: i32,
) -> Option<ResourceFile> {
    get_new_extensioned_file(app, dll_name, EXPORTS_FILE_EXTENSION, size)
}

/// `LibraryLookupTable.getNewSystemExportsFile(String, int)`.
fn get_new_system_exports_file(
    app: &dyn Application,
    name: &str,
    size: i32,
) -> Option<ResourceFile> {
    get_new_system_extensioned_file(app, name, EXPORTS_FILE_EXTENSION, size)
}

/// `LibraryLookupTable.getExistingOrdinalFile(String, int)`.
pub fn get_existing_ordinal_file(
    app: &dyn Application,
    dll_name: &str,
    size: i32,
) -> Option<ResourceFile> {
    get_existing_extensioned_file(app, dll_name, ORDINAL_MAPPING_FILE_EXTENSION, size)
}

/// `LibraryLookupTable.hasFileAndPathAndTimeStampMatch(File, int)`: whether the `.exports` file
/// found for `library_file` was generated from that exact file.
pub fn has_file_and_path_and_time_stamp_match(
    app: &dyn Application,
    library_file: &Path,
    size: i32,
) -> bool {
    let name = library_file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let exports_file = get_existing_exports_file(app, &name, size);
    match LibrarySymbolTable::has_file_and_path_and_time_stamp_match(
        exports_file.as_ref(),
        library_file,
    ) {
        Ok(matched) => matched,
        Err(_) => {
            Msg::debug(
                ORIGINATOR,
                &"got exception looking for .exports file (or parsing, etc.)",
            );
            false
        }
    }
}

/// `LibraryLookupTable.stripPossibleExtensionFromFilename(String)`. Note that the extension-less
/// name is returned lowercased but a name with no extension is returned untouched, which is
/// Java's behavior and is why callers lowercase the result again.
pub fn strip_possible_extension_from_filename(filename: &str) -> String {
    match filename.rfind('.') {
        Some(dot_pos) if dot_pos > 0 => filename[..dot_pos].to_lowercase(),
        _ => filename.to_string(),
    }
}

/// `LibraryLookupTable.getExtensionedFile(ResourceFile, String, String)`.
pub fn get_extensioned_file(base_dir: &ResourceFile, dll_name: &str, extension: &str) -> ResourceFile {
    base_dir.join(&format!("{dll_name}{extension}"))
}

/// `LibraryLookupTable.getStrippedExtensionedFile(ResourceFile, String, String)`.
pub fn get_stripped_extensioned_file(
    base_dir: &ResourceFile,
    dll_name: &str,
    extension: &str,
) -> ResourceFile {
    let strip_name = strip_possible_extension_from_filename(dll_name).to_lowercase();
    get_extensioned_file(base_dir, &strip_name, extension)
}

/// `LibraryLookupTable.getExistingExtensionedFile(String, String, int)`: searches the user's
/// symbol directory and then the system one for a file named after `dll_name` (with or without
/// its extension stripped), matched case-insensitively.
pub fn get_existing_extensioned_file(
    app: &dyn Application,
    dll_name: &str,
    extension: &str,
    size: i32,
) -> Option<ResourceFile> {
    let extension = extension.to_lowercase();
    let stripped_extension_filename =
        format!("{}{extension}", strip_possible_extension_from_filename(dll_name).to_lowercase());
    let extension_filename = format!("{}{extension}", dll_name.to_lowercase());

    // `equalsIgnoreCase` against either spelling.
    let matches = |file: &ResourceFile| {
        let name = file.name().to_lowercase();
        name == stripped_extension_filename || name == extension_filename
    };

    // The user directory wins over the system one, and -- as in Java -- the system directory is
    // only looked up if the user one turned up nothing (it logs a warning when it is missing).
    if let Some(user_dir) = create_user_resource_dir(app, size) {
        if let Some(found) = list_files(&user_dir).and_then(|f| f.into_iter().find(matches)) {
            return Some(found);
        }
    }

    if let Some(system_dir) = get_system_resource_dir(app, size) {
        if let Some(found) = list_files(&system_dir).and_then(|f| f.into_iter().find(matches)) {
            return Some(found);
        }
    }

    None
}

/// `LibraryLookupTable.getNewExtensionedFile(String, String, int)`: where a newly generated file
/// for `dll_name` belongs in the user's symbol directory. `None` if that directory could not be
/// created (Java NPEs instead; see the module docs).
pub fn get_new_extensioned_file(
    app: &dyn Application,
    dll_name: &str,
    extension: &str,
    size: i32,
) -> Option<ResourceFile> {
    let base_dir = create_user_resource_dir(app, size)?;
    Some(get_stripped_extensioned_file(&base_dir, dll_name, extension))
}

/// `LibraryLookupTable.getNewSystemExtensionedFile(String, String, int)`: as
/// [`get_new_extensioned_file`], but in the `Base` module's data directory.
pub fn get_new_system_extensioned_file(
    app: &dyn Application,
    dll_name: &str,
    extension: &str,
    size: i32,
) -> Option<ResourceFile> {
    let base_dir = get_system_resource_dir(app, size)?;
    Some(get_stripped_extensioned_file(&base_dir, dll_name, extension))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::{tempdir, TempDir};

    /// `Application` whose user settings directory is a temp dir and whose module data directory
    /// does not exist, so only the user-directory half of the lookup is exercised.
    struct TempSettingsApplication {
        settings_dir: PathBuf,
    }

    impl TempSettingsApplication {
        fn new() -> (TempDir, Self) {
            let dir = tempdir().unwrap();
            let app = TempSettingsApplication { settings_dir: dir.path().to_path_buf() };
            (dir, app)
        }
    }

    impl Application for TempSettingsApplication {
        fn application_layout(&self) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
            unimplemented!("not exercised by these smoke tests")
        }

        fn current_platform(&self) -> Box<dyn crate::framework::platform::Platform> {
            unimplemented!("not exercised by these smoke tests")
        }

        fn user_settings_directory(&self) -> Option<PathBuf> {
            Some(self.settings_dir.clone())
        }

        fn get_module_data_sub_directory(
            &self,
            module_name: &str,
            relative_path: &str,
        ) -> io::Result<ResourceFile> {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{relative_path} does not exist in module {module_name}"),
            ))
        }
    }

    #[test]
    fn strips_only_a_real_extension_and_lowercases_it() {
        // Java: dotPos > 0 -> substring(0, dotPos).toLowerCase(), else the name untouched.
        assert_eq!(strip_possible_extension_from_filename("KERNEL32.DLL"), "kernel32");
        assert_eq!(strip_possible_extension_from_filename("api-ms-win-CORE.dll"), "api-ms-win-core");
        // Last dot wins.
        assert_eq!(strip_possible_extension_from_filename("MSVCR100.Debug.DLL"), "msvcr100.debug");
        // No dot at all: returned verbatim, *not* lowercased.
        assert_eq!(strip_possible_extension_from_filename("KERNEL32"), "KERNEL32");
        // A leading dot is not an extension separator (dotPos == 0).
        assert_eq!(strip_possible_extension_from_filename(".ORD"), ".ORD");
    }

    #[test]
    fn memory_size_path_matches_java_switch() {
        assert_eq!(get_memory_size_path(64), "win64");
        assert_eq!(get_memory_size_path(32), "win32");
        assert_eq!(get_memory_size_path(16), "win16");
        assert_eq!(get_memory_size_path(8), "win_unsupported");
        assert_eq!(get_memory_size_path(0), "win_unsupported");
    }

    #[test]
    fn extensioned_file_names_match_java() {
        let dir = tempdir().unwrap();
        let base = ResourceFile::new(dir.path().to_path_buf());

        // getExtensionedFile appends verbatim; getStrippedExtensionedFile strips + lowercases.
        assert_eq!(
            get_extensioned_file(&base, "KERNEL32.DLL", EXPORTS_FILE_EXTENSION).name(),
            "KERNEL32.DLL.exports"
        );
        assert_eq!(
            get_stripped_extensioned_file(&base, "KERNEL32.DLL", EXPORTS_FILE_EXTENSION).name(),
            "kernel32.exports"
        );
        assert_eq!(
            get_stripped_extensioned_file(&base, "KERNEL32", ORDINAL_MAPPING_FILE_EXTENSION).name(),
            "kernel32.ord"
        );
    }

    #[test]
    fn user_resource_dir_is_created_under_the_settings_directory() {
        let (dir, app) = TempSettingsApplication::new();

        let win32 = create_user_resource_dir(&app, 32).unwrap();
        assert_eq!(win32.get_file(false).unwrap(), dir.path().join("symbols").join("win32"));
        assert!(dir.path().join("symbols").join("win32").is_dir());

        // A second architecture reuses the already-created `symbols` level.
        let win64 = create_user_resource_dir(&app, 64).unwrap();
        assert_eq!(win64.get_file(false).unwrap(), dir.path().join("symbols").join("win64"));
    }

    #[test]
    fn existing_exports_file_is_found_case_insensitively_stripped_or_not() {
        let (dir, app) = TempSettingsApplication::new();
        let win32 = dir.path().join("symbols").join("win32");
        fs::create_dir_all(&win32).unwrap();

        // Nothing there yet.
        assert!(get_existing_exports_file(&app, "KERNEL32.DLL", 32).is_none());
        assert!(!library_lookup_table_file_exists(&app, "KERNEL32.DLL", 32));

        // The stripped-and-lowercased form is what Ghidra ships.
        fs::write(win32.join("kernel32.exports"), "<LIBRARY/>").unwrap();
        let found = get_existing_exports_file(&app, "KERNEL32.DLL", 32).unwrap();
        assert_eq!(found.name(), "kernel32.exports");
        assert!(library_lookup_table_file_exists(&app, "KERNEL32.DLL", 32));

        // ... and the un-stripped form matches too, case-insensitively.
        fs::write(win32.join("ADVAPI32.dll.exports"), "<LIBRARY/>").unwrap();
        let found = get_existing_exports_file(&app, "advapi32.DLL", 32).unwrap();
        assert_eq!(found.name(), "ADVAPI32.dll.exports");

        // Extensions and sizes are not interchangeable.
        assert!(get_existing_ordinal_file(&app, "KERNEL32.DLL", 32).is_none());
        assert!(get_existing_exports_file(&app, "KERNEL32.DLL", 64).is_none());
    }

    #[test]
    fn new_exports_file_lands_in_the_user_directory_with_a_stripped_name() {
        let (dir, app) = TempSettingsApplication::new();

        let file = get_new_exports_file(&app, "USER32.DLL", 64).unwrap();
        assert_eq!(
            file.get_file(false).unwrap(),
            dir.path().join("symbols").join("win64").join("user32.exports")
        );
        // It is only a path; nothing has been written.
        assert!(!file.exists());

        // The system directory is missing in this Application, so the system form declines.
        assert!(get_new_system_extensioned_file(&app, "USER32.DLL", EXPORTS_FILE_EXTENSION, 64)
            .is_none());
    }

    #[test]
    fn get_files_reports_a_library_with_no_symbol_file_as_unresolved() {
        let (_dir, app) = TempSettingsApplication::new();
        let mut unresolved = HashSet::new();
        let mut resolved = HashSet::new();

        get_files(&app, "NOSUCH.DLL", 32, &mut unresolved, &mut resolved);
        assert_eq!(unresolved, HashSet::from(["NOSUCH.DLL".to_string()]));
        assert!(resolved.is_empty());

        // Already-seen libraries are skipped rather than re-added.
        get_files(&app, "NOSUCH.DLL", 32, &mut unresolved, &mut resolved);
        assert_eq!(unresolved.len(), 1);
    }

    #[test]
    fn cleanup_deletes_queued_files_and_empties_the_queue() {
        let dir = tempdir().unwrap();
        let doomed = dir.path().join("throwaway.exports");
        fs::write(&doomed, "<LIBRARY/>").unwrap();

        files_to_delete().push(ResourceFile::new(doomed.clone()));
        assert!(doomed.exists());

        cleanup();

        assert!(!doomed.exists());
        assert!(files_to_delete().is_empty());
    }

    #[test]
    fn cache_evicts_the_least_recently_used_entry() {
        let mut cache = SymbolTableCache::new(2);

        cache.put("a:32".to_string(), Arc::new(LibrarySymbolTable::new("A.DLL", 32)));
        cache.put("b:32".to_string(), Arc::new(LibrarySymbolTable::new("B.DLL", 32)));
        assert_eq!(cache.len(), 2);

        // Touch "a:32" so "b:32" becomes least-recently-used, then overflow.
        assert!(cache.get(&"a:32".to_string()).is_some());
        cache.put("c:32".to_string(), Arc::new(LibrarySymbolTable::new("C.DLL", 32)));

        assert_eq!(cache.len(), 2);
        assert!(cache.contains_key(&"a:32".to_string()));
        assert!(!cache.contains_key(&"b:32".to_string()));
        assert!(cache.contains_key(&"c:32".to_string()));

        // The cache key is the one `LibrarySymbolTable` computes: stripped, lowercased, ":size".
        assert_eq!(LibrarySymbolTable::new("KERNEL32.DLL", 32).get_cache_key(), "kernel32:32");
        assert_eq!(LibrarySymbolTable::cache_key_for("KERNEL32.DLL", 64), "kernel32:64");
    }
}
