//! Utilities for managing script directories and script metadata.
//!
//! Port of `ghidra.app.script.GhidraScriptUtil`. Java needs a class to hang its statics off; this
//! module holds them directly, so there is no `GhidraScriptUtil` type.
//!
//! Two Java statics are reached through explicit parameters instead of a process-wide singleton:
//! `Application`'s statics take an `&dyn Application` (this crate's convention, see
//! [`Application`]), and the provider list is threaded into the private helpers so callers that
//! already hold one need not re-read the global registry.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::app::seam_stubs::BundleHost;
use crate::framework::application::Application;
use crate::generic::jar::resource_file::ResourceFile;
use crate::script::ghidra_script_constants::{DEFAULT_SCRIPT_NAME, USER_SCRIPTS_DIR_PROPERTY};
use crate::script::seam_stubs::{
    ClassSearcher, FileUtilities, GhidraScriptProvider, ScriptInfo, UnsupportedScriptProvider,
};
use crate::util::classfinder::class_exclusion_filter::ClassExclusionFilter;
use crate::util::msg::Msg;

const SCRIPTS_SUBDIR_NAME: &str = "ghidra_scripts";
const DEV_SCRIPTS_SUBDIR_NAME: &str = "developer_scripts";

/// Originator passed to [`Msg`], standing in for Java's `GhidraScriptUtil.class`.
const ORIGINATOR: &str = "GhidraScriptUtil";

/// Ghidra's singleton bundle host; a reference is also held by `GhidraScriptMgrPlugin`.
static BUNDLE_HOST: Mutex<Option<Arc<BundleHost>>> = Mutex::new(None);

/// The lazily discovered provider list. The mutex plays the role of Java's `synchronized`
/// `getProviders()`, so two threads cannot build the list at once.
static PROVIDERS: Mutex<Option<Vec<Arc<dyn GhidraScriptProvider>>>> = Mutex::new(None);

/// Number of references from the GUI to the bundle host.
static REFERENCE_COUNT: AtomicUsize = AtomicUsize::new(0);

static USER_SCRIPTS_DIR: OnceLock<String> = OnceLock::new();

/// The user's home scripts directory.
///
/// Java exposes this as a mutable `public static String`; the documented way to override it is the
/// `ghidra.user.scripts.dir` system property (read here from the environment), which is honored
/// when this value is first computed.
pub fn user_scripts_dir() -> &'static str {
    USER_SCRIPTS_DIR.get_or_init(build_user_scripts_directory)
}

/// Returns the bundle host used for scripting, mirroring `getBundleHost()`. `None` before
/// [`acquire_bundle_host_reference`] has been called (Java returns `null`).
pub fn get_bundle_host() -> Option<Arc<BundleHost>> {
    BUNDLE_HOST.lock().unwrap().clone()
}

/// Initializes the module state with user and system paths.
///
/// Java wraps the framework start in an `OSGiParallelLock` -- a lock file under the OSGi directory
/// that keeps Ghidra instances running in parallel from racing on shared OSGi resources. That lock
/// is not reproduced: it is acquired via `BundleHost.getOsgiDir()`, and the bundle host is not
/// ported yet.
///
/// # Panics
/// Panics if a bundle host is already installed, mirroring Java's `RuntimeException`.
fn initialize(app: &dyn Application, a_bundle_host: Arc<BundleHost>) {
    {
        let mut bundle_host = BUNDLE_HOST.lock().unwrap();
        assert!(bundle_host.is_none(), "GhidraScriptUtil initialized multiple times!");

        if let Err(e) = a_bundle_host.start_framework() {
            Msg::error_with_error(ORIGINATOR, &"Failed to initialize BundleHost", &e);
        }
        *bundle_host = Some(Arc::clone(&a_bundle_host));
    }

    a_bundle_host.add(&get_user_script_directory(), true, false);
    a_bundle_host.add_all(&get_system_script_directories(app), true, true);
}

/// Disposes of the bundle host and the providers list.
fn dispose() {
    let mut bundle_host = BUNDLE_HOST.lock().unwrap();
    if let Some(host) = bundle_host.take() {
        host.stop_framework();
    }
    *PROVIDERS.lock().unwrap() = None;
}

/// Returns the current script directories. Empty (rather than Java's `NullPointerException`) when
/// no bundle host has been acquired.
pub fn get_script_source_directories() -> Vec<ResourceFile> {
    directories_of(get_bundle_host().map(|host| host.get_bundle_files()).unwrap_or_default())
}

/// Returns the current enabled script directories.
pub fn get_enabled_script_source_directories() -> Vec<ResourceFile> {
    directories_of(
        get_bundle_host().map(|host| host.get_enabled_bundle_files()).unwrap_or_default(),
    )
}

fn directories_of(bundle_files: Vec<ResourceFile>) -> Vec<ResourceFile> {
    bundle_files.into_iter().filter(|file| file.is_directory()).collect()
}

/// Searches the currently managed source directories for the given script file, returning the
/// source directory containing it, or `None` if it is in none of them.
pub fn find_source_directory_containing(source_file: &ResourceFile) -> Option<ResourceFile> {
    let found = get_script_source_directories()
        .into_iter()
        .find(|source_dir| FileUtilities::relativize_path(source_dir, source_file).is_some());
    if found.is_none() {
        Msg::error(
            ORIGINATOR,
            &format!(
                "Failed to find script in any script directory: {}",
                source_file.absolute_path()
            ),
        );
    }
    found
}

/// Searches the currently managed scripts for one with the given name, returning the first match.
pub fn find_script_by_name(script_name: &str) -> Option<ResourceFile> {
    find_script_file_in_paths(&get_script_source_directories(), script_name)
}

fn build_user_scripts_directory() -> String {
    let mut root = user_home_dir();
    if let Ok(override_dir) = std::env::var(USER_SCRIPTS_DIR_PROPERTY) {
        // Java logs the pre-override root here; kept as-is rather than "fixed".
        Msg::debug(ORIGINATOR, &format!("Using Ghidra script source directory: {root}"));
        root = override_dir;
    }
    format!("{root}{}{SCRIPTS_SUBDIR_NAME}", std::path::MAIN_SEPARATOR)
}

/// Stands in for `System.getProperty("user.home")`, which has no Rust equivalent.
fn user_home_dir() -> String {
    if cfg!(windows) {
        std::env::var("USERPROFILE").unwrap_or_default()
    } else {
        std::env::var("HOME").unwrap_or_default()
    }
}

/// Returns the default (installation-provided) script directories, sorted by path as Java's
/// `Collections.sort` over `Comparable` `ResourceFile`s does.
pub fn get_system_script_directories(app: &dyn Application) -> Vec<ResourceFile> {
    let mut dir_list = Vec::new();
    add_script_directories(app, &mut dir_list, SCRIPTS_SUBDIR_NAME);
    add_script_directories(app, &mut dir_list, DEV_SCRIPTS_SUBDIR_NAME);
    dir_list.sort_by_key(|dir| dir.absolute_path());
    dir_list
}

/// The user's home scripts directory as a [`ResourceFile`].
pub fn get_user_script_directory() -> ResourceFile {
    ResourceFile::new(PathBuf::from(user_scripts_dir()))
}

fn add_script_directories(
    app: &dyn Application,
    dir_list: &mut Vec<ResourceFile>,
    directory_name: &str,
) {
    dir_list.extend(app.find_module_sub_directories(directory_name));
}

/// Determines whether the specified script file or directory is contained within the Ghidra
/// installation.
pub fn is_system_script(app: &dyn Application, file: &ResourceFile) -> bool {
    is_system_file(app, file)
}

/// Determines whether the specified file or directory is contained within the Ghidra application
/// root. Java falls back to `true` when the canonical path cannot be resolved; resolving a
/// [`ResourceFile`]'s absolute path cannot fail here, so there is no such fallback.
fn is_system_file(app: &dyn Application, file: &ResourceFile) -> bool {
    let file_path = to_forward_slashes(file);
    if file_path.starts_with(user_scripts_dir()) {
        // a script inside of the user scripts dir is not a 'system' script
        return false;
    }

    app.application_root_directories()
        .iter()
        .any(|root| file_path.starts_with(&to_forward_slashes(root)))
}

fn to_forward_slashes(file: &ResourceFile) -> String {
    file.absolute_path().replace('\\', "/")
}

/// Returns the exploded bundle directories.
#[deprecated(
    note = "accessing class files directly precludes OSGi wiring according to requirements and capabilities"
)]
pub fn get_exploded_compiled_source_bundle_paths(app: &dyn Application) -> Vec<ResourceFile> {
    let Some(osgi_dir) = BundleHost::get_osgi_dir(app) else {
        return Vec::new();
    };
    match std::fs::read_dir(&osgi_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .map(ResourceFile::new)
            .collect(),
        Err(e) => {
            Msg::show_error_with_error(
                ORIGINATOR,
                "error",
                &"error listing user osgi directory",
                &e,
            );
            Vec::new()
        }
    }
}

/// Returns the base name of a script file: given `SomeClass.java`, returns `SomeClass`.
pub fn get_base_name(script: &ResourceFile) -> String {
    let name = script.name();
    match name.rfind('.') {
        None => name,
        Some(pos) => name[..pos].to_string(),
    }
}

/// Returns all supported script providers, priority-sorted, discovering them on first use.
pub fn get_providers() -> Vec<Arc<dyn GhidraScriptProvider>> {
    PROVIDERS
        .lock()
        .unwrap()
        .get_or_insert_with(|| {
            ClassSearcher::get_script_provider_instances(&ClassExclusionFilter::new([
                "UnsupportedScriptProvider",
            ]))
        })
        .clone()
}

/// Returns the script provider for the specified script file: the first provider whose extension
/// matches and whose runtime environment the script accepts, an [`UnsupportedScriptProvider`]
/// wrapping the extension match when the script requires a different runtime (or does not exist
/// yet), or `None` when no provider handles the extension at all.
pub fn get_provider(script_file: &ResourceFile) -> Option<Arc<dyn GhidraScriptProvider>> {
    find_provider(&get_providers(), script_file)
}

/// Returns whether a provider exists that can process the specified file.
pub fn has_script_provider(script_file: &ResourceFile) -> bool {
    get_provider(script_file).is_some()
}

/// Finds the first provider whose extension matches the given file's extension and whose runtime
/// matches the script's `@runtime` tag.
///
/// The file is not guaranteed to exist: the script manager calls this while creating a new script,
/// when all it has to go on is the desired extension and there is no `@runtime` tag to read yet.
fn find_provider(
    providers: &[Arc<dyn GhidraScriptProvider>],
    script_file: &ResourceFile,
) -> Option<Arc<dyn GhidraScriptProvider>> {
    let mut base_provider = None;
    let file_name = script_file.name().to_lowercase();

    for provider in providers {
        if !file_name.ends_with(&provider.get_extension().to_lowercase()) {
            continue;
        }
        base_provider = Some(provider);
        if !script_file.exists() {
            // Use UnsupportedScriptProvider. The provider will be updated later when the file
            // actually exists and we can properly look for an @runtime tag (or confirm that one
            // is not defined).
            break;
        }
        let info = ScriptInfo::new(Some(Arc::clone(provider)), script_file.clone());
        let matches_runtime = match info.get_runtime_environment_name() {
            None => true,
            Some(runtime) => provider
                .get_runtime_environment_name()
                .is_some_and(|provider_runtime| runtime.eq_ignore_ascii_case(&provider_runtime)),
        };
        if matches_runtime {
            return Some(Arc::clone(provider));
        }
    }

    base_provider.map(|base| {
        Arc::new(UnsupportedScriptProvider::new(Arc::clone(base))) as Arc<dyn GhidraScriptProvider>
    })
}

/// Finds the first provider whose extension matches the given file name's extension.
fn find_provider_for_name(
    providers: &[Arc<dyn GhidraScriptProvider>],
    file_name: &str,
) -> Option<Arc<dyn GhidraScriptProvider>> {
    let file_name = file_name.to_lowercase();
    providers
        .iter()
        .find(|provider| file_name.ends_with(&provider.get_extension().to_lowercase()))
        .map(Arc::clone)
}

/// Creates a new script with a name unique across `script_directories`, using `provider`'s
/// extension, in `parent_directory`.
pub fn create_new_script(
    provider: &dyn GhidraScriptProvider,
    parent_directory: &ResourceFile,
    script_directories: &[ResourceFile],
) -> io::Result<ResourceFile> {
    create_new_named_script(
        &get_providers(),
        DEFAULT_SCRIPT_NAME,
        &provider.get_extension(),
        parent_directory,
        script_directories,
    )
}

fn create_new_named_script(
    providers: &[Arc<dyn GhidraScriptProvider>],
    script_name: &str,
    extension: &str,
    parent_directory: &ResourceFile,
    script_directories: &[ResourceFile],
) -> io::Result<ResourceFile> {
    // we want to pick a name that is unique in *any* of the script directories
    let mut class_name = format!("{script_name}{extension}");
    let mut counter = 1;
    while find_script_file_in_paths_of(providers, script_directories, &class_name).is_some() {
        class_name = format!("{script_name}{counter}{extension}");
        counter += 1;
        if counter > 1000 {
            return Err(io::Error::other(
                "Unable to create new script file, temporary files exceeded.",
            ));
        }
    }

    Ok(parent_directory.join(&class_name))
}

/// Returns the script metadata for `file`, resolving its provider.
pub fn new_script_info(file: ResourceFile) -> ScriptInfo {
    let provider = get_provider(&file);
    ScriptInfo::new(provider, file)
}

/// Fixes script name issues for searching in script directories, assuming Java when no provider
/// can be identified. `None` when even the assumed Java provider is missing (Java throws a
/// `NullPointerException` in that case).
///
/// This is part of a poorly specified behavior that is due for future amendment. The intent was to
/// allow some freedom in how a user specifies a script: if the extension is omitted `.java` is
/// assumed, and a Java class name is converted to a relative path.
#[deprecated(note = "part of a poorly specified behavior that is due for future amendment")]
// Java's callers -- `GhidraScript.runScript` and `HeadlessAnalyzer`'s pre/post scripts -- are not
// ported yet, so nothing in the crate calls this today.
#[allow(dead_code)]
pub(crate) fn fixup_name(name: &str) -> Option<String> {
    fixup_name_with(&get_providers(), name)
}

fn fixup_name_with(providers: &[Arc<dyn GhidraScriptProvider>], name: &str) -> Option<String> {
    match find_provider_for_name(providers, name) {
        Some(provider) => Some(provider.fixup_name(name)),
        None => {
            // assume Java if no provider matched
            let name = format!("{name}.java");
            let provider = find_provider_for_name(providers, ".java")?;
            Some(provider.fixup_name(&name))
        }
    }
}

/// Returns the first existing script named `name` under any of `script_directories`.
pub(crate) fn find_script_file_in_paths(
    script_directories: &[ResourceFile],
    name: &str,
) -> Option<ResourceFile> {
    find_script_file_in_paths_of(&get_providers(), script_directories, name)
}

fn find_script_file_in_paths_of(
    providers: &[Arc<dyn GhidraScriptProvider>],
    script_directories: &[ResourceFile],
    name: &str,
) -> Option<ResourceFile> {
    let validated_name = fixup_name_with(providers, name)?;

    script_directories
        .iter()
        .filter(|resource_file| resource_file.is_directory())
        .map(|resource_file| resource_file.join(&validated_name))
        .find(ResourceFile::exists)
}

/// Acquires a reference to the singleton bundle host, initializing it on the first reference.
pub fn acquire_bundle_host_reference(app: &dyn Application) -> Arc<BundleHost> {
    if REFERENCE_COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
        initialize(app, Arc::new(BundleHost::default()));
    }
    get_bundle_host().expect("a bundle host is installed while references are held")
}

/// Releases a bundle host reference. When no references remain, the bundle host and the providers
/// list are disposed of.
pub fn release_bundle_host_reference() {
    if REFERENCE_COUNT.fetch_sub(1, Ordering::SeqCst) == 1 {
        dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::{tempdir, TempDir};

    struct FakeProvider {
        extension: &'static str,
        runtime: Option<&'static str>,
    }

    impl GhidraScriptProvider for FakeProvider {
        fn get_extension(&self) -> String {
            self.extension.to_string()
        }

        fn get_runtime_environment_name(&self) -> Option<String> {
            self.runtime.map(str::to_string)
        }
    }

    /// Mirrors the (Java, Jython) pair of providers that share nothing but their ordering: the
    /// first match by extension wins.
    fn fake_providers() -> Vec<Arc<dyn GhidraScriptProvider>> {
        vec![
            Arc::new(FakeProvider { extension: ".java", runtime: Some("Java") }),
            Arc::new(FakeProvider { extension: ".py", runtime: Some("Jython") }),
        ]
    }

    fn script_dir_with(file_names: &[&str]) -> (TempDir, ResourceFile) {
        let dir = tempdir().unwrap();
        for name in file_names {
            fs::write(dir.path().join(name), b"// script").unwrap();
        }
        let resource = ResourceFile::new(dir.path().to_path_buf());
        (dir, resource)
    }

    #[test]
    fn get_base_name_strips_the_extension() {
        let script = ResourceFile::new(PathBuf::from("/tmp/SomeClass.java"));
        assert_eq!(get_base_name(&script), "SomeClass");
    }

    #[test]
    fn get_base_name_keeps_names_without_an_extension() {
        let script = ResourceFile::new(PathBuf::from("/tmp/SomeClass"));
        assert_eq!(get_base_name(&script), "SomeClass");
    }

    #[test]
    fn user_scripts_dir_is_ghidra_scripts_under_a_root() {
        let expected_suffix = format!("{}{SCRIPTS_SUBDIR_NAME}", std::path::MAIN_SEPARATOR);
        assert!(
            user_scripts_dir().ends_with(&expected_suffix),
            "expected {} to end with {expected_suffix}",
            user_scripts_dir()
        );
    }

    #[test]
    fn fixup_name_assumes_java_when_no_extension_is_given() {
        assert_eq!(
            fixup_name_with(&fake_providers(), "MyScript"),
            Some("MyScript.java".to_string())
        );
    }

    #[test]
    fn fixup_name_keeps_a_recognized_extension() {
        assert_eq!(fixup_name_with(&fake_providers(), "MyScript.py"), Some("MyScript.py".to_string()));
    }

    #[test]
    fn fixup_name_needs_at_least_the_assumed_java_provider() {
        assert_eq!(fixup_name_with(&[], "MyScript"), None);
    }

    #[test]
    fn find_provider_matches_an_existing_script_by_extension() {
        let (_dir, dir_file) = script_dir_with(&["MyScript.py"]);
        let script = dir_file.join("MyScript.py");

        let provider = find_provider(&fake_providers(), &script).expect("a provider matches .py");
        assert_eq!(provider.get_extension(), ".py");
        assert_eq!(provider.get_runtime_environment_name(), Some("Jython".to_string()));
    }

    #[test]
    fn find_provider_wraps_a_missing_script_in_an_unsupported_provider() {
        let (_dir, dir_file) = script_dir_with(&[]);
        let script = dir_file.join("NotYetWritten.java");

        let provider = find_provider(&fake_providers(), &script).expect("the extension matches");
        assert_eq!(provider.get_extension(), ".java");
        // UnsupportedScriptProvider delegates the extension but reports no runtime of its own.
        assert_eq!(provider.get_runtime_environment_name(), None);
    }

    #[test]
    fn find_provider_returns_none_for_an_unknown_extension() {
        let (_dir, dir_file) = script_dir_with(&["notes.txt"]);
        let script = dir_file.join("notes.txt");

        assert!(find_provider(&fake_providers(), &script).is_none());
    }

    #[test]
    fn find_script_file_in_paths_searches_every_directory_and_fixes_up_the_name() {
        let (_empty, empty_dir) = script_dir_with(&[]);
        let (_populated, populated_dir) = script_dir_with(&["MyScript.java"]);
        let directories = [empty_dir, populated_dir];

        let found = find_script_file_in_paths_of(&fake_providers(), &directories, "MyScript")
            .expect("MyScript.java is in the second directory");
        assert_eq!(found.name(), "MyScript.java");
        assert!(found.exists());
    }

    #[test]
    fn find_script_file_in_paths_returns_none_when_the_script_is_absent() {
        let (_empty, empty_dir) = script_dir_with(&[]);
        let directories = [empty_dir];

        assert!(find_script_file_in_paths_of(&fake_providers(), &directories, "Missing").is_none());
    }

    #[test]
    fn create_new_script_uses_the_default_name_when_it_is_free() {
        let (_dir, dir_file) = script_dir_with(&[]);
        let directories = [dir_file.clone()];

        let script =
            create_new_named_script(&fake_providers(), DEFAULT_SCRIPT_NAME, ".java", &dir_file, &directories)
                .unwrap();
        assert_eq!(script.name(), "NewScript.java");
    }

    #[test]
    fn create_new_script_counts_up_past_taken_names() {
        let (_dir, dir_file) = script_dir_with(&["NewScript.java", "NewScript1.java"]);
        let directories = [dir_file.clone()];

        let script =
            create_new_named_script(&fake_providers(), DEFAULT_SCRIPT_NAME, ".java", &dir_file, &directories)
                .unwrap();
        assert_eq!(script.name(), "NewScript2.java");
    }

    #[test]
    fn get_providers_is_empty_until_a_provider_registry_is_ported() {
        assert!(get_providers().is_empty());
    }
}
