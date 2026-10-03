use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::application_properties::REVISION_PROPERTY_PREFIX;
use crate::framework::platform::Platform;
use crate::framework::seam_stubs::{ApplicationLayoutLike, GModuleLike};
use crate::generic::jar::ResourceFile;

const DATA_DIRNAME: &str = "data/";

/// Signals that an attempt to find a Ghidra "OS-file" (native binary) has failed, mirroring
/// `ghidra.framework.OSFileNotFoundException`.
#[derive(Debug, Clone)]
pub struct OSFileNotFoundError {
    /// The module associated with this exception, if any.
    pub module_name: Option<String>,
    /// The file name associated with this exception.
    pub file_name: String,
}

impl OSFileNotFoundError {
    fn new(module_name: Option<&str>, file_name: &str) -> Self {
        Self {
            module_name: module_name.map(str::to_string),
            file_name: file_name.to_string(),
        }
    }
}

impl std::fmt::Display for OSFileNotFoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match &self.module_name {
            Some(name) => format!("{name}/"),
            None => String::new(),
        };
        write!(
            f,
            "{prefix}os/{} does not exist (see GettingStarted.md, 'Building Native Components')",
            self.file_name
        )
    }
}

impl std::error::Error for OSFileNotFoundError {}

/// The Application trait provides a variety of convenience methods for accessing Application
/// elements once an application has been initialized (in the Java original, these are static
/// methods usable only after `Application.initializeApplication` has been called).
///
/// Mirrors `ghidra.framework.Application`. This type was flagged as a package-cycle cut-point, so
/// it is ported to an object-safe trait rather than a concrete struct: callers depend on
/// `Box<dyn Application>`/`Arc<dyn Application>` instead of a single concrete backing
/// implementation. A narrower placeholder for this same Java class,
/// [`ApplicationLike`](crate::framework::seam_stubs::ApplicationLike), already exists as a seam
/// consumed by [`GenericRunInfo`](crate::framework::GenericRunInfo); it is left untouched here
/// (rather than merged into this richer trait) so that existing seam is unaffected, consistent
/// with the project's general practice of letting existing consumers depend on the minimal seam
/// they need rather than this type's full surface.
///
/// The Java class's static lifecycle methods (`initializeApplication`, `isInitialized`, and the
/// `File`-pair overload of `initializeLogging`) are not reproduced: they operate on/construct the
/// process-wide singleton itself rather than being queries against an already-initialized
/// instance, so they don't fit an object-safe accessor trait -- consistent with how
/// [`Platform`] omits the `CURRENT_PLATFORM` static lookup over its own concrete variants, and how
/// [`GenericRunInfo`](crate::framework::GenericRunInfo) omits `Preferences`'s own
/// `store()`/`clear()` persistence methods.
///
/// Likewise, every Java method that resolves "the calling class's module" via
/// `getMyModuleRootDirectory()` (`findFilesByExtensionInMyModule`, the single-argument
/// `getModuleDataSubDirectory`/`getModuleDataFile` overloads, and the single-argument `getOSFile`
/// overload's "try my own module first" step) relies on `ReflectionUtilities` walking the JVM call
/// stack to find the caller's class -- Rust has no equivalent call-stack introspection, so those
/// are omitted (`get_os_file` still ports the "then search every module" fallback those methods
/// end with). `getModuleContainingClass`/`getModuleContainingResourceFile` are omitted for the
/// same reason (`Class.forName`/classloader-relative source lookup has no Rust equivalent).
///
/// `getModuleFile`'s OS-specific-file lookup additionally special-cases the concrete
/// `Platform.WIN_ARM_64`/`WIN_X86_64`/`MAC_ARM_64`/`MAC_X86_64` singletons as emulation/Rosetta 2
/// fallbacks; without concrete `Platform` variants to compare against (see [`Platform`]'s own
/// cycle-breaking doc comment), [`Self::get_os_file`] and [`Self::find_os_file_in_any_module`]
/// only search [`Self::current_platform`]'s own directory name.
///
/// `getUserSettingsFiles` (which copies settings files forward from a previous installation via
/// `GenericRunInfo`/`FileUtilities.copyDir`) and `getLibraryDirectories`'s Java implementation
/// (`ModuleUtilities.getModuleLibDirectories`) are also omitted/inlined respectively:
/// [`Self::library_directories`] reproduces `ModuleUtilities.getModuleLibDirectories`'s two
/// `collectExistingModuleDirs` calls directly (a three-line utility method, not worth a seam), but
/// `getUserSettingsFiles`'s directory-copy side effect would require a `FileUtilities` seam for a
/// single caller and is omitted.
pub trait Application {
    /// Returns the seam onto `ghidra.framework.Application`'s `layout` field, mirroring
    /// `Application.getApplicationLayout()`.
    fn application_layout(&self) -> Box<dyn ApplicationLayoutLike>;

    /// Returns the platform the application is currently running on, standing in for
    /// `Platform.CURRENT_PLATFORM` (see this trait's own doc comment for why that static lookup
    /// isn't reproducible here).
    fn current_platform(&self) -> Box<dyn Platform>;

    /// Returns the name of the application, mirroring `Application.getName()`.
    fn name(&self) -> String {
        self.application_layout().application_properties().application_name()
    }

    /// Returns the value of the given application property name, mirroring
    /// `Application.getApplicationProperty(String)`.
    fn application_property(&self, property_name: &str) -> Option<String> {
        self.application_layout().application_properties().get_property(property_name)
    }

    /// Returns the application root directories, mirroring
    /// `Application.getApplicationRootDirectories()`.
    fn application_root_directories(&self) -> Vec<ResourceFile> {
        self.application_layout().application_root_dirs()
    }

    /// Returns the (first) application root directory, mirroring
    /// `Application.getApplicationRootDirectory()`.
    fn application_root_directory(&self) -> Option<ResourceFile> {
        self.application_root_directories().into_iter().next()
    }

    /// Returns the directory containing the user's configuration settings for this application,
    /// mirroring `Application.getUserSettingsDirectory()`.
    fn user_settings_directory(&self) -> Option<PathBuf> {
        self.application_layout().user_settings_dir()
    }

    /// Returns the temporary directory specific to the user and the application, mirroring
    /// `Application.getUserTempDirectory()`.
    fn user_temp_directory(&self) -> PathBuf {
        self.application_layout()
            .user_temp_dir()
            .unwrap_or_else(|| std::env::temp_dir().join("ghidra"))
    }

    /// Returns the cache directory specific to the user and the application, mirroring
    /// `Application.getUserCacheDirectory()`.
    fn user_cache_directory(&self) -> Option<PathBuf> {
        self.application_layout().user_cache_dir()
    }

    /// Creates a new empty file in the application's temp directory, using the given prefix and
    /// suffix to generate its name, mirroring `Application.createTempFile(String, String)`.
    fn create_temp_file(&self, prefix: &str, suffix: Option<&str>) -> io::Result<PathBuf> {
        if prefix.chars().count() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prefix must be at least three characters long",
            ));
        }
        let suffix = suffix.unwrap_or(".tmp");
        let dir = self.user_temp_directory();
        fs::create_dir_all(&dir)?;

        for attempt in 0u64..10_000 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let candidate =
                dir.join(format!("{prefix}{}{}{suffix}", std::process::id(), nanos + attempt as u128));
            match fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
                Ok(_) => return Ok(candidate),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not create a unique temp file"))
    }

    /// Returns the module root directories, mirroring `Application.getModuleRootDirectories()`.
    fn module_root_directories(&self) -> Vec<ResourceFile> {
        self.application_layout().modules().iter().map(|m| m.module_root()).collect()
    }

    /// Returns the installation directory, mirroring `Application.getInstallationDirectory()`.
    fn installation_directory(&self) -> Option<ResourceFile> {
        self.application_layout().application_installation_dir().cloned()
    }

    /// Returns the module root directory for the module with the given name, mirroring
    /// `Application.getModuleRootDir(String)`.
    fn module_root_dir(&self, module_name: &str) -> Option<ResourceFile> {
        self.application_layout().module_named(module_name).map(|m| m.module_root())
    }

    /// Returns true if this build was created using "buildLocal" rather than the official build
    /// process, mirroring `Application.isTestBuild()`.
    fn is_test_build(&self) -> bool {
        self.application_layout()
            .application_properties()
            .get_property(crate::framework::application_properties::TEST_RELEASE_PROPERTY)
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false)
    }

    /// Checks whether the application is in "single jar" mode, mirroring
    /// `Application.inSingleJarMode()`.
    fn in_single_jar_mode(&self) -> bool {
        self.application_layout().in_single_jar_mode()
    }

    /// Returns the version of this build, mirroring `Application.getApplicationVersion()`.
    fn application_version(&self) -> String {
        self.application_layout().application_properties().application_version()
    }

    /// Returns the date this build was created, mirroring `Application.getBuildDate()`.
    fn build_date(&self) -> String {
        self.application_layout().application_properties().application_build_date()
    }

    /// Returns the release name for this build, mirroring
    /// `Application.getApplicationReleaseName()`.
    fn application_release_name(&self) -> String {
        self.application_layout().application_properties().application_release_name()
    }

    /// Returns the source repository revisions used in the build process, or `None` if not
    /// applicable, mirroring `Application.getApplicationSourceRevisions()`.
    fn application_source_revisions(&self) -> Option<HashMap<String, String>> {
        let layout = self.application_layout();
        let props = layout.application_properties();
        let mut revisions = HashMap::new();
        for key in props.property_names() {
            if key.starts_with(REVISION_PROPERTY_PREFIX) {
                if let Some(value) = props.get_property(&key) {
                    revisions.insert(key, value);
                }
            }
        }
        if revisions.is_empty() {
            None
        } else {
            Some(revisions)
        }
    }

    /// Returns a collection of module library directories, mirroring
    /// `Application.getLibraryDirectories()` (which delegates to
    /// `ModuleUtilities.getModuleLibDirectories`).
    fn library_directories(&self) -> Vec<ResourceFile> {
        let mut dirs = Vec::new();
        for module in self.application_layout().modules() {
            module.collect_existing_module_dirs(&mut dirs, "lib");
            module.collect_existing_module_dirs(&mut dirs, "libs");
        }
        dirs
    }

    /// Returns all files within any module's data directory that end with the given extension,
    /// mirroring `Application.findFilesByExtensionInApplication(String)`.
    fn find_files_by_extension_in_application(&self, extension: &str) -> Vec<ResourceFile> {
        let extension = verify_extension(extension);
        let mut list = Vec::new();
        for module in self.application_layout().modules() {
            module.accumulate_data_files_by_extension(&mut list, &extension);
        }
        list
    }

    /// Finds the first file that exists with the relative path in any module, mirroring
    /// `Application.findDataFileInAnyModule(String)`.
    fn find_data_file_in_any_module(&self, relative_path: &str) -> Option<ResourceFile> {
        let data_path = format!("{DATA_DIRNAME}{relative_path}");
        for module in self.application_layout().modules() {
            if let Some(file) = module.find_module_file(&data_path) {
                return Some(file);
            }
        }
        None
    }

    /// Returns a list of all files with the given extension located in the named module,
    /// mirroring `Application.findFilesByExtension(String, String)`.
    fn find_files_by_extension(&self, module_name: &str, extension: &str) -> Vec<ResourceFile> {
        let extension = verify_extension(extension);
        let mut list = Vec::new();
        if let Some(module) = self.application_layout().module_named(module_name) {
            module.accumulate_data_files_by_extension(&mut list, &extension);
        }
        list
    }

    /// Returns a list of all directories in any module that have the given module-relative path,
    /// mirroring `Application.findModuleSubDirectories(String)`.
    fn find_module_sub_directories(&self, relative_path: &str) -> Vec<ResourceFile> {
        let mut result = Vec::new();
        for module in self.application_layout().modules() {
            module.collect_existing_module_dirs(&mut result, relative_path);
        }
        result
    }

    /// Returns the directory relative to the named module's data directory, mirroring
    /// `Application.getModuleDataSubDirectory(String, String)`.
    fn get_module_data_sub_directory(
        &self,
        module_name: &str,
        relative_path: &str,
    ) -> io::Result<ResourceFile> {
        let data_path = format!("{DATA_DIRNAME}{relative_path}");
        let found = self.find_in_module(module_name, &data_path)?;
        if !found.is_directory() {
            return Err(not_a_directory(&found));
        }
        Ok(found)
    }

    /// Returns the directory relative to the named module's directory, mirroring
    /// `Application.getModuleSubDirectory(String, String)`.
    fn get_module_sub_directory(
        &self,
        module_name: &str,
        relative_path: &str,
    ) -> io::Result<ResourceFile> {
        let found = self.find_in_module(module_name, relative_path)?;
        if !found.is_directory() {
            return Err(not_a_directory(&found));
        }
        Ok(found)
    }

    /// Returns the file relative to the named module's data directory, mirroring
    /// `Application.getModuleDataFile(String, String)`.
    fn get_module_data_file(
        &self,
        module_name: &str,
        relative_data_path: &str,
    ) -> io::Result<ResourceFile> {
        let data_path = format!("{DATA_DIRNAME}{relative_data_path}");
        let found = self.find_in_module(module_name, &data_path)?;
        if found.is_directory() {
            return Err(not_a_file(&found));
        }
        Ok(found)
    }

    /// Returns the file relative to the named module's directory, mirroring
    /// `Application.getModuleFile(String, String)`.
    fn get_module_file(&self, module_name: &str, relative_path: &str) -> io::Result<ResourceFile> {
        let found = self.find_in_module(module_name, relative_path)?;
        if found.is_directory() {
            return Err(not_a_file(&found));
        }
        Ok(found)
    }

    /// Returns the OS-specific file within the given module with the given name, mirroring
    /// `Application.getOSFile(String, String)`.
    fn get_os_file_in_module(
        &self,
        module_name: &str,
        exact_filename: &str,
    ) -> Result<PathBuf, OSFileNotFoundError> {
        let module = self.application_layout().module_named(module_name).ok_or_else(|| {
            OSFileNotFoundError::new(Some(module_name), exact_filename)
        })?;
        let Some(dir_name) = self.current_platform().directory_name().map(str::to_string) else {
            return Err(OSFileNotFoundError::new(Some(module_name), exact_filename));
        };

        module_os_file(module.as_ref(), &dir_name, exact_filename)
            .ok_or_else(|| OSFileNotFoundError::new(Some(module_name), exact_filename))
    }

    /// Returns the specified OS-specific file, searched for across all modules, mirroring the
    /// "search every module" half of `Application.getOSFile(String)` (see this trait's own doc
    /// comment for why the "try my own module first" half is not reproducible).
    fn get_os_file(&self, exact_filename: &str) -> Result<PathBuf, OSFileNotFoundError> {
        let Some(dir_name) = self.current_platform().directory_name().map(str::to_string) else {
            return Err(OSFileNotFoundError::new(None, exact_filename));
        };

        for module in self.application_layout().modules() {
            if let Some(file) = module_os_file(module.as_ref(), &dir_name, exact_filename) {
                return Ok(file);
            }
        }
        Err(OSFileNotFoundError::new(None, exact_filename))
    }

    /// Looks up `relative_path` in the named module's search roots, mirroring the shared
    /// `module not found`/`file ... does not exist` error handling repeated across
    /// `Application`'s `getModuleXxx` private helpers.
    fn find_in_module(&self, module_name: &str, relative_path: &str) -> io::Result<ResourceFile> {
        let module = self.application_layout().module_named(module_name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("module not found: {module_name}"))
        })?;
        module.find_module_file(relative_path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("file {relative_path} does not exist in module {module_name}"),
            )
        })
    }
}

/// Looks up `exact_filename` within `module`'s `build/os/<dir_name>` directory, falling back to
/// `os/<dir_name>`, mirroring the two-step search in `Application.getModuleOSFile` (the private
/// `getModuleFile` helper plus its two call sites).
fn module_os_file(module: &dyn GModuleLike, dir_name: &str, exact_filename: &str) -> Option<PathBuf> {
    module
        .find_module_file(&format!("build/os/{dir_name}/{exact_filename}"))
        .or_else(|| module.find_module_file(&format!("os/{dir_name}/{exact_filename}")))
        .and_then(|f| f.get_file(true))
}

fn not_a_directory(found: &ResourceFile) -> io::Error {
    io::Error::other(format!("{} is a file (expecting directory)", found.absolute_path()))
}

fn not_a_file(found: &ResourceFile) -> io::Error {
    io::Error::other(format!("{} is a directory (expecting file)", found.absolute_path()))
}

/// Normalizes a file extension, prepending a leading `.` if one is not already present,
/// mirroring the private `Application.verifyExtension(String)`.
fn verify_extension(extension: &str) -> String {
    assert!(!extension.contains('/'), "extension cannot contain / (path separator)");
    assert!(!extension.contains('\\'), "extension cannot contain \\ (path separator)");
    let dot_index = extension.find('.');
    assert!(
        dot_index.is_none() || dot_index == Some(0),
        "extension can not contain a \".\" char other than at the beginning"
    );
    if dot_index.is_none() {
        format!(".{extension}")
    } else {
        extension.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::application_properties::{
        ApplicationProperties, APPLICATION_NAME_PROPERTY, APPLICATION_VERSION_PROPERTY,
    };
    use crate::framework::os::OperatingSystem;
    use crate::framework::seam_stubs::Architecture;
    use std::fs;

    struct MockApplicationProperties(HashMap<&'static str, String>);

    impl ApplicationProperties for MockApplicationProperties {
        fn raw_property(&self, property_name: &str) -> Option<String> {
            self.0.get(property_name).cloned()
        }

        fn set_property(&mut self, property_name: &'_ str, value: &str) {
            // Not exercised by these tests; `MockApplicationProperties` is built pre-populated.
            let _ = (property_name, value);
        }

        fn property_names(&self) -> Vec<String> {
            self.0.keys().map(|k| k.to_string()).collect()
        }
    }

    struct MockGModule {
        root: PathBuf,
    }

    impl GModuleLike for MockGModule {
        fn module_root(&self) -> ResourceFile {
            ResourceFile::new(self.root.clone())
        }

        fn accumulate_data_files_by_extension(
            &self,
            accumulator: &mut Vec<ResourceFile>,
            extension: &str,
        ) {
            let data_dir = self.root.join("data");
            accumulate_by_extension(&data_dir, extension, accumulator);
        }

        fn find_module_file(&self, relative_path: &str) -> Option<ResourceFile> {
            let candidate = self.root.join(relative_path);
            candidate.exists().then(|| ResourceFile::new(candidate))
        }

        fn collect_existing_module_dirs(
            &self,
            accumulator: &mut Vec<ResourceFile>,
            relative_path: &str,
        ) {
            let candidate = self.root.join(relative_path);
            if candidate.is_dir() {
                accumulator.push(ResourceFile::new(candidate));
            }
        }
    }

    fn accumulate_by_extension(dir: &std::path::Path, extension: &str, out: &mut Vec<ResourceFile>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                accumulate_by_extension(&path, extension, out);
            } else if path.to_string_lossy().ends_with(extension) {
                out.push(ResourceFile::new(path));
            }
        }
    }

    struct MockArchitecture;
    impl std::fmt::Display for MockArchitecture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "x86_64")
        }
    }
    impl Architecture for MockArchitecture {}

    struct MockPlatform;
    impl Platform for MockPlatform {
        fn operating_system(&self) -> OperatingSystem {
            OperatingSystem::Linux
        }
        fn architecture(&self) -> Box<dyn Architecture> {
            Box::new(MockArchitecture)
        }
        fn directory_name(&self) -> Option<&str> {
            Some("linux_x86_64")
        }
        fn library_extension(&self) -> Option<&str> {
            Some(".so")
        }
        fn executable_extension(&self) -> &str {
            ""
        }
    }

    struct MockApplicationLayout {
        properties: MockApplicationProperties,
        root: PathBuf,
        module_name: String,
    }

    impl ApplicationLayoutLike for MockApplicationLayout {
        fn application_properties(&self) -> &dyn ApplicationProperties {
            &self.properties
        }

        fn application_installation_dir(&self) -> Option<&ResourceFile> {
            None
        }

        fn modules(&self) -> Vec<Box<dyn GModuleLike>> {
            vec![Box::new(MockGModule { root: self.root.clone() })]
        }

        fn module_named(&self, name: &str) -> Option<Box<dyn GModuleLike>> {
            if name == self.module_name {
                Some(Box::new(MockGModule { root: self.root.clone() }))
            } else {
                None
            }
        }

        fn in_single_jar_mode(&self) -> bool {
            true
        }
    }

    struct MockApplication {
        root: PathBuf,
    }

    impl Application for MockApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            let mut props = HashMap::new();
            props.insert(APPLICATION_NAME_PROPERTY, "Ghidra".to_string());
            props.insert(APPLICATION_VERSION_PROPERTY, "11.2".to_string());
            Box::new(MockApplicationLayout {
                properties: MockApplicationProperties(props),
                root: self.root.clone(),
                module_name: "MyModule".to_string(),
            })
        }

        fn current_platform(&self) -> Box<dyn Platform> {
            Box::new(MockPlatform)
        }
    }

    fn setup_module() -> (tempfile::TempDir, MockApplication) {
        let dir = tempfile::tempdir().unwrap();
        let module_root = dir.path().join("MyModule");
        fs::create_dir_all(module_root.join("data")).unwrap();
        fs::create_dir_all(module_root.join("lib")).unwrap();
        fs::create_dir_all(module_root.join("os/linux_x86_64")).unwrap();
        fs::write(module_root.join("data/thing.xml"), b"<xml/>").unwrap();
        fs::write(module_root.join("os/linux_x86_64/mylib.so"), b"binary").unwrap();

        let app = MockApplication { root: module_root };
        (dir, app)
    }

    #[test]
    fn trait_object_usage_and_basic_accessors() {
        let (_dir, app) = setup_module();
        // Prove object-safety: this trait can be used behind a trait object.
        let boxed: Box<dyn Application> = Box::new(app);

        assert_eq!(boxed.name(), "Ghidra");
        assert_eq!(boxed.application_version(), "11.2");
        assert!(boxed.in_single_jar_mode());
    }

    #[test]
    fn find_files_by_extension_in_application_walks_module_data_dirs() {
        let (_dir, app) = setup_module();
        let found = app.find_files_by_extension_in_application("xml");
        assert_eq!(found.len(), 1);
        assert!(found[0].absolute_path().ends_with("thing.xml"));

        // Also accepts a leading dot, mirroring verifyExtension's normalization.
        let found_dotted = app.find_files_by_extension_in_application(".xml");
        assert_eq!(found_dotted.len(), 1);
    }

    #[test]
    fn find_files_by_extension_in_named_module_only_searches_that_module() {
        let (_dir, app) = setup_module();
        assert_eq!(app.find_files_by_extension("MyModule", "xml").len(), 1);
        assert!(app.find_files_by_extension("NoSuchModule", "xml").is_empty());
    }

    #[test]
    fn library_directories_finds_lib_dir() {
        let (_dir, app) = setup_module();
        let dirs = app.library_directories();
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].absolute_path().ends_with("lib"));
    }

    #[test]
    fn get_module_data_file_reports_missing_module_and_missing_file() {
        let (_dir, app) = setup_module();

        let missing_module = app.get_module_data_file("NoSuchModule", "thing.xml");
        assert!(missing_module.is_err());

        let missing_file = app.get_module_data_file("MyModule", "nope.xml");
        assert!(missing_file.is_err());

        let found = app.get_module_data_file("MyModule", "thing.xml").unwrap();
        assert!(found.absolute_path().ends_with("thing.xml"));
    }

    #[test]
    fn get_os_file_in_module_finds_platform_specific_file() {
        let (_dir, app) = setup_module();
        let file = app.get_os_file_in_module("MyModule", "mylib.so").unwrap();
        assert!(file.to_string_lossy().ends_with("mylib.so"));

        let missing = app.get_os_file_in_module("MyModule", "nope.so");
        assert!(missing.is_err());
    }

    #[test]
    fn get_os_file_searches_every_module() {
        let (_dir, app) = setup_module();
        let file = app.get_os_file("mylib.so").unwrap();
        assert!(file.to_string_lossy().ends_with("mylib.so"));
    }

    #[test]
    fn module_root_dir_and_module_root_directories() {
        let (_dir, app) = setup_module();
        assert!(app.module_root_dir("MyModule").is_some());
        assert!(app.module_root_dir("NoSuchModule").is_none());
        assert_eq!(app.module_root_directories().len(), 1);
    }

    #[test]
    fn create_temp_file_creates_a_unique_file_with_prefix_and_suffix() {
        let (_dir, app) = setup_module();
        let file = app.create_temp_file("tmp", Some(".dat")).unwrap();
        assert!(file.exists());
        assert!(file.file_name().unwrap().to_string_lossy().starts_with("tmp"));
        assert!(file.file_name().unwrap().to_string_lossy().ends_with(".dat"));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn create_temp_file_rejects_short_prefix() {
        let (_dir, app) = setup_module();
        assert!(app.create_temp_file("ab", None).is_err());
    }

    #[test]
    #[should_panic(expected = "cannot contain / (path separator)")]
    fn verify_extension_rejects_path_separator() {
        let _ = verify_extension("a/b");
    }
}
