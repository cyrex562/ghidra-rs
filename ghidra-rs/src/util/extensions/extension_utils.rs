use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use crate::framework::Application;
use crate::util::exception::CancelledException;
use crate::util::extensions::ExtensionDetails;
use crate::util::msg::Msg;
use crate::util::seam_stubs::{
    ExtensionsLike, EXTENSION_PROPERTIES_FILE_NAME, EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED,
};
use crate::util::task::TaskMonitor;

/// Magic number identifying the first four bytes of a ZIP archive (`PK\x03\x04`), mirroring the
/// private `ExtensionUtils.ZIPFILE` constant. Used to detect a zip file by content rather than by
/// file extension.
const ZIP_MAGIC_NUMBER: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

/// Utilities for finding, installing, and caching Ghidra extensions.
///
/// Mirrors `ghidra.util.extensions.ExtensionUtils`, a static-method-only utility class that also
/// carries a static cache field (`extensions`). This port maps the Java class to an object-safe
/// trait so that other core types can depend on `Box<dyn ExtensionUtils>`/`Arc<dyn ExtensionUtils>`
/// instead of importing the concrete implementation directly; this type was flagged as a
/// dependency-cycle cut-point. The static cache field becomes ordinary instance state accessed
/// through [`Self::cached_extensions`]/[`Self::cached_extensions_mut`]/[`Self::set_cached_extensions`].
///
/// `Extensions` (the class backing the cache) is stood in for by the [`ExtensionsLike`] placeholder
/// in [`crate::util::seam_stubs`] until it is ported itself; because a placeholder trait cannot
/// stand in for a constructor, [`Self::new_extensions_registry`] takes over building instances
/// (mirroring `new Extensions(log)`). Likewise, because `ExtensionDetails` was itself already
/// turned into a trait (see its own cycle-breaking doc comment), [`Self::new_extension_details`]
/// takes over building instances (mirroring `new ExtensionDetails(name, desc, author, date,
/// version)`) wherever the Java original parses one out of a properties file.
///
/// Every Java method that resolves the process-wide `Application` singleton
/// (`Application.getApplicationLayout()`) instead takes an already-resolved `&dyn Application`
/// parameter, since a trait method has no static context to call through -- the same adaptation
/// [`ExtensionDetails`] makes.
///
/// [`Self::install`] mirrors the Java control flow exactly, including an apparent bug: when
/// installing from a zip file, `copyToInstallationFolder` is called unconditionally *after*
/// `unzipToInstallationFolder` rather than in an `else` branch, so a zip install always also
/// attempts (and, since the "source folder" is a file, generally fails) a directory copy of the
/// zip file itself. This is preserved for fidelity to the original rather than silently "fixed".
pub trait ExtensionUtils {
    /// Builds a new `ExtensionDetails` instance from parsed property values, mirroring `new
    /// ExtensionDetails(name, desc, author, date, version)`.
    fn new_extension_details(
        &self,
        name: String,
        description: Option<String>,
        author: Option<String>,
        created_on: Option<String>,
        version: Option<String>,
    ) -> Box<dyn ExtensionDetails>;

    /// Builds a new, empty extensions registry, mirroring `new Extensions(log)`.
    fn new_extensions_registry(&self) -> Box<dyn ExtensionsLike>;

    /// Returns the cached extensions registry, if the cache has been populated, mirroring reads
    /// of the private static `extensions` field.
    fn cached_extensions(&self) -> Option<&dyn ExtensionsLike>;

    /// Returns a mutable view of the cached extensions registry, if the cache has been populated.
    ///
    /// The trait object is bound `'static` (independent of the `&mut self` borrow's own
    /// lifetime) since implementors back this with an owned `Box<dyn ExtensionsLike>`; a
    /// borrow-scoped bound here would make `Box<dyn ExtensionsLike>`-backed implementations
    /// (the expected case) impossible to write, since `&mut` references are invariant over
    /// their pointee's embedded lifetime bound.
    fn cached_extensions_mut(&mut self) -> Option<&mut (dyn ExtensionsLike + 'static)>;

    /// Replaces the cached extensions registry, mirroring writes of the private static
    /// `extensions` field.
    fn set_cached_extensions(&mut self, extensions: Option<Box<dyn ExtensionsLike>>);

    /// Performs extension maintenance. This should be called at startup, before any plugins or
    /// extension points are loaded, mirroring `ExtensionUtils.initializeExtensions()`.
    fn initialize_extensions(&mut self, app: &dyn Application) {
        self.get_all_installed_extensions(app);
        if let Some(registry) = self.cached_extensions_mut() {
            registry.cleanup_extensions_marked_for_removal(app);
            registry.report_duplicate_extensions();
        }
    }

    /// Returns the installed extension whose install directory contains `path`, mirroring
    /// `ExtensionUtils.getExtension(String path)`.
    fn get_extension_containing_path(
        &mut self,
        path: &Path,
        app: &dyn Application,
    ) -> Option<&dyn ExtensionDetails> {
        let registry = self.get_all_installed_extensions(app);
        registry.active_extensions(app).into_iter().find(|ext| {
            ext.install_dir()
                .is_some_and(|install_dir| is_path_contained_within(&install_dir, path))
        })
    }

    /// Returns true if the given file or directory is a valid Ghidra extension (i.e. it contains
    /// an `extension.properties` file), mirroring `ExtensionUtils.isExtension(File)`.
    fn is_extension(&self, file: &Path) -> bool {
        self.get_extension_from_file(file, true).is_some()
    }

    /// Installs the given extension from `file` (a zip archive or a directory), mirroring
    /// `ExtensionUtils.install(ExtensionDetails, File, TaskMonitor)`. On success, the extension is
    /// added to the cache and its install directory is populated; returns whether installation
    /// succeeded.
    fn install(
        &mut self,
        mut extension: Box<dyn ExtensionDetails>,
        file: &Path,
        monitor: &dyn TaskMonitor,
        app: &dyn Application,
    ) -> bool {
        let result: Result<bool, InstallError> = (|| {
            if file.is_file() {
                // Mirrors the Java original exactly, including the fact that a successful unzip
                // result is discarded below rather than short-circuiting -- see this trait's own
                // doc comment.
                unzip_to_installation_folder(extension.as_mut(), file, monitor, app)?;
            }
            let success = copy_to_installation_folder(extension.as_mut(), file, app)?;
            Ok(success)
        })();

        match result {
            Ok(success) => {
                if success {
                    if self.cached_extensions().is_none() {
                        self.get_all_installed_extensions(app);
                    }
                    if let Some(registry) = self.cached_extensions_mut() {
                        registry.add(extension);
                    }
                }
                success
            }
            Err(InstallError::Cancelled(e)) => {
                Msg::info("ExtensionUtils", &format!("Extension installation cancelled by user: {e}"));
                false
            }
            Err(InstallError::Io(e)) => {
                Msg::show_error(
                    "ExtensionUtils",
                    "Error Installing Extension",
                    &format!("Unexpected error installing extension: {e}"),
                );
                false
            }
        }
    }

    /// Returns all installed extensions that are not marked for uninstall, mirroring
    /// `ExtensionUtils.getActiveInstalledExtensions()`.
    fn get_active_installed_extensions(
        &mut self,
        app: &dyn Application,
    ) -> Vec<&dyn ExtensionDetails> {
        self.get_all_installed_extensions(app).active_extensions(app)
    }

    /// Returns all installed extensions, mirroring `ExtensionUtils.getInstalledExtensions()`.
    fn get_installed_extensions(&mut self, app: &dyn Application) -> Vec<&dyn ExtensionDetails> {
        self.get_all_installed_extensions(app).all_extensions()
    }

    /// Returns (populating the cache first, if necessary) the registry of all installed
    /// extensions found under [`Application::application_layout`]'s extension installation
    /// directories, mirroring `ExtensionUtils.getAllInstalledExtensions()`.
    fn get_all_installed_extensions(&mut self, app: &dyn Application) -> &dyn ExtensionsLike {
        if self.cached_extensions().is_none() {
            let mut registry = self.new_extensions_registry();
            let layout = app.application_layout();
            for install_dir in layout.extension_installation_dirs() {
                if !install_dir.is_directory() {
                    continue;
                }
                let Some(dir_path) = install_dir.get_file(false) else {
                    continue;
                };
                for prop_file in find_extension_property_files(&dir_path) {
                    let Some(mut ext) = self.create_extension_from_properties(&prop_file) else {
                        continue;
                    };
                    if let Some(parent) = prop_file.parent() {
                        ext.set_install_dir(Some(parent.to_path_buf()));
                    }
                    registry.add(ext);
                }
            }
            self.set_cached_extensions(Some(registry));
        }
        self.cached_extensions().expect("cache was just populated")
    }

    /// Returns the extension found at `file` (a properties directory or zip archive), mirroring
    /// `ExtensionUtils.getExtension(File file, boolean quiet)`. Logs at trace level if `quiet`,
    /// otherwise at error level, when reading fails.
    fn get_extension_from_file(&self, file: &Path, quiet: bool) -> Option<Box<dyn ExtensionDetails>> {
        match try_get_extension(self, file) {
            Ok(ext) => ext,
            Err(e) => {
                let message = format!("Exception trying to read an extension from {}: {e}", file.display());
                if quiet {
                    Msg::trace("ExtensionUtils", &message);
                } else {
                    Msg::error("ExtensionUtils", &message);
                }
                None
            }
        }
    }

    /// Clears any cached extensions and searches for extensions, mirroring
    /// `ExtensionUtils.reload()`.
    fn reload(&mut self, app: &dyn Application) {
        Msg::trace("ExtensionUtils", &"Clearing extensions cache".to_string());
        self.clear_cache();
        self.get_all_installed_extensions(app);
    }

    /// Clears any cached extensions, mirroring `ExtensionUtils.clearCache()`.
    fn clear_cache(&mut self) {
        self.set_cached_extensions(None);
    }

    /// Returns all archive extensions found under
    /// [`Application::application_layout`]'s extension archive directory (zip files and
    /// directories), mirroring `ExtensionUtils.getArchiveExtensions()`. Unlike the installed-
    /// extension cache, this is recomputed on every call, matching the Java original.
    fn get_archive_extensions(&self, app: &dyn Application) -> Vec<Box<dyn ExtensionDetails>> {
        let layout = app.application_layout();
        let Some(archive_dir) = layout.extension_archive_dir() else {
            return Vec::new();
        };
        let Some(archive_path) = archive_dir.get_file(false) else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(&archive_path) else {
            return Vec::new();
        };

        let mut results: Vec<Box<dyn ExtensionDetails>> = Vec::new();
        let mut seen_names: HashSet<String> = HashSet::new();

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() || !is_zip_file(&path) {
                continue;
            }
            let Ok(Some(mut ext)) = extension_from_zip_top_level(self, &path) else {
                continue;
            };
            let name = ext.name();
            if !seen_names.insert(name.clone()) {
                Msg::error(
                    "ExtensionUtils",
                    &format!("Skipping extension '{name}' found in zip '{}'; extension by that name already found", path.display()),
                );
                continue;
            }
            ext.set_archive_path(Some(path.to_string_lossy().into_owned()));
            results.push(ext);
        }

        for prop_file in find_extension_property_files(&archive_path) {
            let Some(mut ext) = self.create_extension_from_properties(&prop_file) else {
                continue;
            };
            if let Some(parent) = prop_file.parent() {
                ext.set_archive_path(Some(parent.to_string_lossy().into_owned()));
            }
            let name = ext.name();
            if !seen_names.insert(name.clone()) {
                Msg::error(
                    "ExtensionUtils",
                    &format!("Skipping duplicate extension \"{name}\" found at {:?}", ext.install_path()),
                );
            }
            results.push(ext);
        }

        results
    }

    /// Loads an `ExtensionDetails` from a `extension.properties`-formatted file, mirroring
    /// `ExtensionUtils.createExtensionFromProperties(File)`.
    fn create_extension_from_properties(&self, file: &Path) -> Option<Box<dyn ExtensionDetails>> {
        match load_extension_from_properties(self, file) {
            Ok(ext) => Some(ext),
            Err(e) => {
                Msg::error(
                    "ExtensionUtils",
                    &format!("Error loading extension properties from {}: {e}", file.display()),
                );
                None
            }
        }
    }
}

/// Local error type unifying the two failure modes `ExtensionUtils.install` distinguishes: a
/// user-initiated cancellation versus any other I/O failure.
enum InstallError {
    Cancelled(CancelledException),
    Io(io::Error),
}

impl From<CancelledException> for InstallError {
    fn from(e: CancelledException) -> Self {
        InstallError::Cancelled(e)
    }
}

impl From<io::Error> for InstallError {
    fn from(e: io::Error) -> Self {
        InstallError::Io(e)
    }
}

/// Returns true if the given file is a valid `.zip` archive (checked by content, via the leading
/// 4-byte magic number, not by file extension), mirroring the private `ExtensionUtils.isZip`.
fn is_zip_file(file: &Path) -> bool {
    if file.is_dir() {
        return false;
    }
    let Ok(metadata) = fs::metadata(file) else {
        return false;
    };
    if metadata.len() < 4 {
        return false;
    }
    let Ok(mut f) = fs::File::open(file) else {
        return false;
    };
    let mut buf = [0u8; 4];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == ZIP_MAGIC_NUMBER
}

/// Returns true if `child` is `parent` or nested under it, mirroring
/// `FileUtilities.isPathContainedWithin(File, File)`.
fn is_path_contained_within(parent: &Path, child: &Path) -> bool {
    child.starts_with(parent)
}

/// Deletes a directory and everything under it, returning whether it succeeded, mirroring
/// `FileUtilities.deleteDir(File)`.
fn delete_dir(dir: &Path) -> bool {
    fs::remove_dir_all(dir).is_ok()
}

/// Recursively copies `src` to `dst`, mirroring `FileUtilities.copyDir(File, File, TaskMonitor)`.
fn copy_dir_recursive(src: &Path, dst: &Path, monitor: &dyn TaskMonitor) -> Result<(), InstallError> {
    monitor.check_cancelled()?;
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        monitor.check_cancelled()?;
        let path = entry.path();
        let dest_path = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive(&path, &dest_path, monitor)?;
        } else {
            fs::copy(&path, &dest_path)?;
        }
    }
    Ok(())
}

/// Warns (and returns true) if `extension_folder` already exists, mirroring the private
/// `ExtensionUtils.hasExistingExtension` (whose `TaskMonitor` parameter is unused in the Java
/// original, so it is not reproduced here).
fn has_existing_extension(extension_folder: &Path) -> bool {
    if extension_folder.exists() {
        Msg::show_warn(
            "ExtensionUtils",
            "Duplicate Extension Folder",
            &format!(
                "Attempting to install a new extension over an existing directory.\n\
                 Either remove the extension for that directory from the UI\n\
                 or close Ghidra and delete the directory and try installing again.\n\n\
                 Directory: {}",
                extension_folder.display()
            ),
        );
        return true;
    }
    false
}

/// Copies `source_folder` to the extension install location, mirroring the private
/// `ExtensionUtils.copyToInstallationFolder`.
fn copy_to_installation_folder(
    extension: &mut dyn ExtensionDetails,
    source_folder: &Path,
    app: &dyn Application,
) -> Result<bool, InstallError> {
    let layout = app.application_layout();
    let dirs = layout.extension_installation_dirs();
    let Some(install_dir) = dirs.first() else {
        return Ok(false);
    };
    let Some(install_dir_root) = install_dir.get_file(false) else {
        return Ok(false);
    };
    let name = source_folder.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    let destination_folder = install_dir_root.join(&name);
    if has_existing_extension(&destination_folder) {
        return Ok(false);
    }

    let monitor = crate::util::task::DummyMonitor;
    copy_dir_recursive(source_folder, &destination_folder, &monitor)?;
    extension.set_install_dir(Some(destination_folder));
    Ok(true)
}

/// Unpacks `file` (a zip archive) to the extension install location, mirroring the private
/// `ExtensionUtils.unzipToInstallationFolder`. Restores POSIX file permissions from the archive on
/// unix platforms, matching the Java original's use of Apache Commons Compress's permission-aware
/// zip reader (a no-op on non-unix platforms, matching Java's own `UnsupportedOperationException`
/// swallow there).
fn unzip_to_installation_folder(
    extension: &mut dyn ExtensionDetails,
    file: &Path,
    monitor: &dyn TaskMonitor,
    app: &dyn Application,
) -> Result<bool, InstallError> {
    let ext_name = extension.name();
    if ext_name.contains("..") {
        Msg::error("ExtensionUtils", &"Invalid extension name; name contains path elements".to_string());
        return Ok(false);
    }

    let layout = app.application_layout();
    let dirs = layout.extension_installation_dirs();
    let Some(install_dir) = dirs.first() else {
        return Ok(false);
    };
    let Some(install_dir_root) = install_dir.get_file(false) else {
        return Ok(false);
    };
    let destination_folder = install_dir_root.join(&ext_name);
    if has_existing_extension(&destination_folder) {
        return Ok(false);
    }

    let unzip_result = unzip_entries(file, &install_dir_root, monitor);
    if let Err(e) = unzip_result {
        if !delete_dir(&destination_folder) {
            return Err(io::Error::other(format!(
                "Failed to clean up partially installed extension directory: {}",
                destination_folder.display()
            ))
            .into());
        }
        return Err(e);
    }

    extension.set_install_dir(Some(destination_folder));
    Ok(true)
}

fn unzip_entries(file: &Path, install_dir_root: &Path, monitor: &dyn TaskMonitor) -> Result<(), InstallError> {
    let reader = fs::File::open(file)?;
    let mut archive = ZipArchive::new(reader).map_err(io::Error::other)?;
    for i in 0..archive.len() {
        monitor.check_cancelled()?;
        let mut entry = archive.by_index(i).map_err(io::Error::other)?;
        let entry_name = entry.name().to_string();
        let destination = install_dir_root.join(&entry_name);
        if !is_path_contained_within(install_dir_root, &destination) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Zip entry escapes target directory: {entry_name}"),
            )
            .into());
        }

        if entry_name.ends_with('/') {
            fs::create_dir_all(&destination)?;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out = fs::File::create(&destination)?;
            io::copy(&mut entry, &mut out)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = entry.unix_mode() {
                    if mode != 0 {
                        let _ = fs::set_permissions(&destination, fs::Permissions::from_mode(mode & 0o777));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Returns a list of `extension.properties`/`extension.properties.uninstalled` files found among
/// the immediate children of `install_dir`, mirroring the private
/// `ExtensionUtils.findExtensionPropertyFiles`.
fn find_extension_property_files(install_dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let Ok(entries) = fs::read_dir(install_dir) else {
        return results;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("Skeleton") {
            continue;
        }
        if let Some(prop_file) = get_property_file(&path) {
            results.push(prop_file);
        }
    }
    results
}

/// Returns an `extension.properties` or `extension.properties.uninstalled` file if `dir` contains
/// one (uninstalled takes precedence), mirroring the private `ExtensionUtils.getPropertyFile`.
fn get_property_file(dir: &Path) -> Option<PathBuf> {
    let uninstalled = dir.join(EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED);
    if uninstalled.exists() {
        return Some(uninstalled);
    }
    let installed = dir.join(EXTENSION_PROPERTIES_FILE_NAME);
    if installed.exists() {
        return Some(installed);
    }
    None
}

/// Parses a Java `.properties`-formatted string (`key=value` or `key: value` lines, `#`/`!`
/// comments) into a lookup map, standing in for `java.util.Properties.load(InputStream)`.
fn parse_java_properties(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        if let Some(idx) = trimmed.find(['=', ':']) {
            let key = trimmed[..idx].trim().to_string();
            let value = trimmed[idx + 1..].trim().to_string();
            map.insert(key, value);
        }
    }
    map
}

/// Builds an `ExtensionDetails` from parsed property values, mirroring the private
/// `ExtensionUtils.createExtensionDetails(Properties)`.
fn build_extension_details<U: ExtensionUtils + ?Sized>(
    utils: &U,
    props: &HashMap<String, String>,
) -> Box<dyn ExtensionDetails> {
    utils.new_extension_details(
        props.get("name").cloned().unwrap_or_default(),
        props.get("description").cloned(),
        props.get("author").cloned(),
        props.get("createdOn").cloned(),
        props.get("version").cloned(),
    )
}

/// Loads an `ExtensionDetails` from a properties file on disk, mirroring the private
/// `ExtensionUtils.tryToLoadExtensionFromProperties`.
fn load_extension_from_properties<U: ExtensionUtils + ?Sized>(
    utils: &U,
    file: &Path,
) -> io::Result<Box<dyn ExtensionDetails>> {
    let text = fs::read_to_string(file)?;
    Ok(build_extension_details(utils, &parse_java_properties(&text)))
}

/// Returns true if `name` is an `extension.properties` entry at the top level of a zip archive
/// (i.e. exactly `<dir>/extension.properties`), mirroring the two-part-path check in the private
/// `ExtensionUtils.getProperties(ZipFile, ZipArchiveEntry)`.
fn is_top_level_properties_entry(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').filter(|p| !p.is_empty()).collect();
    parts.len() == 2 && name.ends_with(EXTENSION_PROPERTIES_FILE_NAME)
}

/// Reads the single top-level `extension.properties` entry out of a zip archive, if any, mirroring
/// the private `ExtensionUtils.getProperties(ZipFile)` plus `createExtensionDetails`. Returns an
/// error if more than one such entry is found (mirroring the Java original's thrown
/// `IOException`).
fn extension_from_zip_top_level<U: ExtensionUtils + ?Sized>(
    utils: &U,
    file: &Path,
) -> io::Result<Option<Box<dyn ExtensionDetails>>> {
    let reader = fs::File::open(file)?;
    let mut archive = ZipArchive::new(reader).map_err(io::Error::other)?;
    let mut found: Option<Box<dyn ExtensionDetails>> = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(io::Error::other)?;
        let name = entry.name().to_string();
        if !is_top_level_properties_entry(&name) {
            continue;
        }
        let mut contents = String::new();
        entry.read_to_string(&mut contents)?;
        if found.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Zip file contains multiple extension properties files",
            ));
        }
        found = Some(build_extension_details(utils, &parse_java_properties(&contents)));
    }
    Ok(found)
}

/// Loads an extension from a directory (containing an `extension.properties` file) or a zip
/// archive (containing one at the top level), mirroring the private
/// `ExtensionUtils.tryToGetExtension`.
fn try_get_extension<U: ExtensionUtils + ?Sized>(
    utils: &U,
    file: &Path,
) -> io::Result<Option<Box<dyn ExtensionDetails>>> {
    if file.is_dir() {
        let candidate = file.join(EXTENSION_PROPERTIES_FILE_NAME);
        if candidate.is_file() {
            return load_extension_from_properties(utils, &candidate).map(Some);
        }
    }

    if is_zip_file(file) {
        return match extension_from_zip_top_level(utils, file)? {
            Some(ext) => Ok(Some(ext)),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "No extension.properties file found in zip")),
        };
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::seam_stubs::{ApplicationLayoutLike, Architecture, GModuleLike};
    use crate::framework::{OperatingSystem, Platform};
    use crate::generic::jar::ResourceFile;
    use std::sync::Mutex;

    struct MockExtensionDetails {
        name: String,
        description: Option<String>,
        author: Option<String>,
        created_on: Option<String>,
        version: Option<String>,
        install_dir: Option<PathBuf>,
        archive_path: Option<String>,
    }

    impl Default for MockExtensionDetails {
        fn default() -> Self {
            Self {
                name: String::new(),
                description: None,
                author: None,
                created_on: None,
                version: None,
                install_dir: None,
                archive_path: None,
            }
        }
    }

    impl ExtensionDetails for MockExtensionDetails {
        fn name(&self) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, name: String) {
            self.name = name;
        }
        fn description(&self) -> Option<String> {
            self.description.clone()
        }
        fn set_description(&mut self, description: Option<String>) {
            self.description = description;
        }
        fn author(&self) -> Option<String> {
            self.author.clone()
        }
        fn set_author(&mut self, author: Option<String>) {
            self.author = author;
        }
        fn created_on(&self) -> Option<String> {
            self.created_on.clone()
        }
        fn set_created_on(&mut self, created_on: Option<String>) {
            self.created_on = created_on;
        }
        fn version(&self) -> Option<String> {
            self.version.clone()
        }
        fn set_version(&mut self, version: Option<String>) {
            self.version = version;
        }
        fn install_dir(&self) -> Option<PathBuf> {
            self.install_dir.clone()
        }
        fn set_install_dir(&mut self, install_dir: Option<PathBuf>) {
            self.install_dir = install_dir;
        }
        fn archive_path(&self) -> Option<String> {
            self.archive_path.clone()
        }
        fn set_archive_path(&mut self, archive_path: Option<String>) {
            self.archive_path = archive_path;
        }
    }

    /// A simple, real implementation of [`ExtensionsLike`] backing the smoke tests below, proving
    /// [`ExtensionsLike`] is itself object-safe as well as [`ExtensionUtils`].
    #[derive(Default)]
    struct SimpleExtensionsRegistry {
        by_name: HashMap<String, Vec<Box<dyn ExtensionDetails>>>,
    }

    impl ExtensionsLike for SimpleExtensionsRegistry {
        fn add(&mut self, extension: Box<dyn ExtensionDetails>) {
            self.by_name.entry(extension.name()).or_default().push(extension);
        }

        fn active_extensions(&self, app: &dyn Application) -> Vec<&dyn ExtensionDetails> {
            self.by_name
                .values()
                .filter_map(|list| list.first())
                .filter(|ext| !ext.is_pending_uninstall(app))
                .map(|ext| ext.as_ref())
                .collect()
        }

        fn all_extensions(&self) -> Vec<&dyn ExtensionDetails> {
            self.by_name.values().filter_map(|list| list.first()).map(|ext| ext.as_ref()).collect()
        }

        fn cleanup_extensions_marked_for_removal(&mut self, app: &dyn Application) {
            for list in self.by_name.values_mut() {
                list.retain_mut(|ext| {
                    if !ext.is_pending_uninstall(app) {
                        return true;
                    }
                    let Some(install_dir) = ext.install_dir() else {
                        return false;
                    };
                    if delete_dir(&install_dir) {
                        ext.set_install_dir(None);
                    }
                    false
                });
            }
            self.by_name.retain(|_, list| !list.is_empty());
        }

        fn report_duplicate_extensions(&self) {
            // Logging only; nothing to assert here.
        }
    }

    #[derive(Default)]
    struct SimpleExtensionUtils {
        cache: Option<Box<dyn ExtensionsLike>>,
    }

    impl ExtensionUtils for SimpleExtensionUtils {
        fn new_extension_details(
            &self,
            name: String,
            description: Option<String>,
            author: Option<String>,
            created_on: Option<String>,
            version: Option<String>,
        ) -> Box<dyn ExtensionDetails> {
            Box::new(MockExtensionDetails {
                name,
                description,
                author,
                created_on,
                version,
                ..Default::default()
            })
        }

        fn new_extensions_registry(&self) -> Box<dyn ExtensionsLike> {
            Box::new(SimpleExtensionsRegistry::default())
        }

        fn cached_extensions(&self) -> Option<&dyn ExtensionsLike> {
            self.cache.as_deref()
        }

        fn cached_extensions_mut(&mut self) -> Option<&mut (dyn ExtensionsLike + 'static)> {
            self.cache.as_deref_mut()
        }

        fn set_cached_extensions(&mut self, extensions: Option<Box<dyn ExtensionsLike>>) {
            self.cache = extensions;
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
        extension_dirs: Vec<ResourceFile>,
        archive_dir: Option<ResourceFile>,
    }

    impl ApplicationLayoutLike for MockApplicationLayout {
        fn application_properties(&self) -> &dyn crate::framework::ApplicationProperties {
            unimplemented!("not exercised by ExtensionUtils")
        }
        fn application_installation_dir(&self) -> Option<&ResourceFile> {
            None
        }
        fn extension_installation_dirs(&self) -> Vec<ResourceFile> {
            self.extension_dirs.iter().map(|d| d.clone()).collect()
        }
        fn extension_archive_dir(&self) -> Option<ResourceFile> {
            self.archive_dir.clone()
        }
    }

    struct MockApplication {
        extension_dirs: Vec<PathBuf>,
        archive_dir: Option<PathBuf>,
    }

    impl Application for MockApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            Box::new(MockApplicationLayout {
                extension_dirs: self.extension_dirs.iter().cloned().map(ResourceFile::new).collect(),
                archive_dir: self.archive_dir.clone().map(ResourceFile::new),
            })
        }
        fn current_platform(&self) -> Box<dyn Platform> {
            Box::new(MockPlatform)
        }
    }

    fn write_extension(install_root: &Path, name: &str, extra_properties: &str) -> PathBuf {
        let ext_dir = install_root.join(name);
        fs::create_dir_all(&ext_dir).unwrap();
        fs::write(
            ext_dir.join(EXTENSION_PROPERTIES_FILE_NAME),
            format!("name={name}\ndescription=A test extension\nversion=1.0\n{extra_properties}"),
        )
        .unwrap();
        ext_dir
    }

    #[test]
    fn trait_objects_are_object_safe() {
        // Proves both ExtensionUtils and ExtensionsLike can be used behind a trait object.
        let utils: Box<dyn ExtensionUtils> = Box::new(SimpleExtensionUtils::default());
        let registry: Box<dyn ExtensionsLike> = utils.new_extensions_registry();
        drop(registry);
    }

    #[test]
    fn get_all_installed_extensions_discovers_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        write_extension(dir.path(), "Alpha", "");
        write_extension(dir.path(), "Beta", "");
        // A file matching the "Skeleton" name is skipped entirely.
        fs::create_dir_all(dir.path().join("Skeleton")).unwrap();
        fs::write(dir.path().join("Skeleton").join(EXTENSION_PROPERTIES_FILE_NAME), "name=Skeleton").unwrap();

        let mut utils = SimpleExtensionUtils::default();
        let app = MockApplication { extension_dirs: vec![dir.path().to_path_buf()], archive_dir: None };

        let names: HashSet<String> =
            utils.get_installed_extensions(&app).into_iter().map(|e| e.name()).collect();
        assert_eq!(names, HashSet::from(["Alpha".to_string(), "Beta".to_string()]));

        // A second call reuses the cache rather than re-scanning the filesystem: removing the
        // backing directory doesn't change the result.
        fs::remove_dir_all(dir.path().join("Alpha")).unwrap();
        let cached_names: HashSet<String> =
            utils.get_installed_extensions(&app).into_iter().map(|e| e.name()).collect();
        assert_eq!(cached_names, HashSet::from(["Alpha".to_string(), "Beta".to_string()]));
    }

    #[test]
    fn get_extension_containing_path_finds_owning_extension() {
        let dir = tempfile::tempdir().unwrap();
        let ext_dir = write_extension(dir.path(), "Gamma", "");
        let nested = ext_dir.join("data").join("file.txt");

        let mut utils = SimpleExtensionUtils::default();
        let app = MockApplication { extension_dirs: vec![dir.path().to_path_buf()], archive_dir: None };

        let found = utils.get_extension_containing_path(&nested, &app);
        assert_eq!(found.map(|e| e.name()), Some("Gamma".to_string()));

        let outside = utils.get_extension_containing_path(Path::new("/somewhere/else"), &app);
        assert!(outside.is_none());
    }

    #[test]
    fn create_extension_from_properties_parses_fields() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(EXTENSION_PROPERTIES_FILE_NAME);
        fs::write(&file, "name=Delta\ndescription=Does things\nauthor=Someone\ncreatedOn=2024-01-01\nversion=2.1\n")
            .unwrap();

        let utils = SimpleExtensionUtils::default();
        let ext = utils.create_extension_from_properties(&file).expect("should parse");
        assert_eq!(ext.name(), "Delta");
        assert_eq!(ext.description().as_deref(), Some("Does things"));
        assert_eq!(ext.author().as_deref(), Some("Someone"));
        assert_eq!(ext.version().as_deref(), Some("2.1"));
    }

    #[test]
    fn create_extension_from_properties_missing_file_returns_none() {
        let utils = SimpleExtensionUtils::default();
        let result = utils.create_extension_from_properties(Path::new("/does/not/exist/extension.properties"));
        assert!(result.is_none());
    }

    #[test]
    fn is_extension_true_for_directory_with_properties_and_false_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let ext_dir = write_extension(dir.path(), "Epsilon", "");
        let empty_dir = dir.path().join("NotAnExtension");
        fs::create_dir_all(&empty_dir).unwrap();

        let utils = SimpleExtensionUtils::default();
        assert!(utils.is_extension(&ext_dir));
        assert!(!utils.is_extension(&empty_dir));
    }

    #[test]
    fn install_copies_directory_and_populates_cache() {
        let source_root = tempfile::tempdir().unwrap();
        let source_ext = source_root.path().join("Zeta");
        fs::create_dir_all(source_ext.join("lib")).unwrap();
        fs::write(source_ext.join(EXTENSION_PROPERTIES_FILE_NAME), "name=Zeta\n").unwrap();
        fs::write(source_ext.join("lib").join("thing.jar"), b"jar contents").unwrap();

        let install_root = tempfile::tempdir().unwrap();
        let mut utils = SimpleExtensionUtils::default();
        let app = MockApplication {
            extension_dirs: vec![install_root.path().to_path_buf()],
            archive_dir: None,
        };

        let extension: Box<dyn ExtensionDetails> = Box::new(MockExtensionDetails {
            name: "Zeta".to_string(),
            ..Default::default()
        });
        let monitor = crate::util::task::DummyMonitor;

        let success = utils.install(extension, &source_ext, &monitor, &app);
        assert!(success);

        let installed_lib = install_root.path().join("Zeta").join("lib").join("thing.jar");
        assert!(installed_lib.exists());

        let cached_names: Vec<String> = utils
            .cached_extensions()
            .expect("cache should be populated by install")
            .all_extensions()
            .into_iter()
            .map(|e| e.name())
            .collect();
        assert_eq!(cached_names, vec!["Zeta".to_string()]);
    }

    #[test]
    fn install_fails_when_destination_already_exists() {
        let source_root = tempfile::tempdir().unwrap();
        let source_ext = source_root.path().join("Eta");
        fs::create_dir_all(&source_ext).unwrap();
        fs::write(source_ext.join(EXTENSION_PROPERTIES_FILE_NAME), "name=Eta\n").unwrap();

        let install_root = tempfile::tempdir().unwrap();
        fs::create_dir_all(install_root.path().join("Eta")).unwrap();

        let mut utils = SimpleExtensionUtils::default();
        let app = MockApplication {
            extension_dirs: vec![install_root.path().to_path_buf()],
            archive_dir: None,
        };
        let extension: Box<dyn ExtensionDetails> =
            Box::new(MockExtensionDetails { name: "Eta".to_string(), ..Default::default() });
        let monitor = crate::util::task::DummyMonitor;

        let success = utils.install(extension, &source_ext, &monitor, &app);
        assert!(!success);
    }

    #[test]
    fn clear_cache_forces_rescan() {
        let dir = tempfile::tempdir().unwrap();
        write_extension(dir.path(), "Theta", "");

        let mut utils = SimpleExtensionUtils::default();
        let app = MockApplication { extension_dirs: vec![dir.path().to_path_buf()], archive_dir: None };

        assert_eq!(utils.get_installed_extensions(&app).len(), 1);
        write_extension(dir.path(), "Iota", "");
        assert_eq!(utils.get_installed_extensions(&app).len(), 1, "still cached");

        utils.clear_cache();
        assert_eq!(utils.get_installed_extensions(&app).len(), 2, "rescanned after clear");
    }

    #[test]
    fn reload_rescans_immediately() {
        let dir = tempfile::tempdir().unwrap();
        write_extension(dir.path(), "Kappa", "");

        let mut utils = SimpleExtensionUtils::default();
        let app = MockApplication { extension_dirs: vec![dir.path().to_path_buf()], archive_dir: None };

        assert_eq!(utils.get_installed_extensions(&app).len(), 1);
        write_extension(dir.path(), "Lambda", "");
        utils.reload(&app);
        assert_eq!(utils.get_installed_extensions(&app).len(), 2);
    }

    #[test]
    fn is_top_level_properties_entry_requires_exactly_two_parts() {
        assert!(is_top_level_properties_entry("MyExt/extension.properties"));
        assert!(!is_top_level_properties_entry("extension.properties"));
        assert!(!is_top_level_properties_entry("MyExt/nested/extension.properties"));
        assert!(!is_top_level_properties_entry("MyExt/other.properties"));
    }

    #[test]
    fn parse_java_properties_skips_comments_and_blank_lines() {
        let parsed = parse_java_properties("# a comment\n\nname = Value\n! also a comment\nversion:9\n");
        assert_eq!(parsed.get("name").map(String::as_str), Some("Value"));
        assert_eq!(parsed.get("version").map(String::as_str), Some("9"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn is_zip_file_detects_magic_number() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("thing.zip");
        fs::write(&zip_path, [0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]).unwrap();
        let text_path = dir.path().join("thing.txt");
        fs::write(&text_path, b"not a zip").unwrap();

        assert!(is_zip_file(&zip_path));
        assert!(!is_zip_file(&text_path));
        assert!(!is_zip_file(dir.path()));
    }

    // Ensures cached_extensions_mut's `&mut dyn ExtensionsLike` accessor compiles for a wrapper
    // that stores extra bookkeeping alongside the cache (an object-safety/borrow-shape smoke
    // test, not just a trivially-true assertion).
    #[test]
    fn cached_extensions_mut_allows_direct_mutation() {
        let log: Mutex<Vec<String>> = Mutex::new(Vec::new());
        struct LoggingRegistry<'a> {
            inner: SimpleExtensionsRegistry,
            log: &'a Mutex<Vec<String>>,
        }
        impl ExtensionsLike for LoggingRegistry<'_> {
            fn add(&mut self, extension: Box<dyn ExtensionDetails>) {
                self.log.lock().unwrap().push(extension.name());
                self.inner.add(extension);
            }
            fn active_extensions(&self, app: &dyn Application) -> Vec<&dyn ExtensionDetails> {
                self.inner.active_extensions(app)
            }
            fn all_extensions(&self) -> Vec<&dyn ExtensionDetails> {
                self.inner.all_extensions()
            }
            fn cleanup_extensions_marked_for_removal(&mut self, app: &dyn Application) {
                self.inner.cleanup_extensions_marked_for_removal(app);
            }
            fn report_duplicate_extensions(&self) {
                self.inner.report_duplicate_extensions();
            }
        }

        let mut registry = LoggingRegistry { inner: SimpleExtensionsRegistry::default(), log: &log };
        let cache: &mut dyn ExtensionsLike = &mut registry;
        cache.add(Box::new(MockExtensionDetails { name: "Mu".to_string(), ..Default::default() }));
        assert_eq!(log.lock().unwrap().as_slice(), &["Mu".to_string()]);
    }
}
