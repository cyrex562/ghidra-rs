use std::path::{Path, PathBuf};

use crate::framework::Application;
use crate::util::msg::Msg;
use crate::util::seam_stubs::{
    EXTENSION_PROPERTIES_FILE_NAME, EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED,
    MODULE_MANIFEST_FILE_NAME, MODULE_MANIFEST_FILE_NAME_UNINSTALLED,
};

/// Representation of a Ghidra extension. Encapsulates all information required to uniquely
/// identify an extension and where (or if) it has been installed.
///
/// Mirrors `ghidra.util.extensions.ExtensionDetails`. This type was flagged as a
/// dependency-cycle cut-point, so it is ported to an object-safe trait rather than a concrete
/// struct: callers depend on `Box<dyn ExtensionDetails>`/`&dyn ExtensionDetails` instead of a
/// single concrete backing implementation. Every method that in Java resolves the process-wide
/// `Application` singleton (`Application.inSingleJarMode()`, `Application.getApplicationLayout()`)
/// instead takes an already-resolved `&dyn Application` parameter, since a trait method has no
/// static context to call through.
///
/// Two Java members are not reproduced as such: `hashCode`/`equals` (name-only identity) are
/// exposed here as [`Self::equals_by_name`] rather than the `PartialEq`/`Hash` traits, since those
/// traits are not object-safe against `dyn ExtensionDetails`; likewise `compareTo` is exposed as
/// [`Self::compare_by_name`] rather than `Ord`/`PartialOrd` for the same reason.
pub trait ExtensionDetails {
    /// Returns the name of the extension. This must be unique, mirroring
    /// `ExtensionDetails.getName()`.
    fn name(&self) -> String;

    /// Sets the name of the extension, mirroring `ExtensionDetails.setName(String)`.
    fn set_name(&mut self, name: String);

    /// Returns the brief description, for display purposes only, mirroring
    /// `ExtensionDetails.getDescription()`.
    fn description(&self) -> Option<String>;

    /// Sets the description, mirroring `ExtensionDetails.setDescription(String)`.
    fn set_description(&mut self, description: Option<String>);

    /// Returns the author of the extension, for display purposes only, mirroring
    /// `ExtensionDetails.getAuthor()`.
    fn author(&self) -> Option<String>;

    /// Sets the author, mirroring `ExtensionDetails.setAuthor(String)`.
    fn set_author(&mut self, author: Option<String>);

    /// Returns the date when the extension was created, for display purposes only, mirroring
    /// `ExtensionDetails.getCreatedOn()`.
    fn created_on(&self) -> Option<String>;

    /// Sets the creation date, mirroring `ExtensionDetails.setCreatedOn(String)`.
    fn set_created_on(&mut self, created_on: Option<String>);

    /// Returns the extension version, mirroring `ExtensionDetails.getVersion()`.
    fn version(&self) -> Option<String>;

    /// Sets the extension version, mirroring `ExtensionDetails.setVersion(String)`.
    fn set_version(&mut self, version: Option<String>);

    /// Returns the absolute path to where this extension is installed, or `None` if not
    /// installed, mirroring `ExtensionDetails.getInstallDir()`.
    fn install_dir(&self) -> Option<PathBuf>;

    /// Sets the install directory, mirroring `ExtensionDetails.setInstallDir(File)`.
    fn set_install_dir(&mut self, install_dir: Option<PathBuf>);

    /// Returns the absolute path to where the original source archive (zip) for this extension
    /// can be found, or `None` if there is no archive, mirroring
    /// `ExtensionDetails.getArchivePath()`.
    fn archive_path(&self) -> Option<String>;

    /// Sets the archive path, mirroring `ExtensionDetails.setArchivePath(String)`.
    fn set_archive_path(&mut self, archive_path: Option<String>);

    /// Returns the location where this extension is installed, or `None` if the extension is not
    /// installed, mirroring `ExtensionDetails.getInstallPath()`.
    fn install_path(&self) -> Option<String> {
        self.install_dir().map(|dir| dir.to_string_lossy().into_owned())
    }

    /// Returns true if this extension came from an archive, mirroring
    /// `ExtensionDetails.isFromArchive()`.
    fn is_from_archive(&self) -> bool {
        self.archive_path().is_some()
    }

    /// Returns the paths of all jar files living in the `{extension dir}/lib` directory for an
    /// installed extension, mirroring `ExtensionDetails.getLibraries()` (Java returns
    /// `Set<URL>`; this returns the backing file paths directly since no `URL` type has been
    /// ported yet).
    fn libraries(&self, app: &dyn Application) -> Vec<PathBuf> {
        if !self.is_installed(app) {
            return Vec::new();
        }

        let Some(install_dir) = self.install_dir() else {
            return Vec::new();
        };

        let mut jar_files = Vec::new();
        find_jar_files(&install_dir.join("lib"), &mut jar_files);
        jar_files
    }

    /// Returns true if the extension is installed, mirroring `ExtensionDetails.isInstalled()`.
    /// An extension is known to be installed if it has a valid installation path AND that path
    /// contains a `Module.manifest` file. Extensions that are
    /// [`is_pending_uninstall`](Self::is_pending_uninstall) are still on the filesystem, but will
    /// be removed on next launch.
    fn is_installed(&self, app: &dyn Application) -> bool {
        let Some(install_dir) = self.install_dir() else {
            return false;
        };

        if app.in_single_jar_mode() {
            return true;
        }

        install_dir.join(MODULE_MANIFEST_FILE_NAME).exists()
    }

    /// Returns true if this extension is marked to be uninstalled, mirroring
    /// `ExtensionDetails.isPendingUninstall()`.
    fn is_pending_uninstall(&self, app: &dyn Application) -> bool {
        let Some(install_dir) = self.install_dir() else {
            return false;
        };

        if app.in_single_jar_mode() {
            return false; // can't uninstall from single jar mode
        }

        install_dir.join(MODULE_MANIFEST_FILE_NAME_UNINSTALLED).exists()
    }

    /// Returns true if this extension is installed under an installation folder or inside of a
    /// source control repository folder, mirroring
    /// `ExtensionDetails.isInstalledInInstallationFolder()`.
    fn is_installed_in_installation_folder(&self, app: &dyn Application) -> bool {
        let Some(install_dir) = self.install_dir() else {
            return false; // not installed
        };

        let layout = app.application_layout();
        let ext_dirs = layout.extension_installation_dirs();
        if ext_dirs.len() < 2 {
            Msg::trace(
                "ExtensionDetails",
                &"Unexpected extension installation dirs; revisit this assumption".to_string(),
            );
            return false;
        }

        ext_dirs[1..]
            .iter()
            .any(|dir| install_dir.starts_with(Path::new(&dir.absolute_path())))
    }

    /// Converts the module manifest and extension properties file that are in an installed state
    /// to an uninstalled state, mirroring `ExtensionDetails.markForUninstall()`.
    ///
    /// Specifically, the following are renamed:
    /// - `Module.manifest` to `Module.manifest.uninstalled`
    /// - `extension.properties` to `extension.properties.uninstalled`
    ///
    /// Returns false if any renames fail.
    fn mark_for_uninstall(&mut self) -> bool {
        let Some(install_dir) = self.install_dir() else {
            return false; // already marked as uninstalled
        };

        Msg::trace(
            "ExtensionDetails",
            &format!("Marking extension for uninstall '{}'", install_dir.display()),
        );

        let mut success = true;

        let manifest = install_dir.join(MODULE_MANIFEST_FILE_NAME);
        if manifest.exists() {
            let new_file = install_dir.join(MODULE_MANIFEST_FILE_NAME_UNINSTALLED);
            if std::fs::rename(&manifest, &new_file).is_err() {
                Msg::trace(
                    "ExtensionDetails",
                    &format!("Unable to rename module manifest file: {}", manifest.display()),
                );
                success = false;
            }
        } else {
            Msg::trace(
                "ExtensionDetails",
                &format!("No manifest file found for extension '{}'", self.name()),
            );
        }

        let properties = install_dir.join(EXTENSION_PROPERTIES_FILE_NAME);
        if properties.exists() {
            let new_file = install_dir.join(EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED);
            if std::fs::rename(&properties, &new_file).is_err() {
                Msg::trace(
                    "ExtensionDetails",
                    &format!("Unable to rename properties file: {}", properties.display()),
                );
                success = false;
            }
        } else {
            Msg::trace(
                "ExtensionDetails",
                &format!("No properties file found for extension '{}'", self.name()),
            );
        }

        success
    }

    /// A companion method for [`mark_for_uninstall`](Self::mark_for_uninstall) that allows
    /// extensions marked for cleanup to be restored to the installed state, mirroring
    /// `ExtensionDetails.clearMarkForUninstall()`.
    ///
    /// Specifically, the following are renamed:
    /// - `Module.manifest.uninstalled` to `Module.manifest`
    /// - `extension.properties.uninstalled` to `extension.properties`
    ///
    /// Returns true if successful.
    fn clear_mark_for_uninstall(&mut self) -> bool {
        let Some(install_dir) = self.install_dir() else {
            Msg::error(
                "ExtensionDetails",
                &format!(
                    "Cannot restore extension; extension installation dir is missing for: {}",
                    self.name()
                ),
            );
            return false; // already marked as uninstalled
        };

        Msg::trace(
            "ExtensionDetails",
            &format!("Restoring extension state files for '{}'", install_dir.display()),
        );

        let mut success = true;

        let manifest = install_dir.join(MODULE_MANIFEST_FILE_NAME_UNINSTALLED);
        if manifest.exists() {
            let new_file = install_dir.join(MODULE_MANIFEST_FILE_NAME);
            if std::fs::rename(&manifest, &new_file).is_err() {
                Msg::trace(
                    "ExtensionDetails",
                    &format!("Unable to rename module manifest file: {}", manifest.display()),
                );
                success = false;
            }
        } else {
            Msg::trace(
                "ExtensionDetails",
                &format!("No manifest file found for extension '{}'", self.name()),
            );
        }

        let properties = install_dir.join(EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED);
        if properties.exists() {
            let new_file = install_dir.join(EXTENSION_PROPERTIES_FILE_NAME);
            if std::fs::rename(&properties, &new_file).is_err() {
                Msg::trace(
                    "ExtensionDetails",
                    &format!("Unable to rename properties file: {}", properties.display()),
                );
                success = false;
            }
        } else {
            Msg::trace(
                "ExtensionDetails",
                &format!("No properties file found for extension '{}'", self.name()),
            );
        }

        success
    }

    /// Returns true if this and `other` have the same name, mirroring
    /// `ExtensionDetails.equals(Object)`/`hashCode()` (which are name-only).
    fn equals_by_name(&self, other: &dyn ExtensionDetails) -> bool {
        self.name() == other.name()
    }

    /// Compares this extension to `other` by name, mirroring
    /// `ExtensionDetails.compareTo(ExtensionDetails)`.
    fn compare_by_name(&self, other: &dyn ExtensionDetails) -> std::cmp::Ordering {
        self.name().cmp(&other.name())
    }

    /// Returns a JSON-object rendering of this extension's fields, mirroring
    /// `ExtensionDetails.toString()` (`Json.toString(this)`).
    fn to_json_string(&self) -> String {
        format!(
            "{{\"installDir\":{},\"archivePath\":{},\"name\":{},\"description\":{},\"createdOn\":{},\"author\":{},\"version\":{}}}",
            json_opt_string(self.install_path()),
            json_opt_string(self.archive_path()),
            json_string(&self.name()),
            json_opt_string(self.description()),
            json_opt_string(self.created_on()),
            json_opt_string(self.author()),
            json_opt_string(self.version()),
        )
    }
}

/// Accumulates every `.jar` file directly within `dir`, mirroring the private
/// `ExtensionDetails.findJarFiles(File, Set<File>)`.
fn find_jar_files(dir: &Path, jar_files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "jar") {
            jar_files.push(path);
        }
    }
}

/// Renders a JSON string literal, escaping backslashes and double quotes.
fn json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Renders an optional string as either a JSON string literal or `null`.
fn json_opt_string(value: Option<String>) -> String {
    match value {
        Some(v) => json_string(&v),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::seam_stubs::{ApplicationLayoutLike, Architecture, GModuleLike};
    use crate::framework::{OperatingSystem, Platform};
    use crate::generic::jar::ResourceFile;

    #[derive(Default)]
    struct MockExtensionDetails {
        name: String,
        description: Option<String>,
        author: Option<String>,
        created_on: Option<String>,
        version: Option<String>,
        install_dir: Option<PathBuf>,
        archive_path: Option<String>,
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
        single_jar_mode: bool,
        extension_dirs: Vec<ResourceFile>,
    }

    impl ApplicationLayoutLike for MockApplicationLayout {
        fn application_properties(&self) -> &dyn crate::framework::ApplicationProperties {
            unimplemented!("not exercised by ExtensionDetails")
        }
        fn application_installation_dir(&self) -> Option<&ResourceFile> {
            None
        }
        fn in_single_jar_mode(&self) -> bool {
            self.single_jar_mode
        }
        fn extension_installation_dirs(&self) -> Vec<ResourceFile> {
            self.extension_dirs.iter().map(|d| d.clone()).collect()
        }
    }

    struct MockApplication {
        single_jar_mode: bool,
        extension_dirs: Vec<PathBuf>,
    }

    impl Application for MockApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            Box::new(MockApplicationLayout {
                single_jar_mode: self.single_jar_mode,
                extension_dirs: self.extension_dirs.iter().cloned().map(ResourceFile::new).collect(),
            })
        }
        fn current_platform(&self) -> Box<dyn Platform> {
            Box::new(MockPlatform)
        }
    }

    fn setup_installed_extension() -> (tempfile::TempDir, MockExtensionDetails) {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("MyExtension");
        std::fs::create_dir_all(install_dir.join("lib")).unwrap();
        std::fs::write(install_dir.join(MODULE_MANIFEST_FILE_NAME), b"").unwrap();
        std::fs::write(install_dir.join(EXTENSION_PROPERTIES_FILE_NAME), b"").unwrap();
        std::fs::write(install_dir.join("lib").join("thing.jar"), b"jar").unwrap();
        std::fs::write(install_dir.join("lib").join("readme.txt"), b"not a jar").unwrap();

        let mut ext = MockExtensionDetails {
            name: "MyExtension".to_string(),
            ..Default::default()
        };
        ext.set_install_dir(Some(install_dir));
        (dir, ext)
    }

    #[test]
    fn trait_object_usage_and_install_state() {
        let (_dir, ext) = setup_installed_extension();
        // Prove object-safety: this trait can be used behind a trait object.
        let boxed: Box<dyn ExtensionDetails> = Box::new(ext);

        let app = MockApplication { single_jar_mode: false, extension_dirs: vec![] };
        assert!(boxed.is_installed(&app));
        assert!(!boxed.is_pending_uninstall(&app));
        assert!(!boxed.is_from_archive());
        assert_eq!(boxed.install_path().unwrap(), boxed.install_dir().unwrap().to_string_lossy());
    }

    #[test]
    fn single_jar_mode_is_always_installed_and_never_pending_uninstall() {
        let (_dir, ext) = setup_installed_extension();
        let app = MockApplication { single_jar_mode: true, extension_dirs: vec![] };
        assert!(ext.is_installed(&app));
        assert!(!ext.is_pending_uninstall(&app));
    }

    #[test]
    fn not_installed_without_install_dir() {
        let ext = MockExtensionDetails { name: "NoDir".to_string(), ..Default::default() };
        let app = MockApplication { single_jar_mode: false, extension_dirs: vec![] };
        assert!(!ext.is_installed(&app));
        assert!(ext.libraries(&app).is_empty());
    }

    #[test]
    fn libraries_finds_only_jar_files() {
        let (_dir, ext) = setup_installed_extension();
        let app = MockApplication { single_jar_mode: false, extension_dirs: vec![] };
        let libs = ext.libraries(&app);
        assert_eq!(libs.len(), 1);
        assert!(libs[0].to_string_lossy().ends_with("thing.jar"));
    }

    #[test]
    fn mark_and_clear_uninstall_round_trip() {
        let (_dir, mut ext) = setup_installed_extension();
        let install_dir = ext.install_dir().unwrap();

        assert!(ext.mark_for_uninstall());
        assert!(!install_dir.join(MODULE_MANIFEST_FILE_NAME).exists());
        assert!(install_dir.join(MODULE_MANIFEST_FILE_NAME_UNINSTALLED).exists());
        assert!(!install_dir.join(EXTENSION_PROPERTIES_FILE_NAME).exists());
        assert!(install_dir.join(EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED).exists());

        let app = MockApplication { single_jar_mode: false, extension_dirs: vec![] };
        assert!(!ext.is_installed(&app));
        assert!(ext.is_pending_uninstall(&app));

        assert!(ext.clear_mark_for_uninstall());
        assert!(install_dir.join(MODULE_MANIFEST_FILE_NAME).exists());
        assert!(install_dir.join(EXTENSION_PROPERTIES_FILE_NAME).exists());
        assert!(ext.is_installed(&app));
    }

    #[test]
    fn is_installed_in_installation_folder_checks_remaining_dirs() {
        let (_dir, ext) = setup_installed_extension();
        let install_dir = ext.install_dir().unwrap();
        let repo_parent = install_dir.parent().unwrap().to_path_buf();

        // First entry is the user extension dir and is skipped; the second matches our install
        // dir's parent.
        let app = MockApplication {
            single_jar_mode: false,
            extension_dirs: vec![PathBuf::from("/nonexistent/user/ext/dir"), repo_parent],
        };
        assert!(ext.is_installed_in_installation_folder(&app));

        let app_no_match = MockApplication {
            single_jar_mode: false,
            extension_dirs: vec![
                PathBuf::from("/nonexistent/user/ext/dir"),
                PathBuf::from("/completely/different/path"),
            ],
        };
        assert!(!ext.is_installed_in_installation_folder(&app_no_match));

        let app_too_few = MockApplication {
            single_jar_mode: false,
            extension_dirs: vec![PathBuf::from("/nonexistent/user/ext/dir")],
        };
        assert!(!ext.is_installed_in_installation_folder(&app_too_few));
    }

    #[test]
    fn equals_and_compare_by_name() {
        let a = MockExtensionDetails { name: "Alpha".to_string(), ..Default::default() };
        let b = MockExtensionDetails { name: "Beta".to_string(), ..Default::default() };
        let a2 = MockExtensionDetails { name: "Alpha".to_string(), ..Default::default() };

        assert!(a.equals_by_name(&a2));
        assert!(!a.equals_by_name(&b));
        assert_eq!(a.compare_by_name(&b), std::cmp::Ordering::Less);
    }

    #[test]
    fn to_json_string_renders_fields() {
        let mut ext = MockExtensionDetails { name: "MyExtension".to_string(), ..Default::default() };
        ext.set_description(Some("A test extension".to_string()));
        ext.set_version(Some("1.0".to_string()));

        let json = ext.to_json_string();
        assert!(json.contains("\"name\":\"MyExtension\""));
        assert!(json.contains("\"description\":\"A test extension\""));
        assert!(json.contains("\"version\":\"1.0\""));
        assert!(json.contains("\"installDir\":null"));
    }
}
