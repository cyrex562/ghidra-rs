use std::env;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};

use crate::framework::OperatingSystem;
use crate::generic::jar::ResourceFile;
use crate::util::msg::Msg;
use crate::util::seam_stubs::{ApplicationIdentifierLike, ApplicationPropertiesLike};
use crate::util::system_utilities::SystemUtilities;
use crate::util::xdg_utils::XdgUtils;

/// Name of the file that marks an application root directory, mirroring
/// `ApplicationProperties.PROPERTY_FILE`.
const APPLICATION_PROPERTIES_FILE: &str = "application.properties";

/// Name of system property used to override the location of the user temporary directory.
pub const PROPERTY_TEMP_DIR: &str = "application.tempdir";

/// Name of system property used to override the location of the user cache directory.
pub const PROPERTY_CACHE_DIR: &str = "application.cachedir";

/// Name of system property used to override the location of the user settings directory.
pub const PROPERTY_SETTINGS_DIR: &str = "application.settingsdir";

/// Utility behavior for default application things.
///
/// Mirrors `utility.application.ApplicationUtilities`, a static-method-only utility class. That
/// class and `ghidra.framework.ApplicationIdentifier` import each other
/// (`ApplicationIdentifier`'s constructor calls `ApplicationUtilities.normalizeApplicationName`,
/// while `ApplicationUtilities` imports `ghidra.framework.*` for `ApplicationIdentifier`,
/// `ApplicationProperties`, and `OperatingSystem`), forming a package-level dependency cycle. This
/// port maps the Java class to an object-safe trait so callers can depend on
/// `Box<dyn ApplicationUtilities>`/`Arc<dyn ApplicationUtilities>` instead of importing the
/// concrete `ApplicationIdentifier`/`ApplicationProperties` types directly, breaking the cycle at
/// this cut-point. `ApplicationProperties` and `ApplicationIdentifier` are stood in for by the
/// [`ApplicationPropertiesLike`]/[`ApplicationIdentifierLike`] placeholders in
/// [`crate::util::seam_stubs`] until they are ported themselves.
///
/// Two seam accessors ([`Self::load_application_properties`], required, and
/// [`Self::classpath_entries`], defaulted) stand in for capabilities Java got "for free" from the
/// JVM (reading a `Properties` file, and enumerating the classpath) that a Rust binary does not
/// have an equivalent of without help from its embedder.
pub trait ApplicationUtilities {
    /// Loads application properties from the given file, mirroring
    /// `new ApplicationProperties(ResourceFile)`. Implementors should back this with the real
    /// `ApplicationProperties` port once it exists.
    fn load_application_properties(
        &self,
        properties_file: &ResourceFile,
    ) -> io::Result<Box<dyn ApplicationPropertiesLike>>;

    /// Returns the candidate root directories to search for an application root, standing in for
    /// Java's `System.getProperty("java.class.path")` (Rust binaries have no equivalent notion of
    /// a classpath). Defaults to empty; embedders that know their module layout should override
    /// this.
    fn classpath_entries(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Searches for default application root directories.
    ///
    /// Returns a collection of discovered application root directories (could be empty).
    fn find_default_application_root_dirs(&self) -> Vec<ResourceFile> {
        let mut application_root_dirs = Vec::new();
        if let Some(application_root_dir) = self.find_primary_application_root_dir() {
            application_root_dirs.push(application_root_dir.clone());
            if SystemUtilities::is_in_testing_mode() || SystemUtilities::is_in_development_mode()
            {
                application_root_dirs
                    .extend(find_application_root_dirs_from_repo_config(&application_root_dir));
            }
        }
        application_root_dirs
    }

    /// Finds the primary application root directory from the classpath. The primary application
    /// root directory must contain an application.properties file. No other application root
    /// directories may contain an application.properties file.
    ///
    /// Returns the primary application root directory, or `None` if it could not be found.
    fn find_primary_application_root_dir(&self) -> Option<ResourceFile> {
        for path_entry in self.classpath_entries() {
            let Ok(canonical) = path_entry.canonicalize() else {
                continue;
            };
            let mut path_file = Some(ResourceFile::new(canonical));
            while let Some(pf) = path_file {
                if !pf.exists() {
                    break;
                }
                let application_properties_file = pf.join(APPLICATION_PROPERTIES_FILE);
                if self.validate_application_properties_file(&application_properties_file) {
                    return Some(pf);
                }
                path_file = resource_file_parent(&pf);
            }
        }
        None
    }

    /// Checks to make sure the given application properties file exists and is a valid format.
    ///
    /// Returns true if the given application properties file exists and is a valid format;
    /// otherwise, false.
    fn validate_application_properties_file(&self, application_properties_file: &ResourceFile) -> bool {
        if !application_properties_file.is_file() {
            return false;
        }
        match self.load_application_properties(application_properties_file) {
            Ok(application_properties) => !application_properties.application_name().trim().is_empty(),
            Err(e) => {
                Msg::error_with_error(
                    "ApplicationUtilities",
                    &format!("Failed to read: {}", application_properties_file.absolute_path()),
                    &e,
                );
                false
            }
        }
    }

    /// Gets the application's default user temp directory.
    ///
    /// NOTE: This method creates the directory if it does not exist.
    fn get_default_user_temp_dir(&self, application_name: &str) -> io::Result<PathBuf> {
        let app_name = self.normalize_application_name(application_name);

        if let Some(temp_override_dir) = env_var_path(PROPERTY_TEMP_DIR, false)? {
            let sub_dir = self.get_user_specific_dir_name(&temp_override_dir, &app_name)?;
            return create_dir(&temp_override_dir.join(sub_dir));
        }

        let java_tmp_dir = self.get_java_tmp_dir();
        let sub_dir = self.get_user_specific_dir_name(&java_tmp_dir, &app_name)?;
        create_dir(&java_tmp_dir.join(sub_dir))
    }

    /// Gets the application's default user cache directory.
    ///
    /// NOTE: This method creates the directory if it does not exist.
    fn get_default_user_cache_dir(
        &self,
        application_properties: &dyn ApplicationPropertiesLike,
    ) -> io::Result<PathBuf> {
        let app_name = self.normalize_application_name(&application_properties.application_name());

        if let Some(cache_override_dir) = env_var_path(PROPERTY_CACHE_DIR, false)? {
            let sub_dir = self.get_user_specific_dir_name(&cache_override_dir, &app_name)?;
            return create_dir(&cache_override_dir.join(sub_dir));
        }

        if let Some(xdg_cache_home_dir) = env_var_path(XdgUtils::XDG_CACHE_HOME, false)? {
            let sub_dir = self.get_user_specific_dir_name(&xdg_cache_home_dir, &app_name)?;
            return create_dir(&xdg_cache_home_dir.join(sub_dir));
        }

        let user_dir_name = format!("{}-{}", SystemUtilities::get_user_name(), app_name);
        let platform_default = match OperatingSystem::CURRENT {
            OperatingSystem::Windows => {
                env_var_path("LOCALAPPDATA", true)?.map(|dir| dir.join(&app_name))
            }
            OperatingSystem::Linux | OperatingSystem::FreeBSD | OperatingSystem::MacOSX => {
                Some(PathBuf::from(format!("/var/tmp/{user_dir_name}")))
            }
            OperatingSystem::Unsupported => None,
        };

        let Some(candidate) = platform_default else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Failed to find the user cache directory: Unsupported operating system.",
            ));
        };

        match create_dir(&candidate) {
            Ok(dir) => Ok(dir),
            // Failed to create desired cache directory...use temp directory instead
            Err(_) => self.get_default_user_temp_dir(&application_properties.application_name()),
        }
    }

    /// Gets the application's default user settings directory.
    ///
    /// NOTE: This method creates the directory if it does not exist.
    fn get_default_user_settings_dir(
        &self,
        application_identifier: &dyn ApplicationIdentifierLike,
        installation_directory: &ResourceFile,
    ) -> io::Result<PathBuf> {
        let app_name = application_identifier.application_name();
        let mut versioned_name = application_identifier.versioned_name();
        if SystemUtilities::is_in_development_mode() {
            versioned_name =
                format!("{versioned_name}_location_{}", installation_directory.name());
        }

        if let Some(settings_override_dir) = env_var_path(PROPERTY_SETTINGS_DIR, false)? {
            let sub_dir = self.get_user_specific_dir_name(&settings_override_dir, &app_name)?;
            return create_dir(&settings_override_dir.join(format!("{sub_dir}/{versioned_name}")));
        }

        if let Some(xdg_config_home_dir) = env_var_path(XdgUtils::XDG_CONFIG_HOME, false)? {
            let sub_dir = self.get_user_specific_dir_name(&xdg_config_home_dir, &app_name)?;
            return create_dir(&xdg_config_home_dir.join(format!("{sub_dir}/{versioned_name}")));
        }

        let user_home_dir = self.get_java_user_home_dir()?;
        let versioned_subdir = format!("{app_name}/{versioned_name}");
        let candidate = match OperatingSystem::CURRENT {
            OperatingSystem::Windows => {
                env_var_path("APPDATA", true)?.map(|dir| dir.join(&versioned_subdir))
            }
            OperatingSystem::Linux | OperatingSystem::FreeBSD => {
                Some(user_home_dir.join(format!(".config/{versioned_subdir}")))
            }
            OperatingSystem::MacOSX => {
                Some(user_home_dir.join(format!("Library/{versioned_subdir}")))
            }
            OperatingSystem::Unsupported => None,
        };

        let Some(candidate) = candidate else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Failed to find the user settings directory: Unsupported operating system.",
            ));
        };

        create_dir(&candidate)
    }

    /// Gets the application's legacy (pre-Ghidra 11.1) user settings directory.
    ///
    /// NOTE: This method does not create the directory.
    fn get_legacy_user_settings_dir(
        &self,
        application_identifier: &dyn ApplicationIdentifierLike,
        installation_directory: &ResourceFile,
    ) -> io::Result<PathBuf> {
        let user_home_dir = self.get_java_user_home_dir()?;
        let app_name = application_identifier.application_name();
        let user_settings_parent_dir = user_home_dir.join(format!(".{app_name}"));

        let mut user_settings_dir_name = format!(".{}", application_identifier.versioned_name());
        if SystemUtilities::is_in_development_mode() {
            user_settings_dir_name = format!(
                "{user_settings_dir_name}_location_{}",
                installation_directory.name()
            );
        }

        Ok(user_settings_parent_dir.join(user_settings_dir_name))
    }

    /// Normalizes the application name by removing spaces and converting to lower case.
    fn normalize_application_name(&self, application_name: &str) -> String {
        application_name
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_lowercase()
    }

    /// Gets Java's temporary directory in absolute form. In Rust there is no JVM-managed
    /// `java.io.tmpdir` system property, so this defaults to [`std::env::temp_dir`]; embedders
    /// may override it.
    fn get_java_tmp_dir(&self) -> PathBuf {
        env::temp_dir()
    }

    /// Gets the user's home directory in absolute form.
    fn get_java_user_home_dir(&self) -> io::Result<PathBuf> {
        let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        env_var_path(name, true).map(|opt| opt.expect("env_var_path returns Some when required"))
    }

    /// Gets a directory name that can be used to create a user-specific sub-directory in
    /// `parent_dir`. If `parent_dir` is contained within the user's home directory, `app_name`
    /// can simply be used since it will live in a user-specific location. Otherwise, the user's
    /// name will get prepended to `app_name` so it does not collide with other users' directories
    /// in the shared directory space.
    fn get_user_specific_dir_name(&self, parent_dir: &Path, app_name: &str) -> io::Result<String> {
        let home_dir = self.get_java_user_home_dir()?;
        if is_path_contained_within(&home_dir, parent_dir) {
            Ok(app_name.to_string())
        } else {
            Ok(format!("{}-{}", SystemUtilities::get_user_name(), app_name))
        }
    }
}

/// Finds all application root directories defined in the repository config file.
///
/// `primary_application_root_dir` is the primary application root directory that may contain the
/// repository config file one directory up. Returns the defined application repository root
/// directories.
fn find_application_root_dirs_from_repo_config(
    primary_application_root_dir: &ResourceFile,
) -> Vec<ResourceFile> {
    let mut repo_application_root_dirs = Vec::new();

    let Some(parent) = primary_application_root_dir
        .get_file(false)
        .and_then(|p| p.parent().map(PathBuf::from))
    else {
        return repo_application_root_dirs;
    };

    let repo_config_file = parent.join("ghidra.repos.config");
    if !repo_config_file.is_file() {
        return repo_application_root_dirs;
    }

    let Some(grandparent) = parent.parent().map(PathBuf::from) else {
        return repo_application_root_dirs;
    };

    let content = match std::fs::read_to_string(&repo_config_file) {
        Ok(content) => content,
        Err(_) => {
            Msg::error(
                "ApplicationUtilities",
                &format!("Failed to read: {}", repo_config_file.display()),
            );
            return repo_application_root_dirs;
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let potential_application_root_dir = grandparent.join(line).join("Ghidra");
        if potential_application_root_dir.is_dir() {
            repo_application_root_dirs.push(ResourceFile::new(potential_application_root_dir));
        }
    }

    repo_application_root_dirs
}

/// Returns the parent of `file` as a `ResourceFile`, or `None` if `file` has no parent.
/// `ResourceFile` does not expose `getParentFile()` (Java) directly, so this reconstructs it
/// through the file's backing path.
fn resource_file_parent(file: &ResourceFile) -> Option<ResourceFile> {
    file.get_file(false)
        .and_then(|p| p.parent().map(|parent| ResourceFile::new(parent.to_path_buf())))
}

/// Gets the absolute form of the environment variable by the given name.
///
/// Java distinguishes JVM system properties (`System.getProperty`) from OS environment variables
/// (`System.getenv`); this port -- consistent with [`SystemUtilities`]'s existing treatment of
/// "system properties" as environment variables -- reads both kinds of names from the process
/// environment.
///
/// Returns the absolute form value of the environment variable by the given name, or `None` if
/// it isn't set and not `required`.
///
/// # Errors
/// Returns an error if the value was not an absolute path, or if it is required and not set.
fn env_var_path(name: &str, required: bool) -> io::Result<Option<PathBuf>> {
    let path = match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            if required {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Required environment variable \"{name}\" is not set!"),
                ));
            }
            return Ok(None);
        }
    };

    let file = PathBuf::from(&path);
    if !file.is_absolute() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Environment variable \"{name}\" is not an absolute path: \"{path}\""),
        ));
    }
    Ok(Some(file))
}

/// Returns whether `child` is contained within `parent`, canonicalizing both sides first so
/// symlinks/relative components don't cause false negatives; falls back to a plain prefix check
/// if either side can't be canonicalized (e.g. doesn't exist yet).
fn is_path_contained_within(parent: &Path, child: &Path) -> bool {
    match (parent.canonicalize(), child.canonicalize()) {
        (Ok(p), Ok(c)) => c.starts_with(p),
        _ => child.starts_with(parent),
    }
}

/// Creates the given directory if it does not exist, and sets its permissions to owner-only.
///
/// # Errors
/// Returns an error if the directory failed to be created.
fn create_dir(dir: &Path) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    set_owner_only_permissions(dir);
    Ok(dir.to_path_buf())
}

/// Sets owner-only permissions (`0700`) on `dir`. No-op on non-Unix platforms, mirroring the
/// best-effort nature of the Java original's `FileUtilities.setOwnerOnlyPermissions`.
fn set_owner_only_permissions(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockApplicationProperties(String);

    impl ApplicationPropertiesLike for MockApplicationProperties {
        fn application_name(&self) -> String {
            self.0.clone()
        }
    }

    struct MockApplicationIdentifier {
        name: String,
        versioned: String,
    }

    impl ApplicationIdentifierLike for MockApplicationIdentifier {
        fn application_name(&self) -> String {
            self.name.clone()
        }

        fn versioned_name(&self) -> String {
            self.versioned.clone()
        }
    }

    struct MockApplicationUtilities {
        home_dir: PathBuf,
        java_tmp_dir: PathBuf,
        classpath: Vec<PathBuf>,
    }

    impl ApplicationUtilities for MockApplicationUtilities {
        fn load_application_properties(
            &self,
            properties_file: &ResourceFile,
        ) -> io::Result<Box<dyn ApplicationPropertiesLike>> {
            let path = properties_file
                .get_file(false)
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "no backing path"))?;
            let content = std::fs::read_to_string(&path)?;
            let name = content
                .lines()
                .find_map(|line| line.strip_prefix("application.name="))
                .unwrap_or("")
                .to_string();
            Ok(Box::new(MockApplicationProperties(name)))
        }

        fn classpath_entries(&self) -> Vec<PathBuf> {
            self.classpath.clone()
        }

        fn get_java_tmp_dir(&self) -> PathBuf {
            self.java_tmp_dir.clone()
        }

        fn get_java_user_home_dir(&self) -> io::Result<PathBuf> {
            Ok(self.home_dir.clone())
        }
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        env::temp_dir().join(format!("ghidra_rs_apputil_test_{label}_{}", std::process::id()))
    }

    #[test]
    fn normalize_application_name_strips_whitespace_and_lowercases() {
        let mock = MockApplicationUtilities {
            home_dir: env::temp_dir(),
            java_tmp_dir: env::temp_dir(),
            classpath: vec![],
        };
        assert_eq!(mock.normalize_application_name("My  App\tName"), "myappname");
    }

    #[test]
    fn find_default_application_root_dirs_walks_up_to_locate_root() {
        let root = unique_test_dir("walkup");
        let nested = root.join("a").join("b");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&nested).expect("create nested test dir");
        std::fs::write(
            root.join(APPLICATION_PROPERTIES_FILE),
            "application.name=Ghidra\n",
        )
        .expect("write application.properties");

        let mock = MockApplicationUtilities {
            home_dir: env::temp_dir(),
            java_tmp_dir: env::temp_dir(),
            classpath: vec![nested],
        };

        // Prove object-safety: this trait can be used behind a trait object.
        let boxed: Box<dyn ApplicationUtilities> = Box::new(mock);
        let found = boxed.find_default_application_root_dirs();

        let expected = root.canonicalize().expect("canonicalize expected root");
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].get_file(false), Some(expected));
    }

    #[test]
    fn find_default_application_root_dirs_rejects_missing_or_empty_name() {
        let root = unique_test_dir("empty_name");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test dir");
        std::fs::write(root.join(APPLICATION_PROPERTIES_FILE), "application.name=   \n")
            .expect("write application.properties");

        let mock = MockApplicationUtilities {
            home_dir: env::temp_dir(),
            java_tmp_dir: env::temp_dir(),
            classpath: vec![root.clone()],
        };

        let found = mock.find_default_application_root_dirs();
        let _ = std::fs::remove_dir_all(&root);

        assert!(found.is_empty(), "expected no root dir to be found, got {found:?}");
    }

    #[test]
    fn get_default_user_temp_dir_creates_normalized_subdir_under_java_tmp() {
        let tmp_root = unique_test_dir("javatmp");
        let _ = std::fs::remove_dir_all(&tmp_root);
        std::fs::create_dir_all(&tmp_root).expect("create fake java tmp dir");

        let mock = MockApplicationUtilities {
            home_dir: tmp_root.clone(),
            java_tmp_dir: tmp_root.clone(),
            classpath: vec![],
        };

        let dir = mock
            .get_default_user_temp_dir("My App")
            .expect("temp dir creation should succeed");
        let exists = dir.is_dir();
        let _ = std::fs::remove_dir_all(&tmp_root);

        assert!(exists, "expected created directory to exist: {dir:?}");
        assert!(dir.starts_with(&tmp_root));
        assert_eq!(dir.file_name().unwrap().to_string_lossy(), "myapp");
    }

    #[test]
    fn legacy_user_settings_dir_uses_dotted_versioned_identifier() {
        let mock = MockApplicationUtilities {
            home_dir: PathBuf::from("/home/tester"),
            java_tmp_dir: env::temp_dir(),
            classpath: vec![],
        };
        let identifier = MockApplicationIdentifier {
            name: "ghidra".to_string(),
            versioned: "ghidra_11.2_BETA".to_string(),
        };
        let install_dir = ResourceFile::new(PathBuf::from("/opt/ghidra_11.2"));

        let dir = mock
            .get_legacy_user_settings_dir(&identifier, &install_dir)
            .expect("legacy settings dir should compute without touching disk");

        let expected_parent = PathBuf::from("/home/tester/.ghidra");
        let expected = if SystemUtilities::is_in_development_mode() {
            expected_parent.join(".ghidra_11.2_BETA_location_ghidra_11.2")
        } else {
            expected_parent.join(".ghidra_11.2_BETA")
        };
        assert_eq!(dir, expected);
    }
}
