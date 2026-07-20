use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

use crate::framework::application_identifier::{ApplicationIdentifier, ParsedApplicationIdentifier};
use crate::framework::seam_stubs::{
    ApplicationLike, LegacyUserSettingsLocator, PreferencesLike,
    PREFERENCES_APPLICATION_PREFERENCES_FILENAME, PREFERENCES_PROJECT_DIRECTORY,
};

/// The name appended to application directories during testing.
pub const TEST_DIRECTORY_SUFFIX: &str = "-Test";

/// Application-run information: locates settings directories left behind by previous
/// installations/versions of the application, and the user's preferred projects directory.
///
/// Mirrors `ghidra.framework.GenericRunInfo`, a static-method-only utility class. That class and
/// `ghidra.framework.preferences.Preferences` import each other (`Preferences.store()`/`clear()`
/// call `GenericRunInfo.getPreviousApplicationSettingsFile()`, while `GenericRunInfo` reads
/// `Preferences.APPLICATION_PREFERENCES_FILENAME`/`PROJECT_DIRECTORY` and calls
/// `Preferences.getProperty`/`setProperty`), forming a package-level dependency cycle. This port
/// maps the Java class to an object-safe trait so callers can depend on
/// `Box<dyn GenericRunInfo>`/`Arc<dyn GenericRunInfo>` instead of a single concrete
/// implementation, breaking the cycle at this cut-point. `Application`, `ApplicationLayout`, the
/// legacy-settings-dir lookup, and `Preferences` are stood in for by the
/// [`ApplicationLike`]/[`ApplicationLayoutLike`](crate::framework::seam_stubs::ApplicationLayoutLike)/
/// [`LegacyUserSettingsLocator`]/[`PreferencesLike`] placeholders in
/// [`crate::framework::seam_stubs`] until they are ported themselves.
pub trait GenericRunInfo {
    /// Returns the seam onto `ghidra.framework.Application`'s static surface.
    fn application(&self) -> Box<dyn ApplicationLike>;

    /// Returns the seam onto `ghidra.framework.preferences.Preferences`'s static surface.
    fn preferences(&self) -> Box<dyn PreferencesLike>;

    /// Returns the seam onto `utility.application.ApplicationUtilities.getLegacyUserSettingsDir`.
    fn legacy_user_settings_locator(&self) -> Box<dyn LegacyUserSettingsLocator>;

    /// Get all of the application's settings directories (`.<application_name_version>`) for
    /// various versions in descending order by modification time (`[0]` is most recent). Ignores
    /// Test directories.
    ///
    /// Mirrors the private `getUserSettingsDirsByTime()`.
    fn get_user_settings_dirs_by_time(&self) -> Vec<PathBuf> {
        let app = self.application();
        let layout = app.application_layout();
        let user_settings_directory = app.user_settings_directory();
        let app_name = app.name();

        let mut app_dirs = collect_all_application_directories(
            user_settings_directory.parent(),
            &app_name,
            false,
        );

        if let Some(legacy_dir) = self
            .legacy_user_settings_locator()
            .legacy_user_settings_dir(
                layout.application_properties(),
                layout.application_installation_dir(),
            )
        {
            app_dirs.extend(collect_all_application_directories(
                legacy_dir.parent(),
                &app_name,
                true,
            ));
        }

        app_dirs.sort_by(modify_time_cmp);
        app_dirs
    }

    /// Searches previous Application Settings directories to find a file by the given name. This
    /// is useful for loading previous user settings, such as preferences. Ignores any Test
    /// versions of settings directories.
    ///
    /// Returns the most recent file matching that name found in a previous settings dir.
    fn get_previous_application_settings_file(&self, filename: &str) -> Option<PathBuf> {
        for dir in self.get_previous_application_settings_dirs_by_time() {
            if is_test_dir(&dir) {
                continue;
            }
            let candidate = dir.join(filename);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }

    /// Searches previous Application Settings directories to find a settings directory containing
    /// files that match the given filter. This is useful for loading previous directories of
    /// saved settings files of a particular type. Ignores any Test versions of settings
    /// directories.
    ///
    /// Returns the most recent directory named `dir_name` that contains at least one file matched
    /// by `filter`, found in a previous version's settings directory.
    fn get_previous_application_settings_dir(
        &self,
        dir_name: &str,
        filter: &dyn Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        for dir in self.get_previous_application_settings_dirs_by_time() {
            if is_test_dir(&dir) {
                continue;
            }
            let candidate = dir.join(dir_name);
            if !candidate.is_dir() {
                continue;
            }
            let has_match = fs::read_dir(&candidate)
                .map(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .any(|entry| filter(&entry.path()))
                })
                .unwrap_or(false);
            if has_match {
                return Some(candidate);
            }
        }
        None
    }

    /// The same as [`Self::get_user_settings_dirs_by_time`], except that it doesn't include the
    /// current installation or installations with different release names.
    ///
    /// Returns the list of previous directories, sorted by time.
    fn get_previous_application_settings_dirs_by_time(&self) -> Vec<PathBuf> {
        let mut settings_dirs = Vec::new();

        let app = self.application();
        let layout = app.application_layout();
        let Ok(my_identifier) =
            ParsedApplicationIdentifier::from_properties(layout.application_properties())
        else {
            return settings_dirs;
        };
        let my_release = my_identifier.application_release_name().to_string();
        let my_dir_name = app.user_settings_directory();
        let my_dir_name = my_dir_name.file_name().and_then(|n| n.to_str());

        for dir in self.get_user_settings_dirs_by_time() {
            let Some(dir_name) = dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if Some(dir_name) == my_dir_name {
                continue;
            }

            let stripped = dir_name.strip_prefix('.').unwrap_or(dir_name);

            if let Ok(identifier) = ParsedApplicationIdentifier::parse(stripped) {
                if identifier.application_release_name() == my_release {
                    settings_dirs.push(dir.clone());
                }
            }
        }

        settings_dirs
    }

    /// Get the user's preferred projects directory.
    ///
    /// Returns the projects directory path.
    fn get_projects_dir_path(&self) -> String {
        let path = self.preferences().get_property(
            PREFERENCES_PROJECT_DIRECTORY,
            None,
            true,
        );
        if let Some(path) = path {
            if Path::new(&path).is_dir() {
                return path;
            }
        }
        user_home_dir()
    }

    /// Set the user's current projects directory path. Value is also retained within the user's
    /// set of preferences.
    fn set_projects_dir_path(&self, path: &str) {
        if Path::new(path).is_dir() {
            self.preferences().set_property(PREFERENCES_PROJECT_DIRECTORY, path);
        }
    }
}

/// Returns whether `dir`'s path ends with `"Test"`, mirroring the repeated
/// `dirPath.endsWith("Test")` guard in the Java original.
fn is_test_dir(dir: &Path) -> bool {
    dir.to_string_lossy().ends_with("Test")
}

/// Searches `data_directory_parent_dir` for immediate subdirectories whose name starts with the
/// (optionally dot-prefixed) normalized application name and does not end with
/// [`TEST_DIRECTORY_SUFFIX`], mirroring the private `collectAllApplicationDirectories(File,
/// boolean)`. Returns an empty vec if `data_directory_parent_dir` is `None` or unreadable,
/// mirroring `CollectionUtils.asList`'s null-safe handling of `File.listFiles`'s `null` return.
fn collect_all_application_directories(
    data_directory_parent_dir: Option<&Path>,
    app_name: &str,
    legacy: bool,
) -> Vec<PathBuf> {
    let Some(parent_dir) = data_directory_parent_dir else {
        return Vec::new();
    };

    let normalized_app_name: String =
        app_name.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
    let settings_dir_prefix = if legacy {
        format!(".{normalized_app_name}")
    } else {
        normalized_app_name
    };

    let Ok(entries) = fs::read_dir(parent_dir) else {
        return Vec::new();
    };

    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| {
                        name.starts_with(&settings_dir_prefix)
                            && !name.ends_with(TEST_DIRECTORY_SUFFIX)
                    })
        })
        .collect()
}

/// Compares two settings directories by the modification time of their
/// `Preferences.APPLICATION_PREFERENCES_FILENAME` file, descending (most recently modified
/// first), falling back to an ascending name comparison when the times are equal, mirroring the
/// private `modifyTimeComparator`.
fn modify_time_cmp(a: &PathBuf, b: &PathBuf) -> Ordering {
    let prefs_a = a.join(PREFERENCES_APPLICATION_PREFERENCES_FILENAME);
    let prefs_b = b.join(PREFERENCES_APPLICATION_PREFERENCES_FILENAME);
    let exists_a = prefs_a.exists();
    let exists_b = prefs_b.exists();

    if !exists_a || !exists_b {
        return match (exists_a, exists_b) {
            (false, false) => Ordering::Equal,
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (true, true) => unreachable!(),
        };
    }

    let modify_a = prefs_a.metadata().and_then(|m| m.modified()).ok();
    let modify_b = prefs_b.metadata().and_then(|m| m.modified()).ok();
    match (modify_a, modify_b) {
        (Some(ma), Some(mb)) if ma == mb => a
            .file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default()),
        (Some(ma), Some(mb)) => {
            if ma < mb {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        _ => a.file_name().unwrap_or_default().cmp(b.file_name().unwrap_or_default()),
    }
}

/// Returns the user's home directory, standing in for `System.getProperty("user.home")` (there is
/// no JVM-managed `user.home` system property in Rust).
fn user_home_dir() -> String {
    if cfg!(windows) {
        std::env::var("USERPROFILE").unwrap_or_default()
    } else {
        std::env::var("HOME").unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::application_properties::{
        ApplicationProperties, APPLICATION_NAME_PROPERTY, APPLICATION_VERSION_PROPERTY,
        RELEASE_NAME_PROPERTY,
    };
    use crate::framework::seam_stubs::ApplicationLayoutLike;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::time::{Duration, SystemTime};

    struct MockApplicationProperties(HashMap<&'static str, &'static str>);

    impl ApplicationProperties for MockApplicationProperties {
        fn raw_property(&self, property_name: &str) -> Option<String> {
            self.0.get(property_name).map(|v| v.to_string())
        }

        fn set_property(&mut self, _property_name: &str, _value: &str) {
            unimplemented!("not needed for this test")
        }
    }

    struct MockApplicationLayout {
        properties: MockApplicationProperties,
    }

    impl ApplicationLayoutLike for MockApplicationLayout {
        fn application_properties(&self) -> &dyn ApplicationProperties {
            &self.properties
        }

        fn application_installation_dir(&self) -> Option<&crate::generic::jar::ResourceFile> {
            None
        }
    }

    struct MockApplication {
        name: &'static str,
        properties: HashMap<&'static str, &'static str>,
        user_settings_directory: PathBuf,
    }

    impl ApplicationLike for MockApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            Box::new(MockApplicationLayout {
                properties: MockApplicationProperties(self.properties.clone()),
            })
        }

        fn user_settings_directory(&self) -> PathBuf {
            self.user_settings_directory.clone()
        }

        fn name(&self) -> String {
            self.name.to_string()
        }
    }

    struct MockLegacyUserSettingsLocator;

    impl LegacyUserSettingsLocator for MockLegacyUserSettingsLocator {
        fn legacy_user_settings_dir(
            &self,
            _application_properties: &dyn ApplicationProperties,
            _installation_dir: Option<&crate::generic::jar::ResourceFile>,
        ) -> Option<PathBuf> {
            // No legacy directory in these tests.
            None
        }
    }

    /// Backed by an `Rc<RefCell<..>>` so that repeated `preferences()` calls (each returning a
    /// fresh `Box<dyn PreferencesLike>`) still share the same underlying store, mirroring
    /// `Preferences`'s single shared, globally-mutable Java store.
    #[derive(Clone)]
    struct MockPreferences {
        values: Rc<RefCell<HashMap<String, String>>>,
    }

    impl MockPreferences {
        fn new() -> Self {
            Self { values: Rc::new(RefCell::new(HashMap::new())) }
        }
    }

    impl PreferencesLike for MockPreferences {
        fn get_property(
            &self,
            name: &str,
            default_value: Option<&str>,
            _use_historical_value: bool,
        ) -> Option<String> {
            self.values
                .borrow()
                .get(name)
                .cloned()
                .or_else(|| default_value.map(str::to_string))
        }

        fn set_property(&self, name: &str, value: &str) {
            self.values.borrow_mut().insert(name.to_string(), value.to_string());
        }
    }

    struct MockGenericRunInfo {
        name: &'static str,
        properties: HashMap<&'static str, &'static str>,
        user_settings_directory: PathBuf,
        preferences: MockPreferences,
    }

    impl GenericRunInfo for MockGenericRunInfo {
        fn application(&self) -> Box<dyn ApplicationLike> {
            Box::new(MockApplication {
                name: self.name,
                properties: self.properties.clone(),
                user_settings_directory: self.user_settings_directory.clone(),
            })
        }

        fn preferences(&self) -> Box<dyn PreferencesLike> {
            Box::new(self.preferences.clone())
        }

        fn legacy_user_settings_locator(&self) -> Box<dyn LegacyUserSettingsLocator> {
            Box::new(MockLegacyUserSettingsLocator)
        }
    }

    fn touch_dir_with_prefs_mtime(dir: &Path, offset_secs: u64) {
        fs::create_dir_all(dir).unwrap();
        let prefs = dir.join(PREFERENCES_APPLICATION_PREFERENCES_FILENAME);
        fs::write(&prefs, b"").unwrap();
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + offset_secs);
        let file = fs::File::open(&prefs).unwrap();
        file.set_modified(mtime).unwrap();
    }

    #[test]
    fn trait_object_usage_and_settings_dirs_sorted_most_recent_first() {
        let root = std::env::temp_dir().join(format!(
            "ghidra_rs_generic_run_info_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let user_settings_dir = root.join(".ghidra_ghidra_11.2_U");
        let older_dir = root.join(".ghidra_ghidra_11.1_U");
        let newer_dir = root.join(".ghidra_ghidra_11.0_U");
        let test_dir = root.join(format!(".ghidra_ghidra_11.3_U{TEST_DIRECTORY_SUFFIX}"));

        fs::create_dir_all(&user_settings_dir).unwrap();
        touch_dir_with_prefs_mtime(&older_dir, 100);
        touch_dir_with_prefs_mtime(&newer_dir, 200);
        fs::create_dir_all(&test_dir).unwrap();

        let mut properties = HashMap::new();
        properties.insert(APPLICATION_NAME_PROPERTY, "Ghidra");
        properties.insert(APPLICATION_VERSION_PROPERTY, "11.2");
        properties.insert(RELEASE_NAME_PROPERTY, "U");

        let run_info = MockGenericRunInfo {
            name: "Ghidra",
            properties,
            user_settings_directory: user_settings_dir,
            preferences: MockPreferences::new(),
        };

        // Prove object-safety: this trait can be used behind a trait object.
        let boxed: Box<dyn GenericRunInfo> = Box::new(run_info);

        let all_dirs = boxed.get_user_settings_dirs_by_time();
        let _ = fs::remove_dir_all(&root);

        // newer_dir has the later mtime, so it must sort before older_dir; the current
        // installation and the Test dir are excluded entirely.
        let newer_pos = all_dirs.iter().position(|d| d == &newer_dir);
        let older_pos = all_dirs.iter().position(|d| d == &older_dir);
        assert!(newer_pos.is_some() && older_pos.is_some());
        assert!(newer_pos.unwrap() < older_pos.unwrap());
        assert!(!all_dirs.iter().any(|d| d.to_string_lossy().ends_with(TEST_DIRECTORY_SUFFIX)));
    }

    #[test]
    fn get_projects_dir_path_falls_back_to_home_when_no_preference_set() {
        let mut properties = HashMap::new();
        properties.insert(APPLICATION_NAME_PROPERTY, "Ghidra");
        properties.insert(APPLICATION_VERSION_PROPERTY, "11.2");
        properties.insert(RELEASE_NAME_PROPERTY, "U");

        let run_info = MockGenericRunInfo {
            name: "Ghidra",
            properties,
            user_settings_directory: std::env::temp_dir(),
            preferences: MockPreferences::new(),
        };

        assert_eq!(run_info.get_projects_dir_path(), user_home_dir());
    }

    #[test]
    fn set_projects_dir_path_persists_valid_directory_and_get_returns_it() {
        let mut properties = HashMap::new();
        properties.insert(APPLICATION_NAME_PROPERTY, "Ghidra");
        properties.insert(APPLICATION_VERSION_PROPERTY, "11.2");
        properties.insert(RELEASE_NAME_PROPERTY, "U");

        let run_info = MockGenericRunInfo {
            name: "Ghidra",
            properties,
            user_settings_directory: std::env::temp_dir(),
            preferences: MockPreferences::new(),
        };

        let dir = std::env::temp_dir();
        run_info.set_projects_dir_path(&dir.to_string_lossy());

        assert_eq!(run_info.get_projects_dir_path(), dir.to_string_lossy());
    }

    #[test]
    fn set_projects_dir_path_ignores_non_directory_paths() {
        let mut properties = HashMap::new();
        properties.insert(APPLICATION_NAME_PROPERTY, "Ghidra");
        properties.insert(APPLICATION_VERSION_PROPERTY, "11.2");
        properties.insert(RELEASE_NAME_PROPERTY, "U");

        let run_info = MockGenericRunInfo {
            name: "Ghidra",
            properties,
            user_settings_directory: std::env::temp_dir(),
            preferences: MockPreferences::new(),
        };

        run_info.set_projects_dir_path("/definitely/not/a/real/path/ghidra-rs-test");

        assert_eq!(run_info.get_projects_dir_path(), user_home_dir());
    }
}
