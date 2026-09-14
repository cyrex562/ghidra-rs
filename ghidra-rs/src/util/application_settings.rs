//! Port of `utility.application.ApplicationSettings`.
//!
//! Java's `ApplicationSettings` is a small, `PluggableServiceRegistry`-backed extension point: a
//! static `{}` block registers a default instance of itself, `getUserApplicationSettingsDirectory()`
//! looks that instance up and delegates to its (overridable) `doGetUserApplicationSettingsDirectory()`,
//! and a plugin can register a more specific subclass to change the answer.
//!
//! Per the precedent already set by
//! [`OldLanguageMappingService`](crate::program::model::lang::old_language_mapping_service) for
//! this exact shape (see that module's own docs), this port skips
//! [`PluggableServiceRegistry`](crate::framework::service::PluggableServiceRegistry) -- whose
//! generic API is keyed by `TypeId`/type name of a concrete, `Sized` `T` and cannot represent
//! "whatever concrete type currently implements this trait" the way Java's `Class<? extends T>`
//! key can -- in favor of an overridable "hook" trait ([`ApplicationSettings`]) whose default
//! method reproduces the base class's own behavior, with the process-wide registry lookup
//! replaced by an explicit parameter every caller supplies directly.
//!
//! `doGetUserApplicationSettingsDirectory()` also needs an `ApplicationUtilities` instance (for
//! `ApplicationUtilities.getDefaultUserTempDir(String)`); since
//! [`ApplicationUtilities`](crate::util::application_utilities::ApplicationUtilities) was itself
//! ported as a trait for the same class-of-reasons (see that module's docs), it is threaded
//! through as a second explicit parameter here too.

use std::io;
use std::path::PathBuf;

use crate::util::application_utilities::ApplicationUtilities;
use crate::util::msg::Msg;

/// Name used for the application-settings subdirectory, mirroring the literal
/// `"application.settings"` argument Java passes to `ApplicationUtilities.getDefaultUserTempDir`.
pub const APPLICATION_SETTINGS_DIR_NAME: &str = "application.settings";

/// The extension point Java calls `ApplicationSettings.doGetUserApplicationSettingsDirectory()`.
///
/// Port of the instance contract of `utility.application.ApplicationSettings`. Implementors
/// override [`do_get_user_application_settings_directory`](Self::do_get_user_application_settings_directory)
/// to change where application settings are stored per user, per application version. The default
/// implementation mirrors the Java base class's own method exactly.
pub trait ApplicationSettings {
    /// Returns the directory into which application settings are stored per user, per
    /// application version, or `None` if it could not be created/determined (mirroring Java's
    /// `null` return on `IOException`, which it logs via `Msg.error` rather than propagating).
    ///
    /// Port of `ApplicationSettings.doGetUserApplicationSettingsDirectory()`.
    fn do_get_user_application_settings_directory(
        &self,
        application_utilities: &dyn ApplicationUtilities,
    ) -> Option<PathBuf> {
        match application_utilities.get_default_user_temp_dir(APPLICATION_SETTINGS_DIR_NAME) {
            Ok(dir) => Some(dir),
            Err(e) => {
                log_directory_error(&e);
                None
            }
        }
    }
}

/// Logs the `IOException` Java's `doGetUserApplicationSettingsDirectory()` catches, via
/// `Msg.error(ApplicationSettings.class, "Error creating application.settings directory", e)`.
fn log_directory_error(e: &io::Error) {
    Msg::error_with_error(
        "ApplicationSettings",
        &"Error creating application.settings directory",
        e,
    );
}

/// Returns the directory into which application settings are stored per user, per application
/// version, using `settings` in place of the process-wide `PluggableServiceRegistry` lookup Java
/// performs (see the module docs).
///
/// Port of the static `ApplicationSettings.getUserApplicationSettingsDirectory()`.
pub fn get_user_application_settings_directory(
    settings: &dyn ApplicationSettings,
    application_utilities: &dyn ApplicationUtilities,
) -> Option<PathBuf> {
    settings.do_get_user_application_settings_directory(application_utilities)
}

/// The default `ApplicationSettings` behavior, standing in for the base-class instance Java's
/// static initializer registers with `PluggableServiceRegistry`. Relies entirely on the trait's
/// default method.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DefaultApplicationSettings;

impl ApplicationSettings for DefaultApplicationSettings {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    struct MockApplicationUtilities {
        temp_dir: PathBuf,
        fail: bool,
    }

    impl ApplicationUtilities for MockApplicationUtilities {
        fn load_application_properties(
            &self,
            _properties_file: &crate::generic::jar::ResourceFile,
        ) -> io::Result<Box<dyn crate::util::seam_stubs::ApplicationPropertiesLike>> {
            unimplemented!("not exercised by these tests")
        }

        fn get_default_user_temp_dir(&self, application_name: &str) -> io::Result<PathBuf> {
            if self.fail {
                return Err(io::Error::new(io::ErrorKind::Other, "boom"));
            }
            let dir = self.temp_dir.join(application_name);
            std::fs::create_dir_all(&dir)?;
            Ok(dir)
        }
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        env::temp_dir().join(format!("ghidra_rs_appsettings_test_{label}_{}", std::process::id()))
    }

    #[test]
    fn default_impl_creates_the_application_settings_subdirectory() {
        let tmp = unique_test_dir("default");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let utils = MockApplicationUtilities { temp_dir: tmp.clone(), fail: false };
        let dir = get_user_application_settings_directory(&DefaultApplicationSettings, &utils)
            .expect("directory should be created");

        assert_eq!(dir, tmp.join(APPLICATION_SETTINGS_DIR_NAME));
        assert!(dir.is_dir());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn io_error_is_logged_and_returns_none_rather_than_propagating() {
        let tmp = unique_test_dir("error");
        let utils = MockApplicationUtilities { temp_dir: tmp, fail: true };
        let dir = get_user_application_settings_directory(&DefaultApplicationSettings, &utils);
        assert!(dir.is_none());
    }

    #[test]
    fn a_registered_override_can_change_the_answer() {
        // Mirrors "any potential subclasses can update the returned value" -- a plugin-supplied
        // ApplicationSettings implementation entirely replaces the default directory logic.
        struct FixedApplicationSettings(PathBuf);
        impl ApplicationSettings for FixedApplicationSettings {
            fn do_get_user_application_settings_directory(
                &self,
                _application_utilities: &dyn ApplicationUtilities,
            ) -> Option<PathBuf> {
                Some(self.0.clone())
            }
        }

        let fixed = PathBuf::from("/custom/settings/dir");
        let settings = FixedApplicationSettings(fixed.clone());
        let utils = MockApplicationUtilities { temp_dir: env::temp_dir(), fail: false };

        let dir = get_user_application_settings_directory(&settings, &utils);
        assert_eq!(dir, Some(fixed));
    }

    #[test]
    fn object_safe_as_boxed_trait() {
        let boxed: Box<dyn ApplicationSettings> = Box::new(DefaultApplicationSettings);
        let tmp = unique_test_dir("boxed");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let utils = MockApplicationUtilities { temp_dir: tmp.clone(), fail: false };

        let dir = boxed.do_get_user_application_settings_directory(&utils);
        assert!(dir.is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
