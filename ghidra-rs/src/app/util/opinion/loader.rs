//! An interface that all loaders must implement. A particular loader implementation should be
//! designed to identify one and only one file format.
//!
//! Port of `ghidra.app.util.opinion.Loader`.
//!
//! The Java interface's nested `ImporterSettings` record becomes [`ImporterSettings`] below, and
//! its `Comparable<Loader>` supertype becomes the default [`Loader::compare_to`] method, since a
//! `dyn Loader` cannot itself implement `Ord` (no blanket way to compare two arbitrary trait
//! objects via the standard traits while keeping `Loader` object-safe). `ExtensionPoint` is a
//! marker supertrait mirrored the same way here.

use std::any::Any;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::app::seam_stubs::{ByteProviderLike, LoadResultsLike, LoadSpecLike, MessageLog, OptionLike};
use crate::app::util::opinion::load_exception::LoadException;
use crate::app::util::opinion::loader_tier::LoaderTier;
use crate::framework::model::{DomainObject, Project};
use crate::program::model::listing::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;
use crate::util::exception::{CancelledException, VersionException};
use crate::util::system_utilities::SystemUtilities;
use crate::util::task::TaskMonitor;

/// A string prefixed to each loader headless command line argument to avoid naming conflicts
/// with other headless command line argument names.
pub const COMMAND_LINE_ARG_PREFIX: &str = "-loader";

/// Key used to lookup and store all loader options in the project's saved state.
pub const OPTIONS_PROJECT_SAVE_STATE_KEY: &str = "LOADER_OPTIONS";

static LOGGING_DISABLED: OnceLock<AtomicBool> = OnceLock::new();

/// Whether loaders' message logs being echoed to the application log is disabled.
///
/// Mirrors the mutable static field `Loader.loggingDisabled`, initialized from the
/// `disable.loader.logging` system property.
pub fn logging_disabled() -> bool {
    LOGGING_DISABLED
        .get_or_init(|| {
            AtomicBool::new(SystemUtilities::get_boolean_property(
                "disable.loader.logging",
                false,
            ))
        })
        .load(Ordering::SeqCst)
}

/// Sets whether loaders' message logs being echoed to the application log is disabled.
///
/// Mirrors direct assignment to the mutable static field `Loader.loggingDisabled`.
pub fn set_logging_disabled(disabled: bool) {
    LOGGING_DISABLED
        .get_or_init(|| AtomicBool::new(false))
        .store(disabled, Ordering::SeqCst);
}

/// A [`Loader`] configuration.
///
/// Ports the nested Java `record ImporterSettings`. `consumer` (Java's `Object`) becomes
/// `Box<dyn Any + Send + Sync>`, this crate's established stand-in for opaque `Object` fields
/// (see [`DomainObjectChangeRecord`](crate::framework::model::DomainObjectChangeRecord)).
pub struct ImporterSettings<'a> {
    /// The bytes to load.
    pub provider: &'a dyn ByteProviderLike,
    /// The name for the primary `Loaded` domain object. Path information that appears at the
    /// beginning of the name will be appended to `project_root_path` during saving.
    pub import_name: String,
    /// The project. Loaders can use this to take advantage of existing domain folders/files to
    /// do custom behaviors such as loading libraries. `None` if there is no project.
    pub project: Option<&'a dyn Project>,
    /// The project folder path that all loaded domain objects will be saved relative to. `None`
    /// means "/" will be used.
    pub project_root_path: Option<String>,
    /// True if the filesystem layout should be mirrored when saving; otherwise, false.
    pub mirror_fs_layout: bool,
    /// The load spec to use during load.
    pub load_spec: &'a dyn LoadSpecLike,
    /// The load options.
    pub options: Vec<Box<dyn OptionLike>>,
    /// A reference to the object "consuming" the returned load results.
    pub consumer: Box<dyn Any + Send + Sync>,
    /// The message log.
    pub log: &'a mut dyn MessageLog,
    /// A task monitor.
    pub monitor: &'a dyn TaskMonitor,
}

impl ImporterSettings<'_> {
    /// The name portion of `import_name`, stripping off any leading path information that may be
    /// present.
    ///
    /// Stands in for `ImporterSettings.importNameOnly()`.
    pub fn import_name_only(&self) -> String {
        split_import_name(&self.import_name).1
    }

    /// The path portion of `import_name` if present, stripping off the trailing name (could be
    /// the empty string).
    ///
    /// Stands in for `ImporterSettings.importPathOnly()`.
    pub fn import_path_only(&self) -> String {
        split_import_name(&self.import_name).0
    }
}

/// Splits `path` into `(path_only, name_only)`, mirroring Apache Commons
/// `FilenameUtils.getFullPath`/`getName` for `/` and `\` separated paths.
fn split_import_name(path: &str) -> (String, String) {
    match path.rfind(['/', '\\']) {
        Some(idx) => (path[..=idx].to_string(), path[idx + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

/// Combines the checked exceptions declared on `Loader.load`: `IOException`,
/// `CancelledException`, `VersionException`, and `LoadException`.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Load(#[from] LoadException),
}

/// Combines the checked exceptions declared on `Loader.loadInto`: `IOException`,
/// `LoadException`, and `CancelledException`.
#[derive(Debug, thiserror::Error)]
pub enum LoadIntoError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Load(#[from] LoadException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// An interface that all loaders must implement. A particular loader implementation should be
/// designed to identify one and only one file format.
pub trait Loader: ExtensionPoint {
    /// If this loader supports loading the given [`ByteProviderLike`], returns all supported
    /// [`LoadSpecLike`]s. If this loader cannot support loading the given provider, an empty
    /// collection is returned.
    ///
    /// # Errors
    /// Returns `Err` if there was an IO-related issue finding the load specs.
    fn find_supported_load_specs(
        &self,
        provider: &dyn ByteProviderLike,
    ) -> io::Result<Vec<Box<dyn LoadSpecLike>>>;

    /// Loads bytes in a particular format as one or more new [`LoadResultsLike`]. Note that when
    /// the load completes, the results are not saved to a project; that is the caller's
    /// responsibility.
    ///
    /// # Errors
    /// Returns `Err` if the load failed, was cancelled, hit a version mismatch, or hit an
    /// IO-related problem.
    fn load(&self, settings: ImporterSettings<'_>) -> Result<Box<dyn LoadResultsLike>, LoadError>;

    /// Loads bytes into the specified [`Program`]. This method will not create any new programs;
    /// it is only for adding to an existing program.
    ///
    /// # Errors
    /// Returns `Err` if the load failed, was cancelled, or hit an IO-related problem.
    fn load_into(
        &self,
        program: &mut dyn Program,
        settings: ImporterSettings<'_>,
    ) -> Result<(), LoadIntoError>;

    /// Gets the default loader options.
    fn get_default_options(
        &self,
        provider: &dyn ByteProviderLike,
        load_spec: &dyn LoadSpecLike,
        domain_object: &dyn DomainObject,
        load_into_program: bool,
        mirror_fs_layout: bool,
    ) -> Vec<Box<dyn OptionLike>>;

    /// Validates this loader's options, returning `None` if all options are valid; otherwise, an
    /// error message describing the problem. `program` is the existing program being added to
    /// if this is a load-into, or `None` for a fresh import.
    fn validate_options(
        &self,
        provider: &dyn ByteProviderLike,
        load_spec: &dyn LoadSpecLike,
        options: &[Box<dyn OptionLike>],
        program: Option<&dyn Program>,
    ) -> Option<String>;

    /// Gets this loader's name, used both for display purposes and to identify the loader in the
    /// opinion files.
    fn get_name(&self) -> String;

    /// For ordering purposes; lower tier numbers are more important (and listed first).
    fn get_tier(&self) -> LoaderTier;

    /// For ordering purposes; lower numbers are more important (and listed first, within its
    /// tier).
    fn get_tier_priority(&self) -> i32;

    /// Whether or not this is a "fallback" loader. Fallback loaders are only considered during
    /// the import process if no other non-fallback loaders were compatible with the thing being
    /// imported.
    fn is_fallback(&self) -> bool {
        false
    }

    /// The preferred file name to use when loading. The default behavior is to return the
    /// (cleaned up) name of the given [`ByteProviderLike`].
    fn get_preferred_file_name(&self, provider: &dyn ByteProviderLike) -> Option<String> {
        let name = match provider.get_fsrl() {
            Some(fsrl) => fsrl.name(),
            None => provider.get_name(),
        };
        name.map(|n| collapse_path_separators(&n))
    }

    /// Checks to see if this loader supports loading into an existing program.
    ///
    /// The default behavior is to return false.
    #[deprecated(note = "use supports_load_into_program_for instead, so loaders can restrict \
                          what types of programs can get loaded into other types of programs")]
    fn supports_load_into_program(&self) -> bool {
        false
    }

    /// Checks to see if this loader supports loading into the given program.
    ///
    /// The default behavior delegates to the deprecated no-arg
    /// [`supports_load_into_program`](Self::supports_load_into_program), so existing
    /// implementations that only override that method keep working unmodified.
    #[allow(deprecated)]
    fn supports_load_into_program_for(&self, program: &dyn Program) -> bool {
        let _ = program;
        self.supports_load_into_program()
    }

    /// Checks to see if this loader loads into a new domain folder instead of a new domain file.
    fn loads_into_new_folder(&self) -> bool {
        false
    }

    /// Returns `arg` with [`COMMAND_LINE_ARG_PREFIX`] prepended. A convenience method to make
    /// working with loader command line options less verbose.
    fn create_arg(&self, arg: &str) -> String {
        format!("{COMMAND_LINE_ARG_PREFIX}{arg}")
    }

    /// Orders loaders first by tier, then (within a tier) by tier priority, then by name.
    ///
    /// Mirrors the default `compareTo(Loader)` implementation.
    fn compare_to(&self, other: &dyn Loader) -> std::cmp::Ordering {
        self.get_tier()
            .cmp(&other.get_tier())
            .then_with(|| self.get_tier_priority().cmp(&other.get_tier_priority()))
            .then_with(|| self.get_name().cmp(&other.get_name()))
    }
}

/// Replaces every run of one-or-more `\`, `:`, or `|` characters with a single `/`.
///
/// Mirrors the Java regex `name.replaceAll("[\\\\:|]+", "/")` used by the default
/// `getPreferredFileName`.
fn collapse_path_separators(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut prev_was_sep = false;
    for c in name.chars() {
        if c == '\\' || c == ':' || c == '|' {
            if !prev_was_sep {
                result.push('/');
            }
            prev_was_sep = true;
        } else {
            result.push(c);
            prev_was_sep = false;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::util::task::DummyMonitor;
    use std::cmp::Ordering;

    struct MockProvider {
        name: Option<String>,
    }

    impl ByteProviderLike for MockProvider {
        fn get_fsrl(&self) -> Option<Box<dyn Fsrl>> {
            None
        }

        fn get_name(&self) -> Option<String> {
            self.name.clone()
        }
    }

    struct MockLoadSpec;
    impl LoadSpecLike for MockLoadSpec {}

    struct MockLoadResults;
    impl LoadResultsLike for MockLoadResults {}

    struct MockOption;
    impl OptionLike for MockOption {}

    struct MockDomainObject;
    impl DomainObject for MockDomainObject {}

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.program".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockMessageLog;
    impl MessageLog for MockMessageLog {}

    struct MockLoader {
        tier: LoaderTier,
        priority: i32,
        name: &'static str,
    }

    impl Loader for MockLoader {
        fn find_supported_load_specs(
            &self,
            provider: &dyn ByteProviderLike,
        ) -> io::Result<Vec<Box<dyn LoadSpecLike>>> {
            if provider.get_name().as_deref() == Some("match.bin") {
                Ok(vec![Box::new(MockLoadSpec)])
            } else {
                Ok(vec![])
            }
        }

        fn load(
            &self,
            _settings: ImporterSettings<'_>,
        ) -> Result<Box<dyn LoadResultsLike>, LoadError> {
            Ok(Box::new(MockLoadResults))
        }

        fn load_into(
            &self,
            _program: &mut dyn Program,
            _settings: ImporterSettings<'_>,
        ) -> Result<(), LoadIntoError> {
            Ok(())
        }

        fn get_default_options(
            &self,
            _provider: &dyn ByteProviderLike,
            _load_spec: &dyn LoadSpecLike,
            _domain_object: &dyn DomainObject,
            _load_into_program: bool,
            _mirror_fs_layout: bool,
        ) -> Vec<Box<dyn OptionLike>> {
            vec![Box::new(MockOption)]
        }

        fn validate_options(
            &self,
            _provider: &dyn ByteProviderLike,
            _load_spec: &dyn LoadSpecLike,
            _options: &[Box<dyn OptionLike>],
            _program: Option<&dyn Program>,
        ) -> Option<String> {
            None
        }

        fn get_name(&self) -> String {
            self.name.to_string()
        }

        fn get_tier(&self) -> LoaderTier {
            self.tier
        }

        fn get_tier_priority(&self) -> i32 {
            self.priority
        }
    }

    impl ExtensionPoint for MockLoader {}

    #[test]
    fn mock_loader_is_object_safe_and_finds_specs() {
        let loader: Box<dyn Loader> = Box::new(MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 0,
            name: "Mock",
        });

        let matching = MockProvider {
            name: Some("match.bin".to_string()),
        };
        let specs = loader.find_supported_load_specs(&matching).unwrap();
        assert_eq!(specs.len(), 1);

        let other = MockProvider {
            name: Some("other.bin".to_string()),
        };
        assert!(loader.find_supported_load_specs(&other).unwrap().is_empty());

        let domain_object = MockDomainObject;
        let load_spec = MockLoadSpec;
        assert_eq!(
            loader
                .get_default_options(&matching, &load_spec, &domain_object, false, false)
                .len(),
            1
        );
    }

    #[test]
    fn default_get_preferred_file_name_collapses_separators() {
        let loader = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 0,
            name: "Mock",
        };
        let provider = MockProvider {
            name: Some("C:weird\\path||name".to_string()),
        };
        assert_eq!(
            loader.get_preferred_file_name(&provider),
            Some("C/weird/path/name".to_string())
        );
    }

    #[test]
    fn default_get_preferred_file_name_is_none_when_provider_has_no_name() {
        let loader = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 0,
            name: "Mock",
        };
        let provider = MockProvider { name: None };
        assert_eq!(loader.get_preferred_file_name(&provider), None);
    }

    #[test]
    fn default_compare_to_orders_by_tier_then_priority_then_name() {
        let specialized = MockLoader {
            tier: LoaderTier::SpecializedTargetLoader,
            priority: 5,
            name: "B",
        };
        let generic = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 0,
            name: "A",
        };
        assert_eq!(specialized.compare_to(&generic), Ordering::Less);

        let lower_priority = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 1,
            name: "Z",
        };
        let higher_priority = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 2,
            name: "A",
        };
        assert_eq!(lower_priority.compare_to(&higher_priority), Ordering::Less);

        let name_b = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 1,
            name: "B",
        };
        let name_a = MockLoader {
            tier: LoaderTier::GenericTargetLoader,
            priority: 1,
            name: "A",
        };
        assert_eq!(name_b.compare_to(&name_a), Ordering::Greater);
    }

    #[test]
    fn default_create_arg_prepends_prefix() {
        let loader = MockLoader {
            tier: LoaderTier::UntargetedLoader,
            priority: 0,
            name: "Mock",
        };
        assert_eq!(loader.create_arg("foo"), "-loaderfoo");
    }

    #[test]
    fn default_is_fallback_and_loads_into_new_folder_are_false() {
        let loader = MockLoader {
            tier: LoaderTier::UntargetedLoader,
            priority: 0,
            name: "Mock",
        };
        assert!(!loader.is_fallback());
        assert!(!loader.loads_into_new_folder());
        assert!(!loader.supports_load_into_program_for(&MockProgram));
    }

    #[test]
    fn logging_disabled_flag_round_trips() {
        set_logging_disabled(true);
        assert!(logging_disabled());
        set_logging_disabled(false);
        assert!(!logging_disabled());
    }

    #[test]
    fn importer_settings_splits_import_name() {
        let provider = MockProvider {
            name: Some("ignored".to_string()),
        };
        let load_spec = MockLoadSpec;
        let mut log = MockMessageLog;
        let monitor = DummyMonitor;
        let settings = ImporterSettings {
            provider: &provider,
            import_name: "a/b/c.bin".to_string(),
            project: None,
            project_root_path: None,
            mirror_fs_layout: false,
            load_spec: &load_spec,
            options: vec![],
            consumer: Box::new(()),
            log: &mut log,
            monitor: &monitor,
        };
        assert_eq!(settings.import_name_only(), "c.bin");
        assert_eq!(settings.import_path_only(), "a/b/");
    }

    #[test]
    fn importer_settings_with_no_path_has_empty_path_only() {
        let provider = MockProvider { name: None };
        let load_spec = MockLoadSpec;
        let mut log = MockMessageLog;
        let monitor = DummyMonitor;
        let settings = ImporterSettings {
            provider: &provider,
            import_name: "plain.bin".to_string(),
            project: None,
            project_root_path: None,
            mirror_fs_layout: false,
            load_spec: &load_spec,
            options: vec![],
            consumer: Box::new(()),
            log: &mut log,
            monitor: &monitor,
        };
        assert_eq!(settings.import_name_only(), "plain.bin");
        assert_eq!(settings.import_path_only(), "");
    }
}
