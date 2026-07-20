use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the application properties file.
pub const PROPERTY_FILE: &str = "application.properties";

/// The application name. For example, "Ghidra".
pub const APPLICATION_NAME_PROPERTY: &str = "application.name";

/// The application version. For example, "7.4.2". See
/// [`ApplicationVersion`](crate::framework::ApplicationVersion).
pub const APPLICATION_VERSION_PROPERTY: &str = "application.version";

/// The application's layout version. The layout version should get incremented any time
/// something changes about the application that could affect external tools that need to
/// navigate the application in some way.
pub const APPLICATION_LAYOUT_VERSION_PROPERTY: &str = "application.layout.version";

/// The minimum version of gradle required to build the application.
pub const APPLICATION_GRADLE_MIN_PROPERTY: &str = "application.gradle.min";

/// The earliest version of gradle after [`APPLICATION_GRADLE_MIN_PROPERTY`] that is
/// unsupported. If all versions of Gradle greater than or equal to
/// `APPLICATION_GRADLE_MIN_PROPERTY` are supported, this property should not be set.
pub const APPLICATION_GRADLE_MAX_PROPERTY: &str = "application.gradle.max";

/// The minimum major version of Java required to run the application.
pub const APPLICATION_JAVA_MIN_PROPERTY: &str = "application.java.min";

/// The maximum major version of Java the application will run under. If all versions of
/// Java greater than or equal to [`APPLICATION_JAVA_MIN_PROPERTY`] are supported, this
/// property should not be set.
pub const APPLICATION_JAVA_MAX_PROPERTY: &str = "application.java.max";

/// The Java compiler compliance level that was used to build the application. For example,
/// "1.8".
pub const APPLICATION_JAVA_COMPILER_PROPERTY: &str = "application.java.compiler";

/// A comma-delimited priority-ordered list of versions of Python supported by the
/// application.
pub const APPLICATION_PYTHON_SUPPORTED_PROPERTY: &str = "application.python.supported";

/// The date the application was built on, in a long format. For example,
/// "2018-Jan-11 1346 EST".
pub const BUILD_DATE_PROPERTY: &str = "application.build.date";

/// The date the application was built on, in a short format. For example, "20180111".
pub const BUILD_DATE_SHORT_PROPERTY: &str = "application.build.date.short";

/// The application's release name. For example, "U".
pub const RELEASE_NAME_PROPERTY: &str = "application.release.name";

/// The application's release marking.
pub const RELEASE_MARKING_PROPERTY: &str = "application.release.marking";

/// Property prefix for dynamically generated version control revision number properties.
pub const REVISION_PROPERTY_PREFIX: &str = "application.revision.";

pub const TEST_RELEASE_PROPERTY: &str = "application.test.release";
pub const RELEASE_SOURCE_PROPERTY: &str = "application.release.source";

/// The application properties. Application properties may either be stored on disk, or
/// created dynamically.
///
/// Mirrors `ghidra.framework.ApplicationProperties`, which extends `java.util.Properties`.
/// This type was flagged as a package-cycle cut-point (it and
/// [`ApplicationUtilities`](crate::util::application_utilities::ApplicationUtilities) /
/// `ApplicationIdentifier` import each other), so it is ported to an object-safe trait rather
/// than a concrete struct: callers depend on `Box<dyn ApplicationProperties>`/
/// `Arc<dyn ApplicationProperties>` instead of a single concrete backing implementation.
///
/// The Java class's constructors (`fromFile`, `ApplicationProperties(String)`,
/// `ApplicationProperties(ResourceFile)`, `ApplicationProperties(Collection<ResourceFile>)`)
/// are not mechanically reproduced here, consistent with how
/// [`PropertyFile`](crate::util::property_file::PropertyFile) treats its own constructor:
/// construction (including how/whether a backing `ResourceFile` is read from disk) is
/// implementation-specific and not part of the trait contract.
pub trait ApplicationProperties {
    /// Looks up `property_name` directly in this instance's own backing property store,
    /// mirroring the `super.getProperty(propertyName)` call reached by the Java class's
    /// `getProperty` override once the environment-variable check (see [`Self::get_property`])
    /// misses.
    fn raw_property(&self, property_name: &str) -> Option<String>;

    /// Assigns `value` to `property_name` in the backing property store, mirroring
    /// `Properties.setProperty`.
    fn set_property(&mut self, property_name: &str, value: &str);

    /// Gets the given application property. Note that if the specified property is defined
    /// as an environment variable, the environment variable is given precedence and
    /// returned, mirroring the Java override that consults `System.getProperty` before
    /// falling back to the stored value.
    fn get_property(&self, property_name: &str) -> Option<String> {
        if let Ok(value) = std::env::var(property_name) {
            return Some(value);
        }
        self.raw_property(property_name)
    }

    /// Gets the application's name.
    ///
    /// Returns the application's name (empty string if undefined).
    fn application_name(&self) -> String {
        non_blank_or_empty(self.get_property(APPLICATION_NAME_PROPERTY))
    }

    /// Gets the application's version.
    ///
    /// Returns the application's version (empty string if undefined).
    fn application_version(&self) -> String {
        non_blank_or_empty(self.get_property(APPLICATION_VERSION_PROPERTY))
    }

    /// Gets the application's release name.
    ///
    /// Returns the application's release name (empty string if undefined).
    fn application_release_name(&self) -> String {
        non_blank_or_empty(self.get_property(RELEASE_NAME_PROPERTY))
    }

    /// Gets the application's build date.
    ///
    /// Returns the application's build date, defaulting to today (`yyyy-MMM-dd`) if the
    /// property is not defined.
    fn application_build_date(&self) -> String {
        match self.get_property(BUILD_DATE_PROPERTY) {
            Some(value) if !value.trim().is_empty() => value,
            _ => today_yyyy_mmm_dd(),
        }
    }
}

/// Returns `value` if present and non-blank, otherwise the empty string, mirroring the
/// repeated `appXxx == null || appXxx.trim().isEmpty() ? "" : appXxx` pattern in the Java
/// accessors.
fn non_blank_or_empty(value: Option<String>) -> String {
    match value {
        Some(v) if !v.trim().is_empty() => v,
        _ => String::new(),
    }
}

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats today's date (UTC) as `yyyy-MMM-dd`, mirroring
/// `new SimpleDateFormat("yyyy-MMM-dd").format(new Date())`.
fn today_yyyy_mmm_dd() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
        / 86_400;
    let (year, month, day) = civil_from_days(days);
    format!("{:04}-{}-{:02}", year, MONTH_NAMES[(month - 1) as usize], day)
}

/// Converts a day count since the Unix epoch into a proleptic-Gregorian civil date
/// `(year, month, day)`, with a 1-based month and day. Based on Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockApplicationProperties {
        values: HashMap<String, String>,
    }

    impl MockApplicationProperties {
        fn new() -> Self {
            Self { values: HashMap::new() }
        }
    }

    impl ApplicationProperties for MockApplicationProperties {
        fn raw_property(&self, property_name: &str) -> Option<String> {
            self.values.get(property_name).cloned()
        }

        fn set_property(&mut self, property_name: &str, value: &str) {
            self.values.insert(property_name.to_string(), value.to_string());
        }
    }

    #[test]
    fn trait_object_usage_and_accessors_round_trip() {
        let mut props = MockApplicationProperties::new();
        props.set_property(APPLICATION_NAME_PROPERTY, "Ghidra");
        props.set_property(APPLICATION_VERSION_PROPERTY, "7.4.2");
        props.set_property(RELEASE_NAME_PROPERTY, "U");

        // Prove object-safety: this trait can be used behind a trait object.
        let boxed: Box<dyn ApplicationProperties> = Box::new(props);

        assert_eq!(boxed.application_name(), "Ghidra");
        assert_eq!(boxed.application_version(), "7.4.2");
        assert_eq!(boxed.application_release_name(), "U");
    }

    #[test]
    fn accessors_default_to_empty_string_when_undefined_or_blank() {
        let mut props = MockApplicationProperties::new();
        assert_eq!(props.application_name(), "");

        props.set_property(APPLICATION_NAME_PROPERTY, "   ");
        assert_eq!(props.application_name(), "");
    }

    #[test]
    fn build_date_falls_back_to_today_when_undefined() {
        let props = MockApplicationProperties::new();
        assert_eq!(props.application_build_date(), today_yyyy_mmm_dd());
    }

    #[test]
    fn build_date_uses_stored_value_when_present() {
        let mut props = MockApplicationProperties::new();
        props.set_property(BUILD_DATE_PROPERTY, "2018-Jan-11 1346 EST");
        assert_eq!(props.application_build_date(), "2018-Jan-11 1346 EST");
    }

    #[test]
    fn get_property_prefers_environment_variable_over_stored_value() {
        let key = format!("GHIDRA_RS_APPPROPS_TEST_{}", std::process::id());
        let mut props = MockApplicationProperties::new();
        props.set_property(&key, "stored");

        assert_eq!(props.get_property(&key).as_deref(), Some("stored"));

        std::env::set_var(&key, "from_env");
        assert_eq!(props.get_property(&key).as_deref(), Some("from_env"));
        std::env::remove_var(&key);

        assert_eq!(props.get_property(&key).as_deref(), Some("stored"));
    }

    #[test]
    fn civil_from_days_matches_known_epoch_date() {
        // 1970-01-01 is day 0.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2018-01-11 is day 17542.
        assert_eq!(civil_from_days(17542), (2018, 1, 11));
    }
}
