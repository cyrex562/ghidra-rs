use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use thiserror::Error;

use crate::framework::application_properties::ApplicationProperties;
use crate::framework::version::{ApplicationVersion, VersionError};

/// Represents an application's unique identifier. An application identifier is made up of an
/// application name, an application version, and an application release name.
///
/// ```text
/// The identifier format is (\.+) - \d\.\d(\.\d)?(\-.+)? _ (\.+)
///                          name         version        release name
/// ```
///
/// Application names are normalized to all lowercase and application release names are
/// normalized to all uppercase. Both have spaces removed from their names.
///
/// Mirrors `ghidra.framework.ApplicationIdentifier`. That class and
/// `utility.application.ApplicationUtilities` import each other (`ApplicationIdentifier`'s
/// constructor calls `ApplicationUtilities.normalizeApplicationName`, while
/// [`ApplicationUtilities`](crate::util::application_utilities::ApplicationUtilities) imports
/// `ghidra.framework.*` for `ApplicationIdentifier`, `ApplicationProperties`, and
/// `OperatingSystem`), forming a package-level dependency cycle. This port maps the Java class to
/// an object-safe trait so callers can depend on `Box<dyn ApplicationIdentifier>`/
/// `Arc<dyn ApplicationIdentifier>` instead of a single concrete implementation, and the name/
/// release-name normalization (whitespace stripped, case-folded) that Java sources from
/// `ApplicationUtilities.normalizeApplicationName` is reproduced locally rather than depending on
/// that trait, so this module does not need to import `crate::util` at all.
pub trait ApplicationIdentifier {
    /// Gets the application name.
    fn application_name(&self) -> &str;

    /// Gets the application version.
    fn application_version(&self) -> &ApplicationVersion;

    /// Gets the application release name.
    fn application_release_name(&self) -> &str;

    /// Gets the full versioned identifier (`name_version_releaseName`), mirroring `toString()`.
    fn versioned_name(&self) -> String {
        format!(
            "{}_{}_{}",
            self.application_name(),
            self.application_version(),
            self.application_release_name()
        )
    }

    /// Computes a hash of this identifier's components, mirroring `hashCode()`
    /// (`(applicationName + applicationReleaseName).hashCode() * applicationVersion.hashCode()`).
    fn identifier_hash(&self) -> u64 {
        let mut name_release_hasher = DefaultHasher::new();
        let mut name_release = String::with_capacity(
            self.application_name().len() + self.application_release_name().len(),
        );
        name_release.push_str(self.application_name());
        name_release.push_str(self.application_release_name());
        name_release.hash(&mut name_release_hasher);
        let name_release_hash = name_release_hasher.finish();

        let mut version_hasher = DefaultHasher::new();
        self.application_version().hash(&mut version_hasher);
        let version_hash = version_hasher.finish();

        name_release_hash.wrapping_mul(version_hash)
    }

    /// Compares this identifier against another for equality by component, mirroring
    /// `equals(Object)`.
    fn identifier_eq(&self, other: &dyn ApplicationIdentifier) -> bool {
        self.application_name() == other.application_name()
            && self.application_release_name() == other.application_release_name()
            && self.application_version() == other.application_version()
    }
}

/// Errors that can occur while building an [`ApplicationIdentifier`], mirroring the
/// `IllegalArgumentException`s thrown by the Java constructors.
#[derive(Error, Debug, PartialEq)]
pub enum ApplicationIdentifierError {
    #[error("Application name is undefined.")]
    EmptyApplicationName,
    #[error("Application release name is undefined.")]
    EmptyApplicationReleaseName,
    #[error("Identifier has {0} parts but 3 are required")]
    WrongPartCount(usize),
    #[error(transparent)]
    Version(#[from] VersionError),
}

/// A concrete, immutable [`ApplicationIdentifier`] built either from an
/// [`ApplicationProperties`] or by parsing an identifier string, mirroring the Java class's two
/// public constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedApplicationIdentifier {
    application_name: String,
    application_version: ApplicationVersion,
    application_release_name: String,
}

impl ParsedApplicationIdentifier {
    /// Creates a new identifier from an [`ApplicationProperties`], mirroring
    /// `ApplicationIdentifier(ApplicationProperties)`.
    pub fn from_properties(
        application_properties: &dyn ApplicationProperties,
    ) -> Result<Self, ApplicationIdentifierError> {
        let application_name = normalize_lower(&application_properties.application_name());
        if application_name.is_empty() {
            return Err(ApplicationIdentifierError::EmptyApplicationName);
        }

        let application_version =
            application_properties.application_version().parse::<ApplicationVersion>()?;

        let application_release_name =
            normalize_upper(&application_properties.application_release_name());
        if application_release_name.is_empty() {
            return Err(ApplicationIdentifierError::EmptyApplicationReleaseName);
        }

        Ok(Self {
            application_name,
            application_version,
            application_release_name,
        })
    }

    /// Parses application identifier components out of the given version string, mirroring
    /// `ApplicationIdentifier(String)` / the private `parse(String)` helper.
    pub fn parse(identifier: &str) -> Result<Self, ApplicationIdentifierError> {
        let identifier_parts: Vec<&str> = identifier.split('_').collect();
        if identifier_parts.len() < 3 {
            return Err(ApplicationIdentifierError::WrongPartCount(identifier_parts.len()));
        }

        let application_name = normalize_lower(identifier_parts[0]);
        let application_version = identifier_parts[1].parse::<ApplicationVersion>()?;
        let application_release_name = normalize_upper(identifier_parts[2]);
        // Ignore any parts after the release name...they are not part of the identifier

        Ok(Self {
            application_name,
            application_version,
            application_release_name,
        })
    }
}

impl ApplicationIdentifier for ParsedApplicationIdentifier {
    fn application_name(&self) -> &str {
        &self.application_name
    }

    fn application_version(&self) -> &ApplicationVersion {
        &self.application_version
    }

    fn application_release_name(&self) -> &str {
        &self.application_release_name
    }
}

impl fmt::Display for ParsedApplicationIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.versioned_name())
    }
}

/// Removes whitespace and lowercases `value`, mirroring
/// `ApplicationUtilities.normalizeApplicationName` / `String.replaceAll("\\s", "").toLowerCase()`.
fn normalize_lower(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase()
}

/// Removes whitespace and uppercases `value`, mirroring
/// `String.replaceAll("\\s", "").toUpperCase()`.
fn normalize_upper(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockApplicationProperties(HashMap<&'static str, &'static str>);

    impl ApplicationProperties for MockApplicationProperties {
        fn raw_property(&self, property_name: &str) -> Option<String> {
            self.0.get(property_name).map(|v| v.to_string())
        }

        fn set_property(&mut self, _property_name: &str, _value: &str) {
            unimplemented!("not needed for this test")
        }
    }

    #[test]
    fn trait_object_usage_and_versioned_name_round_trip() {
        // Prove object-safety: this trait can be used behind a trait object.
        let boxed: Box<dyn ApplicationIdentifier> =
            Box::new(ParsedApplicationIdentifier::parse("ghidra_7.4.1-BETA_U").unwrap());

        assert_eq!(boxed.application_name(), "ghidra");
        assert_eq!(boxed.application_version(), &"7.4.1-BETA".parse::<ApplicationVersion>().unwrap());
        assert_eq!(boxed.application_release_name(), "U");
        assert_eq!(boxed.versioned_name(), "ghidra_7.4.1-BETA_U");
    }

    #[test]
    fn parse_normalizes_case_and_strips_whitespace() {
        let id = ParsedApplicationIdentifier::parse("Ghidra Two_7.4_dev release").unwrap();
        assert_eq!(id.application_name(), "ghidratwo");
        assert_eq!(id.application_release_name(), "DEVRELEASE");
    }

    #[test]
    fn parse_rejects_too_few_parts() {
        let err = ParsedApplicationIdentifier::parse("ghidra_7.4").unwrap_err();
        assert_eq!(err, ApplicationIdentifierError::WrongPartCount(2));
    }

    #[test]
    fn parse_ignores_trailing_parts() {
        let id = ParsedApplicationIdentifier::parse("ghidra_7.4_U_extra_stuff").unwrap();
        assert_eq!(id.versioned_name(), "ghidra_7.4_U");
    }

    #[test]
    fn from_properties_builds_identifier() {
        let mut values = HashMap::new();
        values.insert("application.name", "Ghidra");
        values.insert("application.version", "7.4.2");
        values.insert("application.release.name", "u");
        let props = MockApplicationProperties(values);

        let id = ParsedApplicationIdentifier::from_properties(&props).unwrap();
        assert_eq!(id.application_name(), "ghidra");
        assert_eq!(id.application_release_name(), "U");
        assert_eq!(id.application_version(), &"7.4.2".parse::<ApplicationVersion>().unwrap());
    }

    #[test]
    fn from_properties_rejects_empty_application_name() {
        let mut values = HashMap::new();
        values.insert("application.version", "7.4");
        values.insert("application.release.name", "U");
        let props = MockApplicationProperties(values);

        let err = ParsedApplicationIdentifier::from_properties(&props).unwrap_err();
        assert_eq!(err, ApplicationIdentifierError::EmptyApplicationName);
    }

    #[test]
    fn from_properties_rejects_empty_release_name() {
        let mut values = HashMap::new();
        values.insert("application.name", "Ghidra");
        values.insert("application.version", "7.4");
        let props = MockApplicationProperties(values);

        let err = ParsedApplicationIdentifier::from_properties(&props).unwrap_err();
        assert_eq!(err, ApplicationIdentifierError::EmptyApplicationReleaseName);
    }

    #[test]
    fn identifier_eq_and_hash_match_for_equivalent_identifiers_ignoring_version_tag() {
        let a: Box<dyn ApplicationIdentifier> =
            Box::new(ParsedApplicationIdentifier::parse("ghidra_7.4_U").unwrap());
        let b: Box<dyn ApplicationIdentifier> =
            Box::new(ParsedApplicationIdentifier::parse("ghidra_7.4_U").unwrap());
        let c: Box<dyn ApplicationIdentifier> =
            Box::new(ParsedApplicationIdentifier::parse("ghidra_7.5_U").unwrap());

        assert!(a.identifier_eq(b.as_ref()));
        assert_eq!(a.identifier_hash(), b.identifier_hash());
        assert!(!a.identifier_eq(c.as_ref()));
    }
}
