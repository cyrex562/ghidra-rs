use thiserror::Error;

use super::OSGiUtils;

/// Represents an OSGi bundle in the framework.
///
/// Port of `org.osgi.framework.Bundle`. Simplified to include only the properties
/// used by GhidraBundleException.
#[derive(Debug, Clone)]
pub struct Bundle {
    location: String,
}

impl Bundle {
    /// Creates a new bundle with the given location.
    pub fn new(location: impl Into<String>) -> Self {
        Self {
            location: location.into(),
        }
    }

    /// Returns the location identifier of this bundle.
    pub fn get_location(&self) -> &str {
        &self.location
    }
}

/// Represents an exception thrown during OSGi bundle operations.
///
/// Port of `org.osgi.framework.BundleException`. The exception type constants
/// correspond to those defined in the OSGi framework specification.
#[derive(Debug, Clone)]
pub struct BundleException {
    message: String,
    exception_type: i32,
}

impl BundleException {
    /// The operation was unsupported.
    pub const UNSUPPORTED_OPERATION: i32 = 1;
    /// The operation was invalid.
    pub const INVALID_OPERATION: i32 = 2;
    /// The bundle manifest was in error.
    pub const MANIFEST_ERROR: i32 = 3;
    /// The bundle was not resolved.
    pub const RESOLVE_ERROR: i32 = 4;
    /// The bundle activator was in error.
    pub const ACTIVATOR_ERROR: i32 = 5;
    /// The operation failed due to insufficient permissions.
    pub const SECURITY_ERROR: i32 = 6;
    /// The operation failed to complete the requested lifecycle state change.
    pub const STATECHANGE_ERROR: i32 = 7;
    /// The bundle could not be resolved due to an error with the Bundle-NativeCode header.
    pub const NATIVECODE_ERROR: i32 = 8;
    /// The install or update operation failed because another already installed bundle
    /// has the same symbolic name and version.
    pub const DUPLICATE_BUNDLE_ERROR: i32 = 9;
    /// The start transient operation failed because the start level of the bundle
    /// is greater than the current framework start level.
    pub const START_TRANSIENT_ERROR: i32 = 10;
    /// The framework received an error while reading the input stream for a bundle.
    pub const READ_ERROR: i32 = 11;
    /// A framework hook rejected the operation.
    pub const REJECTED_BY_HOOK: i32 = 12;
    /// The operation was unspecified.
    pub const UNSPECIFIED: i32 = 0;

    /// Creates a new BundleException with the given message and type.
    pub fn new(message: impl Into<String>, exception_type: i32) -> Self {
        Self {
            message: message.into(),
            exception_type,
        }
    }

    /// Returns the exception type constant.
    pub fn get_type(&self) -> i32 {
        self.exception_type
    }

    /// Returns the exception message.
    pub fn get_message(&self) -> &str {
        &self.message
    }
}

/// Stores context associated with exceptions thrown during bundle operations.
///
/// Port of `ghidra.app.plugin.core.osgi.GhidraBundleException`.
#[derive(Error, Debug)]
#[error("{0}")]
pub struct GhidraBundleException(String, #[source] Option<Box<dyn std::error::Error + Send + Sync>>);

impl GhidraBundleException {
    /// Creates a new exception originating with the given bundle.
    ///
    /// # Arguments
    /// * `bundle` - The bundle (if available)
    /// * `msg` - A contextual message
    /// * `cause` - The original BundleException
    pub fn with_bundle(bundle: Bundle, msg: &str, cause: &BundleException) -> Self {
        let formatted = format!("{}: {}", msg, Self::parsed_cause(cause));
        Self(formatted, None)
    }

    /// Creates a new exception originating with the bundle having the given location identifier.
    ///
    /// # Arguments
    /// * `bundle_location` - The bundle location identifier (since no bundle is available)
    /// * `msg` - A contextual message
    /// * `cause` - The original BundleException
    pub fn with_location_and_cause(bundle_location: &str, msg: &str, cause: &BundleException) -> Self {
        let formatted = format!("{}: {}", msg, Self::parsed_cause(cause));
        Self(formatted, None)
    }

    /// Creates a new exception originating with the bundle having the given location identifier.
    ///
    /// # Arguments
    /// * `bundle_location` - The bundle location identifier
    /// * `msg` - A contextual message
    pub fn with_location(bundle_location: &str, msg: &str) -> Self {
        Self(msg.to_string(), None)
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Parses the BundleException to extract a meaningful error description.
    ///
    /// This method handles various OSGi exception types and extracts relevant context,
    /// particularly for RESOLVE_ERROR which includes package name information.
    fn parsed_cause(cause: &BundleException) -> String {
        match cause.get_type() {
            BundleException::UNSPECIFIED => cause.get_message().to_string(),
            BundleException::UNSUPPORTED_OPERATION => "UNSUPPORTED_OPERATION".to_string(),
            BundleException::INVALID_OPERATION => "INVALID_OPERATION".to_string(),
            BundleException::MANIFEST_ERROR => "MANIFEST_ERROR".to_string(),
            BundleException::RESOLVE_ERROR => {
                let message = cause.get_message();
                if message.starts_with("Unable to acquire global lock") {
                    message.to_string()
                } else {
                    let packages = OSGiUtils::extract_package_names_from_failed_resolution(message)
                        .into_iter()
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    if packages.is_empty() {
                        "RESOLVE_ERROR".to_string()
                    } else {
                        format!("RESOLVE_ERROR - \n{}", packages.join("\n"))
                    }
                }
            }
            BundleException::ACTIVATOR_ERROR => "ACTIVATOR_ERROR".to_string(),
            BundleException::SECURITY_ERROR => "SECURITY_ERROR".to_string(),
            BundleException::STATECHANGE_ERROR => "STATECHANGE_ERROR".to_string(),
            BundleException::NATIVECODE_ERROR => "NATIVECODE_ERROR".to_string(),
            BundleException::DUPLICATE_BUNDLE_ERROR => "DUPLICATE_BUNDLE_ERROR".to_string(),
            BundleException::START_TRANSIENT_ERROR => "START_TRANSIENT_ERROR".to_string(),
            BundleException::READ_ERROR => "READ_ERROR".to_string(),
            BundleException::REJECTED_BY_HOOK => "REJECTED_BY_HOOK".to_string(),
            _ => "No exception type".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_creation_and_location() {
        let bundle = Bundle::new("file:/path/to/bundle.jar");
        assert_eq!(bundle.get_location(), "file:/path/to/bundle.jar");
    }

    #[test]
    fn bundle_exception_creation() {
        let exc = BundleException::new("test error", BundleException::MANIFEST_ERROR);
        assert_eq!(exc.get_message(), "test error");
        assert_eq!(exc.get_type(), BundleException::MANIFEST_ERROR);
    }

    #[test]
    fn bundle_exception_constants() {
        assert_eq!(BundleException::UNSPECIFIED, 0);
        assert_eq!(BundleException::UNSUPPORTED_OPERATION, 1);
        assert_eq!(BundleException::INVALID_OPERATION, 2);
        assert_eq!(BundleException::MANIFEST_ERROR, 3);
        assert_eq!(BundleException::RESOLVE_ERROR, 4);
        assert_eq!(BundleException::ACTIVATOR_ERROR, 5);
        assert_eq!(BundleException::SECURITY_ERROR, 6);
        assert_eq!(BundleException::STATECHANGE_ERROR, 7);
        assert_eq!(BundleException::NATIVECODE_ERROR, 8);
        assert_eq!(BundleException::DUPLICATE_BUNDLE_ERROR, 9);
        assert_eq!(BundleException::START_TRANSIENT_ERROR, 10);
        assert_eq!(BundleException::READ_ERROR, 11);
        assert_eq!(BundleException::REJECTED_BY_HOOK, 12);
    }

    #[test]
    fn ghidra_bundle_exception_with_bundle() {
        let bundle = Bundle::new("file:/path/to/bundle.jar");
        let cause = BundleException::new("resolution failed", BundleException::RESOLVE_ERROR);
        let exc = GhidraBundleException::with_bundle(bundle, "Failed to start bundle", &cause);
        assert!(exc.message().contains("Failed to start bundle"));
        assert!(exc.message().contains("RESOLVE_ERROR"));
    }

    #[test]
    fn ghidra_bundle_exception_with_location_and_cause() {
        let cause = BundleException::new("unsupported operation", BundleException::UNSUPPORTED_OPERATION);
        let exc = GhidraBundleException::with_location_and_cause(
            "file:/path/to/bundle.jar",
            "Failed to load bundle",
            &cause,
        );
        assert!(exc.message().contains("Failed to load bundle"));
        assert!(exc.message().contains("UNSUPPORTED_OPERATION"));
    }

    #[test]
    fn ghidra_bundle_exception_with_location() {
        let exc = GhidraBundleException::with_location("file:/path/to/bundle.jar", "Bundle not found");
        assert_eq!(exc.message(), "Bundle not found");
    }

    #[test]
    fn parsed_cause_unspecified() {
        let exc = BundleException::new("custom message", BundleException::UNSPECIFIED);
        let result = GhidraBundleException::parsed_cause(&exc);
        assert_eq!(result, "custom message");
    }

    #[test]
    fn parsed_cause_manifest_error() {
        let exc = BundleException::new("invalid manifest", BundleException::MANIFEST_ERROR);
        let result = GhidraBundleException::parsed_cause(&exc);
        assert_eq!(result, "MANIFEST_ERROR");
    }

    #[test]
    fn parsed_cause_activator_error() {
        let exc = BundleException::new("activator failed", BundleException::ACTIVATOR_ERROR);
        let result = GhidraBundleException::parsed_cause(&exc);
        assert_eq!(result, "ACTIVATOR_ERROR");
    }

    #[test]
    fn parsed_cause_resolve_error_with_global_lock_message() {
        let msg = "Unable to acquire global lock while resolving packages";
        let exc = BundleException::new(msg, BundleException::RESOLVE_ERROR);
        let result = GhidraBundleException::parsed_cause(&exc);
        assert_eq!(result, msg);
    }

    #[test]
    fn parsed_cause_resolve_error_with_packages() {
        let msg = "Unable to resolve: (&(osgi.wiring.package=org.slf4j)(version>=1.7.0))";
        let exc = BundleException::new(msg, BundleException::RESOLVE_ERROR);
        let result = GhidraBundleException::parsed_cause(&exc);
        assert!(result.contains("RESOLVE_ERROR"));
        assert!(result.contains("org.slf4j"));
    }

    #[test]
    fn ghidra_bundle_exception_implements_error() {
        let cause = BundleException::new("test error", BundleException::MANIFEST_ERROR);
        let exc = GhidraBundleException::with_location_and_cause("location", "msg", &cause);
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn ghidra_bundle_exception_to_string() {
        let cause = BundleException::new("detail", BundleException::MANIFEST_ERROR);
        let exc = GhidraBundleException::with_location_and_cause("location", "error", &cause);
        let s = exc.to_string();
        assert!(s.contains("error"));
        assert!(s.contains("MANIFEST_ERROR"));
    }
}
