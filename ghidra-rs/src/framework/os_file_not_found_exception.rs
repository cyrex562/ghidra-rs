//! Port of `ghidra.framework.OSFileNotFoundException`.
//!
//! Signals that an attempt to find a Ghidra "OS-file" (native binary) has failed. Java
//! `extends FileNotFoundException` (itself `extends IOException extends Exception`); per this
//! project's "composition over inheritance" rule, Rust has no exception-inheritance hierarchy to
//! fake, so -- matching this exact package's other exception port,
//! [`PluggableServiceRegistryException`](crate::framework::pluggable_service_registry_exception::PluggableServiceRegistryException)
//! -- this stores a precomputed `message: String` and implements `Display`/`std::error::Error`
//! directly, rather than wrapping a `std::io::Error`.
//!
//! A distinct, pre-existing [`OSFileNotFoundError`](crate::framework::application::OSFileNotFoundError)
//! already lives in `framework::application`, used internally by
//! [`Application`](crate::framework::application::Application)'s own OS-file lookup helpers
//! (`get_os_file`/`get_module_os_file`). That type predates this port, is a simplified stand-in
//! rather than a full port of this class (it has no `Platform` field and its message omits the
//! platform-directory-name segment entirely), and is left untouched here: the two are unrelated
//! types that happen to share a similar name and purpose.
//!
//! ## Omitted constructors
//!
//! Java has two additional convenience constructors, `OSFileNotFoundException(String, String)`
//! and `OSFileNotFoundException(String)`, which default `platform` to the static
//! `Platform.CURRENT_PLATFORM`. This port has no such static to default to: [`Platform`] was
//! selected as a dependency-cycle cut-point and ported as a trait with no concrete variants (see
//! that type's own doc comment), so there is no "current platform" singleton to reach for. Every
//! constructor here takes an explicit platform, mirroring how
//! [`Application`](crate::framework::application::Application) similarly omits
//! `Platform.CURRENT_PLATFORM`-dependent behavior for the same reason.
//!
//! ## Faithful quirk: a platform with no directory name formats as literal `"null"`
//!
//! Java builds the message with `String.format("%sos/%s/%s does not exist ...", ..., dirName,
//! fileName)`. Passing a platform whose `getDirectoryName()` returns `null` (e.g. the Java
//! `Platform.UNSUPPORTED` constant) is not special-cased: `Formatter` renders a `null` `%s`
//! argument as the four-character string `"null"`, so the message ends up containing the
//! substring `os/null/<fileName>` verbatim. This port reproduces that literal `"null"` rather
//! than substituting an empty string or omitting the segment. See the
//! `message_embeds_literal_null_when_platform_has_no_directory_name` test.

use crate::framework::platform::Platform;

/// Signals that an attempt to find a Ghidra "OS-file" (native binary) has failed. Port of
/// `ghidra.framework.OSFileNotFoundException`.
pub struct OSFileNotFoundException {
    platform: Box<dyn Platform>,
    module_name: Option<String>,
    file_name: String,
    message: String,
}

impl OSFileNotFoundException {
    /// Creates a new `OSFileNotFoundException` for the given module. Port of
    /// `OSFileNotFoundException(Platform, String, String)`.
    ///
    /// - `platform`: the platform associated with this exception
    /// - `module_name`: the module name associated with this exception, or `None` for an
    ///   unknown module (mirrors passing `null`)
    /// - `file_name`: the file name associated with this exception, from the given module
    pub fn new(platform: Box<dyn Platform>, module_name: Option<&str>, file_name: &str) -> Self {
        let prefix = match module_name {
            Some(name) => format!("{name}/"),
            None => String::new(),
        };
        // Faithful to Java's `String.format("%s", dirName)`: a `None` directory name renders as
        // the literal string "null", not an empty string.
        let dir_name = match platform.directory_name() {
            Some(d) => d.to_string(),
            None => "null".to_string(),
        };
        let message = format!(
            "{prefix}os/{dir_name}/{file_name} does not exist (see GettingStarted.md, 'Building Native Components')"
        );
        Self {
            platform,
            module_name: module_name.map(str::to_string),
            file_name: file_name.to_string(),
            message,
        }
    }

    /// Creates a new `OSFileNotFoundException` with an unknown module. Port of
    /// `OSFileNotFoundException(Platform, String)`.
    pub fn with_unknown_module(platform: Box<dyn Platform>, file_name: &str) -> Self {
        Self::new(platform, None, file_name)
    }

    /// Returns the [`Platform`] associated with this exception. Port of `getPlatform()`.
    pub fn platform(&self) -> &dyn Platform {
        self.platform.as_ref()
    }

    /// Returns the module name associated with this exception, if known.
    pub fn module_name(&self) -> Option<&str> {
        self.module_name.as_deref()
    }

    /// Returns the file name associated with this exception.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Returns the fully formatted exception message (mirrors `getMessage()`, inherited from
    /// `FileNotFoundException`/`IOException`/`Exception`).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Debug for OSFileNotFoundException {
    /// Manual `Debug` impl: [`Platform`] is an object-safe trait (a dependency-cycle cut-point,
    /// per its own doc comment) with no `Debug` supertrait bound, so `Box<dyn Platform>` cannot
    /// be included in a derived `Debug`. The platform is instead rendered via its `Display` impl
    /// (`impl Display for dyn Platform`, which shows `"{os} {arch}"`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OSFileNotFoundException")
            .field("platform", &self.platform.to_string())
            .field("module_name", &self.module_name)
            .field("file_name", &self.file_name)
            .field("message", &self.message)
            .finish()
    }
}

impl std::fmt::Display for OSFileNotFoundException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OSFileNotFoundException {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::os::OperatingSystem;
    use crate::framework::seam_stubs::Architecture;

    struct MockArchitecture(&'static str);

    impl std::fmt::Display for MockArchitecture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Architecture for MockArchitecture {}

    struct MockPlatform {
        directory_name: Option<&'static str>,
    }

    impl Platform for MockPlatform {
        fn operating_system(&self) -> OperatingSystem {
            OperatingSystem::Linux
        }

        fn architecture(&self) -> Box<dyn Architecture> {
            Box::new(MockArchitecture("x86_64"))
        }

        fn directory_name(&self) -> Option<&str> {
            self.directory_name
        }

        fn library_extension(&self) -> Option<&str> {
            Some(".so")
        }

        fn executable_extension(&self) -> &str {
            ""
        }
    }

    fn linux_platform() -> Box<dyn Platform> {
        Box::new(MockPlatform { directory_name: Some("linux_x86_64") })
    }

    fn unsupported_platform() -> Box<dyn Platform> {
        Box::new(MockPlatform { directory_name: None })
    }

    #[test]
    fn new_with_module_formats_message() {
        let ex = OSFileNotFoundException::new(linux_platform(), Some("MyModule"), "libfoo.so");
        assert_eq!(
            ex.message(),
            "MyModule/os/linux_x86_64/libfoo.so does not exist (see GettingStarted.md, 'Building Native Components')"
        );
        assert_eq!(ex.module_name(), Some("MyModule"));
        assert_eq!(ex.file_name(), "libfoo.so");
    }

    #[test]
    fn new_with_none_module_omits_module_prefix() {
        let ex = OSFileNotFoundException::new(linux_platform(), None, "libfoo.so");
        assert_eq!(
            ex.message(),
            "os/linux_x86_64/libfoo.so does not exist (see GettingStarted.md, 'Building Native Components')"
        );
        assert_eq!(ex.module_name(), None);
    }

    #[test]
    fn with_unknown_module_matches_new_with_none() {
        let a = OSFileNotFoundException::new(linux_platform(), None, "libfoo.so");
        let b = OSFileNotFoundException::with_unknown_module(linux_platform(), "libfoo.so");
        assert_eq!(a.message(), b.message());
        assert_eq!(a.module_name(), b.module_name());
    }

    /// Faithful reproduction of Java's `String.format` behavior for a `null` `%s` argument: see
    /// this module's doc comment.
    #[test]
    fn message_embeds_literal_null_when_platform_has_no_directory_name() {
        let ex = OSFileNotFoundException::new(unsupported_platform(), Some("MyModule"), "libfoo.so");
        assert_eq!(
            ex.message(),
            "MyModule/os/null/libfoo.so does not exist (see GettingStarted.md, 'Building Native Components')"
        );
    }

    #[test]
    fn platform_accessor_returns_the_supplied_platform() {
        let ex = OSFileNotFoundException::new(linux_platform(), None, "libfoo.so");
        assert_eq!(ex.platform().directory_name(), Some("linux_x86_64"));
    }

    #[test]
    fn display_matches_message() {
        let ex = OSFileNotFoundException::new(linux_platform(), None, "libfoo.so");
        assert_eq!(ex.to_string(), ex.message());
    }

    #[test]
    fn implements_std_error() {
        let ex = OSFileNotFoundException::new(linux_platform(), None, "libfoo.so");
        let _: &dyn std::error::Error = &ex;
    }

    #[test]
    fn debug_includes_key_fields() {
        let ex = OSFileNotFoundException::new(linux_platform(), Some("MyModule"), "libfoo.so");
        let debug_str = format!("{:?}", ex);
        assert!(debug_str.contains("OSFileNotFoundException"));
        assert!(debug_str.contains("MyModule"));
        assert!(debug_str.contains("libfoo.so"));
    }
}
