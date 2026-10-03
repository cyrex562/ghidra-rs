use crate::framework::os::OperatingSystem;
use crate::framework::seam_stubs::Architecture;

/// Identifies a platform (operating system and architecture) and the module OS directory
/// that holds native binaries for it.
///
/// Ported as a trait rather than the Java `enum` because this type was selected as a
/// dependency-cycle cut-point. In Java, `Platform` is a fixed set of named constants
/// (`WIN_X86_64`, `LINUX_ARM_64`, ...) plus a `CURRENT_PLATFORM` static computed by
/// scanning those constants for one matching the running OS/architecture. That static
/// lookup requires knowing every concrete variant up front, which is exactly the kind of
/// coupling a cut-point trait is meant to avoid: this trait only captures the
/// per-instance accessors, leaving the concrete variants (and the `CURRENT_PLATFORM`
/// lookup over them) to whatever future port supplies `Platform` implementors.
pub trait Platform {
    /// Returns the operating system for this platform.
    fn operating_system(&self) -> OperatingSystem;

    /// Returns the architecture for this platform.
    fn architecture(&self) -> Box<dyn Architecture>;

    /// Returns the directory name of this platform, or `None` if this platform has no
    /// associated native-binary directory (mirrors Java's `null` for `UNSUPPORTED`).
    fn directory_name(&self) -> Option<&str>;

    /// Returns the native library extension for this platform, or `None` if this
    /// platform has no associated native library extension.
    fn library_extension(&self) -> Option<&str>;

    /// Returns the executable extension for this platform (empty string if none).
    fn executable_extension(&self) -> &str;

    /// Based on this platform, returns operating-system-specific library paths that are
    /// not found on the `PATH` environment variable.
    ///
    /// Mirrors the OS-family branches of Java's `getAdditionalLibraryPaths()`. The
    /// original's extra Windows branch special-cases the specific `WIN_X86_64` singleton
    /// (via `CURRENT_PLATFORM == WIN_X86_64`) to probe `%SystemRoot%\SysWOW64`; without
    /// concrete `Platform` variants to compare against, that singleton check isn't
    /// reproducible here, so Windows implementors that need it should override this
    /// default.
    fn additional_library_paths(&self) -> Vec<String> {
        match self.operating_system() {
            OperatingSystem::Linux | OperatingSystem::FreeBSD => vec![
                "/bin".to_string(),
                "/lib".to_string(),
                "/lib64".to_string(),
                "/lib/x86_64-linux-gnu".to_string(),
                "/lib/aarch64-linux-gnu".to_string(),
                "/usr/bin".to_string(),
                "/usr/lib".to_string(),
                "/usr/X11R6/bin".to_string(),
                "/usr/X11R6/lib".to_string(),
            ],
            OperatingSystem::MacOSX => vec![
                "/System/Library/dyld/dyld_shared_cache_arm64e".to_string(),
                "/System/Library/dyld/dyld_shared_cache_x86_64".to_string(),
                "/System/Library/dyld/dyld_shared_cache_x86_64h".to_string(),
                "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e".to_string(),
                "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64".to_string(),
                "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64h".to_string(),
            ],
            _ => Vec::new(),
        }
    }
}

impl std::fmt::Display for dyn Platform {
    /// Mirrors Java's `Platform.toString()`, which concatenates the operating system and
    /// architecture display strings, separated by a space.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.operating_system(), self.architecture())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockArchitecture(&'static str);

    impl std::fmt::Display for MockArchitecture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Architecture for MockArchitecture {}

    /// Trivial mock standing in for a concrete Java `Platform` enum constant (e.g.
    /// `LINUX_X86_64`), proving `Platform` is usable as a trait object.
    struct MockPlatform {
        os: OperatingSystem,
        arch: &'static str,
        directory_name: Option<&'static str>,
        library_extension: Option<&'static str>,
        executable_extension: &'static str,
    }

    impl Platform for MockPlatform {
        fn operating_system(&self) -> OperatingSystem {
            self.os
        }

        fn architecture(&self) -> Box<dyn Architecture> {
            Box::new(MockArchitecture(self.arch))
        }

        fn directory_name(&self) -> Option<&str> {
            self.directory_name
        }

        fn library_extension(&self) -> Option<&str> {
            self.library_extension
        }

        fn executable_extension(&self) -> &str {
            self.executable_extension
        }
    }

    fn linux_x86_64() -> Box<dyn Platform> {
        Box::new(MockPlatform {
            os: OperatingSystem::Linux,
            arch: "x86_64",
            directory_name: Some("linux_x86_64"),
            library_extension: Some(".so"),
            executable_extension: "",
        })
    }

    fn unsupported() -> Box<dyn Platform> {
        Box::new(MockPlatform {
            os: OperatingSystem::Unsupported,
            arch: "Unknown Architecture",
            directory_name: None,
            library_extension: None,
            executable_extension: "",
        })
    }

    #[test]
    fn accessors_roundtrip() {
        let platform = linux_x86_64();
        assert_eq!(platform.operating_system(), OperatingSystem::Linux);
        assert_eq!(platform.directory_name(), Some("linux_x86_64"));
        assert_eq!(platform.library_extension(), Some(".so"));
        assert_eq!(platform.executable_extension(), "");
    }

    #[test]
    fn unsupported_platform_has_no_directory_or_library_extension() {
        let platform = unsupported();
        assert_eq!(platform.directory_name(), None);
        assert_eq!(platform.library_extension(), None);
    }

    #[test]
    fn display_combines_os_and_architecture() {
        let platform = linux_x86_64();
        let expected = format!("{} x86_64", OperatingSystem::Linux);
        assert_eq!(format!("{}", platform.as_ref()), expected);
    }

    #[test]
    fn default_additional_library_paths_covers_linux_and_bsd() {
        let linux_paths = linux_x86_64().additional_library_paths();
        assert!(linux_paths.contains(&"/usr/lib".to_string()));

        let mac_platform: Box<dyn Platform> = Box::new(MockPlatform {
            os: OperatingSystem::MacOSX,
            arch: "x86_64",
            directory_name: Some("mac_x86_64"),
            library_extension: Some(".dylib"),
            executable_extension: "",
        });
        let mac_paths = mac_platform.additional_library_paths();
        assert!(mac_paths
            .contains(&"/System/Library/dyld/dyld_shared_cache_x86_64".to_string()));

        assert!(unsupported().additional_library_paths().is_empty());
    }
}
