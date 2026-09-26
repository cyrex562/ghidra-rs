/// Port of `ghidra.framework.OperatingSystem`.
///
/// The Java enum detects the running OS by substring-matching
/// `System.getProperty("os.name")` (case-insensitively) against each constant's associated
/// display name, in declaration order, falling back to `UNSUPPORTED`. This port instead uses
/// `cfg!(target_os = ..)`, which is resolved at compile time against the actual build target
/// rather than a runtime string property; for every target this crate builds for, the two
/// approaches agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOSX,
    FreeBSD,
    OpenBsd,
    Unsupported,
}

impl OperatingSystem {
    pub const CURRENT: OperatingSystem = Self::find_current();

    /// Mirrors the Java constant's associated display name (the string each `os.name` value is
    /// substring-matched against), e.g. `OperatingSystem.MAC_OS_X`'s `"Mac OS X"`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOSX => "Mac OS X",
            Self::FreeBSD => "FreeBSD",
            Self::OpenBsd => "OpenBSD",
            Self::Unsupported => "Unsupported Operating System",
        }
    }

    const fn find_current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOSX
        } else if cfg!(target_os = "freebsd") {
            Self::FreeBSD
        } else if cfg!(target_os = "openbsd") {
            Self::OpenBsd
        } else {
            Self::Unsupported
        }
    }
}

impl std::fmt::Display for OperatingSystem {
    /// Mirrors `OperatingSystem.toString()`, which returns
    /// `name() + "(" + operatingSystemProperty + ")"` — the built-in `Enum.name()` (e.g.
    /// `"MAC_OS_X"`), not the constructor-supplied display name from
    /// [`OperatingSystem::name`]. `operatingSystemProperty` in Java is
    /// `System.getProperty("os.name")`, the raw OS name string; this port substitutes
    /// `std::env::consts::OS` (e.g. `"linux"`, `"macos"`) as the nearest compile-time
    /// equivalent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enum_name = match self {
            Self::Windows => "WINDOWS",
            Self::Linux => "LINUX",
            Self::MacOSX => "MAC_OS_X",
            Self::FreeBSD => "FREE_BSD",
            Self::OpenBsd => "OPEN_BSD",
            Self::Unsupported => "UNSUPPORTED",
        };
        write!(f, "{}({})", enum_name, std::env::consts::OS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_os() {
        let current = OperatingSystem::CURRENT;
        #[cfg(target_os = "windows")]
        assert_eq!(current, OperatingSystem::Windows);
        #[cfg(target_os = "linux")]
        assert_eq!(current, OperatingSystem::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(current, OperatingSystem::MacOSX);
        #[cfg(target_os = "freebsd")]
        assert_eq!(current, OperatingSystem::FreeBSD);
        #[cfg(target_os = "openbsd")]
        assert_eq!(current, OperatingSystem::OpenBsd);
    }

    /// `OperatingSystem.name()`'s (the constructor-supplied display name, not `Enum.name()`)
    /// values are ported verbatim from the Java constants.
    #[test]
    fn test_display_names_match_java_constants() {
        assert_eq!(OperatingSystem::Windows.name(), "Windows");
        assert_eq!(OperatingSystem::Linux.name(), "Linux");
        assert_eq!(OperatingSystem::MacOSX.name(), "Mac OS X");
        assert_eq!(OperatingSystem::FreeBSD.name(), "FreeBSD");
        assert_eq!(OperatingSystem::OpenBsd.name(), "OpenBSD");
        assert_eq!(OperatingSystem::Unsupported.name(), "Unsupported Operating System");
    }

    /// `toString()` mirrors `Enum.name()` (screaming-snake-case), not the constructor's display
    /// name field — e.g. `MAC_OS_X.toString()` starts with `"MAC_OS_X("`, not `"Mac OS X("`.
    #[test]
    fn test_to_string_uses_enum_constant_name_not_display_name() {
        let s = OperatingSystem::MacOSX.to_string();
        assert!(s.starts_with("MAC_OS_X("));
        assert!(s.ends_with(')'));

        let s = OperatingSystem::OpenBsd.to_string();
        assert!(s.starts_with("OPEN_BSD("));
    }

    #[test]
    fn test_all_variants_distinct() {
        let variants = [
            OperatingSystem::Windows,
            OperatingSystem::Linux,
            OperatingSystem::MacOSX,
            OperatingSystem::FreeBSD,
            OperatingSystem::OpenBsd,
            OperatingSystem::Unsupported,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }
}
