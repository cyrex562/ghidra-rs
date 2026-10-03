/// Port of `ghidra.framework.Architecture`.
///
/// The Java enum detects the running CPU architecture by case-insensitively matching
/// `System.getProperty("os.arch")` against each constant's associated architecture-name array,
/// in declaration order, falling back to `UNKNOWN`. This port follows the precedent set by
/// [`OperatingSystem`](crate::framework::os::OperatingSystem): [`Architecture::CURRENT`] uses
/// `cfg!(target_arch = ..)`, resolved at compile time against the actual build target, rather
/// than a runtime string property. [`Architecture::find_current`] is also provided, mirroring
/// the Java static method's loop-based logic directly (parameterized by the property string so
/// it is testable without depending on the actual build target), for callers that want the
/// Java-faithful runtime lookup instead.
///
/// Java quirk faithfully reproduced: the private `architectureName` field is initialized once,
/// as `System.getProperty("os.arch")` — the *current* runtime architecture property — not
/// anything derived from the specific enum constant. Every constant's field gets the same
/// value. `toString()` is `name() + "(" + architectureName + ")"`, so e.g. `ARM_64.toString()`
/// on an x86_64 JVM prints `"ARM_64(amd64)"`, not `"ARM_64(aarch64)"` — the parenthesized suffix
/// names the *running* architecture, regardless of which constant `toString()` was called on.
/// This port's [`Architecture`]'s `Display` impl reproduces that: it always appends
/// `std::env::consts::ARCH` (this port's analog of `os.arch`), never the variant's own
/// supported-name list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    PowerPC,
    PowerPC64,
    Arm64,
    Unknown,
}

impl Architecture {
    /// All declared constants, in the same order as the Java enum's declaration (the order
    /// [`Architecture::find_current`] searches in).
    const VALUES: [Architecture; 6] = [
        Architecture::X86,
        Architecture::X86_64,
        Architecture::PowerPC,
        Architecture::PowerPC64,
        Architecture::Arm64,
        Architecture::Unknown,
    ];

    /// Mirrors the static `CURRENT_ARCHITECTURE` field, computed at compile time via
    /// `cfg!(target_arch = ..)` rather than a runtime property lookup (see the module docs for
    /// why). For every target this crate builds for, this agrees with what
    /// [`Architecture::find_current`] would return when passed the real `os.arch` value the JVM
    /// would observe on that target.
    pub const CURRENT: Architecture = Self::find_current_at_compile_time();

    /// Mirrors each constant's private `supportedArchitectureNames` field: the varargs strings
    /// passed to the Java constructor.
    pub fn supported_architecture_names(&self) -> &'static [&'static str] {
        match self {
            Self::X86 => &["x86", "i386"],
            Self::X86_64 => &["x86_64", "amd64"],
            Self::PowerPC => &["ppc"],
            Self::PowerPC64 => &["ppc64"],
            Self::Arm64 => &["aarch64", "arm64"],
            Self::Unknown => &["Unknown Architecture"],
        }
    }

    /// Mirrors the private `supportsArchitecture(String)`: true if `architecture`
    /// case-insensitively matches one of this constant's supported architecture names.
    pub fn supports_architecture(&self, architecture: &str) -> bool {
        self.supported_architecture_names()
            .iter()
            .any(|name| name.eq_ignore_ascii_case(architecture))
    }

    /// Mirrors the private static `findCurrentArchitecture()`, parameterized by the
    /// `os.arch`-equivalent property string instead of reading it internally, so this is
    /// directly testable. Searches [`Architecture::VALUES`] in declaration order for the first
    /// constant whose [`Architecture::supports_architecture`] matches, falling back to
    /// [`Architecture::Unknown`].
    pub fn find_current(architecture_name_property: &str) -> Architecture {
        for architecture in Self::VALUES {
            if architecture.supports_architecture(architecture_name_property) {
                return architecture;
            }
        }
        Self::Unknown
    }

    /// Mirrors the built-in `Enum.name()` (screaming-snake-case constant name), used by
    /// `toString()`.
    fn enum_name(&self) -> &'static str {
        match self {
            Self::X86 => "X86",
            Self::X86_64 => "X86_64",
            Self::PowerPC => "POWERPC",
            Self::PowerPC64 => "POWERPC_64",
            Self::Arm64 => "ARM_64",
            Self::Unknown => "UNKNOWN",
        }
    }

    const fn find_current_at_compile_time() -> Self {
        if cfg!(target_arch = "x86") {
            Self::X86
        } else if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else if cfg!(target_arch = "powerpc") {
            Self::PowerPC
        } else if cfg!(target_arch = "powerpc64") {
            Self::PowerPC64
        } else if cfg!(target_arch = "aarch64") {
            Self::Arm64
        } else {
            Self::Unknown
        }
    }
}

impl std::fmt::Display for Architecture {
    /// Mirrors `Architecture.toString()`: `name() + "(" + architectureName + ")"`. As documented
    /// on [`Architecture`], `architectureName` is always the current runtime architecture
    /// property (here, `std::env::consts::ARCH`), never `self`'s own supported-name list — this
    /// is a faithful reproduction of the Java quirk, not this port's own choice.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.enum_name(), std::env::consts::ARCH)
    }
}

impl crate::framework::seam_stubs::Architecture for Architecture {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_architecture_names_match_java_constants() {
        assert_eq!(Architecture::X86.supported_architecture_names(), &["x86", "i386"]);
        assert_eq!(
            Architecture::X86_64.supported_architecture_names(),
            &["x86_64", "amd64"]
        );
        assert_eq!(Architecture::PowerPC.supported_architecture_names(), &["ppc"]);
        assert_eq!(Architecture::PowerPC64.supported_architecture_names(), &["ppc64"]);
        assert_eq!(
            Architecture::Arm64.supported_architecture_names(),
            &["aarch64", "arm64"]
        );
        assert_eq!(
            Architecture::Unknown.supported_architecture_names(),
            &["Unknown Architecture"]
        );
    }

    #[test]
    fn supports_architecture_is_case_insensitive() {
        assert!(Architecture::X86_64.supports_architecture("AMD64"));
        assert!(Architecture::X86_64.supports_architecture("x86_64"));
        assert!(!Architecture::X86_64.supports_architecture("ppc"));
    }

    #[test]
    fn supports_architecture_checks_every_alias() {
        assert!(Architecture::X86.supports_architecture("i386"));
        assert!(Architecture::X86.supports_architecture("x86"));
        assert!(Architecture::Arm64.supports_architecture("arm64"));
        assert!(Architecture::Arm64.supports_architecture("aarch64"));
    }

    #[test]
    fn find_current_matches_first_supporting_constant() {
        assert_eq!(Architecture::find_current("amd64"), Architecture::X86_64);
        assert_eq!(Architecture::find_current("x86_64"), Architecture::X86_64);
        assert_eq!(Architecture::find_current("i386"), Architecture::X86);
        assert_eq!(Architecture::find_current("ppc64"), Architecture::PowerPC64);
        assert_eq!(Architecture::find_current("aarch64"), Architecture::Arm64);
    }

    #[test]
    fn find_current_falls_back_to_unknown_for_unrecognized_property() {
        assert_eq!(Architecture::find_current("sparc"), Architecture::Unknown);
        assert_eq!(Architecture::find_current(""), Architecture::Unknown);
    }

    #[test]
    fn current_matches_target_arch_at_compile_time() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(Architecture::CURRENT, Architecture::X86_64);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(Architecture::CURRENT, Architecture::Arm64);
        #[cfg(target_arch = "x86")]
        assert_eq!(Architecture::CURRENT, Architecture::X86);
    }

    /// Faithful reproduction of the Java quirk documented on [`Architecture`]: every constant's
    /// `toString()` reports the *current* runtime architecture in parentheses, not its own name
    /// or supported-architecture list. `X86` and `Arm64` disagree on their supported names but
    /// must agree on the parenthesized suffix, because both read the same
    /// `std::env::consts::ARCH` rather than anything derived from `self`.
    #[test]
    fn display_suffix_is_the_current_runtime_arch_regardless_of_variant() {
        let x86 = Architecture::X86.to_string();
        let arm64 = Architecture::Arm64.to_string();
        let suffix = format!("({})", std::env::consts::ARCH);
        assert!(x86.starts_with("X86("));
        assert!(x86.ends_with(&suffix));
        assert!(arm64.starts_with("ARM_64("));
        assert!(arm64.ends_with(&suffix));
        // Both variants report the identical parenthesized architecture, even though `X86` does
        // not even list `std::env::consts::ARCH` among its own `supported_architecture_names()`
        // on most build targets.
        assert_eq!(
            x86.rsplit_once('(').unwrap().1,
            arm64.rsplit_once('(').unwrap().1
        );
    }

    #[test]
    fn display_enum_names_match_java_constant_names() {
        assert_eq!(Architecture::PowerPC.enum_name(), "POWERPC");
        assert_eq!(Architecture::PowerPC64.enum_name(), "POWERPC_64");
        assert_eq!(Architecture::Unknown.enum_name(), "UNKNOWN");
        assert!(Architecture::PowerPC.to_string().starts_with("POWERPC("));
        assert!(Architecture::PowerPC64.to_string().starts_with("POWERPC_64("));
    }

    #[test]
    fn all_variants_distinct() {
        let variants = Architecture::VALUES;
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }

    /// Proves the real enum satisfies the pre-existing seam trait
    /// (`crate::framework::seam_stubs::Architecture`) that
    /// [`Platform`](crate::framework::platform::Platform) was written against before this port
    /// existed, so implementors can now use [`Architecture`] directly instead of a mock.
    #[test]
    fn implements_platform_architecture_seam() {
        let boxed: Box<dyn crate::framework::seam_stubs::Architecture> =
            Box::new(Architecture::X86_64);
        assert!(boxed.to_string().starts_with("X86_64("));
    }
}
