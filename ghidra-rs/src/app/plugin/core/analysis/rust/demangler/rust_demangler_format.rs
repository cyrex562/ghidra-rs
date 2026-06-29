/// Enum representation of the available Rust demangler formats.
///
/// Maps to `ghidra.app.plugin.core.analysis.rust.demangler.RustDemanglerFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustDemanglerFormat {
    /// Automatic mangling format detection.
    Auto,
    /// Legacy mangling format.
    Legacy,
    /// v0 mangling format.
    V0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Version {
    Deprecated,
    Modern,
    All,
}

impl RustDemanglerFormat {
    fn version(self) -> Version {
        match self {
            Self::Auto => Version::All,
            Self::Legacy => Version::All,
            Self::V0 => Version::Modern,
        }
    }

    /// Returns the format option string passed to the native demangler via the `-s` option.
    pub fn format(self) -> &'static str {
        match self {
            Self::Auto => "",
            Self::Legacy => "legacy",
            Self::V0 => "v0",
        }
    }

    /// Returns `true` if this format is available in the deprecated rust demangler.
    pub fn is_deprecated_format(self) -> bool {
        matches!(self.version(), Version::Deprecated | Version::All)
    }

    /// Returns `true` if this format is available in a modern version of the rust demangler.
    pub fn is_modern_format(self) -> bool {
        matches!(self.version(), Version::Modern | Version::All)
    }

    /// Returns `true` if this format is available for the specified demangler.
    ///
    /// `is_deprecated` is `true` for the deprecated demangler, `false` for the modern one.
    pub fn is_available(self, is_deprecated: bool) -> bool {
        if is_deprecated {
            self.is_deprecated_format()
        } else {
            self.is_modern_format()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_format_string_is_empty() {
        assert_eq!(RustDemanglerFormat::Auto.format(), "");
    }

    #[test]
    fn legacy_format_string() {
        assert_eq!(RustDemanglerFormat::Legacy.format(), "legacy");
    }

    #[test]
    fn v0_format_string() {
        assert_eq!(RustDemanglerFormat::V0.format(), "v0");
    }

    #[test]
    fn auto_is_both_deprecated_and_modern() {
        assert!(RustDemanglerFormat::Auto.is_deprecated_format());
        assert!(RustDemanglerFormat::Auto.is_modern_format());
    }

    #[test]
    fn legacy_is_both_deprecated_and_modern() {
        assert!(RustDemanglerFormat::Legacy.is_deprecated_format());
        assert!(RustDemanglerFormat::Legacy.is_modern_format());
    }

    #[test]
    fn v0_is_modern_only() {
        assert!(!RustDemanglerFormat::V0.is_deprecated_format());
        assert!(RustDemanglerFormat::V0.is_modern_format());
    }

    #[test]
    fn is_available_deprecated_path() {
        assert!(RustDemanglerFormat::Auto.is_available(true));
        assert!(RustDemanglerFormat::Legacy.is_available(true));
        assert!(!RustDemanglerFormat::V0.is_available(true));
    }

    #[test]
    fn is_available_modern_path() {
        assert!(RustDemanglerFormat::Auto.is_available(false));
        assert!(RustDemanglerFormat::Legacy.is_available(false));
        assert!(RustDemanglerFormat::V0.is_available(false));
    }

    #[test]
    fn copy_and_equality() {
        let f = RustDemanglerFormat::V0;
        let g = f;
        assert_eq!(f, g);
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(RustDemanglerFormat::Auto, RustDemanglerFormat::Legacy);
        assert_ne!(RustDemanglerFormat::Legacy, RustDemanglerFormat::V0);
        assert_ne!(RustDemanglerFormat::Auto, RustDemanglerFormat::V0);
    }
}
