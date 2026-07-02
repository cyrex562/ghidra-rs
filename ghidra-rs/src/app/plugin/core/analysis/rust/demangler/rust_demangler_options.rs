use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::app::plugin::core::analysis::rust::demangler::rust_demangler_format::RustDemanglerFormat;
use crate::demangler::demangler_options::DemanglerOptions;

/// Rust demangler options.
///
/// Mirrors `ghidra.app.plugin.core.analysis.rust.demangler.RustDemanglerOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDemanglerOptions {
    options: DemanglerOptions,
    format: RustDemanglerFormat,
    is_deprecated: bool,
}

impl Default for RustDemanglerOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl RustDemanglerOptions {
    /// Creates a `RustDemanglerOptions` using the modern demangler with auto-detect for the
    /// format. This limits demangling to only known symbols.
    ///
    /// Mirrors `RustDemanglerOptions()`.
    pub fn new() -> Self {
        Self::with_format(RustDemanglerFormat::Auto)
            .expect("RustDemanglerFormat::Auto is always available")
    }

    /// Creates a `RustDemanglerOptions` for the given format.
    ///
    /// Mirrors `RustDemanglerOptions(RustDemanglerFormat)`.
    ///
    /// # Errors
    /// Returns `Err` if `format` is not available for the resulting deprecated/modern
    /// selection, mirroring the `IllegalArgumentException` thrown by the Java source.
    pub fn with_format(format: RustDemanglerFormat) -> Result<Self, String> {
        Self::with_format_and_deprecated(format, !format.is_modern_format())
    }

    /// Creates a `RustDemanglerOptions` for the given format, specifying whether to prefer the
    /// deprecated demangler when both deprecated and modern formats are available.
    ///
    /// Mirrors `RustDemanglerOptions(RustDemanglerFormat, boolean)`.
    ///
    /// # Errors
    /// Returns `Err` if `format` is not available in the deprecated demangler (when
    /// `is_deprecated` is `true`) or the modern demangler (when `is_deprecated` is `false`),
    /// mirroring the `IllegalArgumentException` thrown by the Java source.
    pub fn with_format_and_deprecated(
        format: RustDemanglerFormat,
        is_deprecated: bool,
    ) -> Result<Self, String> {
        if !format.is_available(is_deprecated) {
            return Err(format!("{:?} is not available", format));
        }
        Ok(Self {
            options: DemanglerOptions::new(),
            format,
            is_deprecated,
        })
    }

    /// Creates a `RustDemanglerOptions` from a more generic set of options.
    ///
    /// Mirrors the `RustDemanglerOptions(DemanglerOptions)` copy constructor's fallback branch,
    /// used when `copy` is not itself a `RustDemanglerOptions`: the format defaults to
    /// [`RustDemanglerFormat::Auto`] and `is_deprecated` defaults to `false`.
    pub fn from_demangler_options(copy: &DemanglerOptions) -> Self {
        Self {
            options: DemanglerOptions::copy_of(copy),
            format: RustDemanglerFormat::Auto,
            is_deprecated: false,
        }
    }

    /// Creates a `RustDemanglerOptions` from another `RustDemanglerOptions`.
    ///
    /// Mirrors the `RustDemanglerOptions(DemanglerOptions)` copy constructor's branch taken
    /// when `copy` is itself a `RustDemanglerOptions`: the format and `is_deprecated` are
    /// copied from `other`.
    pub fn copy_of(other: &RustDemanglerOptions) -> Self {
        Self {
            options: DemanglerOptions::copy_of(&other.options),
            format: other.format,
            is_deprecated: other.is_deprecated,
        }
    }

    /// Gets the current demangler format.
    ///
    /// Mirrors `getDemanglerFormat()`.
    pub fn demangler_format(&self) -> RustDemanglerFormat {
        self.format
    }
}

impl Deref for RustDemanglerOptions {
    type Target = DemanglerOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for RustDemanglerOptions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

impl fmt::Display for RustDemanglerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\n\tdoDisassembly: {},\n\tapplySignature: {},\n\tdemangleOnlyKnownPatterns: {},\n}}",
            self.do_disassembly(),
            self.apply_signature(),
            self.demangle_only_known_patterns()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_uses_auto_format_and_modern_demangler() {
        let opts = RustDemanglerOptions::new();
        assert_eq!(opts.demangler_format(), RustDemanglerFormat::Auto);
        assert!(!opts.is_deprecated);
    }

    #[test]
    fn test_with_format_derives_is_deprecated() {
        let legacy = RustDemanglerOptions::with_format(RustDemanglerFormat::Legacy).unwrap();
        assert!(!legacy.is_deprecated);

        let v0 = RustDemanglerOptions::with_format(RustDemanglerFormat::V0).unwrap();
        assert!(!v0.is_deprecated);
    }

    #[test]
    fn test_with_format_and_deprecated_rejects_unavailable_combination() {
        let result =
            RustDemanglerOptions::with_format_and_deprecated(RustDemanglerFormat::V0, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_format_and_deprecated_accepts_available_combination() {
        let result =
            RustDemanglerOptions::with_format_and_deprecated(RustDemanglerFormat::Legacy, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_demangler_options_defaults_format_to_auto() {
        let mut generic = DemanglerOptions::new();
        generic.set_apply_signature(false);

        let opts = RustDemanglerOptions::from_demangler_options(&generic);
        assert_eq!(opts.demangler_format(), RustDemanglerFormat::Auto);
        assert!(!opts.is_deprecated);
        assert!(!opts.apply_signature());
    }

    #[test]
    fn test_copy_of_preserves_format_and_is_deprecated() {
        let original =
            RustDemanglerOptions::with_format_and_deprecated(RustDemanglerFormat::Legacy, true)
                .unwrap();

        let copy = RustDemanglerOptions::copy_of(&original);
        assert_eq!(copy.demangler_format(), RustDemanglerFormat::Legacy);
        assert!(copy.is_deprecated);
    }

    #[test]
    fn test_deref_exposes_demangler_options() {
        let mut opts = RustDemanglerOptions::new();
        assert!(opts.apply_signature());

        opts.set_apply_signature(false);
        assert!(!opts.apply_signature());
    }

    #[test]
    fn test_display_matches_java_format() {
        let opts = RustDemanglerOptions::new();
        assert_eq!(
            opts.to_string(),
            "{\n\tdoDisassembly: true,\n\tapplySignature: true,\n\tdemangleOnlyKnownPatterns: true,\n}"
        );
    }
}
