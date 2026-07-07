use serde::Serialize;
use std::fmt;

use crate::generic::json::Json;

/// A simple struct to contain the various settings for demangling.
///
/// Mirrors `ghidra.app.util.demangler.DemanglerOptions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DemanglerOptions {
    apply_calling_convention: bool,
    apply_signature: bool,
    do_disassembly: bool,
    demangle_only_known_patterns: bool,
}

impl Default for DemanglerOptions {
    fn default() -> Self {
        Self {
            apply_calling_convention: true,
            apply_signature: true,
            do_disassembly: true,
            demangle_only_known_patterns: true,
        }
    }
}

impl DemanglerOptions {
    /// Creates a `DemanglerOptions` with default values.
    ///
    /// Mirrors `DemanglerOptions()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a `DemanglerOptions` copying `apply_signature`, `do_disassembly`, and
    /// `demangle_only_known_patterns` from `other`.
    ///
    /// Mirrors `DemanglerOptions(DemanglerOptions copy)`, which does not copy
    /// `applyCallingConvention` from the source object; that field keeps its default
    /// value instead. This quirk is preserved here to match Java behavior.
    pub fn copy_of(other: &DemanglerOptions) -> Self {
        Self {
            apply_calling_convention: true,
            apply_signature: other.apply_signature,
            do_disassembly: other.do_disassembly,
            demangle_only_known_patterns: other.demangle_only_known_patterns,
        }
    }

    /// Checks if the apply signature option is currently set.
    ///
    /// Mirrors `applySignature()`.
    pub fn apply_signature(&self) -> bool {
        self.apply_signature
    }

    /// Sets the option to apply function signatures that are demangled.
    ///
    /// Mirrors `setApplySignature(boolean)`.
    pub fn set_apply_signature(&mut self, apply_signature: bool) {
        self.apply_signature = apply_signature;
    }

    /// Checks if the option to perform disassembly for known data structures (like
    /// functions) when demangling is set.
    ///
    /// Mirrors `doDisassembly()`.
    pub fn do_disassembly(&self) -> bool {
        self.do_disassembly
    }

    /// Checks if the apply function signature calling convention option is currently set.
    ///
    /// Mirrors `applyCallingConvention()`.
    pub fn apply_calling_convention(&self) -> bool {
        self.apply_calling_convention
    }

    /// Sets the option to apply function signature calling conventions.
    ///
    /// Mirrors `setApplyCallingConvention(boolean)`.
    pub fn set_apply_calling_convention(&mut self, apply_calling_convention: bool) {
        self.apply_calling_convention = apply_calling_convention;
    }

    /// Sets the option to perform disassembly for known data structures (like functions)
    /// when demangling.
    ///
    /// Mirrors `setDoDisassembly(boolean)`.
    pub fn set_do_disassembly(&mut self, do_disassembly: bool) {
        self.do_disassembly = do_disassembly;
    }

    /// Checks if the option to only demangle known mangled patterns is set.
    ///
    /// Mirrors `demangleOnlyKnownPatterns()`.
    pub fn demangle_only_known_patterns(&self) -> bool {
        self.demangle_only_known_patterns
    }

    /// Sets the option to only demangle known mangled patterns. Setting this to `false`
    /// causes most symbols to be demangled, which may result in some symbols getting
    /// demangled that were not actually mangled symbols.
    ///
    /// Generally, a demangler will report an error if a symbol fails to demangle. Hence,
    /// clients can use this flag to prevent such errors, signalling to the demangler to
    /// only attempt those symbols that have a known start pattern. If the known start
    /// pattern list becomes comprehensive, then this flag can go away.
    ///
    /// Mirrors `setDemangleOnlyKnownPatterns(boolean)`.
    pub fn set_demangle_only_known_patterns(&mut self, demangle_only_known_patterns: bool) {
        self.demangle_only_known_patterns = demangle_only_known_patterns;
    }
}

impl fmt::Display for DemanglerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Json::to_string(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let opts = DemanglerOptions::new();
        assert!(opts.apply_calling_convention());
        assert!(opts.apply_signature());
        assert!(opts.do_disassembly());
        assert!(opts.demangle_only_known_patterns());
    }

    #[test]
    fn test_setters() {
        let mut opts = DemanglerOptions::new();

        opts.set_apply_calling_convention(false);
        assert!(!opts.apply_calling_convention());

        opts.set_apply_signature(false);
        assert!(!opts.apply_signature());

        opts.set_do_disassembly(false);
        assert!(!opts.do_disassembly());

        opts.set_demangle_only_known_patterns(false);
        assert!(!opts.demangle_only_known_patterns());
    }

    #[test]
    fn test_copy_of_does_not_copy_apply_calling_convention() {
        let mut original = DemanglerOptions::new();
        original.set_apply_calling_convention(false);
        original.set_apply_signature(false);
        original.set_do_disassembly(false);
        original.set_demangle_only_known_patterns(false);

        let copy = DemanglerOptions::copy_of(&original);

        // Mirrors the Java copy constructor's quirk: applyCallingConvention is not copied.
        assert!(copy.apply_calling_convention());
        assert!(!copy.apply_signature());
        assert!(!copy.do_disassembly());
        assert!(!copy.demangle_only_known_patterns());
    }

    #[test]
    fn test_copy_of_is_independent() {
        let original = DemanglerOptions::new();
        let mut copy = DemanglerOptions::copy_of(&original);
        copy.set_apply_signature(false);
        assert!(original.apply_signature());
        assert!(!copy.apply_signature());
    }

    #[test]
    fn test_clone_is_equal() {
        let opts = DemanglerOptions::new();
        let cloned = opts.clone();
        assert_eq!(opts, cloned);
    }

    #[test]
    fn test_display_contains_field_names() {
        let opts = DemanglerOptions::new();
        let s = opts.to_string();
        assert!(s.contains("apply_signature"));
        assert!(s.contains("do_disassembly"));
    }
}
