//! Port of the Java annotation type
//! `ghidra.app.plugin.core.debug.disassemble.DisassemblyInjectInfo`.
//!
//! # Shape
//!
//! Java declares `@interface DisassemblyInjectInfo` (retained at runtime, targeting types) with a
//! nested `@interface PlatformInfo`. Per the project's R4 decision, an annotation type becomes a
//! plain metadata struct of its elements; an annotated implementor exposes its instance through
//! [`DisassemblyInject::get_info`](super::DisassemblyInject::get_info), typically as a `static`
//! or associated `const`.
//!
//! Both structs hold `&'static` data so the whole annotation can be written as a compile-time
//! constant, exactly as Java annotation element values are compile-time constants.

/// A language-compiler-ID pair identifying a trace platform.
///
/// Port of the nested annotation `DisassemblyInjectInfo.PlatformInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlatformInfo {
    /// The language ID, e.g., `"x86:64:LE:default"`. Mirrors `langID()`.
    pub lang_id: &'static str,
    /// The compiler ID, e.g., `"gcc"` or `"windows"`. Mirrors `compilerID()`.
    ///
    /// Leave as the default (`""`) to apply to all compilers for the language.
    pub compiler_id: &'static str,
}

impl PlatformInfo {
    /// Java's default value of `compilerID()`: the empty string, matching every compiler.
    pub const DEFAULT_COMPILER_ID: &'static str = "";

    /// A platform entry for `lang_id` with an explicit `compiler_id`.
    pub const fn new(lang_id: &'static str, compiler_id: &'static str) -> Self {
        PlatformInfo {
            lang_id,
            compiler_id,
        }
    }

    /// A platform entry for `lang_id` that applies to every compiler, i.e. `compilerID()` left at
    /// its default.
    pub const fn for_language(lang_id: &'static str) -> Self {
        Self::new(lang_id, Self::DEFAULT_COMPILER_ID)
    }

    /// Check whether this entry matches a platform with the given language and compiler-spec IDs.
    ///
    /// This is the per-entry test from Java's `DisassemblyInject.isApplicable`: the language IDs
    /// must be equal, and the compiler ID must either be blank (Java `String.isBlank()`, i.e.
    /// empty or whitespace only) or equal to the platform's compiler-spec ID.
    pub fn matches(&self, lang_id: &str, compiler_spec_id: &str) -> bool {
        self.lang_id == lang_id
            && (self.compiler_id.trim().is_empty() || self.compiler_id == compiler_spec_id)
    }
}

/// Metadata describing where and in what order a
/// [`DisassemblyInject`](super::DisassemblyInject) applies.
///
/// Port of the annotation type `DisassemblyInjectInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisassemblyInjectInfo {
    /// A list of platforms for which this inject applies. Mirrors `platforms()`.
    ///
    /// See [`DisassemblyInject::is_applicable`](super::DisassemblyInject::is_applicable).
    pub platforms: &'static [PlatformInfo],
    /// The "position" of this inject's invocation. Mirrors `priority()`.
    ///
    /// Injects are ordered by priority, lowest first, so that later invocations get to choose how
    /// to resolve conflicts.
    pub priority: i32,
}

impl DisassemblyInjectInfo {
    /// Java's default value of `priority()`.
    pub const DEFAULT_PRIORITY: i32 = 100;

    /// The annotation Java places on the `DisassemblyInject` interface itself,
    /// `@DisassemblyInjectInfo(platforms = {})`, used there as the fallback info: no platforms
    /// and the default priority.
    pub const DEFAULT: DisassemblyInjectInfo = DisassemblyInjectInfo::new(&[]);

    /// Info for the given platforms at the default priority.
    pub const fn new(platforms: &'static [PlatformInfo]) -> Self {
        DisassemblyInjectInfo {
            platforms,
            priority: Self::DEFAULT_PRIORITY,
        }
    }

    /// Info for the given platforms at an explicit priority.
    pub const fn with_priority(platforms: &'static [PlatformInfo], priority: i32) -> Self {
        DisassemblyInjectInfo {
            platforms,
            priority,
        }
    }

    /// Check whether any listed platform matches the given language and compiler-spec IDs, per
    /// [`PlatformInfo::matches`].
    pub fn applies_to(&self, lang_id: &str, compiler_spec_id: &str) -> bool {
        self.platforms
            .iter()
            .any(|info| info.matches(lang_id, compiler_spec_id))
    }
}

impl Default for DisassemblyInjectInfo {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_java_annotation_defaults() {
        let info = DisassemblyInjectInfo::default();
        assert!(info.platforms.is_empty());
        assert_eq!(info.priority, 100);
        assert_eq!(PlatformInfo::for_language("ARM:LE:32:v8").compiler_id, "");
    }

    #[test]
    fn blank_compiler_id_matches_any_compiler() {
        let p = PlatformInfo::for_language("x86:LE:64:default");
        assert!(p.matches("x86:LE:64:default", "gcc"));
        assert!(p.matches("x86:LE:64:default", "windows"));
        assert!(!p.matches("x86:LE:32:default", "gcc"));
        // Java's isBlank() also treats whitespace-only as blank.
        let ws = PlatformInfo::new("x86:LE:64:default", "  ");
        assert!(ws.matches("x86:LE:64:default", "clang"));
    }

    #[test]
    fn explicit_compiler_id_must_equal() {
        let p = PlatformInfo::new("x86:LE:64:default", "windows");
        assert!(p.matches("x86:LE:64:default", "windows"));
        assert!(!p.matches("x86:LE:64:default", "gcc"));
    }

    #[test]
    fn applies_to_any_listed_platform() {
        static PLATFORMS: [PlatformInfo; 2] = [
            PlatformInfo::new("x86:LE:64:default", "windows"),
            PlatformInfo::for_language("ARM:LE:32:v8"),
        ];
        let info = DisassemblyInjectInfo::with_priority(&PLATFORMS, 5);
        assert_eq!(info.priority, 5);
        assert!(info.applies_to("ARM:LE:32:v8", "default"));
        assert!(info.applies_to("x86:LE:64:default", "windows"));
        assert!(!info.applies_to("x86:LE:64:default", "gcc"));
        assert!(!DisassemblyInjectInfo::DEFAULT.applies_to("ARM:LE:32:v8", ""));
    }
}
