//! Port of `ghidra.plugins.importer.batch.BatchGroupLoadSpec`.

use std::cmp::Ordering;
use std::fmt;

use crate::app::util::opinion::load_spec::LoadSpec;
use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;

/// Similar to a [`LoadSpec`], but not associated with a loader, so that load specs from
/// different files can be grouped by what they would load as.
///
/// Port of `ghidra.plugins.importer.batch.BatchGroupLoadSpec`. Equality and hashing are over
/// `(lcs_pair, preferred)` as in Java; ordering compares the [`Display`](fmt::Display) strings
/// (Java `compareTo`), falling back to the fields so that it stays consistent with equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BatchGroupLoadSpec {
    /// The language/compiler pair, or `None` when the loader does not use one.
    pub lcs_pair: Option<LanguageCompilerSpecPair>,
    /// Whether the originating load spec was preferred.
    pub preferred: bool,
}

impl BatchGroupLoadSpec {
    /// Creates a group load spec from a [`LoadSpec`], dropping its loader and image base.
    pub fn new(load_spec: &LoadSpec) -> Self {
        Self {
            lcs_pair: load_spec.get_language_compiler_spec().cloned(),
            preferred: load_spec.is_preferred(),
        }
    }

    /// Whether `load_spec` has the same language/compiler pair as this group spec (both absent
    /// counts as a match). The preferred flag is not compared, as in Java.
    pub fn matches(&self, load_spec: &LoadSpec) -> bool {
        load_spec.get_language_compiler_spec() == self.lcs_pair.as_ref()
    }
}

impl fmt::Display for BatchGroupLoadSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.lcs_pair {
            Some(lcs) => write!(f, "{lcs}")?,
            None => f.write_str("none")?,
        }
        if self.preferred {
            f.write_str("*")?;
        }
        Ok(())
    }
}

impl Ord for BatchGroupLoadSpec {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string()
            .cmp(&other.to_string())
            .then_with(|| self.lcs_pair.cmp(&other.lcs_pair))
            .then_with(|| self.preferred.cmp(&other.preferred))
    }
}

impl PartialOrd for BatchGroupLoadSpec {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::importer::batch::test_support::spec;

    #[test]
    fn built_from_load_spec() {
        let g = BatchGroupLoadSpec::new(&spec("ELF", Some(("x86:LE:64:default", "gcc")), true));
        assert_eq!(g.lcs_pair, Some(LanguageCompilerSpecPair::new("x86:LE:64:default", "gcc")));
        assert!(g.preferred);
    }

    #[test]
    fn to_string_matches_java() {
        let g = BatchGroupLoadSpec::new(&spec("ELF", Some(("x86:LE:64:default", "gcc")), true));
        assert_eq!(g.to_string(), "x86:LE:64:default:gcc*");
        let g = BatchGroupLoadSpec::new(&spec("ELF", Some(("ARM:LE:32:v8", "default")), false));
        assert_eq!(g.to_string(), "ARM:LE:32:v8:default");
        let g = BatchGroupLoadSpec::new(&spec("Raw", None, true));
        assert_eq!(g.to_string(), "none*");
    }

    #[test]
    fn matches_ignores_loader_and_preferred() {
        let g = BatchGroupLoadSpec::new(&spec("ELF", Some(("x86:LE:64:default", "gcc")), true));
        assert!(g.matches(&spec("PE", Some(("x86:LE:64:default", "gcc")), false)));
        assert!(!g.matches(&spec("ELF", Some(("x86:LE:64:default", "windows")), true)));
        assert!(!g.matches(&spec("ELF", None, true)));

        let none = BatchGroupLoadSpec::new(&spec("Raw", None, false));
        assert!(none.matches(&spec("Other", None, true)));
        assert!(!none.matches(&spec("ELF", Some(("x86:LE:64:default", "gcc")), true)));
    }

    #[test]
    fn equality_includes_preferred() {
        let a = BatchGroupLoadSpec::new(&spec("A", Some(("x86:LE:32:default", "gcc")), true));
        let b = BatchGroupLoadSpec::new(&spec("B", Some(("x86:LE:32:default", "gcc")), true));
        let c = BatchGroupLoadSpec::new(&spec("A", Some(("x86:LE:32:default", "gcc")), false));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ordering_is_by_display_string() {
        let mut v = vec![
            BatchGroupLoadSpec::new(&spec("A", Some(("x86:LE:32:default", "gcc")), false)),
            BatchGroupLoadSpec::new(&spec("A", None, false)),
            BatchGroupLoadSpec::new(&spec("A", Some(("ARM:LE:32:v8", "default")), true)),
        ];
        v.sort();
        let s: Vec<String> = v.iter().map(ToString::to_string).collect();
        assert_eq!(s, vec!["ARM:LE:32:v8:default*", "none", "x86:LE:32:default:gcc"]);
    }
}
