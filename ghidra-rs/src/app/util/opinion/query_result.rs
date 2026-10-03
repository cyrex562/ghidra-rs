//! Port of `ghidra.app.util.opinion.QueryResult`.
//!
//! A loader query result: a `LanguageCompilerSpecPair` an `.opinion` file matched, plus whether
//! that pair was the *exact* compiler spec asked for (`preferred`) or just a broader match.
//!
//! A lightweight placeholder of the same name already exists at
//! [`crate::app::seam_stubs::QueryResult`], threaded through
//! [`query_opinion_service`](crate::app::util::opinion::query_opinion_service) and several
//! `Loader` implementations (`elf_loader`, `dyld_cache_loader`, ...) before this file was ported,
//! and paired there with the placeholder
//! [`crate::program::seam_stubs::LanguageCompilerSpecPair`] rather than the real, full-fidelity
//! [`LanguageCompilerSpecPair`](crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair).
//! This module ports the real Java class faithfully against the real pair type instead, the same
//! "independent, full-fidelity type" precedent `LanguageCompilerSpecPair` itself already set (see
//! that module's docs): rewiring the placeholder's existing call sites to this type is a separate,
//! much larger refactor and out of scope here.
//!
//! ## Quirk faithfully preserved: `equals`/`hashCode` ignore `preferred`
//!
//! Java's `QueryResult.equals(Object)` and `hashCode()` both consider only the `pair` field,
//! deliberately ignoring `preferred`:
//!
//! ```java
//! // QueryResult.java
//! public int hashCode() {
//!     final int prime = 31;
//!     int result = 1;
//!     result = prime * result + ((pair == null) ? 0 : pair.hashCode());
//!     return result;
//! }
//!
//! public boolean equals(Object obj) {
//!     ...
//!     QueryResult other = (QueryResult) obj;
//!     if (pair == null) {
//!         if (other.pair != null) {
//!             return false;
//!         }
//!     }
//!     else if (!pair.equals(other.pair)) {
//!         return false;
//!     }
//!     return true;
//! }
//! ```
//!
//! This means two `QueryResult`s with the same `pair` but different `preferred` flags are equal
//! to each other, and collapse into a single entry when stored in a `HashSet<QueryResult>` (as
//! `QueryOpinionService`'s database does). This is reproduced as-is below (see
//! [`PartialEq`]/[`Hash`](std::hash::Hash) impls and the `equality_ignores_preferred_flag` test),
//! not "fixed", per this crate's policy of faithfully reproducing observed Java behavior.

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;

/// A loader query result: a `LanguageCompilerSpecPair` guess for what a binary loader might be,
/// plus whether it was the exact match requested.
///
/// Port of `ghidra.app.util.opinion.QueryResult`.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The language/compiler-spec pair this result names.
    ///
    /// Mirrors the public final field `pair`.
    pub pair: LanguageCompilerSpecPair,
    /// Whether `pair` was the exact compiler spec asked for, rather than a broader match.
    ///
    /// Mirrors the public final field `preferred`.
    pub preferred: bool,
}

impl QueryResult {
    /// Creates a new query result.
    ///
    /// Port of `QueryResult(LanguageCompilerSpecPair, boolean)`.
    pub fn new(pair: LanguageCompilerSpecPair, preferred: bool) -> Self {
        QueryResult { pair, preferred }
    }
}

impl fmt::Display for QueryResult {
    /// Port of `QueryResult.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "query result: {} ({}preferred)", self.pair, if self.preferred { "" } else { "not " })
    }
}

impl PartialEq for QueryResult {
    /// Port of `QueryResult.equals(Object)`, which compares only `pair` and deliberately ignores
    /// `preferred`. See the module docs for the faithfully-preserved quirk this implies.
    fn eq(&self, other: &Self) -> bool {
        self.pair == other.pair
    }
}

impl Eq for QueryResult {}

impl Hash for QueryResult {
    /// Port of `QueryResult.hashCode()`, which hashes only `pair`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pair.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(language: &str, compiler_spec: &str) -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new(language, compiler_spec)
    }

    #[test]
    fn new_stores_pair_and_preferred() {
        let p = pair("x86:LE:32:default", "gcc");
        let result = QueryResult::new(p.clone(), true);
        assert_eq!(result.pair, p);
        assert!(result.preferred);
    }

    #[test]
    fn to_string_reports_preferred_status() {
        let preferred = QueryResult::new(pair("x86:LE:32:default", "gcc"), true);
        assert_eq!(preferred.to_string(), "query result: x86:LE:32:default:gcc (preferred)");

        let not_preferred = QueryResult::new(pair("x86:LE:32:default", "gcc"), false);
        assert_eq!(not_preferred.to_string(), "query result: x86:LE:32:default:gcc (not preferred)");
    }

    #[test]
    fn equal_pairs_are_equal_regardless_of_preferred() {
        let a = QueryResult::new(pair("x86:LE:32:default", "gcc"), true);
        let b = QueryResult::new(pair("x86:LE:32:default", "gcc"), false);
        assert_eq!(a, b, "equals() ignores the preferred flag, mirroring QueryResult.equals");
    }

    #[test]
    fn different_pairs_are_not_equal() {
        let a = QueryResult::new(pair("x86:LE:32:default", "gcc"), true);
        let b = QueryResult::new(pair("x86:LE:32:default", "windows"), true);
        assert_ne!(a, b);
    }

    #[test]
    fn equality_ignores_preferred_flag_when_hashed() {
        // Faithful reproduction of the Java quirk documented in the module docs: two
        // QueryResults differing only in `preferred` hash identically and collapse into one
        // entry in a HashSet, exactly like Java's `Set<QueryResult>` database in
        // QueryOpinionService.
        use std::collections::HashSet;

        let a = QueryResult::new(pair("x86:LE:32:default", "gcc"), true);
        let b = QueryResult::new(pair("x86:LE:32:default", "gcc"), false);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1, "differing only in `preferred` must collapse into one HashSet entry");
    }
}
