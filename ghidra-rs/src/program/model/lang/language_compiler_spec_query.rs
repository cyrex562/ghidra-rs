//! Port of `ghidra.program.model.lang.LanguageCompilerSpecQuery`.
//!
//! An immutable set of optional filter criteria (`Processor`, `Endian`, address size, variant,
//! `CompilerSpecID`) used to query a `LanguageService` for matching `LanguageCompilerSpecPair`s.
//! Every Java field is a nullable reference type (`Processor`, `Endian`, `Integer`, `String`,
//! `CompilerSpecID`), and `null` is a real, load-bearing value here: callers across the codebase
//! construct an all-`null` query as an unrestricted "match everything" wildcard (e.g.
//! `OverrideDebuggerPlatformOpinion`'s `new LanguageCompilerSpecQuery(null, null, null, null,
//! null)`), and `QueryOpinionServiceHandler` explicitly checks each field for `null` to decide
//! whether to fall back to a broader query's value. This port therefore models every field as an
//! `Option<T>`, with `None` as the wildcard, matching Java's `null`.
//!
//! Java does not override `equals()`/`hashCode()` on this class (plain `Object` identity), so --
//! following the precedent set by [`AddressLabelInfo`](super::address_label_info::AddressLabelInfo)
//! (also not `equals()`-overridden in Java) -- this port does not derive `PartialEq` either, to
//! avoid silently introducing structural equality where Java has none.

use std::fmt;

use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::processor::Processor;

/// A query used to filter `LanguageCompilerSpecPair`s. `None` on any field means "no constraint
/// on this criterion" (Java's `null`).
///
/// Port of `ghidra.program.model.lang.LanguageCompilerSpecQuery`.
#[derive(Debug, Clone)]
pub struct LanguageCompilerSpecQuery {
    /// The language's processor, or `None` for no constraint.
    pub processor: Option<Processor>,
    /// The processor's endianness, or `None` for no constraint.
    pub endian: Option<Endian>,
    /// The size of an address in bits, or `None` for no constraint.
    pub size: Option<i32>,
    /// The processor variant, or `None` for no constraint.
    pub variant: Option<String>,
    /// The compiler spec id, or `None` for no constraint.
    pub compiler_spec_id: Option<CompilerSpecID>,
}

impl LanguageCompilerSpecQuery {
    /// Constructs a new `LanguageCompilerSpecQuery`.
    ///
    /// Port of `LanguageCompilerSpecQuery(Processor, Endian, Integer, String, CompilerSpecID)`.
    pub fn new(
        processor: Option<Processor>,
        endian: Option<Endian>,
        size: Option<i32>,
        variant: Option<String>,
        compiler_spec_id: Option<CompilerSpecID>,
    ) -> Self {
        Self { processor, endian, size, variant, compiler_spec_id }
    }
}

/// Formats `o` the way Java string concatenation formats a (possibly-`null`) reference: via its
/// `Display`, or the literal text `"null"`.
fn java_concat<T: fmt::Display>(o: &Option<T>) -> String {
    match o {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

impl fmt::Display for LanguageCompilerSpecQuery {
    /// Port of `LanguageCompilerSpecQuery.toString()`, including Java's `"null"` literal for
    /// unset (`None`) fields, produced by ordinary Java string concatenation of a `null`
    /// reference.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "processor={}; endian={}; size={}; variant={}; compiler={}",
            java_concat(&self.processor),
            java_concat(&self.endian),
            java_concat(&self.size),
            java_concat(&self.variant),
            java_concat(&self.compiler_spec_id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_wildcard_query_stores_all_none() {
        let q = LanguageCompilerSpecQuery::new(None, None, None, None, None);
        assert!(q.processor.is_none());
        assert!(q.endian.is_none());
        assert!(q.size.is_none());
        assert!(q.variant.is_none());
        assert!(q.compiler_spec_id.is_none());
    }

    #[test]
    fn all_wildcard_query_to_string_uses_null_literals() {
        let q = LanguageCompilerSpecQuery::new(None, None, None, None, None);
        assert_eq!(
            q.to_string(),
            "processor=null; endian=null; size=null; variant=null; compiler=null"
        );
    }

    #[test]
    fn fully_populated_query_stores_fields() {
        let processor = Processor::find_or_possibly_create_processor("x86_lcsq_test");
        let q = LanguageCompilerSpecQuery::new(
            Some(processor.clone()),
            Some(Endian::Little),
            Some(32),
            Some("default".to_string()),
            Some(CompilerSpecID::new(Some("gcc"))),
        );
        assert_eq!(q.processor, Some(processor));
        assert_eq!(q.endian, Some(Endian::Little));
        assert_eq!(q.size, Some(32));
        assert_eq!(q.variant.as_deref(), Some("default"));
        assert_eq!(q.compiler_spec_id, Some(CompilerSpecID::new(Some("gcc"))));
    }

    #[test]
    fn fully_populated_query_to_string_matches_java_format() {
        let processor = Processor::find_or_possibly_create_processor("ARM_lcsq_test");
        let q = LanguageCompilerSpecQuery::new(
            Some(processor),
            Some(Endian::Big),
            Some(64),
            Some("v8".to_string()),
            Some(CompilerSpecID::new(Some("default"))),
        );
        assert_eq!(
            q.to_string(),
            "processor=ARM_lcsq_test; endian=big; size=64; variant=v8; compiler=default"
        );
    }

    #[test]
    fn partial_query_mixes_null_and_populated_fields() {
        let q = LanguageCompilerSpecQuery::new(None, Some(Endian::Little), None, None, None);
        assert_eq!(
            q.to_string(),
            "processor=null; endian=little; size=null; variant=null; compiler=null"
        );
    }
}
