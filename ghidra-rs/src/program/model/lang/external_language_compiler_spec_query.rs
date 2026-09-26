//! Port of `ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery`.
//!
//! Analog to [`LanguageCompilerSpecQuery`](super::language_compiler_spec_query::LanguageCompilerSpecQuery),
//! for use with querying "external" languages -- ones that exist in other products, like IDA
//! Pro's `metapc`. Like its sibling, every Java field is a nullable reference type (`String`,
//! `Endian`, `Integer`, `CompilerSpecID`), so this port models every field as `Option<T>`. Java
//! doesn't override `equals()`/`hashCode()` here either, so (matching
//! [`LanguageCompilerSpecQuery`](super::language_compiler_spec_query::LanguageCompilerSpecQuery)'s
//! reasoning) this struct doesn't derive `PartialEq`.

use std::fmt;

use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;

/// A query used to filter external-language compiler specs (e.g. IDA Pro processor names).
/// `None` on any field means "no constraint on this criterion" (Java's `null`).
///
/// Port of `ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery`.
#[derive(Debug, Clone)]
pub struct ExternalLanguageCompilerSpecQuery {
    /// The external tool's processor name (e.g. IDA Pro's `"metapc"`), or `None`.
    pub external_processor_name: Option<String>,
    /// The name of the external tool (e.g. `"IDA-PRO"`), or `None`.
    pub external_tool: Option<String>,
    /// The processor's endianness, or `None`.
    pub endian: Option<Endian>,
    /// The size of an address in bits, or `None`.
    pub size: Option<i32>,
    /// The compiler spec id, or `None`.
    pub compiler_spec_id: Option<CompilerSpecID>,
}

impl ExternalLanguageCompilerSpecQuery {
    /// Constructs a new `ExternalLanguageCompilerSpecQuery`.
    ///
    /// Port of `ExternalLanguageCompilerSpecQuery(String, String, Endian, Integer,
    /// CompilerSpecID)`.
    pub fn new(
        external_processor_name: Option<String>,
        external_tool: Option<String>,
        endian: Option<Endian>,
        size: Option<i32>,
        compiler_spec_id: Option<CompilerSpecID>,
    ) -> Self {
        Self { external_processor_name, external_tool, endian, size, compiler_spec_id }
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

impl fmt::Display for ExternalLanguageCompilerSpecQuery {
    /// Port of `ExternalLanguageCompilerSpecQuery.toString()`, including Java's `"null"` literal
    /// for unset (`None`) fields.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "externalProcessorName={}; externalTool={}; endian={}; size={}; compiler={}",
            java_concat(&self.external_processor_name),
            java_concat(&self.external_tool),
            java_concat(&self.endian),
            java_concat(&self.size),
            java_concat(&self.compiler_spec_id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_wildcard_query_stores_all_none() {
        let q = ExternalLanguageCompilerSpecQuery::new(None, None, None, None, None);
        assert!(q.external_processor_name.is_none());
        assert!(q.external_tool.is_none());
        assert!(q.endian.is_none());
        assert!(q.size.is_none());
        assert!(q.compiler_spec_id.is_none());
    }

    #[test]
    fn all_wildcard_query_to_string_uses_null_literals() {
        let q = ExternalLanguageCompilerSpecQuery::new(None, None, None, None, None);
        assert_eq!(
            q.to_string(),
            "externalProcessorName=null; externalTool=null; endian=null; size=null; compiler=null"
        );
    }

    #[test]
    fn fully_populated_query_stores_fields() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            Some("metapc".to_string()),
            Some("IDA-PRO".to_string()),
            Some(Endian::Little),
            Some(32),
            Some(CompilerSpecID::new(Some("windows"))),
        );
        assert_eq!(q.external_processor_name.as_deref(), Some("metapc"));
        assert_eq!(q.external_tool.as_deref(), Some("IDA-PRO"));
        assert_eq!(q.endian, Some(Endian::Little));
        assert_eq!(q.size, Some(32));
        assert_eq!(q.compiler_spec_id, Some(CompilerSpecID::new(Some("windows"))));
    }

    #[test]
    fn fully_populated_query_to_string_matches_java_format() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            Some("metapc".to_string()),
            Some("IDA-PRO".to_string()),
            Some(Endian::Big),
            Some(64),
            Some(CompilerSpecID::new(Some("default"))),
        );
        assert_eq!(
            q.to_string(),
            "externalProcessorName=metapc; externalTool=IDA-PRO; endian=big; size=64; compiler=default"
        );
    }

    #[test]
    fn partial_query_mixes_null_and_populated_fields() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            Some("metapc".to_string()),
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            q.to_string(),
            "externalProcessorName=metapc; externalTool=null; endian=null; size=null; compiler=null"
        );
    }
}
