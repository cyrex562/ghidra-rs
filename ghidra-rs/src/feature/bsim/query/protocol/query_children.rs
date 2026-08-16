//! Port of `ghidra.features.bsim.query.protocol.QueryChildren`.
//!
//! Query based on a single executable and a specific list of function names within the
//! executable. The response is the corresponding `FunctionDescription` records and a record for
//! each child of the specified functions.

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::{FunctionEntry, LSHVectorFactory, ResponseChildren};
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;
use std::io::Write;

/// Query based on a single executable and a specific list of function names within the
/// executable.
///
/// Java: `QueryChildren extends BSimQuery<ResponseChildren>`.
pub struct QueryChildren {
    /// If set, identifies the executable by its MD5 hash; takes priority over
    /// `name_exec`/`arch`/`name_compiler` when non-empty.
    pub md5sum: Option<String>,

    /// Name of the executable, used when `md5sum` is not set.
    pub name_exec: Option<String>,

    /// Architecture of the executable, used when `md5sum` is not set.
    pub arch: Option<String>,

    /// Name of the compiler used to build the executable, used when `md5sum` is not set.
    pub name_compiler: Option<String>,

    /// The list of function keys to query children for.
    pub function_keys: Vec<Box<dyn FunctionEntry>>,

    /// The response object (same as `response` in the parent BSimQuery).
    pub childrenresponse: Option<Box<dyn ResponseChildren>>,

    base: crate::feature::bsim::query::protocol::QueryResponseRecordBase,
}

impl QueryChildren {
    /// Create a new QueryChildren query with default settings.
    ///
    /// Java: `QueryChildren()`.
    pub fn new() -> Self {
        Self {
            md5sum: None,
            name_exec: None,
            arch: None,
            name_compiler: None,
            function_keys: Vec::new(),
            childrenresponse: None,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new(
                "querychildren",
            ),
        }
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.childrenresponse.is_none() {
            // In the real implementation, ResponseChildren would be a concrete type
            // constructed with a back-reference to this query:
            // self.childrenresponse = Some(Box::new(ResponseChildren::new(self)));
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        let name = self.base.get_name();
        write!(fwrite, "<{}>\n", name)?;
        let use_md5 = self.md5sum.as_deref().is_some_and(|s| !s.is_empty());
        if use_md5 {
            write!(fwrite, "  <md5>{}</md5>\n", self.md5sum.as_deref().unwrap())?;
        } else {
            fwrite.write_all(b"  <name>")?;
            if let Some(name_exec) = &self.name_exec {
                let mut escaped = String::new();
                spec_xml_utils::xml_escape(&mut escaped, name_exec);
                fwrite.write_all(escaped.as_bytes())?;
            }
            fwrite.write_all(b"</name>\n")?;

            fwrite.write_all(b"  <arch>")?;
            if let Some(arch) = &self.arch {
                let mut escaped = String::new();
                spec_xml_utils::xml_escape(&mut escaped, arch);
                fwrite.write_all(escaped.as_bytes())?;
            }
            fwrite.write_all(b"</arch>\n")?;

            fwrite.write_all(b"  <compiler>")?;
            if let Some(name_compiler) = &self.name_compiler {
                let mut escaped = String::new();
                spec_xml_utils::xml_escape(&mut escaped, name_compiler);
                fwrite.write_all(escaped.as_bytes())?;
            }
            fwrite.write_all(b"</compiler>\n")?;
        }
        for key in &self.function_keys {
            key.save_xml(fwrite)?;
        }
        write!(fwrite, "</{}>\n", name)?;
        Ok(())
    }

    /// Restore this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // parser.start(self.base.get_name());
        // let el = parser.start();
        // if el.get_name() == "md5" {
        //     self.md5sum = Some(parser.end().get_text().to_string());
        //     self.name_exec = None;
        //     self.arch = None;
        //     self.name_compiler = None;
        // } else {
        //     self.md5sum = None;
        //     self.name_exec = Some(parser.end().get_text().to_string());
        //     parser.start("arch");
        //     self.arch = Some(parser.end().get_text().to_string());
        //     parser.start("compiler");
        //     self.name_compiler = Some(parser.end().get_text().to_string());
        // }
        // while parser.peek().is_start() {
        //     let function_key = FunctionEntry::restore_xml(parser);
        //     self.function_keys.push(function_key);
        // }
        // parser.end();
        Ok(())
    }
}

impl Default for QueryChildren {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for QueryChildren {
    fn base(&self) -> &crate::feature::bsim::query::protocol::QueryResponseRecordBase {
        &self.base
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        Self::save_xml(self, fwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFunctionEntry {
        name: String,
    }

    impl FunctionEntry for MockFunctionEntry {
        fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
            write!(fwrite, "  <fkey>{}</fkey>\n", self.name)
        }
    }

    #[test]
    fn test_query_children_new() {
        let query = QueryChildren::new();
        assert!(query.md5sum.is_none());
        assert!(query.name_exec.is_none());
        assert!(query.arch.is_none());
        assert!(query.name_compiler.is_none());
        assert!(query.function_keys.is_empty());
        assert!(query.childrenresponse.is_none());
        assert_eq!(query.base.get_name(), "querychildren");
    }

    #[test]
    fn test_query_children_default() {
        let query = QueryChildren::default();
        assert_eq!(query.base.get_name(), "querychildren");
    }

    #[test]
    fn test_query_children_query_response_record_trait() {
        let query = QueryChildren::new();
        let record: &dyn QueryResponseRecord = &query;
        assert_eq!(record.get_name(), "querychildren");
    }

    #[test]
    fn test_query_children_build_response_template() {
        let mut query = QueryChildren::new();
        assert!(query.childrenresponse.is_none());
        query.build_response_template();
        // Still none since ResponseChildren is not implemented yet.
        assert!(query.childrenresponse.is_none());
    }

    #[test]
    fn test_query_children_save_xml_with_md5() {
        let mut query = QueryChildren::new();
        query.md5sum = Some("deadbeef".to_string());
        // name_exec/arch/name_compiler are ignored when md5sum is set.
        query.name_exec = Some("ignored".to_string());

        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert_eq!(
            xml_str,
            "<querychildren>\n  <md5>deadbeef</md5>\n</querychildren>\n"
        );
    }

    #[test]
    fn test_query_children_save_xml_with_name_arch_compiler() {
        let mut query = QueryChildren::new();
        query.name_exec = Some("my<exe>".to_string());
        query.arch = Some("x86:LE:64".to_string());
        query.name_compiler = Some("gcc & clang".to_string());

        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert_eq!(
            xml_str,
            "<querychildren>\n  <name>my&lt;exe&gt;</name>\n  <arch>x86:LE:64</arch>\n  <compiler>gcc &amp; clang</compiler>\n</querychildren>\n"
        );
    }

    #[test]
    fn test_query_children_save_xml_empty_md5_falls_back_to_name() {
        let mut query = QueryChildren::new();
        query.md5sum = Some(String::new());
        query.name_exec = Some("myexe".to_string());

        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert!(xml_str.contains("<name>myexe</name>"));
        assert!(!xml_str.contains("<md5>"));
    }

    #[test]
    fn test_query_children_save_xml_no_fields_set() {
        let query = QueryChildren::new();
        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert_eq!(
            xml_str,
            "<querychildren>\n  <name></name>\n  <arch></arch>\n  <compiler></compiler>\n</querychildren>\n"
        );
    }

    #[test]
    fn test_query_children_save_xml_with_function_keys() {
        let mut query = QueryChildren::new();
        query.md5sum = Some("cafef00d".to_string());
        query.function_keys.push(Box::new(MockFunctionEntry {
            name: "foo".to_string(),
        }));
        query.function_keys.push(Box::new(MockFunctionEntry {
            name: "bar".to_string(),
        }));

        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert_eq!(
            xml_str,
            "<querychildren>\n  <md5>cafef00d</md5>\n  <fkey>foo</fkey>\n  <fkey>bar</fkey>\n</querychildren>\n"
        );
    }

    #[test]
    fn test_query_children_restore_xml_stub_ok() {
        struct DummyParser;
        impl XmlPullParser for DummyParser {
            fn start(&self, _name: &str) {}
            fn end(&self) {}
        }
        struct DummyVectorFactory;
        impl LSHVectorFactory for DummyVectorFactory {
            fn build_zero_vector(&self) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn build_vector(
                &self,
                _feature: &[i32],
            ) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn restore_vector_from_xml(
                &self,
                _parser: &dyn XmlPullParser,
            ) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn restore_vector_from_sql(
                &self,
                _sql: &str,
            ) -> std::io::Result<Box<dyn crate::feature::seam_stubs::LSHVector>> {
                unimplemented!()
            }
            fn set(
                &self,
                _w_factory: &dyn crate::feature::seam_stubs::WeightFactory,
                _i_lookup: &dyn crate::feature::seam_stubs::IDFLookup,
                _settings: i32,
            ) {
            }
            fn is_loaded(&self) -> bool {
                false
            }
            fn get_significance_scale(&self) -> f64 {
                0.0
            }
            fn get_significance_addend(&self) -> f64 {
                0.0
            }
            fn get_settings(&self) -> i32 {
                0
            }
            fn get_self_significance(
                &self,
                _vector: &dyn crate::feature::seam_stubs::LSHVector,
            ) -> f64 {
                0.0
            }
            fn calculate_significance(
                &self,
                _data: &dyn crate::feature::seam_stubs::VectorCompare,
            ) -> f64 {
                0.0
            }
            fn read_weights(&self, _parser: &dyn XmlPullParser) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut query = QueryChildren::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }
}
