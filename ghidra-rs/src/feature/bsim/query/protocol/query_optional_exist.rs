//! Port of `ghidra.features.bsim.query.protocol.QueryOptionalExist`.
//!
//! Query whether an optional table exists. If it doesn't exist it can be created. If it exists,
//! it can be cleared.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseOptionalExist};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;

/// Query whether an optional table exists, with the option to create or clear it.
///
/// Java: `QueryOptionalExist extends BSimQuery<ResponseOptionalExist>`.
pub struct QueryOptionalExist {
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub optionalresponse: Option<ResponseOptionalExist>,
    /// Formal SQL name of the table.
    pub table_name: Option<String>,
    /// Type-code for the key column (from `java.sql.Types`).
    pub key_type: i32,
    /// Type-code for the value column.
    pub value_type: i32,
    /// True if the table should be created if it doesn't exist.
    pub attempt_creation: bool,
    /// If true, and the table already exists, clear all rows of the table.
    pub clear_table: bool,

    base: BSimQueryBase,
}

impl QueryOptionalExist {
    /// Java: `QueryOptionalExist()`.
    pub fn new() -> Self {
        Self {
            optionalresponse: None,
            table_name: None,
            key_type: -1,
            value_type: -1,
            attempt_creation: false,
            clear_table: false,
            base: BSimQueryBase::new("queryoptionalexist"),
        }
    }

    /// Java: `getName()` (inherited from `BSimQuery`).
    pub fn get_name(&self) -> &str {
        self.base.get_name()
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.optionalresponse.is_none() {
            self.optionalresponse = Some(ResponseOptionalExist::new());
        }
    }

    /// Serializes this query, including its response-shaping fields.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a real Java bug: `table_name`
    /// starts out `None` (see [`new`](Self::new)) and `saveXml` calls
    /// `SpecXmlUtils.xmlEscapeWriter(fwrite, tableName)` unconditionally, with no null check, so
    /// calling this before `table_name` is populated throws a `NullPointerException` in the real
    /// Ghidra code, and panics here for the same reason (see
    /// [`tests::save_xml_panics_when_table_name_is_unset`]).
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        let name = self.get_name();
        write!(fwrite, "<{name}>\n")?;
        let table_name = self.table_name.as_deref().expect(
            "Java: QueryOptionalExist.saveXml calls SpecXmlUtils.xmlEscapeWriter(fwrite, \
             tableName) unconditionally; tableName is null until explicitly set, so this throws \
             a NullPointerException in the real Ghidra code too",
        );
        write!(fwrite, "<tablename>")?;
        let mut escaped = String::new();
        spec_xml_utils::xml_escape(&mut escaped, table_name);
        write!(fwrite, "{escaped}")?;
        write!(fwrite, "</tablename>\n")?;
        write!(fwrite, "<keytype>{}</keytype>\n", self.key_type)?;
        write!(fwrite, "<valuetype>{}</valuetype>\n", self.value_type)?;
        write!(fwrite, "<create>{}</create>\n", self.attempt_creation)?;
        write!(fwrite, "<clear>{}</clear>\n", self.clear_table)?;
        write!(fwrite, "</{name}>\n")
    }

    /// Restores this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    ///
    /// This port's `XmlPullParser`/`LSHVectorFactory` here are the placeholder traits required
    /// by the [`BSimQuery`] trait's object-safe signature (see that trait's module docs), which
    /// don't yet expose enough to drive real parsing; this mirrors every other `BSimQuery`
    /// implementor in this package (e.g. `QueryNearest`, `AdjustVectorIndex`) by leaving the
    /// real logic in a comment until a functional parser is wired through that signature.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // parser.start(name);
        // parser.start("tablename");
        // self.table_name = Some(parser.end().get_text().to_string());
        // parser.start("keytype");
        // self.key_type = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.start("valuetype");
        // self.value_type = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.start("create");
        // self.attempt_creation = spec_xml_utils::decode_boolean(parser.end().get_text());
        // parser.start("clear");
        // self.clear_table = spec_xml_utils::decode_boolean(parser.end().get_text());
        // parser.end();
        Ok(())
    }
}

impl Default for QueryOptionalExist {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `QueryOptionalExist extends BSimQuery<ResponseOptionalExist>`. Each method forwards to
/// the inherent one of the same name, which is where the behaviour lives.
impl BSimQuery for QueryOptionalExist {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        QueryOptionalExist::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        QueryOptionalExist::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        QueryOptionalExist::restore_xml(self, parser, vector_factory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        fn build_vector(&self, _feature: &[i32]) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
            unimplemented!()
        }
        fn restore_vector_from_xml(&self, _parser: &dyn XmlPullParser) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
            unimplemented!()
        }
        fn restore_vector_from_sql(&self, _sql: &str) -> std::io::Result<Box<dyn crate::feature::seam_stubs::LSHVector>> {
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
        fn get_self_significance(&self, _vector: &dyn crate::feature::seam_stubs::LSHVector) -> f64 {
            0.0
        }
        fn calculate_significance(&self, _data: &dyn crate::feature::seam_stubs::VectorCompare) -> f64 {
            0.0
        }
        fn read_weights(&self, _parser: &dyn XmlPullParser) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn new_default_config() {
        let query = QueryOptionalExist::new();
        assert_eq!(query.get_name(), "queryoptionalexist");
        assert!(query.optionalresponse.is_none());
        assert!(query.table_name.is_none());
        assert_eq!(query.key_type, -1);
        assert_eq!(query.value_type, -1);
        assert!(!query.attempt_creation);
        assert!(!query.clear_table);
    }

    #[test]
    fn default_matches_new() {
        let query = QueryOptionalExist::default();
        assert_eq!(query.get_name(), "queryoptionalexist");
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = QueryOptionalExist::new();
        query.build_response_template();
        assert!(query.optionalresponse.is_some());
        query.optionalresponse.as_mut().unwrap().table_exists = true;
        // Calling again must not clobber an existing response.
        query.build_response_template();
        assert!(query.optionalresponse.as_ref().unwrap().table_exists);
    }

    #[test]
    fn save_xml_panics_when_table_name_is_unset() {
        let query = QueryOptionalExist::new();
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_matches_java_format() {
        let mut query = QueryOptionalExist::new();
        query.table_name = Some("mytable".to_string());
        query.key_type = 4;
        query.value_type = 8;
        query.attempt_creation = true;
        query.clear_table = false;

        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<queryoptionalexist>\n<tablename>mytable</tablename>\n<keytype>4</keytype>\n\
             <valuetype>8</valuetype>\n<create>true</create>\n<clear>false</clear>\n\
             </queryoptionalexist>\n"
        );
    }

    #[test]
    fn save_xml_escapes_table_name() {
        let mut query = QueryOptionalExist::new();
        query.table_name = Some("a<b>".to_string());
        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("<tablename>a&lt;b&gt;</tablename>"));
    }

    #[test]
    fn restore_xml_stub_ok() {
        let mut query = QueryOptionalExist::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = QueryOptionalExist::new();
        assert_eq!(BSimQuery::get_name(&query), "queryoptionalexist");
        BSimQuery::build_response_template(&mut query);
        assert!(query.optionalresponse.is_some());
    }
}
