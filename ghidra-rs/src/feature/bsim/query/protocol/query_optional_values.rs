//! Port of `ghidra.features.bsim.query.protocol.QueryOptionalValues`.
//!
//! Query for values from an optional table, given a set of keys.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseOptionalValues};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;

/// Query for values from an optional table, given a set of keys.
///
/// Java: `QueryOptionalValues extends BSimQuery<ResponseOptionalValues>`.
///
/// As with [`InsertOptionalValues`](super::InsertOptionalValues), Java models `keys` as
/// `Object[]` but only ever calls `.toString()` on its elements, so this port models the field
/// as `Vec<String>` directly.
pub struct QueryOptionalValues {
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub optionalresponse: Option<ResponseOptionalValues>,
    /// Keys to query. `None` mirrors Java's `keys == null`.
    pub keys: Option<Vec<String>>,
    /// Name of the optional table. `None` mirrors Java's `tableName == null` (the field is
    /// never initialized by the constructor).
    pub table_name: Option<String>,
    /// Type of the key, as per `java.sql.Types`.
    pub key_type: i32,
    /// Type of the value.
    pub value_type: i32,

    base: BSimQueryBase,
}

impl QueryOptionalValues {
    /// Java: `QueryOptionalValues()`.
    pub fn new() -> Self {
        Self {
            optionalresponse: None,
            keys: None,
            table_name: None,
            key_type: -1,
            value_type: -1,
            base: BSimQueryBase::new("queryoptionalvalues"),
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
            self.optionalresponse = Some(ResponseOptionalValues::new());
        }
    }

    /// Serializes this query, including the keys to look up.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces two real Java bugs, both
    /// unconditional, un-null-checked accesses to fields the constructor leaves `null`:
    ///
    /// - `SpecXmlUtils.xmlEscapeWriter(fwrite, tableName)` with `tableName == null` throws a
    ///   `NullPointerException` -- see [`tests::save_xml_panics_when_table_name_is_unset`].
    /// - `for (Object key : keys)` with `keys == null` throws a `NullPointerException` (Java's
    ///   enhanced for-loop NPEs on a null array) -- see
    ///   [`tests::save_xml_panics_when_keys_is_unset`].
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        let name = self.get_name();
        write!(fwrite, "<{name}>\n")?;
        write!(fwrite, "<tablename>")?;
        let table_name = self.table_name.as_deref().expect(
            "Java: QueryOptionalValues.saveXml calls SpecXmlUtils.xmlEscapeWriter(fwrite, \
             tableName) unconditionally; tableName is null until explicitly set, so this throws \
             a NullPointerException in the real Ghidra code too",
        );
        let mut escaped = String::new();
        spec_xml_utils::xml_escape(&mut escaped, table_name);
        write!(fwrite, "{escaped}")?;
        write!(fwrite, "</tablename>\n")?;
        write!(fwrite, "<keytype>{}</keytype>\n", self.key_type)?;
        write!(fwrite, "<valuetype>{}</valuetype>\n", self.value_type)?;
        let keys = self.keys.as_ref().expect(
            "Java: QueryOptionalValues.saveXml iterates `keys` with a for-each loop \
             unconditionally; keys is null until explicitly set, so this throws a \
             NullPointerException in the real Ghidra code too",
        );
        for key in keys {
            write!(fwrite, "<key>")?;
            let mut escaped = String::new();
            spec_xml_utils::xml_escape(&mut escaped, key);
            write!(fwrite, "{escaped}")?;
            write!(fwrite, "</key>\n")?;
        }
        write!(fwrite, "</{name}>\n")
    }

    /// Restores this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    ///
    /// This port's `XmlPullParser`/`LSHVectorFactory` here are the placeholder traits required
    /// by the [`BSimQuery`] trait's object-safe signature (see that trait's module docs), which
    /// don't yet expose enough to drive real parsing; this mirrors every other `BSimQuery`
    /// implementor in this package (e.g. `QueryOptionalExist`, `InsertOptionalValues`) by
    /// leaving the real logic in a comment until a functional parser is wired through that
    /// signature.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // self.keys = None;
        // let mut result_keys = Vec::new();
        // parser.start(name);
        // parser.start("tablename");
        // self.table_name = Some(parser.end().get_text().to_string());
        // parser.start("keytype");
        // self.key_type = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.start("valuetype");
        // self.value_type = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // while parser.peek().is_start() {
        //     parser.start();
        //     result_keys.push(parser.end().get_text().to_string());
        // }
        // parser.end();
        // if !result_keys.is_empty() {
        //     self.keys = Some(result_keys);
        // }
        Ok(())
    }
}

impl Default for QueryOptionalValues {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `QueryOptionalValues extends BSimQuery<ResponseOptionalValues>`. Each method forwards
/// to the inherent one of the same name, which is where the behaviour lives.
impl BSimQuery for QueryOptionalValues {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        QueryOptionalValues::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        QueryOptionalValues::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        QueryOptionalValues::restore_xml(self, parser, vector_factory)
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
        let query = QueryOptionalValues::new();
        assert_eq!(query.get_name(), "queryoptionalvalues");
        assert!(query.optionalresponse.is_none());
        assert!(query.keys.is_none());
        assert!(query.table_name.is_none());
        assert_eq!(query.key_type, -1);
        assert_eq!(query.value_type, -1);
    }

    #[test]
    fn default_matches_new() {
        let query = QueryOptionalValues::default();
        assert_eq!(query.get_name(), "queryoptionalvalues");
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = QueryOptionalValues::new();
        query.build_response_template();
        assert!(query.optionalresponse.is_some());
    }

    #[test]
    fn save_xml_panics_when_table_name_is_unset() {
        let query = QueryOptionalValues::new();
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_panics_when_keys_is_unset() {
        let mut query = QueryOptionalValues::new();
        query.table_name = Some("mytable".to_string());
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_matches_java_format() {
        let mut query = QueryOptionalValues::new();
        query.table_name = Some("mytable".to_string());
        query.key_type = 4;
        query.value_type = 8;
        query.keys = Some(vec!["k1".to_string(), "k2".to_string()]);

        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<queryoptionalvalues>\n<tablename>mytable</tablename>\n<keytype>4</keytype>\n\
             <valuetype>8</valuetype>\n<key>k1</key>\n<key>k2</key>\n</queryoptionalvalues>\n"
        );
    }

    #[test]
    fn save_xml_escapes_table_name_and_keys() {
        let mut query = QueryOptionalValues::new();
        query.table_name = Some("a<b>".to_string());
        query.keys = Some(vec!["k&1".to_string()]);

        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.contains("<tablename>a&lt;b&gt;</tablename>"));
        assert!(xml.contains("<key>k&amp;1</key>"));
    }

    #[test]
    fn restore_xml_stub_ok() {
        let mut query = QueryOptionalValues::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = QueryOptionalValues::new();
        assert_eq!(BSimQuery::get_name(&query), "queryoptionalvalues");
        BSimQuery::build_response_template(&mut query);
        assert!(query.optionalresponse.is_some());
    }
}
