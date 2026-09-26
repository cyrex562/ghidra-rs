//! Port of `ghidra.features.bsim.query.protocol.InsertOptionalValues`.
//!
//! Insert key/value pairs into an optional table.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseOptionalExist};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;

/// Insert key/value pairs into an optional table.
///
/// Java: `InsertOptionalValues extends BSimQuery<ResponseOptionalExist>`.
///
/// Java models `keys`/`values` as `Object[]`, but every real use only ever calls `.toString()`
/// on the elements when writing XML and only ever produces `String`s when reading it back --
/// exactly the situation already documented on [`ResponseOptionalValues`](super::ResponseOptionalValues).
/// This port models both fields as `Vec<String>` directly for the same reason.
pub struct InsertOptionalValues {
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub optionalresponse: Option<ResponseOptionalExist>,
    /// Name of optional SQL table. `None` mirrors Java's `tableName == null` (the field is
    /// never initialized by the constructor).
    pub table_name: Option<String>,
    /// Type-code of key as per `java.sql.Types`.
    pub key_type: i32,
    /// Type-code of value.
    pub value_type: i32,
    /// Keys to be inserted. `None` mirrors Java's `keys == null`.
    pub keys: Option<Vec<String>>,
    /// Values (corresponding to keys) to be inserted. `None` mirrors Java's `values == null`.
    pub values: Option<Vec<String>>,

    base: BSimQueryBase,
}

impl InsertOptionalValues {
    /// Java: `InsertOptionalValues()`.
    pub fn new() -> Self {
        Self {
            optionalresponse: None,
            table_name: None,
            key_type: -1,
            value_type: -1,
            keys: None,
            values: None,
            base: BSimQueryBase::new("insertoptionalvalues"),
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

    /// Serializes this query, including the key/value pairs to insert.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces three real Java bugs, each an
    /// unconditional, un-null-checked access to a field the constructor leaves `null`:
    ///
    /// - `SpecXmlUtils.xmlEscapeWriter(fwrite, tableName)` with `tableName == null` throws a
    ///   `NullPointerException` -- see [`tests::save_xml_panics_when_table_name_is_unset`].
    /// - `for (Object key : keys)` with `keys == null` throws a `NullPointerException` (Java's
    ///   enhanced for-loop NPEs on a null array) -- see
    ///   [`tests::save_xml_panics_when_keys_is_unset`].
    /// - `for (Object val : values)` with `values == null` throws the same, once `keys` is
    ///   non-null but `values` isn't -- see [`tests::save_xml_panics_when_values_is_unset`].
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        let name = self.get_name();
        write!(fwrite, "<{name}>\n")?;
        write!(fwrite, "<tablename>")?;
        let table_name = self.table_name.as_deref().expect(
            "Java: InsertOptionalValues.saveXml calls SpecXmlUtils.xmlEscapeWriter(fwrite, \
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
            "Java: InsertOptionalValues.saveXml iterates `keys` with a for-each loop \
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
        let values = self.values.as_ref().expect(
            "Java: InsertOptionalValues.saveXml iterates `values` with a for-each loop \
             unconditionally; values is null until explicitly set, so this throws a \
             NullPointerException in the real Ghidra code too",
        );
        for val in values {
            write!(fwrite, "<val>")?;
            let mut escaped = String::new();
            spec_xml_utils::xml_escape(&mut escaped, val);
            write!(fwrite, "{escaped}")?;
            write!(fwrite, "</val>\n")?;
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
    /// implementor in this package (e.g. `QueryOptionalExist`, `QueryNearest`) by leaving the
    /// real logic in a comment until a functional parser is wired through that signature.
    ///
    /// The commented-out logic below also preserves a real Java quirk worth flagging for
    /// whoever wires up the functional parser later: after the loop, Java only guards the
    /// `keys`/`values` assignment on `!resultKeys.isEmpty()` -- if every child element happened
    /// to be a `<val>` (so `resultKeys` stays empty while `resultValues` doesn't), both `keys`
    /// *and* `values` are left `null`, silently discarding the values that were parsed.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // self.keys = None;
        // self.values = None;
        // let mut result_keys = Vec::new();
        // let mut result_values = Vec::new();
        // parser.start(name);
        // parser.start("tablename");
        // self.table_name = Some(parser.end().get_text().to_string());
        // parser.start("keytype");
        // self.key_type = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.start("valuetype");
        // self.value_type = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // while parser.peek().is_start() {
        //     let el = parser.start();
        //     let nm = el.get_name();
        //     let body = parser.end().get_text().to_string();
        //     if nm == "key" {
        //         result_keys.push(body);
        //     } else {
        //         result_values.push(body);
        //     }
        // }
        // parser.end();
        // // Java quirk: only checks `!result_keys.is_empty()`, so an all-`<val>` document would
        // // leave both `keys` and `values` as `None` here too.
        // if !result_keys.is_empty() {
        //     self.keys = Some(result_keys);
        //     self.values = Some(result_values);
        // }
        Ok(())
    }
}

impl Default for InsertOptionalValues {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `InsertOptionalValues extends BSimQuery<ResponseOptionalExist>`. Each method forwards
/// to the inherent one of the same name, which is where the behaviour lives.
impl BSimQuery for InsertOptionalValues {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        InsertOptionalValues::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        InsertOptionalValues::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        InsertOptionalValues::restore_xml(self, parser, vector_factory)
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
        let query = InsertOptionalValues::new();
        assert_eq!(query.get_name(), "insertoptionalvalues");
        assert!(query.optionalresponse.is_none());
        assert!(query.table_name.is_none());
        assert_eq!(query.key_type, -1);
        assert_eq!(query.value_type, -1);
        assert!(query.keys.is_none());
        assert!(query.values.is_none());
    }

    #[test]
    fn default_matches_new() {
        let query = InsertOptionalValues::default();
        assert_eq!(query.get_name(), "insertoptionalvalues");
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = InsertOptionalValues::new();
        query.build_response_template();
        assert!(query.optionalresponse.is_some());
    }

    #[test]
    fn save_xml_panics_when_table_name_is_unset() {
        let query = InsertOptionalValues::new();
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_panics_when_keys_is_unset() {
        let mut query = InsertOptionalValues::new();
        query.table_name = Some("mytable".to_string());
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_panics_when_values_is_unset() {
        let mut query = InsertOptionalValues::new();
        query.table_name = Some("mytable".to_string());
        query.keys = Some(vec!["a".to_string()]);
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_matches_java_format() {
        let mut query = InsertOptionalValues::new();
        query.table_name = Some("mytable".to_string());
        query.key_type = 4;
        query.value_type = 12;
        query.keys = Some(vec!["k1".to_string(), "k2".to_string()]);
        query.values = Some(vec!["v1".to_string()]);

        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<insertoptionalvalues>\n<tablename>mytable</tablename>\n<keytype>4</keytype>\n\
             <valuetype>12</valuetype>\n<key>k1</key>\n<key>k2</key>\n<val>v1</val>\n\
             </insertoptionalvalues>\n"
        );
    }

    #[test]
    fn save_xml_escapes_special_characters() {
        let mut query = InsertOptionalValues::new();
        query.table_name = Some("a<b>".to_string());
        query.keys = Some(vec!["k&1".to_string()]);
        query.values = Some(vec!["v\"1".to_string()]);

        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.contains("<tablename>a&lt;b&gt;</tablename>"));
        assert!(xml.contains("<key>k&amp;1</key>"));
    }

    #[test]
    fn restore_xml_stub_ok() {
        let mut query = InsertOptionalValues::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = InsertOptionalValues::new();
        assert_eq!(BSimQuery::get_name(&query), "insertoptionalvalues");
        BSimQuery::build_response_template(&mut query);
        assert!(query.optionalresponse.is_some());
    }
}
