//! Port of `ghidra.features.bsim.query.protocol.QueryInfo`.
//!
//! Request the `DatabaseInformation` object for a specific BSim database.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseInfo};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;

/// Request the `DatabaseInformation` object for a specific BSim database.
///
/// Java: `QueryInfo extends BSimQuery<ResponseInfo>`.
pub struct QueryInfo {
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub inforesponse: Option<ResponseInfo>,

    base: BSimQueryBase,
}

impl QueryInfo {
    /// Java: `QueryInfo()`.
    pub fn new() -> Self {
        Self { inforesponse: None, base: BSimQueryBase::new("queryinfo") }
    }

    /// Java: `getName()` (inherited from `BSimQuery`).
    pub fn get_name(&self) -> &str {
        self.base.get_name()
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.inforesponse.is_none() {
            self.inforesponse = Some(ResponseInfo::new());
        }
    }

    /// Serializes this query as a self-closing `<queryinfo/>` element.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}/>\n", self.get_name())
    }

    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`. Empty in the real Java source
    /// ("Nothing to do").
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        Ok(())
    }
}

impl Default for QueryInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `QueryInfo extends BSimQuery<ResponseInfo>`. Each method forwards to the inherent one
/// of the same name, which is where the behaviour lives.
impl BSimQuery for QueryInfo {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        QueryInfo::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        QueryInfo::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        QueryInfo::restore_xml(self, parser, vector_factory)
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
        let query = QueryInfo::new();
        assert_eq!(query.get_name(), "queryinfo");
        assert!(query.inforesponse.is_none());
    }

    #[test]
    fn default_matches_new() {
        let query = QueryInfo::default();
        assert_eq!(query.get_name(), "queryinfo");
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = QueryInfo::new();
        query.build_response_template();
        assert!(query.inforesponse.is_some());
    }

    #[test]
    fn save_xml_writes_self_closing_tag() {
        let query = QueryInfo::new();
        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<queryinfo/>\n");
    }

    #[test]
    fn restore_xml_is_a_no_op() {
        let mut query = QueryInfo::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = QueryInfo::new();
        assert_eq!(BSimQuery::get_name(&query), "queryinfo");
        BSimQuery::build_response_template(&mut query);
        assert!(query.inforesponse.is_some());
    }
}
