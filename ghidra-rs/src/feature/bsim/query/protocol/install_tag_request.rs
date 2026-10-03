//! Port of `ghidra.features.bsim.query.protocol.InstallTagRequest`.
//!
//! Request that a new function tag be installed for a specific BSim server.

use std::io::{self, Write};

use crate::feature::bsim::query::description::CategoryRecord;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseInfo};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;

/// Request that a new function tag be installed for a specific BSim server.
///
/// Java: `InstallTagRequest extends BSimQuery<ResponseInfo>`.
pub struct InstallTagRequest {
    /// Name of new function tag.
    pub tag_name: String,
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub installresponse: Option<ResponseInfo>,

    base: BSimQueryBase,
}

impl InstallTagRequest {
    /// Java: `InstallTagRequest()`.
    pub fn new() -> Self {
        Self {
            tag_name: String::new(),
            installresponse: None,
            base: BSimQueryBase::new("installtag"),
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
        if self.installresponse.is_none() {
            self.installresponse = Some(ResponseInfo::new());
        }
    }

    /// Serializes this request as a `<installtag>tag_name</installtag>` element.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a real Java behavior: the
    /// constructor defaults `tag_name` to `""` (not `null`), and `""` fails
    /// `CategoryRecord.enforceTypeCharacters` (which rejects empty strings), so calling this on
    /// a freshly constructed `InstallTagRequest` throws an `IOException("Bad characters in
    /// requested category type")` in the real Ghidra code, and returns the equivalent
    /// [`io::Error`] here for the same reason -- see
    /// [`tests::save_xml_errors_on_default_empty_tag_name`].
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        if !CategoryRecord::enforce_type_characters(&self.tag_name) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad characters in requested category type"));
        }
        let name = self.get_name();
        write!(fwrite, "<{name}>")?;
        write!(fwrite, "{}", self.tag_name)?;
        write!(fwrite, "</{name}>\n")
    }

    /// Restores this request from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    ///
    /// This port's `XmlPullParser`/`LSHVectorFactory` here are the placeholder traits required
    /// by the [`BSimQuery`] trait's object-safe signature (see that trait's module docs), which
    /// don't yet expose enough to drive real parsing; this mirrors every other `BSimQuery`
    /// implementor in this package (e.g. `QueryOptionalExist`, `QueryNearest`) by leaving the
    /// real logic in a comment until a functional parser is wired through that signature.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // parser.start(name);
        // self.tag_name = parser.end().get_text().to_string();
        Ok(())
    }
}

impl Default for InstallTagRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `InstallTagRequest extends BSimQuery<ResponseInfo>`. Each method forwards to the
/// inherent one of the same name, which is where the behaviour lives.
impl BSimQuery for InstallTagRequest {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        InstallTagRequest::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        InstallTagRequest::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        InstallTagRequest::restore_xml(self, parser, vector_factory)
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
        let query = InstallTagRequest::new();
        assert_eq!(query.get_name(), "installtag");
        assert_eq!(query.tag_name, "");
        assert!(query.installresponse.is_none());
    }

    #[test]
    fn default_matches_new() {
        let query = InstallTagRequest::default();
        assert_eq!(query.tag_name, "");
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = InstallTagRequest::new();
        query.build_response_template();
        assert!(query.installresponse.is_some());
    }

    #[test]
    fn save_xml_errors_on_default_empty_tag_name() {
        // Faithful reproduction: the default tag_name is "" (not null), and
        // enforceTypeCharacters("") is false, so this must error rather than panic or succeed.
        let query = InstallTagRequest::new();
        let mut buf = Vec::new();
        let result = query.save_xml(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Bad characters in requested category type");
    }

    #[test]
    fn save_xml_errors_on_disallowed_characters() {
        let mut query = InstallTagRequest::new();
        query.tag_name = "bad,tag".to_string();
        let mut buf = Vec::new();
        assert!(query.save_xml(&mut buf).is_err());
    }

    #[test]
    fn save_xml_writes_valid_tag_name() {
        let mut query = InstallTagRequest::new();
        query.tag_name = "MyTag".to_string();
        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<installtag>MyTag</installtag>\n");
    }

    #[test]
    fn restore_xml_stub_ok() {
        let mut query = InstallTagRequest::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = InstallTagRequest::new();
        assert_eq!(BSimQuery::get_name(&query), "installtag");
        BSimQuery::build_response_template(&mut query);
        assert!(query.installresponse.is_some());
    }
}
