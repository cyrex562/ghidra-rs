//! Port of `ghidra.features.bsim.query.protocol.CreateDatabase`.
//!
//! Request that a new BSim database be created on a server, from a named configuration template
//! plus overrides.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DatabaseInformation;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseInfo};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;

/// Request that a new BSim database be created on a server.
///
/// Java: `CreateDatabase extends BSimQuery<ResponseInfo>`.
pub struct CreateDatabase {
    /// Name of configuration to use for database. `None` mirrors Java's `config_template ==
    /// null` (the field is never initialized by the constructor).
    pub config_template: Option<String>,
    /// Some overrides for the configuration. `None` mirrors Java's `info == null` (the field is
    /// never initialized by the constructor).
    pub info: Option<DatabaseInformation>,
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub inforesponse: Option<ResponseInfo>,

    base: BSimQueryBase,
}

impl CreateDatabase {
    /// Java: `CreateDatabase()`.
    pub fn new() -> Self {
        Self {
            config_template: None,
            info: None,
            inforesponse: None,
            base: BSimQueryBase::new("createdatabase"),
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
        if self.inforesponse.is_none() {
            self.inforesponse = Some(ResponseInfo::new());
        }
    }

    /// Serializes this query as a `<createdatabase template="...">` element wrapping the
    /// `info` overrides.
    ///
    /// Java: `saveXml(Writer)`. This faithfully reproduces two distinct Java quirks that fall
    /// out of the same unconditional-field-access pattern seen elsewhere in this package, but
    /// which behave *differently* here because Java's `Writer.append(CharSequence)` explicitly
    /// tolerates a `null` argument (appending the four characters `"null"`, per its Javadoc)
    /// while a plain method call on a `null` receiver does not:
    ///
    /// - `fwrite.append(config_template)` with `config_template == null` (its state right after
    ///   [`new`](Self::new)) does **not** throw -- it writes the literal text `null`. See
    ///   [`tests::save_xml_writes_literal_null_when_config_template_unset`].
    /// - `info.saveXml(fwrite)` with `info == null` (likewise its state right after
    ///   [`new`](Self::new)) **does** throw a `NullPointerException`, because it's a method
    ///   invocation on a null receiver rather than a null argument to `append`. This panics here
    ///   for the same reason -- see
    ///   [`tests::save_xml_panics_when_info_is_unset`].
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        let name = self.get_name();
        write!(fwrite, "<{name}")?;
        write!(fwrite, " template=\"")?;
        match &self.config_template {
            Some(template) => write!(fwrite, "{template}")?,
            None => write!(fwrite, "null")?,
        }
        write!(fwrite, "\">\n")?;
        let info = self.info.as_ref().expect(
            "Java: CreateDatabase.saveXml calls info.saveXml(fwrite) unconditionally; info is \
             null until explicitly set, so this throws a NullPointerException in the real \
             Ghidra code too",
        );
        // `DatabaseInformation::save_xml` is generic over `W: Write` (implicitly `Sized`), so it
        // can't be called directly with the `&mut dyn Write` this trait method receives; buffer
        // its output and copy it through instead.
        let mut info_buf = Vec::new();
        info.save_xml(&mut info_buf)?;
        fwrite.write_all(&info_buf)?;
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
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // let el = parser.start(name);
        // self.config_template = Some(el.get_attribute("template"));
        // let mut info = DatabaseInformation::new();
        // info.restore_xml(parser)?;
        // self.info = Some(info);
        // parser.end();
        Ok(())
    }
}

impl Default for CreateDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `CreateDatabase extends BSimQuery<ResponseInfo>`. Each method forwards to the inherent
/// one of the same name, which is where the behaviour lives.
impl BSimQuery for CreateDatabase {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        CreateDatabase::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        CreateDatabase::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        CreateDatabase::restore_xml(self, parser, vector_factory)
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
        let query = CreateDatabase::new();
        assert_eq!(query.get_name(), "createdatabase");
        assert!(query.config_template.is_none());
        assert!(query.info.is_none());
        assert!(query.inforesponse.is_none());
    }

    #[test]
    fn default_matches_new() {
        let query = CreateDatabase::default();
        assert_eq!(query.get_name(), "createdatabase");
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = CreateDatabase::new();
        query.build_response_template();
        assert!(query.inforesponse.is_some());
    }

    #[test]
    fn save_xml_writes_literal_null_when_config_template_unset() {
        // Faithful reproduction: Writer.append(CharSequence) treats a null argument specially,
        // appending the literal text "null" instead of throwing -- unlike the unconditional
        // xmlEscapeWriter(..., null) NPEs seen in sibling classes.
        let mut query = CreateDatabase::new();
        query.info = Some(DatabaseInformation::new());
        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.starts_with("<createdatabase template=\"null\">\n"));
    }

    #[test]
    fn save_xml_panics_when_info_is_unset() {
        let query = CreateDatabase::new();
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| query.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_writes_template_and_nested_info() {
        let mut query = CreateDatabase::new();
        query.config_template = Some("medium_nosize".to_string());
        query.info = Some(DatabaseInformation::new());
        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.starts_with("<createdatabase template=\"medium_nosize\">\n"));
        assert!(xml.contains("<info>\n"));
        assert!(xml.ends_with("</createdatabase>\n"));
    }

    #[test]
    fn restore_xml_stub_ok() {
        let mut query = CreateDatabase::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = CreateDatabase::new();
        assert_eq!(BSimQuery::get_name(&query), "createdatabase");
        BSimQuery::build_response_template(&mut query);
        assert!(query.inforesponse.is_some());
    }
}
