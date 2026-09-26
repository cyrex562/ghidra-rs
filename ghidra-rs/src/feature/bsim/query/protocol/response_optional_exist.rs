//! Port of `ghidra.features.bsim.query.protocol.ResponseOptionalExist`.
//!
//! Response to a QueryOptionalExist, reporting whether an optional table exists.

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;
use std::io::Write;

/// Response to a QueryOptionalExist, reporting whether an optional table exists.
///
/// Java: `ResponseOptionalExist extends QueryResponseRecord`.
pub struct ResponseOptionalExist {
    /// True if the queried table exists.
    pub table_exists: bool,

    /// True if this query caused creation of table.
    pub was_created: bool,

    base: crate::feature::bsim::query::protocol::QueryResponseRecordBase,
}

impl ResponseOptionalExist {
    /// Create a new ResponseOptionalExist with default settings.
    ///
    /// Java: `ResponseOptionalExist()`.
    pub fn new() -> Self {
        Self {
            table_exists: false,
            was_created: false,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("responseoptionalexist"),
        }
    }

    /// Save this response to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        fwrite.write_all(b"<")?;
        fwrite.write_all(self.base.get_name().as_bytes())?;
        fwrite.write_all(b">\n")?;
        if self.table_exists {
            fwrite.write_all(b"<exists>true</exists>\n")?;
        } else {
            fwrite.write_all(b"<exists>false</exists>\n")?;
        }
        if self.was_created {
            fwrite.write_all(b"<created>true</created>\n")?;
        } else {
            fwrite.write_all(b"<created>false</created>\n")?;
        }
        fwrite.write_all(b"</")?;
        fwrite.write_all(self.base.get_name().as_bytes())?;
        fwrite.write_all(b">\n")?;
        Ok(())
    }

    /// Restore this response from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser
        // For now, this is a stub implementation
        // self.table_exists = false;
        // self.was_created = false;
        // parser.start(self.base.get_name());
        // if parser.peek().get_name() == "exists" {
        //     parser.start("exists");
        //     self.table_exists = spec_xml_utils::decode_boolean(parser.end().get_text());
        // }
        // if parser.peek().get_name() == "created" {
        //     parser.start("created");
        //     self.was_created = spec_xml_utils::decode_boolean(parser.end().get_text());
        // }
        // parser.end();
        Ok(())
    }
}

impl Default for ResponseOptionalExist {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseOptionalExist {
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

    #[test]
    fn test_response_optional_exist_new() {
        let response = ResponseOptionalExist::new();
        assert!(!response.table_exists);
        assert!(!response.was_created);
        assert_eq!(response.base.get_name(), "responseoptionalexist");
    }

    #[test]
    fn test_response_optional_exist_default() {
        let response = ResponseOptionalExist::default();
        assert!(!response.table_exists);
        assert!(!response.was_created);
        assert_eq!(response.base.get_name(), "responseoptionalexist");
    }

    #[test]
    fn test_response_optional_exist_with_values() {
        let mut response = ResponseOptionalExist::new();
        response.table_exists = true;
        response.was_created = true;

        assert!(response.table_exists);
        assert!(response.was_created);
    }

    #[test]
    fn test_response_optional_exist_save_xml_both_true() {
        let response = ResponseOptionalExist {
            table_exists: true,
            was_created: true,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("responseoptionalexist"),
        };

        let mut buffer = Vec::new();
        let result = response.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("<exists>true</exists>"));
        assert!(xml_str.contains("<created>true</created>"));
        assert!(xml_str.contains("</responseoptionalexist>"));
    }

    #[test]
    fn test_response_optional_exist_save_xml_both_false() {
        let response = ResponseOptionalExist {
            table_exists: false,
            was_created: false,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("responseoptionalexist"),
        };

        let mut buffer = Vec::new();
        let result = response.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("<exists>false</exists>"));
        assert!(xml_str.contains("<created>false</created>"));
    }

    #[test]
    fn test_response_optional_exist_save_xml_mixed() {
        let response = ResponseOptionalExist {
            table_exists: true,
            was_created: false,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("responseoptionalexist"),
        };

        let mut buffer = Vec::new();
        let result = response.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("<exists>true</exists>"));
        assert!(xml_str.contains("<created>false</created>"));
    }

    #[test]
    fn test_response_optional_exist_query_response_record_trait() {
        let response = ResponseOptionalExist::new();
        let record: &dyn QueryResponseRecord = &response;
        assert_eq!(record.get_name(), "responseoptionalexist");
    }
}
