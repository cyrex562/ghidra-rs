//! Port of `ghidra.features.bsim.query.protocol.PasswordChange`.
//!
//! A query that requests a password change for a specific user.
//! Currently provides no explicit protection for password data on the client.
//! Should be used in conjunction with connection encryption (SSL) to protect
//! data in transit to the server.

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::{ResponsePassword, LSHVectorFactory};
use crate::util::seam_stubs::XmlPullParser;
use std::io::Write;

/// Request a password change for a specific user.
///
/// Java: `PasswordChange extends BSimQuery<ResponsePassword>`.
pub struct PasswordChange {
    /// The response object (same as `response` in the parent BSimQuery).
    pub password_response: Option<Box<dyn ResponsePassword>>,

    /// Identifier for user whose password should be changed.
    pub username: Option<String>,

    /// The new password as raw character data.
    pub new_password: Vec<char>,

    base: crate::feature::bsim::query::protocol::QueryResponseRecordBase,
}

impl PasswordChange {
    /// Create a new PasswordChange query with default settings.
    ///
    /// Java: `PasswordChange()`.
    pub fn new() -> Self {
        Self {
            password_response: None,
            username: None,
            new_password: Vec::new(),
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("passwordchange"),
        }
    }

    /// Clear the password data. Should be used by database client immediately upon sending request to server.
    ///
    /// Java: `clearPassword()`.
    pub fn clear_password(&mut self) {
        // Replace password characters with spaces to clear them
        for c in &mut self.new_password {
            *c = ' ';
        }
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.password_response.is_none() {
            // In the real implementation, ResponsePassword would be a concrete type
            // For now, this is a stub that would create a ResponsePassword instance
            // self.password_response = Some(Box::new(ResponsePassword::new()));
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        fwrite.write_all(b"<")?;
        fwrite.write_all(self.base.get_name().as_bytes())?;
        fwrite.write_all(b" username=\"")?;
        if let Some(username) = &self.username {
            fwrite.write_all(username.as_bytes())?;
        }
        fwrite.write_all(b"\">")?;
        // Escape password characters for XML
        let password_str: String = self.new_password.iter().collect();
        for c in password_str.chars() {
            match c {
                '&' => fwrite.write_all(b"&amp;")?,
                '<' => fwrite.write_all(b"&lt;")?,
                '>' => fwrite.write_all(b"&gt;")?,
                '"' => fwrite.write_all(b"&quot;")?,
                '\'' => fwrite.write_all(b"&apos;")?,
                other => {
                    let mut tmp = [0u8; 4];
                    fwrite.write_all(other.encode_utf8(&mut tmp).as_bytes())?;
                }
            }
        }
        fwrite.write_all(b"</")?;
        fwrite.write_all(self.base.get_name().as_bytes())?;
        fwrite.write_all(b">\n")?;
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
        // This would normally parse the XML element using the parser
        // For now, this is a stub implementation
        // let el = parser.start(self.base.get_name());
        // self.username = Some(el.get_attribute("username").unwrap_or_default());
        // let password_text = parser.end().get_text();
        // self.new_password = password_text.chars().collect();
        Ok(())
    }
}

impl Default for PasswordChange {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for PasswordChange {
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
    fn test_password_change_new() {
        let query = PasswordChange::new();
        assert!(query.password_response.is_none());
        assert!(query.username.is_none());
        assert!(query.new_password.is_empty());
        assert_eq!(query.base.get_name(), "passwordchange");
    }

    #[test]
    fn test_password_change_default() {
        let query = PasswordChange::default();
        assert!(query.password_response.is_none());
        assert!(query.username.is_none());
        assert!(query.new_password.is_empty());
        assert_eq!(query.base.get_name(), "passwordchange");
    }

    #[test]
    fn test_password_change_with_username_and_password() {
        let mut query = PasswordChange::new();
        query.username = Some("testuser".to_string());
        query.new_password = vec!['p', 'a', 's', 's', '1', '2', '3'];

        assert_eq!(query.username, Some("testuser".to_string()));
        assert_eq!(query.new_password.len(), 7);
    }

    #[test]
    fn test_password_change_clear_password() {
        let mut query = PasswordChange::new();
        query.new_password = vec!['s', 'e', 'c', 'r', 'e', 't'];

        query.clear_password();

        for c in query.new_password.iter() {
            assert_eq!(*c, ' ');
        }
    }

    #[test]
    fn test_password_change_save_xml_basic() {
        let mut query = PasswordChange::new();
        query.username = Some("john".to_string());
        query.new_password = vec!['p', 'a', 's', 's'];

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("passwordchange"));
        assert!(xml_str.contains("username=\"john\""));
        assert!(xml_str.contains("pass"));
        assert!(xml_str.contains("</passwordchange>"));
    }

    #[test]
    fn test_password_change_save_xml_xml_escaping() {
        let mut query = PasswordChange::new();
        query.username = Some("user".to_string());
        query.new_password = vec!['<', '&', '>'];

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("&lt;"));
        assert!(xml_str.contains("&amp;"));
        assert!(xml_str.contains("&gt;"));
    }

    #[test]
    fn test_password_change_query_response_record_trait() {
        let query = PasswordChange::new();
        let record: &dyn QueryResponseRecord = &query;
        assert_eq!(record.get_name(), "passwordchange");
    }

    #[test]
    fn test_password_change_build_response_template() {
        let mut query = PasswordChange::new();
        assert!(query.password_response.is_none());

        query.build_response_template();

        // Still none since ResponsePassword is not implemented yet
        assert!(query.password_response.is_none());
    }

    #[test]
    fn test_password_change_save_xml_empty_username() {
        let query = PasswordChange::new();

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("username=\"\""));
    }

    #[test]
    fn test_password_change_save_xml_empty_password() {
        let mut query = PasswordChange::new();
        query.username = Some("testuser".to_string());

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("username=\"testuser\""));
    }
}
