use std::io::{self, Write};

use crate::util::exception::AssertException;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Metadata describing a BSim database: name, owner, signature-strategy versioning,
/// and the set of executable categories/function tags it recognizes.
///
/// Port of `ghidra.features.bsim.query.description.DatabaseInformation`.
#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseInformation {
    /// Formal name of this database.
    pub databasename: Option<String>,
    /// Owner of this database.
    pub owner: Option<String>,
    /// Description of the database.
    pub description: Option<String>,
    /// Signature strategy -- major version.
    pub major: i16,
    /// Signature strategy -- minor version.
    pub minor: i16,
    /// Settings for signature generation.
    pub settings: i32,
    /// Executable categories for this database.
    pub execats: Option<Vec<String>>,
    /// Named boolean properties on functions.
    pub function_tags: Option<Vec<String>>,
    /// An override of the name "Ingest Date".
    pub date_column_name: Option<String>,
    /// Version of the database layout.
    pub layout_version: i32,
    /// `true` if database is readonly.
    pub readonly: bool,
    /// `true` if database tracks callgraph information of executables.
    pub trackcallgraph: bool,
}

impl Default for DatabaseInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseInformation {
    pub fn new() -> Self {
        Self {
            databasename: Some("Example Database".to_string()),
            owner: Some("Example Owner".to_string()),
            description: Some("A collection of functions for testing purposes".to_string()),
            // A zero major version indicates no data has been inserted yet.
            major: 0,
            minor: 0,
            settings: 0,
            execats: None,
            function_tags: None,
            date_column_name: None,
            layout_version: 0,
            readonly: false,
            trackcallgraph: true,
        }
    }

    pub fn save_xml<W: Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_all(b"<info>\n")?;
        match &self.databasename {
            Some(name) => write!(write, " <name>{}</name>\n", name)?,
            None => write.write_all(b" <name/>\n")?,
        }
        match &self.owner {
            Some(owner) => write!(write, " <owner>{}</owner>\n", owner)?,
            None => write.write_all(b" <owner/>\n")?,
        }
        match &self.description {
            Some(description) => write!(write, " <description>{}</description>\n", description)?,
            None => write.write_all(b" <description/>\n")?,
        }
        write!(write, " <major>{}</major>\n", self.major)?;
        write!(write, " <minor>{}</minor>\n", self.minor)?;
        write!(write, " <settings>0x{:x}</settings>\n", self.settings as u32)?;
        if let Some(execats) = &self.execats {
            for cat in execats {
                write!(write, " <execategory>{}</execategory>\n", cat)?;
            }
        }
        if let Some(function_tags) = &self.function_tags {
            for tag in function_tags {
                write!(write, " <functiontag>{}</functiontag>\n", tag)?;
            }
        }
        if let Some(date_column_name) = &self.date_column_name {
            write!(write, " <datename>{}</datename>\n", date_column_name)?;
        }
        if self.readonly {
            write.write_all(b" <readonly>true</readonly>\n")?;
        }
        if !self.trackcallgraph {
            write.write_all(b" <trackcallgraph>false</trackcallgraph>\n")?;
        }
        write!(write, " <layout>{}</layout>\n", self.layout_version)?;
        write.write_all(b"</info>\n")?;
        Ok(())
    }

    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<(), XmlException> {
        parser.start(&["info"])?;
        parser.start(&["name"])?;
        let databasename = parser.end()?.get_text().to_string();
        self.databasename = if databasename.is_empty() { None } else { Some(databasename) };
        parser.start(&["owner"])?;
        let owner = parser.end()?.get_text().to_string();
        self.owner = if owner.is_empty() { None } else { Some(owner) };
        parser.start(&["description"])?;
        let description = parser.end()?.get_text().to_string();
        self.description = if description.is_empty() { None } else { Some(description) };
        parser.start(&["major"])?;
        self.major = spec_xml_utils::decode_int(Some(parser.end()?.get_text())) as i16;
        parser.start(&["minor"])?;
        self.minor = spec_xml_utils::decode_int(Some(parser.end()?.get_text())) as i16;
        parser.start(&["settings"])?;
        self.settings = spec_xml_utils::decode_int(Some(parser.end()?.get_text()));
        self.readonly = false;
        self.trackcallgraph = true;
        self.layout_version = 0;
        self.execats = None;
        self.function_tags = None;
        self.date_column_name = None;
        while parser.peek().is_start() {
            let el = parser.start(&[])?;
            match el.get_name() {
                "readonly" => {
                    self.readonly = spec_xml_utils::decode_boolean(parser.end()?.get_text());
                }
                "trackcallgraph" => {
                    self.trackcallgraph = spec_xml_utils::decode_boolean(parser.end()?.get_text());
                }
                "layout" => {
                    self.layout_version = spec_xml_utils::decode_int(Some(parser.end()?.get_text()));
                }
                "execategory" => {
                    let cat = parser.end()?.get_text().to_string();
                    self.execats.get_or_insert_with(Vec::new).push(cat);
                }
                "functiontag" => {
                    let tag = parser.end()?.get_text().to_string();
                    self.function_tags.get_or_insert_with(Vec::new).push(tag);
                }
                "datename" => {
                    self.date_column_name = Some(parser.end()?.get_text().to_string());
                }
                _ => {}
            }
        }
        parser.end()?;
        Ok(())
    }

    /// Port of the Java `equals` override, which always throws (a FIXME in the original
    /// notes that a hashcode method is missing and questions whether `equals` is even
    /// used).
    ///
    /// # Panics
    ///
    /// Always panics with an [`AssertException`].
    #[allow(clippy::should_implement_trait)]
    pub fn equals(&self, _obj: &DatabaseInformation) -> bool {
        panic!(
            "{}",
            AssertException::with_message(
                "DatabaseInformation.equals is used - should add hashcode method"
            )
        );
    }

    pub fn check_signature_settings(&self, maj: i16, min: i16, set: i32) -> i32 {
        if maj == 0 || set == 0 {
            return 3; // No setting information
        }
        if self.major == 0 || self.settings == 0 {
            return 4; // This has no setting information
        }
        if self.major != maj || self.settings != set {
            return 2; // There is a setting mismatch, major version and settings must match
        }
        if self.minor == min {
            return 0; // There is a complete settings match
        }
        if self.minor > min {
            if self.minor - min > 1 {
                return 2; // Settings mismatch (minor versions differ too much)
            }
        } else if min - self.minor > 1 {
            return 2; // Settings mismatch
        }
        1 // Only a minor difference in version and settings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;

    struct VecParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl VecParser {
        fn new(elements: Vec<XmlElementImpl>) -> Self {
            Self { elements, pos: 0 }
        }
    }

    impl XmlPullParser for VecParser {
        type Element = XmlElementImpl;

        fn get_name(&self) -> &str {
            "VecParser"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn is_pulling_content(&self) -> bool {
            true
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> Self::Element {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> Self::Element {
            let el = self.elements[self.pos].clone();
            self.pos += 1;
            el
        }

        fn dispose(&mut self) {}
    }

    fn start(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0)
            .unwrap()
    }

    fn end_of(name: &str) -> XmlElementImpl {
        end_with_text(name, "")
    }

    // --- new / defaults ---

    #[test]
    fn test_new_sets_example_defaults() {
        let info = DatabaseInformation::new();
        assert_eq!(info.databasename.as_deref(), Some("Example Database"));
        assert_eq!(info.owner.as_deref(), Some("Example Owner"));
        assert_eq!(info.major, 0);
        assert_eq!(info.minor, 0);
        assert_eq!(info.settings, 0);
        assert!(info.execats.is_none());
        assert!(info.function_tags.is_none());
        assert!(info.date_column_name.is_none());
        assert_eq!(info.layout_version, 0);
        assert!(!info.readonly);
        assert!(info.trackcallgraph);
    }

    // --- save_xml ---

    #[test]
    fn test_save_xml_full_fields() {
        let mut info = DatabaseInformation::new();
        info.execats = Some(vec!["Compiler".to_string()]);
        info.function_tags = Some(vec!["thunk".to_string()]);
        info.date_column_name = Some("Ingest".to_string());
        info.readonly = true;
        info.trackcallgraph = false;
        info.layout_version = 5;
        info.settings = 255;

        let mut buf = Vec::new();
        info.save_xml(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(text.starts_with("<info>\n"));
        assert!(text.contains(" <name>Example Database</name>\n"));
        assert!(text.contains(" <owner>Example Owner</owner>\n"));
        assert!(text
            .contains(" <description>A collection of functions for testing purposes</description>\n"));
        assert!(text.contains(" <major>0</major>\n"));
        assert!(text.contains(" <minor>0</minor>\n"));
        assert!(text.contains(" <settings>0xff</settings>\n"));
        assert!(text.contains(" <execategory>Compiler</execategory>\n"));
        assert!(text.contains(" <functiontag>thunk</functiontag>\n"));
        assert!(text.contains(" <datename>Ingest</datename>\n"));
        assert!(text.contains(" <readonly>true</readonly>\n"));
        assert!(text.contains(" <trackcallgraph>false</trackcallgraph>\n"));
        assert!(text.contains(" <layout>5</layout>\n"));
        assert!(text.ends_with("</info>\n"));
    }

    #[test]
    fn test_save_xml_none_fields_use_self_closing_tags() {
        let mut info = DatabaseInformation::new();
        info.databasename = None;
        info.owner = None;
        info.description = None;

        let mut buf = Vec::new();
        info.save_xml(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(text.contains(" <name/>\n"));
        assert!(text.contains(" <owner/>\n"));
        assert!(text.contains(" <description/>\n"));
        // Default trackcallgraph is true and readonly is false, so neither tag appears.
        assert!(!text.contains("<readonly>"));
        assert!(!text.contains("<trackcallgraph>"));
    }

    // --- restore_xml ---

    #[test]
    fn test_restore_xml_round_trips_minimal() {
        let mut parser = VecParser::new(vec![
            start("info"),
            start("name"),
            end_with_text("name", "MyDb"),
            start("owner"),
            end_with_text("owner", "MyOwner"),
            start("description"),
            end_with_text("description", "MyDesc"),
            start("major"),
            end_with_text("major", "1"),
            start("minor"),
            end_with_text("minor", "2"),
            start("settings"),
            end_with_text("settings", "0xff"),
            end_of("info"),
        ]);

        let mut info = DatabaseInformation::new();
        info.restore_xml(&mut parser).unwrap();

        assert_eq!(info.databasename.as_deref(), Some("MyDb"));
        assert_eq!(info.owner.as_deref(), Some("MyOwner"));
        assert_eq!(info.description.as_deref(), Some("MyDesc"));
        assert_eq!(info.major, 1);
        assert_eq!(info.minor, 2);
        assert_eq!(info.settings, 255);
        assert!(!info.readonly);
        assert!(info.trackcallgraph);
        assert_eq!(info.layout_version, 0);
        assert!(info.execats.is_none());
        assert!(info.function_tags.is_none());
        assert!(info.date_column_name.is_none());
    }

    #[test]
    fn test_restore_xml_empty_text_becomes_none() {
        let mut parser = VecParser::new(vec![
            start("info"),
            start("name"),
            end_of("name"),
            start("owner"),
            end_of("owner"),
            start("description"),
            end_of("description"),
            start("major"),
            end_with_text("major", "0"),
            start("minor"),
            end_with_text("minor", "0"),
            start("settings"),
            end_with_text("settings", "0"),
            end_of("info"),
        ]);

        let mut info = DatabaseInformation::new();
        info.restore_xml(&mut parser).unwrap();

        assert!(info.databasename.is_none());
        assert!(info.owner.is_none());
        assert!(info.description.is_none());
    }

    #[test]
    fn test_restore_xml_optional_trailing_elements() {
        let mut parser = VecParser::new(vec![
            start("info"),
            start("name"),
            end_with_text("name", "MyDb"),
            start("owner"),
            end_with_text("owner", "MyOwner"),
            start("description"),
            end_with_text("description", "MyDesc"),
            start("major"),
            end_with_text("major", "1"),
            start("minor"),
            end_with_text("minor", "2"),
            start("settings"),
            end_with_text("settings", "0"),
            start("readonly"),
            end_with_text("readonly", "true"),
            start("trackcallgraph"),
            end_with_text("trackcallgraph", "false"),
            start("layout"),
            end_with_text("layout", "7"),
            start("execategory"),
            end_with_text("execategory", "Compiler"),
            start("execategory"),
            end_with_text("execategory", "Vendor"),
            start("functiontag"),
            end_with_text("functiontag", "thunk"),
            start("datename"),
            end_with_text("datename", "MyDate"),
            end_of("info"),
        ]);

        let mut info = DatabaseInformation::new();
        info.restore_xml(&mut parser).unwrap();

        assert!(info.readonly);
        assert!(!info.trackcallgraph);
        assert_eq!(info.layout_version, 7);
        assert_eq!(
            info.execats,
            Some(vec!["Compiler".to_string(), "Vendor".to_string()])
        );
        assert_eq!(info.function_tags, Some(vec!["thunk".to_string()]));
        assert_eq!(info.date_column_name.as_deref(), Some("MyDate"));
    }

    #[test]
    fn test_restore_xml_resets_stale_fields_from_prior_call() {
        let mut parser = VecParser::new(vec![
            start("info"),
            start("name"),
            end_with_text("name", "MyDb"),
            start("owner"),
            end_with_text("owner", "MyOwner"),
            start("description"),
            end_with_text("description", "MyDesc"),
            start("major"),
            end_with_text("major", "1"),
            start("minor"),
            end_with_text("minor", "2"),
            start("settings"),
            end_with_text("settings", "0"),
            end_of("info"),
        ]);

        let mut info = DatabaseInformation::new();
        info.readonly = true;
        info.trackcallgraph = false;
        info.layout_version = 99;
        info.execats = Some(vec!["Stale".to_string()]);
        info.function_tags = Some(vec!["Stale".to_string()]);
        info.date_column_name = Some("Stale".to_string());

        info.restore_xml(&mut parser).unwrap();

        assert!(!info.readonly);
        assert!(info.trackcallgraph);
        assert_eq!(info.layout_version, 0);
        assert!(info.execats.is_none());
        assert!(info.function_tags.is_none());
        assert!(info.date_column_name.is_none());
    }

    #[test]
    fn test_restore_xml_wrong_start_element_errors() {
        let mut parser = VecParser::new(vec![start("notinfo"), end_of("notinfo")]);
        let mut info = DatabaseInformation::new();
        assert!(info.restore_xml(&mut parser).is_err());
    }

    // --- equals ---

    #[test]
    #[should_panic(expected = "DatabaseInformation.equals is used - should add hashcode method")]
    fn test_equals_always_panics() {
        let a = DatabaseInformation::new();
        let b = DatabaseInformation::new();
        a.equals(&b);
    }

    // --- check_signature_settings ---

    #[test]
    fn test_check_signature_settings_no_setting_information_from_caller() {
        let info = DatabaseInformation::new();
        assert_eq!(info.check_signature_settings(0, 0, 5), 3);
        assert_eq!(info.check_signature_settings(1, 0, 0), 3);
    }

    #[test]
    fn test_check_signature_settings_no_setting_information_locally() {
        let mut info = DatabaseInformation::new();
        info.major = 0;
        info.settings = 0;
        assert_eq!(info.check_signature_settings(1, 0, 5), 4);
    }

    #[test]
    fn test_check_signature_settings_mismatch() {
        let mut info = DatabaseInformation::new();
        info.major = 2;
        info.settings = 5;
        assert_eq!(info.check_signature_settings(3, 0, 5), 2);
        assert_eq!(info.check_signature_settings(2, 0, 6), 2);
    }

    #[test]
    fn test_check_signature_settings_complete_match() {
        let mut info = DatabaseInformation::new();
        info.major = 2;
        info.minor = 3;
        info.settings = 5;
        assert_eq!(info.check_signature_settings(2, 3, 5), 0);
    }

    #[test]
    fn test_check_signature_settings_minor_difference() {
        let mut info = DatabaseInformation::new();
        info.major = 2;
        info.minor = 3;
        info.settings = 5;
        assert_eq!(info.check_signature_settings(2, 4, 5), 1);
        assert_eq!(info.check_signature_settings(2, 2, 5), 1);
    }

    #[test]
    fn test_check_signature_settings_minor_too_far_apart() {
        let mut info = DatabaseInformation::new();
        info.major = 2;
        info.minor = 5;
        info.settings = 5;
        assert_eq!(info.check_signature_settings(2, 1, 5), 2);
        assert_eq!(info.check_signature_settings(2, 9, 5), 2);
    }
}
