use std::io::Write;

use crate::program::model::listing::Function;
use crate::util::exception::CancelledException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Generic interface for a function database.
///
/// Port of `ghidra.app.analyzers.FuncDB<T>`. A trait for querying and persisting
/// function-related data with XML serialization support.
///
/// # Type Parameters
/// * `T` - The type of query result returned by this database.
pub trait FuncDB<T> {
    /// Queries the database for results related to the given function.
    ///
    /// # Arguments
    /// * `func` - The function to query
    ///
    /// # Returns
    /// A vector of results of type `T`
    ///
    /// # Errors
    /// Returns `CancelledException` if the operation is cancelled by the user.
    fn query<F: Function + ?Sized>(&self, func: &F) -> Result<Vec<T>, CancelledException>;

    /// Restores the database state from XML.
    ///
    /// # Arguments
    /// * `parser` - The XML pull parser to read from
    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P);

    /// Saves the database state to XML.
    ///
    /// # Arguments
    /// * `writer` - The writer to serialize XML to
    ///
    /// # Errors
    /// Returns an IO error if writing fails.
    fn save_xml(&self, writer: &mut dyn Write) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element::XmlElement;
    use std::collections::HashMap;

    struct TestFuncDB {
        data: Vec<String>,
    }

    impl TestFuncDB {
        fn new() -> Self {
            Self { data: vec![] }
        }

        fn add_data(&mut self, item: String) {
            self.data.push(item);
        }
    }

    struct MockXmlElement;

    impl XmlElement for MockXmlElement {
        fn get_level(&self) -> i32 {
            0
        }

        fn is_start(&self) -> bool {
            false
        }

        fn is_end(&self) -> bool {
            false
        }

        fn is_content(&self) -> bool {
            false
        }

        fn get_name(&self) -> &str {
            "mock"
        }

        fn get_attributes(&self) -> HashMap<String, String> {
            HashMap::new()
        }

        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(std::iter::empty())
        }

        fn has_attribute(&self, _key: &str) -> bool {
            false
        }

        fn get_attribute(&self, _key: &str) -> Option<String> {
            None
        }

        fn get_text(&self) -> &str {
            ""
        }

        fn get_column_number(&self) -> i32 {
            0
        }

        fn get_line_number(&self) -> i32 {
            0
        }

        fn set_attribute(&mut self, _key: impl Into<String>, _value: impl Into<String>) {}

        fn is_start_with(&self, _name: &str) -> bool {
            false
        }
    }

    struct MockXmlParser;

    impl XmlPullParser for MockXmlParser {
        type Element = MockXmlElement;

        fn get_name(&self) -> &str {
            "mock"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn has_next(&self) -> bool {
            false
        }

        fn peek(&self) -> Self::Element {
            MockXmlElement
        }

        fn next(&mut self) -> Self::Element {
            MockXmlElement
        }

        fn is_pulling_content(&self) -> bool {
            false
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn dispose(&mut self) {}
    }

    impl FuncDB<String> for TestFuncDB {
        fn query<F: Function + ?Sized>(&self, _func: &F) -> Result<Vec<String>, CancelledException> {
            Ok(self.data.clone())
        }

        fn restore_xml<P: XmlPullParser>(&mut self, _parser: &mut P) {}

        fn save_xml(&self, _writer: &mut dyn Write) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_func_db_trait_implementation() {
        let mut db = TestFuncDB::new();
        db.add_data("result1".to_string());
        db.add_data("result2".to_string());
        assert_eq!(db.data.len(), 2);
    }

    #[test]
    fn test_func_db_save_xml() {
        let db = TestFuncDB::new();
        let mut output = Vec::new();
        let result = db.save_xml(&mut output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_func_db_restore_xml() {
        let mut db = TestFuncDB::new();
        let mut parser = MockXmlParser;
        db.restore_xml(&mut parser);
        assert_eq!(db.data.len(), 0);
    }
}
