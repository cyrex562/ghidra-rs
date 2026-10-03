//! Describes a string that has been annotated, allowing rendering and functionality to be
//! added to strings.
//!
//! Port of `ghidra.app.util.viewer.field.AnnotatedStringHandler`. This is a genuine open
//! extension point (six in-repo implementors), so it is ported as a trait.
//!
//! NOTE: all `AnnotatedStringHandler` implementations must have type names ending in
//! `"StringHandler"` -- if not, the `ClassSearcher` will not find them.

use crate::app::seam_stubs::Navigatable;
use crate::app::util::viewer::field::annotation_exception::AnnotationException;
use crate::docking::seam_stubs::AttributedString;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;

/// Escapes a string that is intended to be used as an annotated string portion.
///
/// Quotes are escaped; `'}'` and `' '` cause the whole string to be wrapped in quotes.
///
/// Corresponds to the Java `static` method `AnnotatedStringHandler.escapeAnnotationPart(String)`.
pub fn escape_annotation_part(s: Option<&str>) -> String {
    let s = s.unwrap_or("");
    let escaped = s.replace('"', "\\\"");
    if escaped != s || escaped.contains('}') || escaped.contains(' ') {
        format!("\"{}\"", escaped)
    } else {
        escaped
    }
}

/// Describes a string that has been annotated, allowing rendering and functionality to be
/// added to strings.
///
/// Port of `ghidra.app.util.viewer.field.AnnotatedStringHandler`.
pub trait AnnotatedStringHandler: ExtensionPoint {
    /// Creates an [`AttributedString`] based on the given array of strings. The first string in
    /// the list is expected to be the annotation tag used to create the annotation. At the very
    /// least the array is expected to be comprised of two elements, the annotation and some
    /// data. Extra data may be provided as needed by implementing classes.
    ///
    /// # Arguments
    /// * `prototype_string` - the prototype `AttributedString` that dictates the attributes for
    ///   the newly created string. Implementations may change attributes as needed.
    /// * `text` - the annotation parts used to create the returned `AttributedString`.
    /// * `program` - the program with which the returned string is associated.
    ///
    /// # Errors
    /// Returns an [`AnnotationException`] if the given text data does not fit the expected
    /// format for this handler implementation.
    fn create_annotated_string(
        &self,
        prototype_string: &AttributedString,
        text: &[String],
        program: &dyn Program,
    ) -> Result<AttributedString, AnnotationException>;

    /// Returns the annotation string names that this handler supports (e.g., `"symbol"`,
    /// `"address"`, etc...).
    fn get_supported_annotations(&self) -> Vec<String>;

    /// Notified when an annotation is clicked. Returns `true` if this annotation handles the
    /// click; returns `false` if this annotation does not do anything with the click.
    ///
    /// # Arguments
    /// * `text` - the constituent parts of the annotation
    /// * `source_navigatable` - the location in the program that was clicked
    /// * `service_provider` - the service provider for needed services
    fn handle_mouse_click(
        &self,
        text: &[String],
        source_navigatable: &dyn Navigatable,
        service_provider: &dyn ServiceProvider,
    ) -> bool;

    /// Returns the string that represents the GUI presence of this option.
    fn get_display_string(&self) -> String;

    /// Returns an example string of how the annotation is used.
    fn get_prototype_string(&self) -> String;

    /// Returns an example string of how the annotation is used, given the text that may be
    /// wrapped.
    ///
    /// Corresponds to the Java default method `getPrototypeString(String)`.
    fn get_prototype_string_for(&self, _display_text: &str) -> String {
        self.get_prototype_string()
    }

    /// Returns an array with modifications by the annotation; `None` otherwise, using
    /// [`SpecialAddress::no_address`] as the address of the annotation.
    ///
    /// Corresponds to the Java default method `modify(String[], Program)`, deprecated for
    /// removal in favor of [`AnnotatedStringHandler::modify_at`].
    #[deprecated]
    fn modify(&self, text: &[String], program: &dyn Program) -> Option<Vec<String>> {
        self.modify_at(text, program, &SpecialAddress::no_address())
    }

    /// Returns an array with modifications by the annotation; `None` otherwise. Called by the
    /// framework when comments are created, before they are applied, allowing the handler to
    /// perform fixups on the input text before it is saved to the database.
    ///
    /// # Arguments
    /// * `text` - the array of annotation parts to modify
    /// * `program` - the program
    /// * `addr` - address of the annotation in the program
    ///
    /// Corresponds to the Java default method `modify(String[], Program, Address)`.
    fn modify_at(&self, _text: &[String], _program: &dyn Program, _addr: &Address) -> Option<Vec<String>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAnnotatedStringHandler;

    impl ExtensionPoint for MockAnnotatedStringHandler {}

    impl AnnotatedStringHandler for MockAnnotatedStringHandler {
        fn create_annotated_string(
            &self,
            _prototype_string: &AttributedString,
            _text: &[String],
            _program: &dyn Program,
        ) -> Result<AttributedString, AnnotationException> {
            Ok(AttributedString::default())
        }

        fn get_supported_annotations(&self) -> Vec<String> {
            vec!["mock".to_string()]
        }

        fn handle_mouse_click(
            &self,
            _text: &[String],
            _source_navigatable: &dyn Navigatable,
            _service_provider: &dyn ServiceProvider,
        ) -> bool {
            false
        }

        fn get_display_string(&self) -> String {
            "Mock".to_string()
        }

        fn get_prototype_string(&self) -> String {
            "{@mock text}".to_string()
        }
    }

    #[test]
    fn test_escape_annotation_part_plain() {
        assert_eq!(escape_annotation_part(Some("hello")), "hello");
    }

    #[test]
    fn test_escape_annotation_part_none() {
        assert_eq!(escape_annotation_part(None), "");
    }

    #[test]
    fn test_escape_annotation_part_quotes() {
        assert_eq!(
            escape_annotation_part(Some("say \"hi\"")),
            "\"say \\\"hi\\\"\""
        );
    }

    #[test]
    fn test_escape_annotation_part_brace() {
        assert_eq!(escape_annotation_part(Some("a}b")), "\"a}b\"");
    }

    #[test]
    fn test_escape_annotation_part_space() {
        assert_eq!(escape_annotation_part(Some("a b")), "\"a b\"");
    }

    #[test]
    fn test_get_prototype_string_for_defaults_to_get_prototype_string() {
        let handler = MockAnnotatedStringHandler;
        assert_eq!(
            handler.get_prototype_string_for("wrapped text"),
            handler.get_prototype_string()
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_modify_deprecated_forwards_to_modify_at() {
        struct RecordingHandler;

        impl ExtensionPoint for RecordingHandler {}

        impl AnnotatedStringHandler for RecordingHandler {
            fn create_annotated_string(
                &self,
                _prototype_string: &AttributedString,
                _text: &[String],
                _program: &dyn Program,
            ) -> Result<AttributedString, AnnotationException> {
                Ok(AttributedString::default())
            }

            fn get_supported_annotations(&self) -> Vec<String> {
                vec![]
            }

            fn handle_mouse_click(
                &self,
                _text: &[String],
                _source_navigatable: &dyn Navigatable,
                _service_provider: &dyn ServiceProvider,
            ) -> bool {
                false
            }

            fn get_display_string(&self) -> String {
                String::new()
            }

            fn get_prototype_string(&self) -> String {
                String::new()
            }

            fn modify_at(
                &self,
                _text: &[String],
                _program: &dyn Program,
                addr: &Address,
            ) -> Option<Vec<String>> {
                Some(vec![addr.to_string()])
            }
        }

        struct MockProgram;
        impl crate::framework::model::DomainObject for MockProgram {}
        impl Program for MockProgram {
            fn get_name(&self) -> String {
                "mock".to_string()
            }
            fn get_language_id(&self) -> String {
                String::new()
            }
        }

        let handler = RecordingHandler;
        let result = handler.modify(&[], &MockProgram);
        assert_eq!(result, Some(vec!["NO ADDRESS".to_string()]));
    }

    #[test]
    fn test_modify_at_default_returns_none() {
        let handler = MockAnnotatedStringHandler;
        struct MockProgram;
        impl crate::framework::model::DomainObject for MockProgram {}
        impl Program for MockProgram {
            fn get_name(&self) -> String {
                "mock".to_string()
            }
            fn get_language_id(&self) -> String {
                String::new()
            }
        }

        let addr = SpecialAddress::no_address();
        assert_eq!(handler.modify_at(&[], &MockProgram, &addr), None);
    }
}
