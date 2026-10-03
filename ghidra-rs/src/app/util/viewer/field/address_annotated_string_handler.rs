//! An annotated string handler that handles `{@address ...}`/`{@addr ...}` annotations. This
//! class expects one string following the annotation text that is an address string, and will
//! display that string as its display text.
//!
//! Port of `ghidra.app.util.viewer.field.AddressAnnotatedStringHandler`.

use crate::app::seam_stubs::Navigatable;
use crate::app::services::GoToService;
use crate::app::util::viewer::field::annotated_string_handler::{
    escape_annotation_part, AnnotatedStringHandler,
};
use crate::app::util::viewer::field::annotation_exception::AnnotationException;
use crate::docking::seam_stubs::{AttributedString, Color};
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;
use crate::util::msg::Msg;

/// Corresponds to the Java `private static final String INVALID_SYMBOL_TEXT`, whose value is
/// exactly this (a missing space is baked into the original Java string-concatenation literal).
const INVALID_SYMBOL_TEXT: &str = "@address annotation must have an addressstring";

/// Corresponds to the Java `private static final String[] SUPPORTED_ANNOTATIONS`.
const SUPPORTED_ANNOTATIONS: [&str; 2] = ["address", "addr"];

/// An annotated string handler that allows handles annotations that begin with
/// [`SUPPORTED_ANNOTATIONS`]. This class expects one string following the annotation text that
/// is an address string and will display that string as its display text.
///
/// Port of `ghidra.app.util.viewer.field.AddressAnnotatedStringHandler`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AddressAnnotatedStringHandler;

impl AddressAnnotatedStringHandler {
    /// Constructs a well-formed Address Annotation comment string.
    ///
    /// `destination_address` is the destination of the annotation; `display_text` is the text
    /// used as the body of the annotation (problematic characters are escaped).
    ///
    /// Port of `AddressAnnotatedStringHandler.createAddressAnnotationString(Address, String)`.
    pub fn create_address_annotation_string(
        destination_address: &Address,
        display_text: &str,
    ) -> String {
        format!(
            "{{@address {} {}}}",
            destination_address.format(false, 8),
            escape_annotation_part(Some(display_text))
        )
    }

    /// Constructs a well-formed Address Annotation comment string.
    ///
    /// `address_offset` is the destination of the annotation; `display_text` is the text used as
    /// the body of the annotation (problematic characters are escaped).
    ///
    /// Port of `AddressAnnotatedStringHandler.createAddressAnnotationString(long, String)`.
    pub fn create_address_annotation_string_for_offset(
        address_offset: i64,
        display_text: &str,
    ) -> String {
        format!(
            "{{@address {:#x} {}}}",
            address_offset,
            escape_annotation_part(Some(display_text))
        )
    }
}

impl ExtensionPoint for AddressAnnotatedStringHandler {}

impl AnnotatedStringHandler for AddressAnnotatedStringHandler {
    /// Port of `AddressAnnotatedStringHandler.createAnnotatedString(AttributedString, String[],
    /// Program)`. The Java method's `program == null` branch (reached only during merge
    /// operations, where it falls back to an undecorated string built from `text`) has no
    /// counterpart here: this trait's `program` parameter is a non-nullable `&dyn Program`
    /// reference, so that branch is unreachable and is not ported.
    fn create_annotated_string(
        &self,
        prototype_string: &AttributedString,
        text: &[String],
        program: &dyn Program,
    ) -> Result<AttributedString, AnnotationException> {
        if text.len() <= 1 {
            return Err(AnnotationException::new(INVALID_SYMBOL_TEXT));
        }

        let address = program
            .get_address_factory()
            .and_then(|factory| factory.get_address(&text[1]));

        let Some(address) = address else {
            return Ok(AttributedString::new(
                format!("No address: {}", text[1]),
                Color,
                prototype_string.get_font_metrics(0),
            ));
        };

        let address_text = if text.len() > 2 {
            text[2..].join(" ")
        } else {
            address.format(true, 8)
        };

        Ok(AttributedString::with_underline(
            address_text,
            prototype_string.get_color(0),
            prototype_string.get_font_metrics(0),
            true,
            Some(prototype_string.get_color(0)),
        ))
    }

    fn get_supported_annotations(&self) -> Vec<String> {
        SUPPORTED_ANNOTATIONS.iter().map(|s| s.to_string()).collect()
    }

    fn handle_mouse_click(
        &self,
        text: &[String],
        source_navigatable: &dyn Navigatable,
        service_provider: &dyn ServiceProvider,
    ) -> bool {
        let go_to_service: Option<Box<dyn GoToService>> = service_provider
            .get_service("GoToService")
            .and_then(|service| service.downcast::<Box<dyn GoToService>>().ok())
            .map(|boxed| *boxed);

        let program = source_navigatable.get_program();
        let address_text = &text[1];
        let address = program
            .get_address_factory()
            .and_then(|factory| factory.get_address(address_text));

        if let Some(address) = address {
            return go_to_service
                .map(|service| service.go_to_navigatable_address(source_navigatable, &address))
                .unwrap_or(false);
        }

        Msg::show_info(
            "AddressAnnotatedStringHandler",
            &format!("No address: {}", address_text),
            &format!("Unable to locate address \"{}\"", address_text),
        );
        false
    }

    fn get_display_string(&self) -> String {
        "Address".to_string()
    }

    fn get_prototype_string(&self) -> String {
        "{@address 0x00}".to_string()
    }

    fn get_prototype_string_for(&self, display_text: &str) -> String {
        format!("{{@address {}}}", display_text.trim())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockProgram {
        factory: DefaultAddressFactory,
    }

    impl MockProgram {
        fn new() -> Self {
            Self {
                factory: DefaultAddressFactory::new(vec![ram_space()]),
            }
        }
    }

    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            Some(Arc::new(self.factory.clone()))
        }
    }

    struct MockNavigatable;

    impl Navigatable for MockNavigatable {
        fn is_connected(&self) -> bool {
            true
        }

        fn get_program(&self) -> Box<dyn Program> {
            Box::new(MockProgram::new())
        }
    }

    struct MockServiceProvider {
        go_to: bool,
    }

    impl ServiceProvider for MockServiceProvider {
        fn get_service(
            &self,
            service_class: &str,
        ) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            if service_class == "GoToService" && self.go_to {
                let service: Box<dyn GoToService> = Box::new(MockGoToService);
                Some(Box::new(service))
            } else {
                None
            }
        }

        fn add_service_listener(
            &mut self,
            _listener: Box<dyn crate::framework::plugintool::util::ServiceListener>,
        ) {
        }

        fn remove_service_listener(
            &mut self,
            _listener: Box<dyn crate::framework::plugintool::util::ServiceListener>,
        ) {
        }
    }

    struct MockGoToService;

    #[allow(deprecated)]
    impl GoToService for MockGoToService {
        fn go_to(&self, _loc: &dyn crate::program::util::ProgramLocation) -> bool {
            false
        }
        fn go_to_in_program(
            &self,
            _loc: &dyn crate::program::util::ProgramLocation,
            _program: &dyn Program,
        ) -> bool {
            false
        }
        fn go_to_navigatable_location(
            &self,
            _navigatable: &dyn Navigatable,
            _loc: &dyn crate::program::util::ProgramLocation,
            _program: &dyn Program,
        ) -> bool {
            false
        }
        fn go_to_navigatable_address_with_ref(
            &self,
            _navigatable: &dyn Navigatable,
            _program: &dyn Program,
            _address: &Address,
            _ref_address: &Address,
        ) -> bool {
            false
        }
        fn go_to_from_address(&self, _from_address: &Address, _address: &Address) -> bool {
            false
        }
        fn go_to_navigatable_address(&self, _navigatable: &dyn Navigatable, _go_to_address: &Address) -> bool {
            true
        }
        fn go_to_address(&self, _go_to_address: &Address) -> bool {
            false
        }
        fn go_to_address_in_program(&self, _go_to_address: &Address, _program: &dyn Program) -> bool {
            false
        }
        fn go_to_external_location(
            &self,
            _external_loc: &dyn crate::program::model::symbol::ExternalLocation,
            _check_navigation_option: bool,
        ) -> bool {
            false
        }
        fn go_to_navigatable_external_location(
            &self,
            _navigatable: &dyn Navigatable,
            _external_loc: &dyn crate::program::model::symbol::ExternalLocation,
            _check_navigation_option: bool,
        ) -> bool {
            false
        }
        fn go_to_query(
            &self,
            _from_addr: &Address,
            _query_data: &crate::app::services::query_data::QueryData,
            _listener: &dyn crate::app::services::GoToServiceListener,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            false
        }
        fn go_to_query_navigatable(
            &self,
            _navigatable: &dyn Navigatable,
            _from_addr: &Address,
            _query_data: &crate::app::services::query_data::QueryData,
            _listener: &dyn crate::app::services::GoToServiceListener,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            false
        }
        fn get_default_navigatable(&self) -> Arc<dyn Navigatable> {
            Arc::new(MockNavigatable)
        }
        fn get_override_service(
            &self,
        ) -> Option<Arc<dyn crate::app::seam_stubs::GoToOverrideService>> {
            None
        }
        fn set_override_service(
            &mut self,
            _override_service: Option<Arc<dyn crate::app::seam_stubs::GoToOverrideService>>,
        ) {
        }
    }

    #[test]
    fn test_create_address_annotation_string() {
        let space = ram_space();
        let addr = space.address(0x1000);
        let s = AddressAnnotatedStringHandler::create_address_annotation_string(&addr, "hello");
        assert_eq!(s, "{@address 00001000 hello}");
    }

    #[test]
    fn test_create_address_annotation_string_for_offset() {
        let s = AddressAnnotatedStringHandler::create_address_annotation_string_for_offset(
            0x1000, "hello",
        );
        assert_eq!(s, "{@address 0x1000 hello}");
    }

    #[test]
    fn test_create_annotated_string_requires_two_parts() {
        let handler = AddressAnnotatedStringHandler;
        let program = MockProgram::new();
        let prototype = AttributedString::default();
        let err = handler
            .create_annotated_string(&prototype, &["address".to_string()], &program)
            .unwrap_err();
        assert_eq!(err.to_string(), INVALID_SYMBOL_TEXT);
    }

    #[test]
    fn test_create_annotated_string_valid_address() {
        let handler = AddressAnnotatedStringHandler;
        let program = MockProgram::new();
        let prototype = AttributedString::default();
        let text = vec!["address".to_string(), "1000".to_string()];
        let result = handler
            .create_annotated_string(&prototype, &text, &program)
            .unwrap();
        assert_eq!(result.text(), "ram:00001000");
    }

    #[test]
    fn test_create_annotated_string_invalid_address() {
        let handler = AddressAnnotatedStringHandler;
        let program = MockProgram::new();
        let prototype = AttributedString::default();
        let text = vec!["address".to_string(), "not_an_address".to_string()];
        let result = handler
            .create_annotated_string(&prototype, &text, &program)
            .unwrap();
        assert_eq!(result.text(), "No address: not_an_address");
    }

    #[test]
    fn test_create_annotated_string_uses_display_text_when_present() {
        let handler = AddressAnnotatedStringHandler;
        let program = MockProgram::new();
        let prototype = AttributedString::default();
        let text = vec![
            "address".to_string(),
            "1000".to_string(),
            "my".to_string(),
            "label".to_string(),
        ];
        let result = handler
            .create_annotated_string(&prototype, &text, &program)
            .unwrap();
        assert_eq!(result.text(), "my label");
    }

    #[test]
    fn test_get_supported_annotations() {
        let handler = AddressAnnotatedStringHandler;
        assert_eq!(handler.get_supported_annotations(), vec!["address", "addr"]);
    }

    #[test]
    fn test_get_display_string() {
        assert_eq!(AddressAnnotatedStringHandler.get_display_string(), "Address");
    }

    #[test]
    fn test_get_prototype_string() {
        assert_eq!(
            AddressAnnotatedStringHandler.get_prototype_string(),
            "{@address 0x00}"
        );
    }

    #[test]
    fn test_get_prototype_string_for() {
        assert_eq!(
            AddressAnnotatedStringHandler.get_prototype_string_for("  ram:1000  "),
            "{@address ram:1000}"
        );
    }

    #[test]
    fn test_handle_mouse_click_navigates_on_valid_address() {
        let handler = AddressAnnotatedStringHandler;
        let navigatable = MockNavigatable;
        let provider = MockServiceProvider { go_to: true };
        let text = vec!["address".to_string(), "1000".to_string()];
        assert!(handler.handle_mouse_click(&text, &navigatable, &provider));
    }

    #[test]
    fn test_handle_mouse_click_returns_false_without_service() {
        let handler = AddressAnnotatedStringHandler;
        let navigatable = MockNavigatable;
        let provider = MockServiceProvider { go_to: false };
        let text = vec!["address".to_string(), "1000".to_string()];
        assert!(!handler.handle_mouse_click(&text, &navigatable, &provider));
    }

    #[test]
    fn test_handle_mouse_click_returns_false_on_invalid_address() {
        let handler = AddressAnnotatedStringHandler;
        let navigatable = MockNavigatable;
        let provider = MockServiceProvider { go_to: true };
        let text = vec!["address".to_string(), "not_an_address".to_string()];
        assert!(!handler.handle_mouse_click(&text, &navigatable, &provider));
    }
}
