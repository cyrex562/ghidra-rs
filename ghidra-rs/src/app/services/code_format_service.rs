//! Service provided by a plugin that gives access to a manager for the field formats used by a
//! listing.
//!
//! Mirrors `ghidra.app.services.CodeFormatService`. The Java `@ServiceInfo` annotation (default
//! provider `CodeBrowserPlugin`) has no Rust equivalent and is omitted.

use crate::app::seam_stubs::FormatManager;

/// Service provided by a plugin that gives access to a manager for the field formats used by a
/// listing.
pub trait CodeFormatService {
    /// Gets the format manager used by this service.
    fn get_format_manager(&self) -> Box<dyn FormatManager>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFormatManager;
    impl FormatManager for MockFormatManager {}

    struct MockCodeFormatService;

    impl CodeFormatService for MockCodeFormatService {
        fn get_format_manager(&self) -> Box<dyn FormatManager> {
            Box::new(MockFormatManager)
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn CodeFormatService> = Box::new(MockCodeFormatService);
        let _manager = service.get_format_manager();
    }
}
