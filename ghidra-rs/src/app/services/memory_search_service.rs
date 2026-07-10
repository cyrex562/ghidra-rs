//! Service for invoking the memory search provider.
//!
//! Port of `ghidra.app.services.MemorySearchService`. The Java interface is annotated
//! `@Deprecated(since = "11.2")`; the whole trait carries `#[deprecated]` here since Rust has no
//! per-declaration equivalent of a Javadoc-only deprecation note. `Navigatable` and
//! `SearchSettings` are not yet ported, so they are represented by placeholder traits in
//! [`crate::app::seam_stubs`].

use crate::app::seam_stubs::{Navigatable, SearchSettings};

/// Service for invoking the memory search provider.
#[deprecated(note = "not a generally useful service, may go away at some point")]
pub trait MemorySearchService {
    /// Creates a new memory search provider window.
    ///
    /// `navigatable` is used to get bytes to search, `input` is the input string to search for,
    /// `settings` determines how to interpret the input string, and `use_selection` controls
    /// whether the provider automatically restricts to a selection if one exists in the
    /// navigatable.
    fn create_memory_search_provider(
        &self,
        navigatable: &dyn Navigatable,
        input: &str,
        settings: &dyn SearchSettings,
        use_selection: bool,
    );
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    struct MockNavigatable;
    impl Navigatable for MockNavigatable {}

    struct MockSearchSettings;
    impl SearchSettings for MockSearchSettings {}

    struct MockService;

    impl MemorySearchService for MockService {
        fn create_memory_search_provider(
            &self,
            _navigatable: &dyn Navigatable,
            _input: &str,
            _settings: &dyn SearchSettings,
            _use_selection: bool,
        ) {
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn MemorySearchService> = Box::new(MockService);
        service.create_memory_search_provider(
            &MockNavigatable,
            "deadbeef",
            &MockSearchSettings,
            true,
        );
    }
}
