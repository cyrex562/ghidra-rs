//! Port of `ghidra.app.decompiler.DecompilerMarginService`.
//!
//! A service that allows clients to add custom margins in the Decompiler UI.

use crate::app::seam_stubs::{DecompilerPanel, DecompilerMarginProvider};

/// A service that allows clients to add custom margins in the Decompiler UI.
///
/// This is a port of the Java interface `ghidra.app.decompiler.DecompilerMarginService`.
pub trait DecompilerMarginService: Send + Sync {
    /// Add a margin to the Decompiler's primary window.
    fn add_margin_provider(&self, provider: &dyn DecompilerMarginProvider);

    /// Remove a margin from the Decompiler's primary window.
    fn remove_margin_provider(&self, provider: &dyn DecompilerMarginProvider);

    /// Get the panel associated with this margin.
    fn get_decompiler_panel(&self) -> Box<dyn DecompilerPanel>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMarginProvider;
    impl DecompilerMarginProvider for TestMarginProvider {}

    struct TestPanel;
    impl DecompilerPanel for TestPanel {}

    struct TestMarginService;
    impl DecompilerMarginService for TestMarginService {
        fn add_margin_provider(&self, _provider: &dyn DecompilerMarginProvider) {}

        fn remove_margin_provider(&self, _provider: &dyn DecompilerMarginProvider) {}

        fn get_decompiler_panel(&self) -> Box<dyn DecompilerPanel> {
            Box::new(TestPanel)
        }
    }

    #[test]
    fn test_add_margin_provider() {
        let service = TestMarginService;
        let provider = TestMarginProvider;
        service.add_margin_provider(&provider);
    }

    #[test]
    fn test_remove_margin_provider() {
        let service = TestMarginService;
        let provider = TestMarginProvider;
        service.remove_margin_provider(&provider);
    }

    #[test]
    fn test_get_decompiler_panel() {
        let service = TestMarginService;
        let _panel = service.get_decompiler_panel();
    }

    #[test]
    fn test_as_trait_object() {
        let service: Box<dyn DecompilerMarginService> = Box::new(TestMarginService);
        let provider = TestMarginProvider;
        service.add_margin_provider(&provider);
        let _panel = service.get_decompiler_panel();
    }
}
