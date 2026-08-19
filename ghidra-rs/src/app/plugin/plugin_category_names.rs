//! A listing of commonly used plugin-description category names.
//!
//! Maps to `ghidra.app.plugin.PluginCategoryNames`.

pub trait PluginCategoryNames {
    const ANALYSIS: &'static str = "Analysis";

    // common to tools that open programs
    const COMMON: &'static str = "Common";
    const CODE_VIEWER: &'static str = "Code Viewer";
    const DEBUGGER: &'static str = "Debugger";
    const DIAGNOSTIC: &'static str = "Diagnostic";
    const EXAMPLES: &'static str = "Examples";
    const FRAMEWORK: &'static str = "Framework";
    const GRAPH: &'static str = "Graph";
    const NAVIGATION: &'static str = "Navigation";
    const SEARCH: &'static str = "Search";
    const SELECTION: &'static str = "Selection";
    const PROGRAM_ORGANIZATION: &'static str = "Program Organization";
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCategoryNames;
    impl PluginCategoryNames for MockCategoryNames {}

    #[test]
    fn default_constants_have_expected_values() {
        assert_eq!(MockCategoryNames::ANALYSIS, "Analysis");
        assert_eq!(MockCategoryNames::COMMON, "Common");
        assert_eq!(MockCategoryNames::CODE_VIEWER, "Code Viewer");
        assert_eq!(MockCategoryNames::DEBUGGER, "Debugger");
        assert_eq!(MockCategoryNames::DIAGNOSTIC, "Diagnostic");
        assert_eq!(MockCategoryNames::EXAMPLES, "Examples");
        assert_eq!(MockCategoryNames::FRAMEWORK, "Framework");
        assert_eq!(MockCategoryNames::GRAPH, "Graph");
        assert_eq!(MockCategoryNames::NAVIGATION, "Navigation");
        assert_eq!(MockCategoryNames::SEARCH, "Search");
        assert_eq!(MockCategoryNames::SELECTION, "Selection");
        assert_eq!(MockCategoryNames::PROGRAM_ORGANIZATION, "Program Organization");
    }
}
