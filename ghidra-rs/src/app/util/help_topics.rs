//! Help topic constants for Ghidra UI components.
//!
//! These strings correspond to folders under the "topics" resource and are used
//! to link UI elements to their corresponding help documentation.

/// Help topic for "About."
pub const ABOUT: &str = "About";

/// Help topic for auto analysis.
pub const AUTO_ANALYSIS: &str = "AutoAnalysisPlugin";

/// Help topic for block models.
pub const BLOCK_MODEL: &str = "BlockModel";

/// Help topic for bookmarks.
pub const BOOKMARKS: &str = "BookmarkPlugin";

/// Help topic for the byte viewer.
pub const BYTE_VIEWER: &str = "ByteViewerPlugin";

/// Help topic for the code browser.
pub const CODE_BROWSER: &str = "CodeBrowserPlugin";

/// Help topic for the Console Plugin.
pub const CONSOLE: &str = "ConsolePlugin";

/// Help topic for comments.
pub const COMMENTS: &str = "CommentsPlugin";

/// Help topic for data.
pub const DATA: &str = "DataPlugin";

/// Help topic for the data manager.
pub const DATA_MANAGER: &str = "DataTypeManagerPlugin";

/// Help topic for the data type editors.
pub const DATA_TYPE_EDITORS: &str = "DataTypeEditors";

/// Help topic for the decompiler.
pub const DECOMPILER: &str = "DecompilePlugin";

/// Help topic for doing diffs between programs.
pub const DIFF: &str = "Diff";

/// Help topic for equates.
pub const EQUATES: &str = "EquatePlugin";

/// Help topic for the exporters.
pub const EXPORTER: &str = "ExporterPlugin";

/// Help topic for references searching.
pub const FIND_REFERENCES: &str = "LocationReferencesPlugin";

/// Help topic for the front end (Ghidra Project Window).
pub const FRONT_END: &str = "FrontEndPlugin";

/// Help topic for the glossary.
pub const GLOSSARY: &str = "Glossary";

/// Help topic for highlighting.
pub const HIGHLIGHT: &str = "SetHighlightPlugin";

/// Help topic for the importers.
pub const IMPORTER: &str = "ImporterPlugin";

/// Help topic for intro topics.
pub const INTRO: &str = "Intro";

/// Help topic for the add/edit label.
pub const LABEL: &str = "LabelMgrPlugin";

/// Help topic for navigation.
pub const NAVIGATION: &str = "Navigation";

/// Help topic for the memory map.
pub const MEMORY_MAP: &str = "MemoryMapPlugin";

/// Help topic for the P2 to XML exporter.
pub const PE2XML: &str = "PE2XMLPlugin";

/// Help topic for programs (open, close, save, etc.).
pub const PROGRAM: &str = "ProgramManagerPlugin";

/// Help topic for the program tree.
pub const PROGRAM_TREE: &str = "ProgramTreePlugin";

/// Help topic for references.
pub const REFERENCES: &str = "ReferencesPlugin";

/// Help topic for the relocation table.
pub const RELOCATION_TABLE: &str = "RelocationTablePlugin";

/// Help topic for the project repository.
pub const REPOSITORY: &str = "Repository";

/// Help topic for the Runtime Info Plugin.
pub const RUNTIME_INFO: &str = "RuntimeInfoPlugin";

/// Help topic for search functions.
pub const SEARCH: &str = "Search";

/// Help topic for selection.
pub const SELECTION: &str = "Selection";

/// Help topic for the symbol table.
pub const SYMBOL_TABLE: &str = "SymbolTablePlugin";

/// Help topic for the symbol tree.
pub const SYMBOL_TREE: &str = "SymbolTreePlugin";

/// Help topic for tools.
pub const TOOL: &str = "Tool";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_topic_values() {
        // Verify that all help topics are non-empty strings
        assert!(!ABOUT.is_empty());
        assert!(!AUTO_ANALYSIS.is_empty());
        assert!(!BLOCK_MODEL.is_empty());
        assert!(!BOOKMARKS.is_empty());
        assert!(!BYTE_VIEWER.is_empty());
        assert!(!CODE_BROWSER.is_empty());
        assert!(!CONSOLE.is_empty());
        assert!(!COMMENTS.is_empty());
        assert!(!DATA.is_empty());
        assert!(!DATA_MANAGER.is_empty());
        assert!(!DATA_TYPE_EDITORS.is_empty());
        assert!(!DECOMPILER.is_empty());
        assert!(!DIFF.is_empty());
        assert!(!EQUATES.is_empty());
        assert!(!EXPORTER.is_empty());
        assert!(!FIND_REFERENCES.is_empty());
        assert!(!FRONT_END.is_empty());
        assert!(!GLOSSARY.is_empty());
        assert!(!HIGHLIGHT.is_empty());
        assert!(!IMPORTER.is_empty());
        assert!(!INTRO.is_empty());
        assert!(!LABEL.is_empty());
        assert!(!NAVIGATION.is_empty());
        assert!(!MEMORY_MAP.is_empty());
        assert!(!PE2XML.is_empty());
        assert!(!PROGRAM.is_empty());
        assert!(!PROGRAM_TREE.is_empty());
        assert!(!REFERENCES.is_empty());
        assert!(!RELOCATION_TABLE.is_empty());
        assert!(!REPOSITORY.is_empty());
        assert!(!RUNTIME_INFO.is_empty());
        assert!(!SEARCH.is_empty());
        assert!(!SELECTION.is_empty());
        assert!(!SYMBOL_TABLE.is_empty());
        assert!(!SYMBOL_TREE.is_empty());
        assert!(!TOOL.is_empty());
    }

    #[test]
    fn test_specific_help_topics() {
        assert_eq!(ABOUT, "About");
        assert_eq!(AUTO_ANALYSIS, "AutoAnalysisPlugin");
        assert_eq!(BLOCK_MODEL, "BlockModel");
        assert_eq!(BOOKMARKS, "BookmarkPlugin");
        assert_eq!(BYTE_VIEWER, "ByteViewerPlugin");
        assert_eq!(CODE_BROWSER, "CodeBrowserPlugin");
        assert_eq!(CONSOLE, "ConsolePlugin");
        assert_eq!(COMMENTS, "CommentsPlugin");
        assert_eq!(DATA, "DataPlugin");
        assert_eq!(DATA_MANAGER, "DataTypeManagerPlugin");
        assert_eq!(DATA_TYPE_EDITORS, "DataTypeEditors");
        assert_eq!(DECOMPILER, "DecompilePlugin");
        assert_eq!(DIFF, "Diff");
        assert_eq!(EQUATES, "EquatePlugin");
        assert_eq!(EXPORTER, "ExporterPlugin");
        assert_eq!(FIND_REFERENCES, "LocationReferencesPlugin");
        assert_eq!(FRONT_END, "FrontEndPlugin");
        assert_eq!(GLOSSARY, "Glossary");
        assert_eq!(HIGHLIGHT, "SetHighlightPlugin");
        assert_eq!(IMPORTER, "ImporterPlugin");
        assert_eq!(INTRO, "Intro");
        assert_eq!(LABEL, "LabelMgrPlugin");
        assert_eq!(NAVIGATION, "Navigation");
        assert_eq!(MEMORY_MAP, "MemoryMapPlugin");
        assert_eq!(PE2XML, "PE2XMLPlugin");
        assert_eq!(PROGRAM, "ProgramManagerPlugin");
        assert_eq!(PROGRAM_TREE, "ProgramTreePlugin");
        assert_eq!(REFERENCES, "ReferencesPlugin");
        assert_eq!(RELOCATION_TABLE, "RelocationTablePlugin");
        assert_eq!(REPOSITORY, "Repository");
        assert_eq!(RUNTIME_INFO, "RuntimeInfoPlugin");
        assert_eq!(SEARCH, "Search");
        assert_eq!(SELECTION, "Selection");
        assert_eq!(SYMBOL_TABLE, "SymbolTablePlugin");
        assert_eq!(SYMBOL_TREE, "SymbolTreePlugin");
        assert_eq!(TOOL, "Tool");
    }

    #[test]
    fn test_plugin_name_conventions() {
        // Verify that most topics follow either "Plugin" or descriptive naming
        assert!(AUTO_ANALYSIS.contains("Plugin") || AUTO_ANALYSIS.chars().all(|c| c.is_alphanumeric() || c == '_'));
        assert!(CODE_BROWSER.contains("Plugin"));
        assert!(BYTE_VIEWER.contains("Plugin"));
        // Structural topics use descriptive names
        assert_eq!(DIFF, "Diff");
        assert_eq!(SEARCH, "Search");
    }
}
