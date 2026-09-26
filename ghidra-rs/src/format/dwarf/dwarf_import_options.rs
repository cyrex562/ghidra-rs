use std::fmt;

use crate::app::plugin::core::analysis::analysis_options_updater::AnalysisOptionsUpdater;
use crate::framework::options::Options;

const OPTION_IMPORT_DATATYPES: &str = "Import Data Types";
const OPTION_IMPORT_DATATYPES_DESC: &str = "Import data types defined in the DWARF debug info.";

const OPTION_IMPORT_FUNCS: &str = "Import Functions";
const OPTION_IMPORT_FUNCS_DESC: &str =
    "Import function information defined in the DWARF debug info\n\
     (implies 'Import Data Types' is selected).";

const OPTION_OUTPUT_SOURCE_INFO: &str = "Output Source Info";
const OPTION_OUTPUT_SOURCE_INFO_DESC: &str =
    "Include source code location info (filename:linenumber) in comments attached to the \
     Ghidra datatype or function or variable created.";

const OPTION_SOURCE_LINEINFO: &str = "Import Source Line Info";
const OPTION_SOURCE_LINEINFO_DESC: &str =
    "Create source map entries containing the source code filename, line number, address, and \
     length at each location provided in the DWARF data";

const OPTION_OUTPUT_DWARF_DIE_INFO: &str = "Output DWARF DIE Info";
const OPTION_OUTPUT_DWARF_DIE_INFO_DESC: &str =
    "Include DWARF DIE offset info in comments attached to the Ghidra datatype or function \
     or variable created.";

const OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS: &str = "Add Lexical Block Comments";
const OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC: &str =
    "Add comments to the start of lexical blocks";

const OPTION_OUTPUT_INLINE_FUNC_COMMENTS: &str = "Add Inlined Functions Comments";
const OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC: &str =
    "Add comments to the start of inlined functions";

const OPTION_OUTPUT_FUNC_SIGS: &str = "Create Function Signatures";
const OPTION_OUTPUT_FUNC_SIGS_DESC: &str =
    "Create function signature data types for each function encountered in the DWARF debug \
     data.";

const OPTION_TRY_PACK_STRUCTS: &str = "Try To Pack Structs";
const OPTION_TRY_PACK_STRUCTS_DESC: &str = "Try to pack structure/union data types.";

const OPTION_IMPORT_LOCAL_VARS: &str = "Import Local Variable Info";
const OPTION_IMPORT_LOCAL_VARS_DESC: &str =
    "Import local variable information from DWARF and attempt to create Ghidra local variables.";

const OPTION_IGNORE_PARAM_STORAGE: &str = "Ignore Parameter Storage Info";
const OPTION_IGNORE_PARAM_STORAGE_DESC: &str =
    "Ignore any function parameter storage info specifed, allow automatic layout.";

const OPTION_DEFAULT_CC: &str = "Default Calling Convention";
const OPTION_DEFAULT_CC_DESC: &str =
    "Name of default calling convention to assign to functions (e.g. __cdecl, __stdcall, etc), or leave blank.";

const OPTION_MAX_SOURCE_ENTRY_LENGTH: &str = "Maximum Source Map Entry Length";
const OPTION_MAX_SOURCE_ENTRY_LENGTH_DESC: &str =
    "Maximum length for a source map entry.  Longer lengths will be replaced with 0";

const OPTION_COPY_EXTERNAL_DEBUG_FILE_SYMBOLS: &str = "Copy External Debug File Symbols";
const OPTION_COPY_EXTERNAL_DEBUG_FILE_SYMBOLS_DESC: &str =
    "Copies symbols (which will typically be mangled) from a found external debug file into \
     the main program.  See Edit | DWARF External Debug Config to control how those \
     external debug files are found.";

const OPTION_CHARSET_NAME: &str = "Debug Strings Charset";
const OPTION_CHARSET_NAME_DESC: &str =
    "Charset to use when decoding debug strings (symbols, filenames, etc).\n\
     Default is utf-8.  Typical values will be 'ascii' or 'utf-8'.";

const OPTION_SHOW_VARIABLE_STORAGE_INFO: &str = "Output Storage Info";
const OPTION_SHOW_VARIABLE_STORAGE_DESC: &str =
    "Add DWARF storage info for parameters and variables to EOL comments.";

const OPTION_MACRO_ENUM_NAME: &str = "Create Enums from Macros";
const OPTION_MACRO_ENUM_DESC: &str =
    "Controls which DWARF macro info entries are used to create enums";

//==================================================================================================
// Old Option Names - Should stick around for multiple major versions after 10.2
//==================================================================================================

const OPTION_IMPORT_DATATYPES_OLD: &str = "Import data types";
const OPTION_IMPORT_FUNCS_OLD: &str = "Import functions";
const OPTION_OUTPUT_SOURCE_INFO_OLD: &str = "Output Source info";
const OPTION_OUTPUT_DWARF_DIE_INFO_OLD: &str = "Output DWARF DIE info";
const OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_OLD: &str = "Lexical block comments";
const OPTION_OUTPUT_INLINE_FUNC_COMMENTS_OLD: &str = "Inlined functions comments";
const OPTION_OUTPUT_FUNC_SIGS_OLD: &str = "Output function signatures";

//==================================================================================================
// End Old Option Names
//==================================================================================================

/// Used to control which macro info entries are used to create enums.
///
/// Maps to `DWARFImportOptions.MacroEnumSetting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacroEnumSetting {
    None,
    IgnoreCommandLine,
    All,
}

impl MacroEnumSetting {
    /// The value a fresh [`DWARFImportOptions`] starts with, matching the Java
    /// `OPTION_DEFAULT_MACRO_ENUM_SETTING` constant.
    pub const DEFAULT: MacroEnumSetting = MacroEnumSetting::IgnoreCommandLine;
}

impl Default for MacroEnumSetting {
    fn default() -> Self {
        MacroEnumSetting::DEFAULT
    }
}

impl fmt::Display for MacroEnumSetting {
    /// Renders the Java enum constant name, which is what `Enum.toString()` (and therefore the
    /// stored option value) produces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MacroEnumSetting::None => "NONE",
            MacroEnumSetting::IgnoreCommandLine => "IGNORE_COMMAND_LINE",
            MacroEnumSetting::All => "ALL",
        };
        f.write_str(name)
    }
}

/// Import options exposed by the DWARF analyzer.
///
/// Maps to `ghidra.app.util.bin.format.dwarf.DWARFImportOptions`. The Java class is a plain
/// mutable option holder with a getter/setter pair per field, so the fields are public here;
/// where the Java accessor name differs from the field name it is noted in the field's doc
/// comment. The two values with extra behavior ([`Self::set_max_source_map_entry_length`] clamps
/// negatives, [`Self::get_charset`] falls back to a default) keep their methods.
pub struct DWARFImportOptions {
    /// Handles migrating values stored under this analyzer's pre-10.2 option names.
    pub options_updater: AnalysisOptionsUpdater,

    /// Tag data types and functions with their source code location (ie. filename : line
    /// number) if the information is present in the DWARF record.
    ///
    /// Java accessors: `isOutputSourceLocationInfo` / `setOutputSourceLocationInfo`.
    pub output_dwarf_location_info: bool,

    /// Tag data types and functions with their DWARF DIE record number.
    ///
    /// Java accessors: `isOutputDIEInfo` / `setOutputDIEInfo`.
    pub output_dwarf_die_info: bool,

    /// Skip creating a typedef if its dest has the same name.
    pub elide_typedefs_with_same_name: bool,

    /// Turn on/off the import of data types.
    pub import_data_types: bool,

    /// Turn on/off the import of funcs.
    pub import_funcs: bool,

    /// Tag inlined-functions with comments.
    pub output_inline_func_comments: bool,

    /// Tag lexical blocks with Ghidra comments.
    pub output_lexical_block_comments: bool,

    /// Copy anonymous types into a structure's "namespace" `CategoryPath`, giving that anonymous
    /// type a new name based on the structure's field's name.
    pub copy_rename_anon_types: bool,

    /// Create function signature data types for each function definition found in the DWARF
    /// debug data.
    pub create_func_signatures: bool,

    /// Organize imported datatypes into sub-folders based on their source file name.
    pub organize_types_by_source_file: bool,

    /// Enable packing on structures/unions created during the DWARF import. If packing would
    /// change the structure's details, packing is left disabled.
    ///
    /// Java setter: `setTryPackDataTypes`.
    pub try_pack_structs: bool,

    /// Recognize named base types that have an explicit size in the name (eg "int32_t") and use
    /// statically sized data types instead of compiler-dependent data types.
    pub special_case_sized_base_types: bool,

    /// Import local variable info from DWARF.
    pub import_local_variables: bool,

    /// Use bookmarks to record import problems.
    pub use_bookmarks: bool,

    /// Store source map info from DWARF in the Program.
    pub output_source_line_info: bool,

    /// Ignore any function parameter storage info specified, allowing automatic layout.
    pub ignore_param_storage: bool,

    /// Name of the default calling convention to assign to functions, or blank for none.
    pub default_cc: String,

    /// Maximum length of a source map entry; a longer calculated length is replaced with 0.
    ///
    /// Java models this as a `long` that its setter clamps at 0; use
    /// [`Self::set_max_source_map_entry_length`] when the incoming value may be negative.
    pub max_source_map_entry_length: u64,

    /// Copy symbols from a found external debug file into the main program.
    pub copy_external_debug_file_symbols: bool,

    /// Name of the charset to use when decoding debug strings; blank means "use the caller's
    /// default". See [`Self::get_charset`].
    pub charset_name: String,

    /// Add DWARF storage info for parameters and variables to EOL comments.
    pub show_variable_storage_info: bool,

    /// Use the static stack frame register value instead of tracking the frame base.
    pub use_static_stack_frame_register_value: bool,

    /// Controls which macro info entries are used to create enums.
    pub macro_enum_setting: MacroEnumSetting,
}

impl DWARFImportOptions {
    /// Creates a new instance holding the Java defaults, with the pre-10.2 option name
    /// replacements registered on its [`AnalysisOptionsUpdater`].
    pub fn new() -> Self {
        let mut options_updater = AnalysisOptionsUpdater::new();
        options_updater.register_replacement(OPTION_IMPORT_DATATYPES, OPTION_IMPORT_DATATYPES_OLD);
        options_updater.register_replacement(OPTION_IMPORT_FUNCS, OPTION_IMPORT_FUNCS_OLD);
        options_updater
            .register_replacement(OPTION_OUTPUT_SOURCE_INFO, OPTION_OUTPUT_SOURCE_INFO_OLD);
        options_updater
            .register_replacement(OPTION_OUTPUT_DWARF_DIE_INFO, OPTION_OUTPUT_DWARF_DIE_INFO_OLD);
        options_updater.register_replacement(
            OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
            OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_OLD,
        );
        options_updater.register_replacement(
            OPTION_OUTPUT_INLINE_FUNC_COMMENTS,
            OPTION_OUTPUT_INLINE_FUNC_COMMENTS_OLD,
        );
        options_updater.register_replacement(OPTION_OUTPUT_FUNC_SIGS, OPTION_OUTPUT_FUNC_SIGS_OLD);

        DWARFImportOptions {
            options_updater,
            output_dwarf_location_info: false,
            output_dwarf_die_info: false,
            elide_typedefs_with_same_name: true,
            import_data_types: true,
            import_funcs: true,
            output_inline_func_comments: false,
            output_lexical_block_comments: false,
            copy_rename_anon_types: true,
            create_func_signatures: true,
            organize_types_by_source_file: true,
            try_pack_structs: true,
            special_case_sized_base_types: true,
            import_local_variables: true,
            use_bookmarks: true,
            output_source_line_info: true,
            ignore_param_storage: false,
            default_cc: String::new(),
            max_source_map_entry_length: 2000,
            copy_external_debug_file_symbols: true,
            charset_name: String::new(),
            show_variable_storage_info: false,
            use_static_stack_frame_register_value: true,
            macro_enum_setting: MacroEnumSetting::DEFAULT,
        }
    }

    /// Sets the maximum length of a source map entry, clamping negative lengths to 0.
    ///
    /// Mirrors `DWARFImportOptions.setMaxSourceMapEntryLength(long)`.
    pub fn set_max_source_map_entry_length(&mut self, max_length: i64) {
        self.max_source_map_entry_length = max_length.max(0) as u64;
    }

    /// Returns the configured charset name, or `default_charset` if none was configured.
    ///
    /// Mirrors `DWARFImportOptions.getCharset(Charset)`. Charsets are identified by name in this
    /// crate (see `DataTypeWithCharset::get_charset_name`), so there is no registry to reject an
    /// unsupported name against; a blank name falls back to the default just as it does in Java.
    pub fn get_charset(&self, default_charset: &str) -> String {
        if self.charset_name.trim().is_empty() {
            default_charset.to_string()
        } else {
            self.charset_name.clone()
        }
    }

    /// Registers this analyzer's options and their current values as the defaults.
    ///
    /// Mirrors `DWARFImportOptions.registerOptions(Options)`; see
    /// [`Analyzer::register_options`](crate::app::services::analyzer::Analyzer::register_options).
    pub fn register_options(&self, options: &mut dyn Options) {
        options.register_option(
            OPTION_IMPORT_DATATYPES,
            Box::new(self.import_data_types),
            None,
            OPTION_IMPORT_DATATYPES_DESC,
        );

        options.register_option(
            OPTION_IMPORT_FUNCS,
            Box::new(self.import_funcs),
            None,
            OPTION_IMPORT_FUNCS_DESC,
        );

        options.register_option(
            OPTION_OUTPUT_DWARF_DIE_INFO,
            Box::new(self.output_dwarf_die_info),
            None,
            OPTION_OUTPUT_DWARF_DIE_INFO_DESC,
        );

        options.register_option(
            OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
            Box::new(self.output_lexical_block_comments),
            None,
            OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC,
        );

        options.register_option(
            OPTION_OUTPUT_INLINE_FUNC_COMMENTS,
            Box::new(self.output_inline_func_comments),
            None,
            OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC,
        );

        options.register_option(
            OPTION_OUTPUT_SOURCE_INFO,
            Box::new(self.output_dwarf_location_info),
            None,
            OPTION_OUTPUT_SOURCE_INFO_DESC,
        );

        options.register_option(
            OPTION_OUTPUT_FUNC_SIGS,
            Box::new(self.create_func_signatures),
            None,
            OPTION_OUTPUT_FUNC_SIGS_DESC,
        );

        options.register_option(
            OPTION_TRY_PACK_STRUCTS,
            Box::new(self.try_pack_structs),
            None,
            OPTION_TRY_PACK_STRUCTS_DESC,
        );

        options.register_option(
            OPTION_IMPORT_LOCAL_VARS,
            Box::new(self.import_local_variables),
            None,
            OPTION_IMPORT_LOCAL_VARS_DESC,
        );

        options.register_option(
            OPTION_SOURCE_LINEINFO,
            Box::new(self.output_source_line_info),
            None,
            OPTION_SOURCE_LINEINFO_DESC,
        );

        options.register_option(
            OPTION_IGNORE_PARAM_STORAGE,
            Box::new(self.ignore_param_storage),
            None,
            OPTION_IGNORE_PARAM_STORAGE_DESC,
        );

        options.register_option(
            OPTION_DEFAULT_CC,
            Box::new(self.default_cc.clone()),
            None,
            OPTION_DEFAULT_CC_DESC,
        );
        options.register_option(
            OPTION_MAX_SOURCE_ENTRY_LENGTH,
            Box::new(self.max_source_map_entry_length as i64),
            None,
            OPTION_MAX_SOURCE_ENTRY_LENGTH_DESC,
        );

        options.register_option(
            OPTION_COPY_EXTERNAL_DEBUG_FILE_SYMBOLS,
            Box::new(self.copy_external_debug_file_symbols),
            None,
            OPTION_COPY_EXTERNAL_DEBUG_FILE_SYMBOLS_DESC,
        );

        options.register_option(
            OPTION_CHARSET_NAME,
            Box::new(self.charset_name.clone()),
            None,
            OPTION_CHARSET_NAME_DESC,
        );

        options.register_option(
            OPTION_SHOW_VARIABLE_STORAGE_INFO,
            Box::new(self.show_variable_storage_info),
            None,
            OPTION_SHOW_VARIABLE_STORAGE_DESC,
        );

        options.register_option(
            OPTION_MACRO_ENUM_NAME,
            Box::new(self.macro_enum_setting),
            None,
            OPTION_MACRO_ENUM_DESC,
        );
    }

    /// Re-reads every option value, leaving the current value in place for any option the
    /// supplied [`Options`] does not hold.
    ///
    /// Mirrors `DWARFImportOptions.optionsChanged(Options)`; see
    /// [`Analyzer::options_changed`](crate::app::services::analyzer::Analyzer::options_changed).
    pub fn options_changed(&mut self, options: &dyn Options) {
        self.output_dwarf_die_info =
            options.get_boolean(OPTION_OUTPUT_DWARF_DIE_INFO, self.output_dwarf_die_info);
        self.output_dwarf_location_info =
            options.get_boolean(OPTION_OUTPUT_SOURCE_INFO, self.output_dwarf_location_info);
        self.output_lexical_block_comments = options.get_boolean(
            OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
            self.output_lexical_block_comments,
        );
        self.output_inline_func_comments = options
            .get_boolean(OPTION_OUTPUT_INLINE_FUNC_COMMENTS, self.output_inline_func_comments);
        self.import_data_types =
            options.get_boolean(OPTION_IMPORT_DATATYPES, self.import_data_types);
        self.import_funcs = options.get_boolean(OPTION_IMPORT_FUNCS, self.import_funcs);
        self.create_func_signatures =
            options.get_boolean(OPTION_OUTPUT_FUNC_SIGS, self.create_func_signatures);
        self.try_pack_structs =
            options.get_boolean(OPTION_TRY_PACK_STRUCTS, self.try_pack_structs);
        self.import_local_variables =
            options.get_boolean(OPTION_IMPORT_LOCAL_VARS, self.import_local_variables);
        self.output_source_line_info =
            options.get_boolean(OPTION_SOURCE_LINEINFO, self.output_source_line_info);
        self.ignore_param_storage =
            options.get_boolean(OPTION_IGNORE_PARAM_STORAGE, self.ignore_param_storage);
        self.default_cc = options.get_string(OPTION_DEFAULT_CC, &self.default_cc);
        let max_length = options.get_long(
            OPTION_MAX_SOURCE_ENTRY_LENGTH,
            self.max_source_map_entry_length as i64,
        );
        self.set_max_source_map_entry_length(max_length);
        self.copy_external_debug_file_symbols = options.get_boolean(
            OPTION_COPY_EXTERNAL_DEBUG_FILE_SYMBOLS,
            self.copy_external_debug_file_symbols,
        );
        self.charset_name = options.get_string(OPTION_CHARSET_NAME, &self.charset_name);
        self.show_variable_storage_info = options
            .get_boolean(OPTION_SHOW_VARIABLE_STORAGE_INFO, self.show_variable_storage_info);
        // `Options::get_enum` is generic and therefore unavailable through `dyn Options`, so the
        // stored enum object is fetched and downcast instead.
        self.macro_enum_setting = options
            .get_object(OPTION_MACRO_ENUM_NAME, Box::new(self.macro_enum_setting))
            .downcast::<MacroEnumSetting>()
            .map(|setting| *setting)
            .unwrap_or(self.macro_enum_setting);
    }
}

impl Default for DWARFImportOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    /// A minimal [`Options`] mock: `register_option` records what was registered, and the getters
    /// serve whatever values a test seeded.
    #[derive(Default)]
    struct MapOptions {
        registered: Vec<(String, String)>,
        booleans: HashMap<String, bool>,
        strings: HashMap<String, String>,
        longs: HashMap<String, i64>,
        objects: HashMap<String, MacroEnumSetting>,
    }

    impl MapOptions {
        /// Renders a registered default value the way a test can assert on it, regardless of
        /// which concrete type the caller boxed.
        fn describe(value: &dyn Any) -> String {
            if let Some(b) = value.downcast_ref::<bool>() {
                return b.to_string();
            }
            if let Some(s) = value.downcast_ref::<String>() {
                return format!("{:?}", s);
            }
            if let Some(n) = value.downcast_ref::<i64>() {
                return n.to_string();
            }
            if let Some(setting) = value.downcast_ref::<MacroEnumSetting>() {
                return setting.to_string();
            }
            "<unknown>".to_string()
        }

        fn registered_default(&self, option_name: &str) -> Option<&str> {
            self.registered
                .iter()
                .find(|(name, _)| name == option_name)
                .map(|(_, value)| value.as_str())
        }
    }

    impl Options for MapOptions {
        fn register_option(
            &mut self,
            option_name: &str,
            default_value: Box<dyn Any>,
            _help: Option<Box<dyn crate::framework::seam_stubs::HelpLocation>>,
            _description: &str,
        ) {
            self.registered
                .push((option_name.to_string(), Self::describe(default_value.as_ref())));
        }

        fn get_boolean(&self, option_name: &str, default_value: bool) -> bool {
            *self.booleans.get(option_name).unwrap_or(&default_value)
        }

        fn get_string(&self, option_name: &str, default_value: &str) -> String {
            self.strings
                .get(option_name)
                .cloned()
                .unwrap_or_else(|| default_value.to_string())
        }

        fn get_long(&self, option_name: &str, default_value: i64) -> i64 {
            *self.longs.get(option_name).unwrap_or(&default_value)
        }

        fn get_object(&self, option_name: &str, default_value: Box<dyn Any>) -> Box<dyn Any> {
            match self.objects.get(option_name) {
                Some(setting) => Box::new(*setting),
                None => default_value,
            }
        }
    }

    #[test]
    fn defaults_match_java_field_initializers() {
        let options = DWARFImportOptions::new();

        assert!(!options.output_dwarf_location_info);
        assert!(!options.output_dwarf_die_info);
        assert!(options.elide_typedefs_with_same_name);
        assert!(options.import_data_types);
        assert!(options.import_funcs);
        assert!(!options.output_inline_func_comments);
        assert!(!options.output_lexical_block_comments);
        assert!(options.copy_rename_anon_types);
        assert!(options.create_func_signatures);
        assert!(options.organize_types_by_source_file);
        assert!(options.try_pack_structs);
        assert!(options.special_case_sized_base_types);
        assert!(options.import_local_variables);
        assert!(options.use_bookmarks);
        assert!(options.output_source_line_info);
        assert!(!options.ignore_param_storage);
        assert_eq!(options.default_cc, "");
        assert_eq!(options.max_source_map_entry_length, 2000);
        assert!(options.copy_external_debug_file_symbols);
        assert_eq!(options.charset_name, "");
        assert!(!options.show_variable_storage_info);
        assert!(options.use_static_stack_frame_register_value);
        assert_eq!(options.macro_enum_setting, MacroEnumSetting::IgnoreCommandLine);
    }

    #[test]
    fn constructor_registers_the_seven_old_option_names() {
        let options = DWARFImportOptions::new();

        let mut pairs: Vec<(String, String)> = options
            .options_updater
            .get_replaceable_options()
            .iter()
            .map(|option| (option.get_new_name().to_string(), option.get_old_name().to_string()))
            .collect();
        pairs.sort();

        let mut expected = vec![
            ("Import Data Types".to_string(), "Import data types".to_string()),
            ("Import Functions".to_string(), "Import functions".to_string()),
            ("Output Source Info".to_string(), "Output Source info".to_string()),
            ("Output DWARF DIE Info".to_string(), "Output DWARF DIE info".to_string()),
            ("Add Lexical Block Comments".to_string(), "Lexical block comments".to_string()),
            (
                "Add Inlined Functions Comments".to_string(),
                "Inlined functions comments".to_string(),
            ),
            ("Create Function Signatures".to_string(), "Output function signatures".to_string()),
        ];
        expected.sort();

        assert_eq!(pairs, expected);
    }

    #[test]
    fn set_max_source_map_entry_length_clamps_negatives_to_zero() {
        let mut options = DWARFImportOptions::new();

        options.set_max_source_map_entry_length(1234);
        assert_eq!(options.max_source_map_entry_length, 1234);

        options.set_max_source_map_entry_length(-1);
        assert_eq!(options.max_source_map_entry_length, 0);
    }

    #[test]
    fn get_charset_falls_back_to_default_when_name_blank() {
        let mut options = DWARFImportOptions::new();
        assert_eq!(options.get_charset("UTF-8"), "UTF-8");

        options.charset_name = "   ".to_string();
        assert_eq!(options.get_charset("UTF-8"), "UTF-8");

        options.charset_name = "US-ASCII".to_string();
        assert_eq!(options.get_charset("UTF-8"), "US-ASCII");
    }

    #[test]
    fn macro_enum_setting_renders_java_constant_names() {
        assert_eq!(MacroEnumSetting::None.to_string(), "NONE");
        assert_eq!(MacroEnumSetting::IgnoreCommandLine.to_string(), "IGNORE_COMMAND_LINE");
        assert_eq!(MacroEnumSetting::All.to_string(), "ALL");
    }

    #[test]
    fn register_options_publishes_every_option_with_its_current_value() {
        let mut options = DWARFImportOptions::new();
        options.import_funcs = false;
        options.default_cc = "__stdcall".to_string();
        options.set_max_source_map_entry_length(-5);
        options.macro_enum_setting = MacroEnumSetting::All;

        let mut sink = MapOptions::default();
        options.register_options(&mut sink);

        assert_eq!(sink.registered.len(), 17);
        assert_eq!(sink.registered_default("Import Data Types"), Some("true"));
        assert_eq!(sink.registered_default("Import Functions"), Some("false"));
        assert_eq!(sink.registered_default("Output DWARF DIE Info"), Some("false"));
        assert_eq!(sink.registered_default("Try To Pack Structs"), Some("true"));
        assert_eq!(sink.registered_default("Default Calling Convention"), Some("\"__stdcall\""));
        assert_eq!(sink.registered_default("Maximum Source Map Entry Length"), Some("0"));
        assert_eq!(sink.registered_default("Debug Strings Charset"), Some("\"\""));
        assert_eq!(sink.registered_default("Create Enums from Macros"), Some("ALL"));
    }

    #[test]
    fn options_changed_reads_stored_values_and_keeps_current_ones_otherwise() {
        let mut sink = MapOptions::default();
        sink.booleans.insert("Output DWARF DIE Info".to_string(), true);
        sink.booleans.insert("Import Functions".to_string(), false);
        sink.booleans.insert("Output Storage Info".to_string(), true);
        sink.strings.insert("Default Calling Convention".to_string(), "__cdecl".to_string());
        sink.strings.insert("Debug Strings Charset".to_string(), "ascii".to_string());
        sink.longs.insert("Maximum Source Map Entry Length".to_string(), -3);
        sink.objects.insert("Create Enums from Macros".to_string(), MacroEnumSetting::None);

        let mut options = DWARFImportOptions::new();
        options.options_changed(&sink);

        assert!(options.output_dwarf_die_info);
        assert!(!options.import_funcs);
        assert!(options.show_variable_storage_info);
        assert_eq!(options.default_cc, "__cdecl");
        assert_eq!(options.charset_name, "ascii");
        // the setter's clamp applies to values arriving from the options store too
        assert_eq!(options.max_source_map_entry_length, 0);
        assert_eq!(options.macro_enum_setting, MacroEnumSetting::None);

        // untouched options keep the value they had before the call
        assert!(options.import_data_types);
        assert!(options.output_source_line_info);
        assert!(!options.output_dwarf_location_info);
    }

    #[test]
    fn options_changed_ignores_a_stored_value_of_the_wrong_type() {
        let mut options = DWARFImportOptions::new();
        options.macro_enum_setting = MacroEnumSetting::All;

        // no "Create Enums from Macros" object stored -> the current value survives
        options.options_changed(&MapOptions::default());

        assert_eq!(options.macro_enum_setting, MacroEnumSetting::All);
    }
}
