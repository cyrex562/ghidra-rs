//! Option name and default-value constants used by the Version Tracking accept-match,
//! apply-markup, and auto-VT correlator option groups.

use crate::feature::vt::gui::util::vt_match_apply_choices::{
    CallingConventionChoices, CommentChoices, FunctionNameChoices, FunctionSignatureChoices,
    HighestSourcePriorityChoices, LabelChoices, ParameterDataTypeChoices, ReplaceChoices,
    ReplaceDataChoices, SourcePriorityChoices,
};

// Accept Options
pub const ACCEPT_MATCH_OPTIONS_NAME: &str = "Accept Match Options";
pub const AUTO_CREATE_IMPLIED_MATCH: &str = "Accept Match Options.Auto Create Implied Matches";
pub const APPLY_FUNCTION_NAME_ON_ACCEPT: &str =
    "Accept Match Options.Automatically Apply Function Name on Accept";
pub const APPLY_DATA_NAME_ON_ACCEPT: &str =
    "Accept Match Options.Automatically Apply Data Label on Accept";

// Apply Options
pub const APPLY_MARKUP_OPTIONS_NAME: &str = "Apply Markup Options";

pub const DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS: bool = false;
pub const DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS: bool = false;
pub const DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY: bool = false;
pub const DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE: ReplaceDataChoices =
    ReplaceDataChoices::ReplaceUndefinedDataOnly;
pub const DEFAULT_OPTION_FOR_FUNCTION_NAME: FunctionNameChoices =
    FunctionNameChoices::AddAsPrimary;
pub const DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE: FunctionSignatureChoices =
    FunctionSignatureChoices::WhenSameParameterCount;
pub const DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE: ParameterDataTypeChoices =
    ParameterDataTypeChoices::ReplaceUndefinedDataTypesOnly;
pub const DEFAULT_OPTION_FOR_INLINE: ReplaceChoices = ReplaceChoices::Replace;
pub const DEFAULT_OPTION_FOR_NO_RETURN: ReplaceChoices = ReplaceChoices::Replace;
pub const DEFAULT_OPTION_FOR_CALLING_CONVENTION: CallingConventionChoices =
    CallingConventionChoices::SameLanguage;
pub const DEFAULT_OPTION_FOR_CALL_FIXUP: ReplaceChoices = ReplaceChoices::Replace;
pub const DEFAULT_OPTION_FOR_VAR_ARGS: ReplaceChoices = ReplaceChoices::Replace;
pub const DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES: ParameterDataTypeChoices =
    ParameterDataTypeChoices::ReplaceUndefinedDataTypesOnly;
pub const DEFAULT_OPTION_FOR_PARAMETER_NAMES: SourcePriorityChoices =
    SourcePriorityChoices::PriorityReplace;
pub const DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY: HighestSourcePriorityChoices =
    HighestSourcePriorityChoices::UserPriorityHighest;
pub const DEFAULT_OPTION_FOR_PARAMETER_COMMENTS: CommentChoices =
    CommentChoices::AppendToExisting;
pub const DEFAULT_OPTION_FOR_LABELS: LabelChoices = LabelChoices::Add;
pub const DEFAULT_OPTION_FOR_PLATE_COMMENTS: CommentChoices = CommentChoices::AppendToExisting;
pub const DEFAULT_OPTION_FOR_PRE_COMMENTS: CommentChoices = CommentChoices::AppendToExisting;
pub const DEFAULT_OPTION_FOR_EOL_COMMENTS: CommentChoices = CommentChoices::AppendToExisting;
pub const DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS: CommentChoices =
    CommentChoices::AppendToExisting;
pub const DEFAULT_OPTION_FOR_POST_COMMENTS: CommentChoices = CommentChoices::AppendToExisting;

pub const DEFAULT_OPTION_FOR_NAMESPACE_FUNCTIONS: bool = false;
pub const DEFAULT_OPTION_FOR_USE_EMPTY_STRUCTURES: bool = false;

pub const FUNCTION_NAME: &str = "Apply Markup Options.Function Name";
pub const FUNCTION_RETURN_TYPE: &str = "Apply Markup Options.Function Return Type";
pub const LABELS: &str = "Apply Markup Options.Labels";
pub const PLATE_COMMENT: &str = "Apply Markup Options.Plate Comment";
pub const PRE_COMMENT: &str = "Apply Markup Options.Pre Comment";
pub const END_OF_LINE_COMMENT: &str = "Apply Markup Options.End of Line Comment";
pub const REPEATABLE_COMMENT: &str = "Apply Markup Options.Repeatable Comment";
pub const POST_COMMENT: &str = "Apply Markup Options.Post Comment";
pub const DATA_MATCH_DATA_TYPE: &str = "Apply Markup Options.Data Match Data Type";
pub const FUNCTION_SIGNATURE: &str = "Apply Markup Options.Function Signature";
pub const CALLING_CONVENTION: &str = "Apply Markup Options.Function Calling Convention";
pub const INLINE: &str = "Apply Markup Options.Function Inline";
pub const NO_RETURN: &str = "Apply Markup Options.Function No Return";
pub const PARAMETER_DATA_TYPES: &str = "Apply Markup Options.Function Parameter Data Types";
pub const PARAMETER_NAMES: &str = "Apply Markup Options.Function Parameter Names";
pub const HIGHEST_NAME_PRIORITY: &str =
    "Apply Markup Options.Function Parameter Names Highest Name Priority";
pub const PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY: &str =
    "Apply Markup Options.Function Parameter Names Replace If Same Priority";
pub const PARAMETER_COMMENTS: &str = "Apply Markup Options.Function Parameter Comments";
pub const VAR_ARGS: &str = "Apply Markup Options.Function Var Args";
pub const CALL_FIXUP: &str = "Apply Markup Options.Function Call Fixup";

pub const IGNORE_INCOMPLETE_MARKUP_ITEMS: &str =
    "Apply Markup Options.Set Incomplete Markup Items To Ignored";
pub const IGNORE_EXCLUDED_MARKUP_ITEMS: &str =
    "Apply Markup Options.Set Excluded Markup Items To Ignored";

pub const DISPLAY_APPLY_MARKUP_OPTIONS: &str =
    "Apply Markup Options.Display Apply Markup Options";

pub const USE_NAMESPACE_FUNCTIONS: &str = "Apply Markup Options.Replace Namespace";

pub const USE_NAMESPACE_TOOLTIP: &str =
    "Apply the non-Global source namespace to the destination function";

pub const USE_EMPTY_COMPOSITES: &str = "Apply Markup Options.Use Emtpy Composite Types";
pub const USE_EMPTY_COMPOSITES_TOOLTIP: &str =
    "Create empty composite data types in destination function signatures";

// Auto VT Options
pub const AUTO_VT_OPTIONS_NAME: &str = "Auto Version Tracking Options";

pub const AUTO_VT_SYMBOL_CORRELATOR: &str = "Symbol Correlator Options";
pub const AUTO_VT_DATA_CORRELATOR: &str = "Data Correlator Options";
pub const AUTO_VT_EXACT_FUNCTION_CORRELATORS: &str = "Exact Function Correlators Options";
pub const AUTO_VT_DUPLICATE_FUNCTION_CORRELATOR: &str =
    "Duplicate Function Correlator Options";
pub const AUTO_VT_REFERENCE_CORRELATORS: &str = "Reference Correlators Options";
pub const AUTO_VT_IMPLIED_MATCH_CORRELATOR: &str = "Implied Match Correlator Options";

pub const CREATE_IMPLIED_MATCHES_OPTION_TEXT: &str = "Create Implied Matches";
pub const CREATE_IMPLIED_MATCHES_OPTION: &str =
    "Auto Version Tracking Options.Create Implied Matches";

pub const RUN_EXACT_DATA_OPTION_TEXT: &str = "Run Exact Data Correlator";
pub const RUN_EXACT_DATA_OPTION: &str = "Auto Version Tracking Options.Run Exact Data Correlator";

pub const RUN_EXACT_SYMBOL_OPTION_TEXT: &str = "Run Exact Symbol Correlator";
pub const RUN_EXACT_SYMBOL_OPTION: &str =
    "Auto Version Tracking Options.Run Exact Symbol Correlator";

pub const RUN_EXACT_FUNCTION_BYTES_OPTION_TEXT: &str = "Run Exact Function Bytes Correlator";
pub const RUN_EXACT_FUNCTION_BYTES_OPTION: &str =
    "Auto Version Tracking Options.Run Exact Function Bytes Correlator";

pub const RUN_EXACT_FUNCTION_INST_OPTION_TEXT: &str =
    "Run Exact Function Instructions Correlators";
pub const RUN_EXACT_FUNCTION_INST_OPTION: &str =
    "Auto Version Tracking Options.Run Exact Function Instructions Correlators";

pub const RUN_DUPE_FUNCTION_OPTION_TEXT: &str = "Run Duplicate Function Correlator";
pub const RUN_DUPE_FUNCTION_OPTION: &str =
    "Auto Version Tracking Options.Run Duplicate Function Correlator";

pub const RUN_REF_CORRELATORS_OPTION_TEXT: &str = "Run the Reference Correlators";
pub const RUN_REF_CORRELATORS_OPTION: &str =
    "Auto Version Tracking Options.Run the Reference Correlators";

pub const APPLY_IMPLIED_MATCHES_OPTION_TEXT: &str = "Apply Implied Matches";
pub const APPLY_IMPLIED_MATCHES_OPTION: &str =
    "Auto Version Tracking Options.Implied Match Correlator Options.Apply Implied Matches";

pub const MIN_VOTES_OPTION_TEXT: &str = "Minimum Votes Needed";
pub const MIN_VOTES_OPTION: &str =
    "Auto Version Tracking Options.Implied Match Correlator Options.Minimum Votes Needed";

pub const MAX_CONFLICTS_OPTION_TEXT: &str = "Maximum Conflicts Allowed";
pub const MAX_CONFLICTS_OPTION: &str =
    "Auto Version Tracking Options.Implied Match Correlator Options.Maximum Conflicts Allowed";

pub const SYMBOL_CORRELATOR_MIN_LEN_OPTION_TEXT: &str =
    "Symbol Correlator Minimum Symbol Length";
pub const SYMBOL_CORRELATOR_MIN_LEN_OPTION: &str = "Auto Version Tracking Options.Symbol Correlator Options.Symbol Correlator Minimum Symbol Length";

pub const DATA_CORRELATOR_MIN_LEN_OPTION_TEXT: &str = "Data Correlator Minimum Data Length";
pub const DATA_CORRELATOR_MIN_LEN_OPTION: &str =
    "Auto Version Tracking Options.Data Correlator Options.Data Correlator Minimum Data Length";

pub const FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT: &str =
    "Exact Function Correlators Minimum Function Length";
pub const FUNCTION_CORRELATOR_MIN_LEN_OPTION: &str = "Auto Version Tracking Options.Exact Function Correlators Options.Exact Function Correlators Minimum Function Length";

pub const DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT: &str =
    "Duplicate Function Correlator Minimum Function Length";
pub const DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION: &str = "Auto Version Tracking Options.Duplicate Function Correlator Options.Duplicate Function Correlator Minimum Function Length";

pub const REF_CORRELATOR_MIN_SCORE_OPTION_TEXT: &str = "Reference Correlators Minimum Score";
pub const REF_CORRELATOR_MIN_SCORE_OPTION: &str = "Auto Version Tracking Options.Reference Correlators Options.Reference Correlators Minimum Score";

pub const REF_CORRELATOR_MIN_CONF_OPTION_TEXT: &str =
    "Reference Correlators Minimum Confidence";
pub const REF_CORRELATOR_MIN_CONF_OPTION: &str = "Auto Version Tracking Options.Reference Correlators Options.Reference Correlators Minimum Confidence";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_option_names_are_namespaced_under_accept_match_options() {
        assert_eq!(
            AUTO_CREATE_IMPLIED_MATCH,
            "Accept Match Options.Auto Create Implied Matches"
        );
        assert_eq!(
            APPLY_FUNCTION_NAME_ON_ACCEPT,
            "Accept Match Options.Automatically Apply Function Name on Accept"
        );
        assert_eq!(
            APPLY_DATA_NAME_ON_ACCEPT,
            "Accept Match Options.Automatically Apply Data Label on Accept"
        );
    }

    #[test]
    fn apply_markup_option_names_are_namespaced_under_apply_markup_options() {
        for name in [
            FUNCTION_NAME,
            FUNCTION_RETURN_TYPE,
            LABELS,
            PLATE_COMMENT,
            PRE_COMMENT,
            END_OF_LINE_COMMENT,
            REPEATABLE_COMMENT,
            POST_COMMENT,
            DATA_MATCH_DATA_TYPE,
            FUNCTION_SIGNATURE,
            CALLING_CONVENTION,
            INLINE,
            NO_RETURN,
            PARAMETER_DATA_TYPES,
            PARAMETER_NAMES,
            HIGHEST_NAME_PRIORITY,
            PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
            PARAMETER_COMMENTS,
            VAR_ARGS,
            CALL_FIXUP,
            IGNORE_INCOMPLETE_MARKUP_ITEMS,
            IGNORE_EXCLUDED_MARKUP_ITEMS,
            DISPLAY_APPLY_MARKUP_OPTIONS,
            USE_NAMESPACE_FUNCTIONS,
            USE_EMPTY_COMPOSITES,
        ] {
            assert!(
                name.starts_with(APPLY_MARKUP_OPTIONS_NAME),
                "{name} should be namespaced under {APPLY_MARKUP_OPTIONS_NAME}"
            );
        }
    }

    #[test]
    fn use_empty_composites_preserves_original_typo() {
        assert_eq!(
            USE_EMPTY_COMPOSITES,
            "Apply Markup Options.Use Emtpy Composite Types"
        );
    }

    #[test]
    fn display_apply_markup_options_uses_options_delimiter() {
        assert_eq!(
            DISPLAY_APPLY_MARKUP_OPTIONS,
            format!(
                "{APPLY_MARKUP_OPTIONS_NAME}{}Display Apply Markup Options",
                crate::framework::options::DELIMITER
            )
        );
    }

    #[test]
    fn defaults_match_java_source() {
        assert!(!DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS);
        assert!(!DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS);
        assert!(!DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);
        assert!(!DEFAULT_OPTION_FOR_NAMESPACE_FUNCTIONS);
        assert!(!DEFAULT_OPTION_FOR_USE_EMPTY_STRUCTURES);
        assert_eq!(
            DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE,
            ReplaceDataChoices::ReplaceUndefinedDataOnly
        );
        assert_eq!(DEFAULT_OPTION_FOR_FUNCTION_NAME, FunctionNameChoices::AddAsPrimary);
        assert_eq!(
            DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE,
            FunctionSignatureChoices::WhenSameParameterCount
        );
        assert_eq!(
            DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE,
            ParameterDataTypeChoices::ReplaceUndefinedDataTypesOnly
        );
        assert_eq!(DEFAULT_OPTION_FOR_INLINE, ReplaceChoices::Replace);
        assert_eq!(DEFAULT_OPTION_FOR_NO_RETURN, ReplaceChoices::Replace);
        assert_eq!(
            DEFAULT_OPTION_FOR_CALLING_CONVENTION,
            CallingConventionChoices::SameLanguage
        );
        assert_eq!(DEFAULT_OPTION_FOR_CALL_FIXUP, ReplaceChoices::Replace);
        assert_eq!(DEFAULT_OPTION_FOR_VAR_ARGS, ReplaceChoices::Replace);
        assert_eq!(
            DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES,
            ParameterDataTypeChoices::ReplaceUndefinedDataTypesOnly
        );
        assert_eq!(DEFAULT_OPTION_FOR_PARAMETER_NAMES, SourcePriorityChoices::PriorityReplace);
        assert_eq!(
            DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY,
            HighestSourcePriorityChoices::UserPriorityHighest
        );
        assert_eq!(DEFAULT_OPTION_FOR_PARAMETER_COMMENTS, CommentChoices::AppendToExisting);
        assert_eq!(DEFAULT_OPTION_FOR_LABELS, LabelChoices::Add);
        assert_eq!(DEFAULT_OPTION_FOR_PLATE_COMMENTS, CommentChoices::AppendToExisting);
        assert_eq!(DEFAULT_OPTION_FOR_PRE_COMMENTS, CommentChoices::AppendToExisting);
        assert_eq!(DEFAULT_OPTION_FOR_EOL_COMMENTS, CommentChoices::AppendToExisting);
        assert_eq!(DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS, CommentChoices::AppendToExisting);
        assert_eq!(DEFAULT_OPTION_FOR_POST_COMMENTS, CommentChoices::AppendToExisting);
    }

    #[test]
    fn auto_vt_option_names_are_namespaced_under_auto_vt_options() {
        for name in [
            CREATE_IMPLIED_MATCHES_OPTION,
            RUN_EXACT_DATA_OPTION,
            RUN_EXACT_SYMBOL_OPTION,
            RUN_EXACT_FUNCTION_BYTES_OPTION,
            RUN_EXACT_FUNCTION_INST_OPTION,
            RUN_DUPE_FUNCTION_OPTION,
            RUN_REF_CORRELATORS_OPTION,
            APPLY_IMPLIED_MATCHES_OPTION,
            MIN_VOTES_OPTION,
            MAX_CONFLICTS_OPTION,
            SYMBOL_CORRELATOR_MIN_LEN_OPTION,
            DATA_CORRELATOR_MIN_LEN_OPTION,
            FUNCTION_CORRELATOR_MIN_LEN_OPTION,
            DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION,
            REF_CORRELATOR_MIN_SCORE_OPTION,
            REF_CORRELATOR_MIN_CONF_OPTION,
        ] {
            assert!(
                name.starts_with(AUTO_VT_OPTIONS_NAME),
                "{name} should be namespaced under {AUTO_VT_OPTIONS_NAME}"
            );
        }
    }

    #[test]
    fn implied_match_correlator_options_are_double_namespaced() {
        let prefix = format!("{AUTO_VT_OPTIONS_NAME}.{AUTO_VT_IMPLIED_MATCH_CORRELATOR}.");
        assert_eq!(
            APPLY_IMPLIED_MATCHES_OPTION,
            format!("{prefix}{APPLY_IMPLIED_MATCHES_OPTION_TEXT}")
        );
        assert_eq!(MIN_VOTES_OPTION, format!("{prefix}{MIN_VOTES_OPTION_TEXT}"));
        assert_eq!(MAX_CONFLICTS_OPTION, format!("{prefix}{MAX_CONFLICTS_OPTION_TEXT}"));
    }
}
