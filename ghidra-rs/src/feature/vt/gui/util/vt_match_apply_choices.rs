use std::fmt;

/// Controls whether a match item is applied, replacing any existing value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplaceChoices {
    /// Do not apply the match item.
    Exclude,
    /// Replace any existing value with the source value.
    Replace,
}

impl fmt::Display for ReplaceChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplaceChoices::Exclude => write!(f, "Do Not Apply"),
            ReplaceChoices::Replace => write!(f, "Replace"),
        }
    }
}

/// Controls whether a match item is applied, with special handling for default values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplaceDefaultChoices {
    /// Do not apply the match item.
    Exclude,
    /// Always replace, regardless of whether the destination is a default value.
    ReplaceAlways,
    /// Replace only when the destination holds the default value.
    ReplaceDefaultOnly,
}

impl fmt::Display for ReplaceDefaultChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplaceDefaultChoices::Exclude => write!(f, "Do Not Apply"),
            ReplaceDefaultChoices::ReplaceAlways => write!(f, "Replace Always"),
            ReplaceDefaultChoices::ReplaceDefaultOnly => write!(f, "Replace Default Only"),
        }
    }
}

/// Controls how data types are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplaceDataChoices {
    /// Do not apply the match item.
    Exclude,
    /// Replace only the first data item at the destination.
    ReplaceFirstDataOnly,
    /// Replace all data items at the destination.
    ReplaceAllData,
    /// Replace only where the destination data is undefined.
    ReplaceUndefinedDataOnly,
}

impl fmt::Display for ReplaceDataChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplaceDataChoices::Exclude => write!(f, "Do Not Apply"),
            ReplaceDataChoices::ReplaceFirstDataOnly => write!(f, "Replace First Data Only"),
            ReplaceDataChoices::ReplaceAllData => write!(f, "Replace All Data"),
            ReplaceDataChoices::ReplaceUndefinedDataOnly => {
                write!(f, "Replace Undefined Data Only")
            }
        }
    }
}

/// Controls how comments are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommentChoices {
    /// Do not apply the comment.
    Exclude,
    /// Append the source comment to any existing comment at the destination.
    AppendToExisting,
    /// Overwrite any existing comment with the source comment.
    OverwriteExisting,
}

impl fmt::Display for CommentChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommentChoices::Exclude => write!(f, "Do Not Apply"),
            CommentChoices::AppendToExisting => write!(f, "Add To Existing"),
            CommentChoices::OverwriteExisting => write!(f, "Replace Existing"),
        }
    }
}

/// Controls how function names are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FunctionNameChoices {
    /// Do not apply the function name.
    Exclude,
    /// Add the source name as a non-primary label.
    Add,
    /// Add the source name and promote it to primary.
    AddAsPrimary,
    /// Always replace the destination name with the source name.
    ReplaceAlways,
    /// Replace the destination name only when it holds the default value.
    ReplaceDefaultOnly,
}

impl fmt::Display for FunctionNameChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionNameChoices::Exclude => write!(f, "Do Not Apply"),
            FunctionNameChoices::Add => write!(f, "Add"),
            FunctionNameChoices::AddAsPrimary => write!(f, "Add As Primary"),
            FunctionNameChoices::ReplaceAlways => write!(f, "Replace Always"),
            FunctionNameChoices::ReplaceDefaultOnly => write!(f, "Replace Default Only"),
        }
    }
}

/// Controls how labels are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LabelChoices {
    /// Do not apply any labels.
    Exclude,
    /// Add the source label without changing the primary label.
    Add,
    /// Add the source label and set it as primary.
    AddAsPrimary,
    /// Replace all destination labels with the source labels.
    ReplaceAll,
    /// Replace only the default label at the destination.
    ReplaceDefaultOnly,
}

impl fmt::Display for LabelChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelChoices::Exclude => write!(f, "Do Not Apply"),
            LabelChoices::Add => write!(f, "Add"),
            LabelChoices::AddAsPrimary => write!(f, "Add As Primary"),
            LabelChoices::ReplaceAll => write!(f, "Replace All"),
            LabelChoices::ReplaceDefaultOnly => write!(f, "Replace Default Only"),
        }
    }
}

/// Selects how parameter markup is sourced during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParameterSourceChoices {
    /// Apply the entire parameter signature as a single markup item.
    EntireParameterSignatureMarkup,
    /// Apply individual parameter items as separate markup.
    IndividualParameterMarkup,
}

impl fmt::Display for ParameterSourceChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterSourceChoices::EntireParameterSignatureMarkup => {
                write!(f, "Use Entire Parameters Signature")
            }
            ParameterSourceChoices::IndividualParameterMarkup => {
                write!(f, "Use Individual Parameter Items")
            }
        }
    }
}

/// Controls how calling conventions are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallingConventionChoices {
    /// Do not apply the calling convention.
    Exclude,
    /// Replace the calling convention only when source and destination share a language.
    SameLanguage,
    /// Replace the calling convention only when the destination has a named convention.
    NameMatch,
}

impl fmt::Display for CallingConventionChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallingConventionChoices::Exclude => write!(f, "Do Not Apply"),
            CallingConventionChoices::SameLanguage => write!(f, "Replace If Same Language"),
            CallingConventionChoices::NameMatch => {
                write!(f, "Replace If Has Named Convention")
            }
        }
    }
}

/// Controls how function signatures are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FunctionSignatureChoices {
    /// Do not apply the function signature.
    Exclude,
    /// Replace the destination signature unconditionally.
    Replace,
    /// Replace the signature only when source and destination have the same parameter count.
    WhenSameParameterCount,
}

impl fmt::Display for FunctionSignatureChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionSignatureChoices::Exclude => write!(f, "Do Not Apply"),
            FunctionSignatureChoices::Replace => write!(f, "Replace"),
            FunctionSignatureChoices::WhenSameParameterCount => {
                write!(f, "Replace When Same Parameter Count")
            }
        }
    }
}

/// Controls how parameter data types are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParameterDataTypeChoices {
    /// Do not apply the parameter data types.
    Exclude,
    /// Replace only parameters whose current type is undefined.
    ReplaceUndefinedDataTypesOnly,
    /// Replace all parameter data types.
    Replace,
}

impl fmt::Display for ParameterDataTypeChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterDataTypeChoices::Exclude => write!(f, "Do Not Apply"),
            ParameterDataTypeChoices::ReplaceUndefinedDataTypesOnly => {
                write!(f, "Replace Undefined Data Types Only")
            }
            ParameterDataTypeChoices::Replace => write!(f, "Replace"),
        }
    }
}

/// Controls how function attributes (e.g. inline, no-return) are applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FunctionAttributeChoices {
    /// Do not apply any function attributes.
    Exclude,
    /// Replace destination attributes unconditionally.
    Replace,
    /// Replace attributes only when the signature is also being replaced.
    WhenTakingSignature,
}

impl fmt::Display for FunctionAttributeChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionAttributeChoices::Exclude => write!(f, "Do Not Apply"),
            FunctionAttributeChoices::Replace => write!(f, "Replace"),
            FunctionAttributeChoices::WhenTakingSignature => {
                write!(f, "Replace When Replacing Signature")
            }
        }
    }
}

/// Controls how symbol source priority is applied during a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourcePriorityChoices {
    /// Do not apply source priority information.
    Exclude,
    /// Replace only when the destination holds the default (lowest) priority.
    ReplaceDefaultsOnly,
    /// Replace the source priority unconditionally.
    Replace,
    /// Replace and promote to the highest priority.
    PriorityReplace,
}

impl fmt::Display for SourcePriorityChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourcePriorityChoices::Exclude => write!(f, "Do Not Apply"),
            SourcePriorityChoices::ReplaceDefaultsOnly => write!(f, "Replace Default Only"),
            SourcePriorityChoices::Replace => write!(f, "Replace"),
            SourcePriorityChoices::PriorityReplace => write!(f, "Priority Replace"),
        }
    }
}

/// Determines which symbol source type is considered highest priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HighestSourcePriorityChoices {
    /// User-created symbols take priority over imported symbols.
    UserPriorityHighest,
    /// Imported symbols take priority over user-created symbols.
    ImportPriorityHighest,
}

impl fmt::Display for HighestSourcePriorityChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HighestSourcePriorityChoices::UserPriorityHighest => write!(f, "User"),
            HighestSourcePriorityChoices::ImportPriorityHighest => write!(f, "Import"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_choices_display() {
        assert_eq!(ReplaceChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(ReplaceChoices::Replace.to_string(), "Replace");
    }

    #[test]
    fn replace_default_choices_display() {
        assert_eq!(ReplaceDefaultChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(ReplaceDefaultChoices::ReplaceAlways.to_string(), "Replace Always");
        assert_eq!(ReplaceDefaultChoices::ReplaceDefaultOnly.to_string(), "Replace Default Only");
    }

    #[test]
    fn replace_data_choices_display() {
        assert_eq!(ReplaceDataChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(
            ReplaceDataChoices::ReplaceFirstDataOnly.to_string(),
            "Replace First Data Only"
        );
        assert_eq!(ReplaceDataChoices::ReplaceAllData.to_string(), "Replace All Data");
        assert_eq!(
            ReplaceDataChoices::ReplaceUndefinedDataOnly.to_string(),
            "Replace Undefined Data Only"
        );
    }

    #[test]
    fn comment_choices_display() {
        assert_eq!(CommentChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(CommentChoices::AppendToExisting.to_string(), "Add To Existing");
        assert_eq!(CommentChoices::OverwriteExisting.to_string(), "Replace Existing");
    }

    #[test]
    fn function_name_choices_display() {
        assert_eq!(FunctionNameChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(FunctionNameChoices::Add.to_string(), "Add");
        assert_eq!(FunctionNameChoices::AddAsPrimary.to_string(), "Add As Primary");
        assert_eq!(FunctionNameChoices::ReplaceAlways.to_string(), "Replace Always");
        assert_eq!(FunctionNameChoices::ReplaceDefaultOnly.to_string(), "Replace Default Only");
    }

    #[test]
    fn label_choices_display() {
        assert_eq!(LabelChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(LabelChoices::Add.to_string(), "Add");
        assert_eq!(LabelChoices::AddAsPrimary.to_string(), "Add As Primary");
        assert_eq!(LabelChoices::ReplaceAll.to_string(), "Replace All");
        assert_eq!(LabelChoices::ReplaceDefaultOnly.to_string(), "Replace Default Only");
    }

    #[test]
    fn parameter_source_choices_display() {
        assert_eq!(
            ParameterSourceChoices::EntireParameterSignatureMarkup.to_string(),
            "Use Entire Parameters Signature"
        );
        assert_eq!(
            ParameterSourceChoices::IndividualParameterMarkup.to_string(),
            "Use Individual Parameter Items"
        );
    }

    #[test]
    fn calling_convention_choices_display() {
        assert_eq!(CallingConventionChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(CallingConventionChoices::SameLanguage.to_string(), "Replace If Same Language");
        assert_eq!(
            CallingConventionChoices::NameMatch.to_string(),
            "Replace If Has Named Convention"
        );
    }

    #[test]
    fn function_signature_choices_display() {
        assert_eq!(FunctionSignatureChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(FunctionSignatureChoices::Replace.to_string(), "Replace");
        assert_eq!(
            FunctionSignatureChoices::WhenSameParameterCount.to_string(),
            "Replace When Same Parameter Count"
        );
    }

    #[test]
    fn parameter_data_type_choices_display() {
        assert_eq!(ParameterDataTypeChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(
            ParameterDataTypeChoices::ReplaceUndefinedDataTypesOnly.to_string(),
            "Replace Undefined Data Types Only"
        );
        assert_eq!(ParameterDataTypeChoices::Replace.to_string(), "Replace");
    }

    #[test]
    fn function_attribute_choices_display() {
        assert_eq!(FunctionAttributeChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(FunctionAttributeChoices::Replace.to_string(), "Replace");
        assert_eq!(
            FunctionAttributeChoices::WhenTakingSignature.to_string(),
            "Replace When Replacing Signature"
        );
    }

    #[test]
    fn source_priority_choices_display() {
        assert_eq!(SourcePriorityChoices::Exclude.to_string(), "Do Not Apply");
        assert_eq!(SourcePriorityChoices::ReplaceDefaultsOnly.to_string(), "Replace Default Only");
        assert_eq!(SourcePriorityChoices::Replace.to_string(), "Replace");
        assert_eq!(SourcePriorityChoices::PriorityReplace.to_string(), "Priority Replace");
    }

    #[test]
    fn highest_source_priority_choices_display() {
        assert_eq!(HighestSourcePriorityChoices::UserPriorityHighest.to_string(), "User");
        assert_eq!(HighestSourcePriorityChoices::ImportPriorityHighest.to_string(), "Import");
    }

    #[test]
    fn copy_and_eq() {
        let a = ReplaceChoices::Replace;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, ReplaceChoices::Exclude);
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CommentChoices::Exclude);
        set.insert(CommentChoices::AppendToExisting);
        set.insert(CommentChoices::OverwriteExisting);
        assert_eq!(set.len(), 3);
    }
}
