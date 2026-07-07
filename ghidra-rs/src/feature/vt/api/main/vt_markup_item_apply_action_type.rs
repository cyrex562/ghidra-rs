use super::vt_markup_item_status::VtMarkupItemStatus;

/// The action to apply to a markup item during version tracking operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtMarkupItemApplyActionType {
    /// Add the source value to the destination.
    Add,
    /// Add the source value as the primary value at the destination.
    AddAsPrimary,
    /// Replace the destination value only if it is a default value.
    ReplaceDefaultOnly,
    /// Always replace the destination value.
    Replace,
    /// Replace the destination value only if it won't overwrite other defined data beyond the first.
    ReplaceFirstOnly,
}

impl VtMarkupItemApplyActionType {
    /// Returns the resulting status when this action is applied.
    pub fn apply_status(&self) -> VtMarkupItemStatus {
        match self {
            Self::Add | Self::AddAsPrimary => VtMarkupItemStatus::Added,
            Self::ReplaceDefaultOnly | Self::Replace | Self::ReplaceFirstOnly => {
                VtMarkupItemStatus::Replaced
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_status() {
        assert_eq!(
            VtMarkupItemApplyActionType::Add.apply_status(),
            VtMarkupItemStatus::Added
        );
    }

    #[test]
    fn add_as_primary_status() {
        assert_eq!(
            VtMarkupItemApplyActionType::AddAsPrimary.apply_status(),
            VtMarkupItemStatus::Added
        );
    }

    #[test]
    fn replace_default_only_status() {
        assert_eq!(
            VtMarkupItemApplyActionType::ReplaceDefaultOnly.apply_status(),
            VtMarkupItemStatus::Replaced
        );
    }

    #[test]
    fn replace_status() {
        assert_eq!(
            VtMarkupItemApplyActionType::Replace.apply_status(),
            VtMarkupItemStatus::Replaced
        );
    }

    #[test]
    fn replace_first_only_status() {
        assert_eq!(
            VtMarkupItemApplyActionType::ReplaceFirstOnly.apply_status(),
            VtMarkupItemStatus::Replaced
        );
    }

    #[test]
    fn all_variants_have_status() {
        let variants = [
            VtMarkupItemApplyActionType::Add,
            VtMarkupItemApplyActionType::AddAsPrimary,
            VtMarkupItemApplyActionType::ReplaceDefaultOnly,
            VtMarkupItemApplyActionType::Replace,
            VtMarkupItemApplyActionType::ReplaceFirstOnly,
        ];
        for variant in variants {
            let status = variant.apply_status();
            assert!(
                status == VtMarkupItemStatus::Added || status == VtMarkupItemStatus::Replaced
            );
        }
    }

    #[test]
    fn copy_and_clone() {
        let a = VtMarkupItemApplyActionType::Add;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.clone(), b);
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(
            VtMarkupItemApplyActionType::Add,
            VtMarkupItemApplyActionType::AddAsPrimary
        );
        assert_ne!(
            VtMarkupItemApplyActionType::Add,
            VtMarkupItemApplyActionType::Replace
        );
        assert_ne!(
            VtMarkupItemApplyActionType::Replace,
            VtMarkupItemApplyActionType::ReplaceFirstOnly
        );
    }
}
