use crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType;
use std::sync::OnceLock;

/// An action that can be displayed to the user during version tracking operations.
///
/// This wraps an optional [`VtMarkupItemApplyActionType`] with a human-readable display string.
/// Instances are created via static constants that define the standard actions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DisplayableMarkupItemAction {
    display_string: String,
    action: Option<VtMarkupItemApplyActionType>,
}

impl DisplayableMarkupItemAction {
    /// Creates a new displayable action with the given string and optional apply action type.
    pub fn new(display_string: String, action: Option<VtMarkupItemApplyActionType>) -> Self {
        Self {
            display_string,
            action,
        }
    }

    /// Returns the human-readable display string for this action.
    pub fn display_string(&self) -> &str {
        &self.display_string
    }

    /// Returns the apply action type, if one is associated with this action.
    pub fn action(&self) -> Option<VtMarkupItemApplyActionType> {
        self.action
    }

    /// Action that indicates the markup item should not be applied.
    pub fn exclude_action() -> &'static Self {
        static EXCLUDE: OnceLock<DisplayableMarkupItemAction> = OnceLock::new();
        EXCLUDE.get_or_init(|| {
            DisplayableMarkupItemAction::new("Do Not Apply".to_string(), None)
        })
    }

    /// Action that replaces the destination with the source value.
    pub fn replace_action() -> &'static Self {
        static REPLACE: OnceLock<DisplayableMarkupItemAction> = OnceLock::new();
        REPLACE.get_or_init(|| {
            DisplayableMarkupItemAction::new(
                "Replace".to_string(),
                Some(VtMarkupItemApplyActionType::Replace),
            )
        })
    }

    /// Action that adds the source value to the destination (equivalent to merge).
    pub fn add_action() -> &'static Self {
        static ADD: OnceLock<DisplayableMarkupItemAction> = OnceLock::new();
        ADD.get_or_init(|| {
            DisplayableMarkupItemAction::new(
                "Add".to_string(),
                Some(VtMarkupItemApplyActionType::Add),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_action_has_no_type() {
        let action = DisplayableMarkupItemAction::exclude_action();
        assert_eq!(action.display_string(), "Do Not Apply");
        assert_eq!(action.action(), None);
    }

    #[test]
    fn replace_action_has_replace_type() {
        let action = DisplayableMarkupItemAction::replace_action();
        assert_eq!(action.display_string(), "Replace");
        assert_eq!(action.action(), Some(VtMarkupItemApplyActionType::Replace));
    }

    #[test]
    fn add_action_has_add_type() {
        let action = DisplayableMarkupItemAction::add_action();
        assert_eq!(action.display_string(), "Add");
        assert_eq!(action.action(), Some(VtMarkupItemApplyActionType::Add));
    }

    #[test]
    fn static_instances_are_singleton() {
        let exclude1 = DisplayableMarkupItemAction::exclude_action();
        let exclude2 = DisplayableMarkupItemAction::exclude_action();
        assert!(std::ptr::eq(exclude1, exclude2));

        let replace1 = DisplayableMarkupItemAction::replace_action();
        let replace2 = DisplayableMarkupItemAction::replace_action();
        assert!(std::ptr::eq(replace1, replace2));

        let add1 = DisplayableMarkupItemAction::add_action();
        let add2 = DisplayableMarkupItemAction::add_action();
        assert!(std::ptr::eq(add1, add2));
    }

    #[test]
    fn new_instance_can_be_created() {
        let custom = DisplayableMarkupItemAction::new(
            "Custom Action".to_string(),
            Some(VtMarkupItemApplyActionType::Add),
        );
        assert_eq!(custom.display_string(), "Custom Action");
        assert_eq!(custom.action(), Some(VtMarkupItemApplyActionType::Add));
    }

    #[test]
    fn custom_with_no_action() {
        let custom = DisplayableMarkupItemAction::new("No Action".to_string(), None);
        assert_eq!(custom.display_string(), "No Action");
        assert_eq!(custom.action(), None);
    }

    #[test]
    fn clone_is_independent() {
        let original = DisplayableMarkupItemAction::new(
            "Test".to_string(),
            Some(VtMarkupItemApplyActionType::Replace),
        );
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert_eq!(original.display_string(), cloned.display_string());
        assert_eq!(original.action(), cloned.action());
    }

    #[test]
    fn equality() {
        let a = DisplayableMarkupItemAction::new("Test".to_string(), None);
        let b = DisplayableMarkupItemAction::new("Test".to_string(), None);
        assert_eq!(a, b);

        let c = DisplayableMarkupItemAction::new("Different".to_string(), None);
        assert_ne!(a, c);
    }

    #[test]
    fn equality_with_action() {
        let a = DisplayableMarkupItemAction::new(
            "Replace".to_string(),
            Some(VtMarkupItemApplyActionType::Replace),
        );
        let b = DisplayableMarkupItemAction::new(
            "Replace".to_string(),
            Some(VtMarkupItemApplyActionType::Replace),
        );
        assert_eq!(a, b);

        let c = DisplayableMarkupItemAction::new(
            "Replace".to_string(),
            Some(VtMarkupItemApplyActionType::Add),
        );
        assert_ne!(a, c);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = DisplayableMarkupItemAction::new("Test".to_string(), None);
        let b = DisplayableMarkupItemAction::new("Test".to_string(), None);

        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn debug_format() {
        let action = DisplayableMarkupItemAction::new("Test".to_string(), None);
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("DisplayableMarkupItemAction"));
        assert!(debug_str.contains("Test"));
    }
}
