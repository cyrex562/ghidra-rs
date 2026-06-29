/// Describes the source of an event, allowing clients to distinguish between user-initiated
/// actions, programmatic API calls, model-driven changes, and internal-only notifications.
///
/// Corresponds to `docking.widgets.EventTrigger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventTrigger {
    /// Change initiated by a widget from a GUI action (like a mouse click).
    GuiAction,
    /// Change triggered by a programmatic API call.
    ApiCall,
    /// Change triggered by a change to the underlying data model.
    ModelChange,
    /// Change that is for internal use, not to be propagated.
    InternalOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(EventTrigger::GuiAction, EventTrigger::ApiCall);
        assert_ne!(EventTrigger::ApiCall, EventTrigger::ModelChange);
        assert_ne!(EventTrigger::ModelChange, EventTrigger::InternalOnly);
        assert_ne!(EventTrigger::GuiAction, EventTrigger::InternalOnly);
    }

    #[test]
    fn clone_and_copy() {
        let original = EventTrigger::GuiAction;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", EventTrigger::GuiAction), "GuiAction");
        assert_eq!(format!("{:?}", EventTrigger::ApiCall), "ApiCall");
        assert_eq!(format!("{:?}", EventTrigger::ModelChange), "ModelChange");
        assert_eq!(format!("{:?}", EventTrigger::InternalOnly), "InternalOnly");
    }

    #[test]
    fn equality_same_variant() {
        assert_eq!(EventTrigger::ApiCall, EventTrigger::ApiCall);
        assert_eq!(EventTrigger::ModelChange, EventTrigger::ModelChange);
    }
}
