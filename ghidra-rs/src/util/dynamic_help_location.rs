use crate::framework::seam_stubs::HelpLocation;

/// An interface that can be added to the help service that signals the client has help that
/// may change over time. The help system will query this trait to see if there is help for the
/// registered object at the time help is requested. A client may register a static help
/// location and an instance of this trait with the help system.
///
/// This can be used by a component to change the help location based on focus or mouse
/// interaction. Typically a component will have one static help location. However, if that
/// component has help for different areas within the component, then this trait allows that
/// component to return any active help. This is useful for components that perform custom
/// painting of regions, in which case that region has no object to use for adding help to the
/// help system.
///
/// Port of `ghidra.util.DynamicHelpLocation`.
pub trait DynamicHelpLocation {
    /// Returns the current help location, or `None` if there is currently no help for the
    /// client.
    fn get_active_help_location(&self) -> Option<Box<dyn HelpLocation>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticHelp;

    impl HelpLocation for StaticHelp {}

    struct MockDynamicHelp {
        has_help: bool,
    }

    impl DynamicHelpLocation for MockDynamicHelp {
        fn get_active_help_location(&self) -> Option<Box<dyn HelpLocation>> {
            if self.has_help {
                Some(Box::new(StaticHelp))
            } else {
                None
            }
        }
    }

    #[test]
    fn returns_none_when_no_active_help() {
        let mock = MockDynamicHelp { has_help: false };
        assert!(mock.get_active_help_location().is_none());
    }

    #[test]
    fn returns_some_when_active_help_present() {
        let mock = MockDynamicHelp { has_help: true };
        assert!(mock.get_active_help_location().is_some());
    }

    #[test]
    fn trait_object_dispatch() {
        let mock = MockDynamicHelp { has_help: true };
        let obj: &dyn DynamicHelpLocation = &mock;
        assert!(obj.get_active_help_location().is_some());
    }
}
