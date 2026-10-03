//! Port of `ghidra.util.Location`.
//!
//! Java declares this as a small marker-ish interface for "a generic location" -- something that
//! can describe itself and attempt to navigate a tool there (e.g. a code-browser address, or a
//! web page). It has no fields and no default method bodies, so it maps directly onto a Rust
//! trait with no associated data.

use crate::framework::plugintool::ServiceProvider;

/// Interface for objects that represent a generic location.
///
/// Port of `ghidra.util.Location`.
pub trait Location {
    /// Returns a displayable representation of this location.
    fn get_string_representation(&self) -> String;

    /// Returns a description for the location. This should probably describe the significance of
    /// the location. For example, if this location is from an Issue, then what is its
    /// relationship to the issue.
    fn get_description(&self) -> String;

    /// Will attempt to navigate to the location as appropriate. For example, it may use the goto
    /// service to navigate the code browser to a program and an address. Or it could launch a
    /// browser and display a web page.
    ///
    /// `provider` is a service provider that this location can use to find a service to help with
    /// navigation. Returns `true` if the navigation was successful, `false` otherwise.
    fn go(&self, provider: &dyn ServiceProvider) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::util::ServiceListener;
    use std::any::Any;

    struct FixedLocation {
        text: String,
        description: String,
        navigable: bool,
    }

    impl Location for FixedLocation {
        fn get_string_representation(&self) -> String {
            self.text.clone()
        }

        fn get_description(&self) -> String {
            self.description.clone()
        }

        fn go(&self, _provider: &dyn ServiceProvider) -> bool {
            self.navigable
        }
    }

    struct NoServicesProvider;

    impl ServiceProvider for NoServicesProvider {
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn Any + Send + Sync>> {
            None
        }

        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}

        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
    }

    #[test]
    fn exposes_string_representation_and_description() {
        let loc = FixedLocation {
            text: "0x00401000".to_string(),
            description: "entry point".to_string(),
            navigable: true,
        };
        assert_eq!(loc.get_string_representation(), "0x00401000");
        assert_eq!(loc.get_description(), "entry point");
    }

    #[test]
    fn go_reports_navigation_outcome() {
        let provider = NoServicesProvider;
        let reachable = FixedLocation {
            text: "a".into(),
            description: "b".into(),
            navigable: true,
        };
        let unreachable = FixedLocation {
            text: "a".into(),
            description: "b".into(),
            navigable: false,
        };
        assert!(reachable.go(&provider));
        assert!(!unreachable.go(&provider));
    }

    #[test]
    fn works_through_dyn_location_dispatch() {
        let loc: Box<dyn Location> = Box::new(FixedLocation {
            text: "web-page".into(),
            description: "help doc".into(),
            navigable: true,
        });
        let provider = NoServicesProvider;
        assert_eq!(loc.get_string_representation(), "web-page");
        assert!(loc.go(&provider));
    }
}
