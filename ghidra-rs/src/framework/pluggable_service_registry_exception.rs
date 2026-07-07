/// Error raised when a pluggable service cannot be registered due to an incompatible existing instance.
///
/// Mirrors `ghidra.framework.PluggableServiceRegistryException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluggableServiceRegistryException {
    message: String,
}

impl PluggableServiceRegistryException {
    /// Creates a new exception for a service registration conflict.
    ///
    /// Constructs an error message from three service class identifiers:
    /// - `pluggable_service_class`: the class being registered for
    /// - `already_registered_class`: the class of the existing instance
    /// - `replacement_instance_class`: the class of the new instance being registered
    pub fn new(
        pluggable_service_class: impl AsRef<str>,
        already_registered_class: impl AsRef<str>,
        replacement_instance_class: impl AsRef<str>,
    ) -> Self {
        let message = format!(
            "{} already has registered instance of type {} which is not a super- or subclass of {}",
            pluggable_service_class.as_ref(),
            already_registered_class.as_ref(),
            replacement_instance_class.as_ref()
        );
        Self { message }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for PluggableServiceRegistryException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PluggableServiceRegistryException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_constructs_detailed_message() {
        let ex = PluggableServiceRegistryException::new("ServiceA", "TypeX", "TypeY");
        assert_eq!(
            ex.message(),
            "ServiceA already has registered instance of type TypeX which is not a super- or subclass of TypeY"
        );
    }

    #[test]
    fn display_formats_message() {
        let ex = PluggableServiceRegistryException::new("com.example.Service", "ExistingImpl", "NewImpl");
        let expected = "com.example.Service already has registered instance of type ExistingImpl which is not a super- or subclass of NewImpl";
        assert_eq!(ex.to_string(), expected);
    }

    #[test]
    fn accepts_owned_strings() {
        let s1 = String::from("Service1");
        let s2 = String::from("Type1");
        let s3 = String::from("Type2");
        let ex = PluggableServiceRegistryException::new(s1, s2, s3);
        assert!(ex.message().contains("Service1"));
        assert!(ex.message().contains("Type1"));
        assert!(ex.message().contains("Type2"));
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = PluggableServiceRegistryException::new("S", "A", "B");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_holds_for_same_classes() {
        let a = PluggableServiceRegistryException::new("Service", "Old", "New");
        let b = PluggableServiceRegistryException::new("Service", "Old", "New");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = PluggableServiceRegistryException::new("S1", "A", "B");
        let b = PluggableServiceRegistryException::new("S2", "A", "B");
        assert_ne!(a, b);
    }

    #[test]
    fn implements_error_trait() {
        let ex = PluggableServiceRegistryException::new("S", "A", "B");
        let _: &dyn Error = &ex;
    }

    #[test]
    fn error_source_is_none() {
        let ex = PluggableServiceRegistryException::new("S", "A", "B");
        assert!(ex.source().is_none());
    }

    #[test]
    fn debug_format_includes_message() {
        let ex = PluggableServiceRegistryException::new("ServiceClass", "RegisteredType", "ReplacementType");
        let debug_str = format!("{:?}", ex);
        assert!(debug_str.contains("PluggableServiceRegistryException"));
        assert!(debug_str.contains("ServiceClass"));
    }

    #[test]
    fn message_accessor_returns_full_message() {
        let ex = PluggableServiceRegistryException::new("MyService", "OldType", "NewType");
        let msg = ex.message();
        assert!(msg.starts_with("MyService already has"));
        assert!(msg.contains("OldType"));
        assert!(msg.contains("NewType"));
        assert!(msg.ends_with("NewType"));
    }
}
