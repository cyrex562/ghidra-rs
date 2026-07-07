use std::any::Any;
use std::fmt;

/// A pair consisting of a service interface and its implementation provider.
///
/// Mirrors `ghidra.framework.plugintool.ServiceInterfaceImplementationPair`.
/// This is a simple holder for service metadata used by the plugin system.
pub struct ServiceInterfaceImplementationPair {
    /// The service interface type, stored as a string representation.
    pub interface_class: String,
    /// The implementation provider for the service (stored as Any for flexibility).
    pub provider: Box<dyn Any + Send + Sync>,
}

impl ServiceInterfaceImplementationPair {
    /// Constructs a new pair with the given interface class name and provider.
    ///
    /// # Arguments
    /// * `interface_class` - string representation of the service interface type
    /// * `provider` - the implementation object
    pub fn new(interface_class: impl Into<String>, provider: Box<dyn Any + Send + Sync>) -> Self {
        Self {
            interface_class: interface_class.into(),
            provider,
        }
    }
}

impl fmt::Debug for ServiceInterfaceImplementationPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceInterfaceImplementationPair")
            .field("interface_class", &self.interface_class)
            .field("provider", &"<provider>")
            .finish()
    }
}

impl fmt::Display for ServiceInterfaceImplementationPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{\n  \"interface_class\": \"{}\",\n  \"provider\": \"<provider>\"\n}}", self.interface_class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_interface_class_and_provider() {
        let provider: Box<dyn Any + Send + Sync> = Box::new("test_provider");
        let pair = ServiceInterfaceImplementationPair::new("TestService", provider);
        assert_eq!(pair.interface_class, "TestService");
    }

    #[test]
    fn accepts_string_for_interface_class() {
        let provider: Box<dyn Any + Send + Sync> = Box::new(42i32);
        let pair = ServiceInterfaceImplementationPair::new(String::from("MyInterface"), provider);
        assert_eq!(pair.interface_class, "MyInterface");
    }

    #[test]
    fn accepts_str_literal_for_interface_class() {
        let provider: Box<dyn Any + Send + Sync> = Box::new("provider");
        let pair = ServiceInterfaceImplementationPair::new("Service", provider);
        assert_eq!(pair.interface_class, "Service");
    }

    #[test]
    fn debug_format_contains_interface_class() {
        let provider: Box<dyn Any + Send + Sync> = Box::new("impl");
        let pair = ServiceInterfaceImplementationPair::new("TestService", provider);
        let debug_str = format!("{:?}", pair);
        assert!(debug_str.contains("ServiceInterfaceImplementationPair"));
        assert!(debug_str.contains("TestService"));
    }

    #[test]
    fn debug_format_contains_provider_placeholder() {
        let provider: Box<dyn Any + Send + Sync> = Box::new(123);
        let pair = ServiceInterfaceImplementationPair::new("Svc", provider);
        let debug_str = format!("{:?}", pair);
        assert!(debug_str.contains("<provider>"));
    }

    #[test]
    fn display_format_produces_json_like_output() {
        let provider: Box<dyn Any + Send + Sync> = Box::new("test");
        let pair = ServiceInterfaceImplementationPair::new("Service", provider);
        let display = pair.to_string();
        assert!(display.contains("interface_class"));
        assert!(display.contains("Service"));
        assert!(display.contains("provider"));
    }

    #[test]
    fn display_contains_braces_for_json_structure() {
        let provider: Box<dyn Any + Send + Sync> = Box::new(());
        let pair = ServiceInterfaceImplementationPair::new("Iface", provider);
        let display = pair.to_string();
        assert!(display.contains("{"));
        assert!(display.contains("}"));
    }

    #[test]
    fn can_store_different_provider_types() {
        let int_provider: Box<dyn Any + Send + Sync> = Box::new(42i32);
        let pair1 = ServiceInterfaceImplementationPair::new("IntService", int_provider);
        assert_eq!(pair1.interface_class, "IntService");

        let str_provider: Box<dyn Any + Send + Sync> = Box::new("hello");
        let pair2 = ServiceInterfaceImplementationPair::new("StrService", str_provider);
        assert_eq!(pair2.interface_class, "StrService");
    }

    #[test]
    fn provider_can_be_downcast() {
        let val = 123i32;
        let provider: Box<dyn Any + Send + Sync> = Box::new(val);
        let pair = ServiceInterfaceImplementationPair::new("Service", provider);

        let downcast_val = pair.provider.downcast_ref::<i32>();
        assert_eq!(downcast_val, Some(&123i32));
    }

    #[test]
    fn interface_class_empty_string_is_valid() {
        let provider: Box<dyn Any + Send + Sync> = Box::new("");
        let pair = ServiceInterfaceImplementationPair::new("", provider);
        assert_eq!(pair.interface_class, "");
    }
}
