/// Marks a field as providing a service through the plugin-tool framework,
/// mirroring Java's `@AutoServiceProvided` runtime annotation.
///
/// In Java this annotation is placed on fields so that the plugin-tool framework
/// can automatically register the field's value as an implementation of a given
/// service interface at runtime. The required `iface()` element names the
/// `Class<?>` of the service interface being provided.
///
/// In Rust, where there is no reflective annotation system, the same metadata is
/// carried in this struct. The interface is identified by name rather than by a
/// `Class` object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AutoServiceProvided {
    /// The fully-qualified name of the service interface being provided.
    ///
    /// Corresponds to `iface()` in Java's `@AutoServiceProvided`.
    pub iface: String,
}

impl AutoServiceProvided {
    /// Creates an `AutoServiceProvided` that declares the given interface name,
    /// matching `@AutoServiceProvided(iface = SomeService.class)`.
    ///
    /// # Panics
    ///
    /// Panics when `iface` is empty.
    pub fn new(iface: impl Into<String>) -> Self {
        let iface = iface.into();
        assert!(!iface.is_empty(), "AutoServiceProvided: iface name must not be empty");
        Self { iface }
    }

    /// Returns the interface name carried by this descriptor.
    pub fn iface(&self) -> &str {
        &self.iface
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_iface_name() {
        let a = AutoServiceProvided::new("SomeService");
        assert_eq!(a.iface(), "SomeService");
    }

    #[test]
    fn iface_accessor_matches_field() {
        let a = AutoServiceProvided::new("ghidra.framework.MyService");
        assert_eq!(a.iface, a.iface().to_string());
    }

    #[test]
    fn equality_holds_for_same_iface() {
        let a = AutoServiceProvided::new("SomeService");
        let b = AutoServiceProvided::new("SomeService");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_iface() {
        let a = AutoServiceProvided::new("ServiceA");
        let b = AutoServiceProvided::new("ServiceB");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = AutoServiceProvided::new("SomeService");
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn debug_contains_iface_name() {
        let a = AutoServiceProvided::new("DebugService");
        let s = format!("{a:?}");
        assert!(s.contains("DebugService"));
    }

    #[test]
    fn hash_is_stable_for_equal_instances() {
        use std::collections::HashSet;
        let a = AutoServiceProvided::new("SomeService");
        let b = AutoServiceProvided::new("SomeService");
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    #[should_panic(expected = "iface name must not be empty")]
    fn empty_iface_name_panics() {
        AutoServiceProvided::new("");
    }
}
