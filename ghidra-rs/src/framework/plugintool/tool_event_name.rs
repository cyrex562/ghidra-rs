/// Carries the tool-event name for a type, mirroring Java's `@ToolEventName` runtime annotation.
///
/// In Java this annotation is placed on a class so that the tool connection dialog can display
/// a human-readable name for the event that class publishes. The single `value()` element holds
/// that name string.
///
/// In Rust, where there is no reflective annotation system, the same metadata is held in
/// this struct.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolEventName {
    value: String,
}

impl ToolEventName {
    /// Creates a `ToolEventName` with the given event name string.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into() }
    }

    /// Returns the event name, mirroring the `value()` element of `@ToolEventName`.
    pub fn value(&self) -> &str {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_value() {
        let t = ToolEventName::new("MyEvent");
        assert_eq!(t.value(), "MyEvent");
    }

    #[test]
    fn accepts_owned_string() {
        let s = String::from("OwnedEvent");
        let t = ToolEventName::new(s);
        assert_eq!(t.value(), "OwnedEvent");
    }

    #[test]
    fn empty_value_is_valid() {
        let t = ToolEventName::new("");
        assert_eq!(t.value(), "");
    }

    #[test]
    fn equality_holds_for_same_value() {
        let a = ToolEventName::new("Evt");
        let b = ToolEventName::new("Evt");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_values() {
        let a = ToolEventName::new("Alpha");
        let b = ToolEventName::new("Beta");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = ToolEventName::new("Clone");
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn copy_via_clone_is_independent() {
        let a = ToolEventName::new("Orig");
        let b = a.clone();
        assert_eq!(a.value(), b.value());
    }

    #[test]
    fn debug_contains_value() {
        let t = ToolEventName::new("DebugEvt");
        let s = format!("{t:?}");
        assert!(s.contains("DebugEvt"));
    }

    #[test]
    fn hash_is_consistent_for_equal_values() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ToolEventName::new("Same"));
        set.insert(ToolEventName::new("Same"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn distinct_values_produce_distinct_hash_entries() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ToolEventName::new("A"));
        set.insert(ToolEventName::new("B"));
        assert_eq!(set.len(), 2);
    }
}
