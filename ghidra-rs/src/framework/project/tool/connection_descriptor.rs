use std::fmt;

/// Describes the connection between two tools for a specific event.
///
/// Used when serializing tool-set state: each `ConnectionDescriptor` records
/// which tool produces an event, which tool consumes it, and the event name
/// that represents the connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ConnectionDescriptor {
    producer_name: String,
    consumer_name: String,
    event: String,
}

impl ConnectionDescriptor {
    /// Creates a new `ConnectionDescriptor`.
    ///
    /// * `producer_name` – name of the tool that produces the event
    /// * `consumer_name` – name of the tool that consumes the event
    /// * `event` – name of the event that represents the connection
    pub fn new(
        producer_name: impl Into<String>,
        consumer_name: impl Into<String>,
        event: impl Into<String>,
    ) -> Self {
        Self {
            producer_name: producer_name.into(),
            consumer_name: consumer_name.into(),
            event: event.into(),
        }
    }

    /// Returns the name of the tool that produces the event.
    pub fn producer_name(&self) -> &str {
        &self.producer_name
    }

    /// Returns the name of the tool that consumes the event.
    pub fn consumer_name(&self) -> &str {
        &self.consumer_name
    }

    /// Returns the name of the event that connects the two tools.
    pub fn event(&self) -> &str {
        &self.event
    }
}

impl fmt::Display for ConnectionDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Producer={}, Consumer={}, Event={}",
            self.producer_name, self.consumer_name, self.event
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn cd(p: &str, c: &str, e: &str) -> ConnectionDescriptor {
        ConnectionDescriptor::new(p, c, e)
    }

    #[test]
    fn stores_fields() {
        let d = cd("ToolA", "ToolB", "DataChanged");
        assert_eq!(d.producer_name(), "ToolA");
        assert_eq!(d.consumer_name(), "ToolB");
        assert_eq!(d.event(), "DataChanged");
    }

    #[test]
    fn accepts_owned_strings() {
        let p = String::from("P");
        let c = String::from("C");
        let e = String::from("E");
        let d = ConnectionDescriptor::new(p, c, e);
        assert_eq!(d.producer_name(), "P");
        assert_eq!(d.consumer_name(), "C");
        assert_eq!(d.event(), "E");
    }

    #[test]
    fn equality_same_fields() {
        let a = cd("P", "C", "E");
        let b = cd("P", "C", "E");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_producer() {
        assert_ne!(cd("P1", "C", "E"), cd("P2", "C", "E"));
    }

    #[test]
    fn inequality_different_consumer() {
        assert_ne!(cd("P", "C1", "E"), cd("P", "C2", "E"));
    }

    #[test]
    fn inequality_different_event() {
        assert_ne!(cd("P", "C", "E1"), cd("P", "C", "E2"));
    }

    #[test]
    fn equal_instances_hash_identically() {
        let mut set = HashSet::new();
        set.insert(cd("P", "C", "E"));
        set.insert(cd("P", "C", "E"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn distinct_instances_occupy_separate_buckets() {
        let mut set = HashSet::new();
        set.insert(cd("P1", "C", "E"));
        set.insert(cd("P2", "C", "E"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn display_matches_java_format() {
        let d = cd("ToolA", "ToolB", "DataChanged");
        assert_eq!(d.to_string(), "Producer=ToolA, Consumer=ToolB, Event=DataChanged");
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = cd("P", "C", "E");
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn debug_contains_struct_name() {
        let d = cd("P", "C", "E");
        let s = format!("{d:?}");
        assert!(s.contains("ConnectionDescriptor"));
    }

    #[test]
    fn usable_as_hash_map_key() {
        use std::collections::HashMap;
        let mut map: HashMap<ConnectionDescriptor, u32> = HashMap::new();
        let key = cd("P", "C", "E");
        map.insert(key.clone(), 42);
        assert_eq!(map[&key], 42);
    }
}
