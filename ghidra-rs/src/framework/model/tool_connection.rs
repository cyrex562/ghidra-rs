use crate::framework::seam_stubs::PluginTool;

/// Represents a connection between a producer tool and a consumer tool.
///
/// Port of `ghidra.framework.model.ToolConnection`.
pub trait ToolConnection {
    /// Get the tool that produces an event.
    fn get_producer(&self) -> &dyn PluginTool;

    /// Get the tool that consumes an event.
    fn get_consumer(&self) -> &dyn PluginTool;

    /// Get the list of event names that is an intersection between what the producer produces
    /// and what the consumers consumes.
    fn get_events(&self) -> Vec<String>;

    /// Connect the tools for the given event name.
    ///
    /// Returns `Err` if `event_name` is not valid for this producer/consumer pair (stands in for
    /// `IllegalArgumentException`).
    fn connect(&mut self, event_name: &str) -> Result<(), String>;

    /// Break the connection between the tools for the given event name.
    ///
    /// Returns `Err` if `event_name` is not valid for this producer/consumer pair (stands in for
    /// `IllegalArgumentException`).
    fn disconnect(&mut self, event_name: &str) -> Result<(), String>;

    /// Return whether the tools are connected for the given event name.
    fn is_connected(&self, event_name: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct MockToolConnection {
        producer: MockPluginTool,
        consumer: MockPluginTool,
        events: Vec<String>,
        connected: HashSet<String>,
    }

    impl ToolConnection for MockToolConnection {
        fn get_producer(&self) -> &dyn PluginTool {
            &self.producer
        }

        fn get_consumer(&self) -> &dyn PluginTool {
            &self.consumer
        }

        fn get_events(&self) -> Vec<String> {
            self.events.clone()
        }

        fn connect(&mut self, event_name: &str) -> Result<(), String> {
            if !self.events.iter().any(|e| e == event_name) {
                return Err(format!("invalid event name: {event_name}"));
            }
            self.connected.insert(event_name.to_string());
            Ok(())
        }

        fn disconnect(&mut self, event_name: &str) -> Result<(), String> {
            if !self.events.iter().any(|e| e == event_name) {
                return Err(format!("invalid event name: {event_name}"));
            }
            self.connected.remove(event_name);
            Ok(())
        }

        fn is_connected(&self, event_name: &str) -> bool {
            self.connected.contains(event_name)
        }
    }

    #[test]
    fn mock_tool_connection_is_object_safe_and_usable() {
        let mut conn: Box<dyn ToolConnection> = Box::new(MockToolConnection {
            producer: MockPluginTool,
            consumer: MockPluginTool,
            events: vec!["domainObjectRenamed".to_string()],
            connected: HashSet::new(),
        });

        assert_eq!(conn.get_events(), vec!["domainObjectRenamed".to_string()]);
        assert!(!conn.is_connected("domainObjectRenamed"));

        conn.connect("domainObjectRenamed").unwrap();
        assert!(conn.is_connected("domainObjectRenamed"));

        conn.disconnect("domainObjectRenamed").unwrap();
        assert!(!conn.is_connected("domainObjectRenamed"));

        assert!(conn.connect("bogusEvent").is_err());
    }
}
