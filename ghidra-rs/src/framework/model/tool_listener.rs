use crate::framework::plugintool::PluginEvent;

/// Interface to be implemented by objects that want to receive PluginEvents.
/// Tools must be registered for a particular event to actually receive it.
///
/// Port of `ghidra.framework.model.ToolListener`.
pub trait ToolListener {
    /// This method is invoked when the registered PluginEvent event occurs.
    fn process_tool_event(&mut self, tool_event: &PluginEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockToolListener {
        event_count: usize,
        last_event_name: Option<String>,
    }

    impl ToolListener for MockToolListener {
        fn process_tool_event(&mut self, tool_event: &PluginEvent) {
            self.event_count += 1;
            self.last_event_name = Some(tool_event.event_name().to_string());
        }
    }

    #[test]
    fn listener_receives_single_event() {
        let mut listener = MockToolListener { event_count: 0, last_event_name: None };
        let event = PluginEvent::new("TestPlugin", "TestEvent");

        listener.process_tool_event(&event);

        assert_eq!(listener.event_count, 1);
        assert_eq!(listener.last_event_name, Some("TestEvent".to_string()));
    }

    #[test]
    fn listener_receives_multiple_events() {
        let mut listener = MockToolListener { event_count: 0, last_event_name: None };
        let event1 = PluginEvent::new("Plugin1", "Event1");
        let event2 = PluginEvent::new("Plugin2", "Event2");

        listener.process_tool_event(&event1);
        listener.process_tool_event(&event2);

        assert_eq!(listener.event_count, 2);
        assert_eq!(listener.last_event_name, Some("Event2".to_string()));
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener = MockToolListener { event_count: 0, last_event_name: None };
        let dyn_listener: &mut dyn ToolListener = &mut listener;
        let event = PluginEvent::new("TestPlugin", "TestEvent");

        dyn_listener.process_tool_event(&event);
        dyn_listener.process_tool_event(&event);

        assert_eq!(listener.event_count, 2);
    }
}
