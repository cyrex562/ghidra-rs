use crate::framework::plugintool::PluginEvent;

/// Listener that is notified when an event is generated.
///
/// Port of `ghidra.framework.plugintool.util.PluginEventListener`, a Java listener interface.
pub trait PluginEventListener {
    /// Notification that the given plugin event was sent.
    fn event_sent(&self, event: &PluginEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        events_received: std::cell::RefCell<Vec<String>>,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                events_received: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<String> {
            self.events_received.borrow().clone()
        }
    }

    impl PluginEventListener for TestListener {
        fn event_sent(&self, event: &PluginEvent) {
            self.events_received.borrow_mut().push(event.event_name().to_string());
        }
    }

    #[test]
    fn listener_receives_event() {
        let listener = TestListener::new();
        let event = PluginEvent::new("TestSource", "TestEvent");

        listener.event_sent(&event);

        assert_eq!(listener.events(), vec!["TestEvent"]);
    }

    #[test]
    fn listener_receives_multiple_events() {
        let listener = TestListener::new();
        let event1 = PluginEvent::new("Source1", "Event1");
        let event2 = PluginEvent::new("Source2", "Event2");

        listener.event_sent(&event1);
        listener.event_sent(&event2);

        assert_eq!(listener.events(), vec!["Event1", "Event2"]);
    }

    #[test]
    fn listener_can_access_event_details() {
        let listener = TestListener::new();
        let event = PluginEvent::new("TestSource", "TestEvent");
        assert_eq!(event.source_name(), "TestSource");
        assert_eq!(event.event_name(), "TestEvent");
    }
}
