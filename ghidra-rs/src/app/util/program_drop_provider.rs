/// Represents a drag-event context, abstracting Java's `java.awt.dnd.DropTargetDragEvent`.
///
/// Holds the set of data flavors (MIME type strings) offered by the drag source so that
/// [`ProgramDropProvider`] implementations can decide whether to accept a drop.
pub struct DropTargetDragEvent {
    available_flavors: Vec<String>,
}

impl DropTargetDragEvent {
    /// Creates a new event with the given set of available data flavors.
    pub fn new(available_flavors: Vec<String>) -> Self {
        DropTargetDragEvent { available_flavors }
    }

    /// Returns `true` if the given data flavor (MIME type) is offered by the drag source.
    pub fn is_data_flavor_supported(&self, flavor: &str) -> bool {
        self.available_flavors.iter().any(|f| f == flavor)
    }

    /// Returns all data flavors available from the drag source.
    pub fn current_data_flavors(&self) -> &[String] {
        &self.available_flavors
    }
}

/// Generic trait to handle drag and drop.
///
/// Equivalent to Java's `ghidra.app.util.ProgramDropProvider` interface.
pub trait ProgramDropProvider {
    /// Returns the priority of this provider.  Higher-priority providers are chosen
    /// when multiple providers accept the same type in the same context.
    fn priority(&self) -> i32;

    /// Returns the data flavors (MIME type strings) that this drop service accepts.
    fn data_flavors(&self) -> Vec<String>;

    /// Returns `true` if this service can accept a drop in the given context.
    ///
    /// * `context` – the object where the drop will occur
    /// * `event`   – the drag event carrying the available data flavors
    fn is_drop_ok(&self, context: &dyn std::any::Any, event: &DropTargetDragEvent) -> bool;

    /// Processes the dropped data.
    ///
    /// * `context` – the object where the drop occurred
    /// * `data`    – the actual data that was dropped
    /// * `flavor`  – the selected data flavor (MIME type string)
    fn add(
        &mut self,
        context: &dyn std::any::Any,
        data: &dyn std::any::Any,
        flavor: &str,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    const FLAVOR_TEXT: &str = "text/plain";
    const FLAVOR_HTML: &str = "text/html";

    struct TestProvider {
        priority: i32,
        accepted_flavors: Vec<String>,
        added_count: usize,
    }

    impl TestProvider {
        fn new(priority: i32, flavors: &[&str]) -> Self {
            TestProvider {
                priority,
                accepted_flavors: flavors.iter().map(|s| s.to_string()).collect(),
                added_count: 0,
            }
        }
    }

    impl ProgramDropProvider for TestProvider {
        fn priority(&self) -> i32 {
            self.priority
        }

        fn data_flavors(&self) -> Vec<String> {
            self.accepted_flavors.clone()
        }

        fn is_drop_ok(&self, _context: &dyn Any, event: &DropTargetDragEvent) -> bool {
            self.accepted_flavors
                .iter()
                .any(|f| event.is_data_flavor_supported(f))
        }

        fn add(&mut self, _context: &dyn Any, _data: &dyn Any, _flavor: &str) {
            self.added_count += 1;
        }
    }

    #[test]
    fn test_drop_target_drag_event_flavor_supported() {
        let event =
            DropTargetDragEvent::new(vec![FLAVOR_TEXT.to_string(), FLAVOR_HTML.to_string()]);
        assert!(event.is_data_flavor_supported(FLAVOR_TEXT));
        assert!(event.is_data_flavor_supported(FLAVOR_HTML));
        assert!(!event.is_data_flavor_supported("application/octet-stream"));
    }

    #[test]
    fn test_drop_target_drag_event_current_flavors() {
        let event = DropTargetDragEvent::new(vec![FLAVOR_TEXT.to_string()]);
        assert_eq!(event.current_data_flavors(), &[FLAVOR_TEXT]);
    }

    #[test]
    fn test_drop_target_drag_event_empty() {
        let event = DropTargetDragEvent::new(vec![]);
        assert!(!event.is_data_flavor_supported(FLAVOR_TEXT));
        assert!(event.current_data_flavors().is_empty());
    }

    #[test]
    fn test_provider_priority() {
        let low = TestProvider::new(10, &[FLAVOR_TEXT]);
        let high = TestProvider::new(50, &[FLAVOR_TEXT]);
        assert!(high.priority() > low.priority());
    }

    #[test]
    fn test_provider_data_flavors() {
        let provider = TestProvider::new(1, &[FLAVOR_TEXT, FLAVOR_HTML]);
        let flavors = provider.data_flavors();
        assert_eq!(flavors.len(), 2);
        assert!(flavors.contains(&FLAVOR_TEXT.to_string()));
        assert!(flavors.contains(&FLAVOR_HTML.to_string()));
    }

    #[test]
    fn test_is_drop_ok_matching_flavor() {
        let provider = TestProvider::new(1, &[FLAVOR_TEXT]);
        let event = DropTargetDragEvent::new(vec![FLAVOR_TEXT.to_string()]);
        let context: String = "ctx".to_string();
        assert!(provider.is_drop_ok(&context, &event));
    }

    #[test]
    fn test_is_drop_ok_no_matching_flavor() {
        let provider = TestProvider::new(1, &[FLAVOR_TEXT]);
        let event = DropTargetDragEvent::new(vec![FLAVOR_HTML.to_string()]);
        let context: String = "ctx".to_string();
        assert!(!provider.is_drop_ok(&context, &event));
    }

    #[test]
    fn test_add_increments_count() {
        let mut provider = TestProvider::new(1, &[FLAVOR_TEXT]);
        let context: String = "ctx".to_string();
        let data: String = "hello".to_string();
        provider.add(&context, &data, FLAVOR_TEXT);
        provider.add(&context, &data, FLAVOR_TEXT);
        assert_eq!(provider.added_count, 2);
    }
}
