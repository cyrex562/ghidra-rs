/// Types of events that can be fired through the FVEventListener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    CopySelection,
    DecrementSelection,
    DecrementAndAddSelection,
    FileChanged,
    IncrementSelection,
    IncrementAndAddSelection,
    OpenFileLocation,
    ReloadFile,
    SliderChanged,
    ScrollLockOff,
    ScrollLockOn,
    ViewportUpdate,
    ViewportUp,
    ViewportDown,
    ViewportPageUp,
    ViewportPageDown,
    ScrollHome,
    ScrollEnd,
    ScrollEnd2,
}

/// Custom events to be used in conjunction with the FVEventListener module. Users should
/// construct an event, then fire it using `FVEventListener::send(FVEvent)`.
///
/// Two items are passed along with each event:
/// - The `event_type` attribute specifies the event that is being fired.
/// - The `arg` is a generic object and can be populated with whatever is appropriate for the
///   associated event. It's up to the receiver to understand how to parse it.
#[derive(Debug)]
pub struct FVEvent {
    pub event_type: EventType,
    pub arg: Box<dyn std::any::Any + Send + Sync>,
}

impl FVEvent {
    /// Creates a new FVEvent with the specified event type and argument.
    pub fn new(event_type: EventType, arg: Box<dyn std::any::Any + Send + Sync>) -> Self {
        FVEvent { event_type, arg }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_copy_selection() {
        let event = FVEvent::new(
            EventType::CopySelection,
            Box::new("test_arg".to_string()),
        );
        assert_eq!(event.event_type, EventType::CopySelection);
    }

    #[test]
    fn test_event_type_file_changed() {
        let event = FVEvent::new(EventType::FileChanged, Box::new(42i32));
        assert_eq!(event.event_type, EventType::FileChanged);
    }

    #[test]
    fn test_all_event_types_distinct() {
        let types = [
            EventType::CopySelection,
            EventType::DecrementSelection,
            EventType::DecrementAndAddSelection,
            EventType::FileChanged,
            EventType::IncrementSelection,
            EventType::IncrementAndAddSelection,
            EventType::OpenFileLocation,
            EventType::ReloadFile,
            EventType::SliderChanged,
            EventType::ScrollLockOff,
            EventType::ScrollLockOn,
            EventType::ViewportUpdate,
            EventType::ViewportUp,
            EventType::ViewportDown,
            EventType::ViewportPageUp,
            EventType::ViewportPageDown,
            EventType::ScrollHome,
            EventType::ScrollEnd,
            EventType::ScrollEnd2,
        ];

        for i in 0..types.len() {
            for j in 0..types.len() {
                if i == j {
                    assert_eq!(types[i], types[j]);
                } else {
                    assert_ne!(types[i], types[j]);
                }
            }
        }
    }

    #[test]
    fn test_event_new_creates_event() {
        let event = FVEvent::new(
            EventType::SliderChanged,
            Box::new(100i32),
        );
        assert_eq!(event.event_type, EventType::SliderChanged);
    }

    #[test]
    fn test_event_debug_format() {
        let event = FVEvent::new(EventType::ScrollLockOn, Box::new(true));
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("ScrollLockOn"));
    }
}
