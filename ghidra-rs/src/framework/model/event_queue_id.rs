/// Marker type identifying an event queue for a domain object.
///
/// Corresponds to `ghidra.framework.model.EventQueueID` in the original Java source.
/// The Java class is intentionally empty; this struct carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventQueueID;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_queue_id_is_copy() {
        let id = EventQueueID;
        let id2 = id;
        // Both are usable after copy — no move error.
        let _ = id;
        let _ = id2;
    }

    #[test]
    fn test_event_queue_id_equality() {
        let a = EventQueueID;
        let b = EventQueueID;
        assert_eq!(a, b);
    }

    #[test]
    fn test_event_queue_id_debug() {
        let id = EventQueueID;
        assert_eq!(format!("{:?}", id), "EventQueueID");
    }
}
