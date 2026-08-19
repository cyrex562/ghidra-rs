use crate::framework::model::{DomainObjectEventIdGenerator, EventType};
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Basic event types for all domain objects.
///
/// This enum represents the various types of events that can be fired by a domain object
/// to notify listeners of state changes. Each variant is assigned a unique, compact id
/// via [`DomainObjectEventIdGenerator::next()`] for efficient event filtering with bit sets.
///
/// Port of `ghidra.framework.model.DomainObjectEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEvent {
    /// The domain object was saved.
    Saved,
    /// The associated domain file changed (file moved, renamed, etc.).
    FileChanged,
    /// The domain object was renamed.
    Renamed,
    /// The domain object was changed; all data should be assumed stale.
    Restored,
    /// A generic property of this domain object changed.
    PropertyChanged,
    /// The domain object was closed.
    Closed,
    /// A fatal error occurred.
    Error,
}

static EVENT_IDS: Lazy<HashMap<DomainObjectEvent, i32>> = Lazy::new(|| {
    let mut map = HashMap::new();
    let events = [
        DomainObjectEvent::Saved,
        DomainObjectEvent::FileChanged,
        DomainObjectEvent::Renamed,
        DomainObjectEvent::Restored,
        DomainObjectEvent::PropertyChanged,
        DomainObjectEvent::Closed,
        DomainObjectEvent::Error,
    ];

    for event in events.iter() {
        map.insert(*event, DomainObjectEventIdGenerator::next());
    }
    map
});

impl EventType for DomainObjectEvent {
    fn get_id(&self) -> i32 {
        EVENT_IDS
            .get(self)
            .copied()
            .expect("DomainObjectEvent variant should have an id")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_events_have_unique_ids() {
        let mut ids = vec![];
        let events = [
            DomainObjectEvent::Saved,
            DomainObjectEvent::FileChanged,
            DomainObjectEvent::Renamed,
            DomainObjectEvent::Restored,
            DomainObjectEvent::PropertyChanged,
            DomainObjectEvent::Closed,
            DomainObjectEvent::Error,
        ];

        for event in events.iter() {
            ids.push(event.get_id());
        }

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();

        assert_eq!(ids.len(), sorted.len(), "All event ids should be unique");
        assert_eq!(ids.len(), 7, "Should have 7 events");
    }

    #[test]
    fn event_ids_are_positive() {
        let events = [
            DomainObjectEvent::Saved,
            DomainObjectEvent::FileChanged,
            DomainObjectEvent::Renamed,
            DomainObjectEvent::Restored,
            DomainObjectEvent::PropertyChanged,
            DomainObjectEvent::Closed,
            DomainObjectEvent::Error,
        ];

        for event in events.iter() {
            assert!(event.get_id() > 0, "Event id should be positive");
        }
    }

    #[test]
    fn same_event_has_consistent_id() {
        let event = DomainObjectEvent::Saved;
        let id1 = event.get_id();
        let id2 = event.get_id();
        assert_eq!(id1, id2, "Same event should always return same id");
    }

    #[test]
    fn different_events_have_different_ids() {
        let event1 = DomainObjectEvent::Saved;
        let event2 = DomainObjectEvent::FileChanged;
        assert_ne!(
            event1.get_id(),
            event2.get_id(),
            "Different events should have different ids"
        );
    }

    #[test]
    fn test_copy_trait() {
        let event = DomainObjectEvent::Saved;
        let event2 = event;
        let _ = event;
        let _ = event2;
    }

    #[test]
    fn test_all_variants_have_ids() {
        let variants = [
            DomainObjectEvent::Saved,
            DomainObjectEvent::FileChanged,
            DomainObjectEvent::Renamed,
            DomainObjectEvent::Restored,
            DomainObjectEvent::PropertyChanged,
            DomainObjectEvent::Closed,
            DomainObjectEvent::Error,
        ];

        for variant in variants.iter() {
            let id = variant.get_id();
            assert!(id > 0, "{:?} should have a positive id, got {}", variant, id);
        }
    }

    #[test]
    fn test_equality() {
        let saved = DomainObjectEvent::Saved;
        let saved2 = DomainObjectEvent::Saved;
        let closed = DomainObjectEvent::Closed;

        assert_eq!(saved, saved2);
        assert_ne!(saved, closed);
    }

    #[test]
    fn test_debug_format() {
        let event = DomainObjectEvent::Saved;
        let s = format!("{:?}", event);
        assert_eq!(s, "Saved");
    }
}
