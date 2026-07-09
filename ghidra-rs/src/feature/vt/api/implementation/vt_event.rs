use std::sync::OnceLock;
use crate::framework::model::{DomainObjectEventIdGenerator, EventType};

/// Event types for version tracking operations.
/// Each variant represents a distinct event that can occur in the version tracking system.
/// Each variant is assigned a unique, compact ID suitable for use in bitsets for efficient event filtering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtEvent {
    /// A match set was added
    MatchSetAdded,
    /// A match association status changed
    AssociationStatusChanged,
    /// A match association markup status changed
    AssociationMarkupStatusChanged,
    /// A match was added
    MatchAdded,
    /// A match was deleted
    MatchDeleted,
    /// The tag for a match changed
    MatchTagChanged,
    /// An association was created
    AssociationAdded,
    /// An association was deleted
    AssociationRemoved,
    /// A markup item's status changed
    MarkupItemStatusChanged,
    /// A markup item's destination changed
    MarkupItemDestinationChanged,
    /// A tag type was created
    TagAdded,
    /// A tag type was deleted
    TagRemoved,
    /// The vote count for a match changed
    VoteCountChanged,
}

impl VtEvent {
    /// Returns the unique event id for this event type.
    /// The id is assigned once at application startup and remains constant for the run.
    /// Multiple runs may assign different ids to the same event type.
    pub fn id(self) -> i32 {
        VARIANT_IDS.get_or_init(initialize_ids)[self.variant_index()]
    }

    fn variant_index(self) -> usize {
        match self {
            VtEvent::MatchSetAdded => 0,
            VtEvent::AssociationStatusChanged => 1,
            VtEvent::AssociationMarkupStatusChanged => 2,
            VtEvent::MatchAdded => 3,
            VtEvent::MatchDeleted => 4,
            VtEvent::MatchTagChanged => 5,
            VtEvent::AssociationAdded => 6,
            VtEvent::AssociationRemoved => 7,
            VtEvent::MarkupItemStatusChanged => 8,
            VtEvent::MarkupItemDestinationChanged => 9,
            VtEvent::TagAdded => 10,
            VtEvent::TagRemoved => 11,
            VtEvent::VoteCountChanged => 12,
        }
    }
}

impl EventType for VtEvent {
    fn get_id(&self) -> i32 {
        self.id()
    }
}

static VARIANT_IDS: OnceLock<Vec<i32>> = OnceLock::new();

fn initialize_ids() -> Vec<i32> {
    (0..13).map(|_| DomainObjectEventIdGenerator::next()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_unique_ids() {
        let variants = [
            VtEvent::MatchSetAdded,
            VtEvent::AssociationStatusChanged,
            VtEvent::AssociationMarkupStatusChanged,
            VtEvent::MatchAdded,
            VtEvent::MatchDeleted,
            VtEvent::MatchTagChanged,
            VtEvent::AssociationAdded,
            VtEvent::AssociationRemoved,
            VtEvent::MarkupItemStatusChanged,
            VtEvent::MarkupItemDestinationChanged,
            VtEvent::TagAdded,
            VtEvent::TagRemoved,
            VtEvent::VoteCountChanged,
        ];

        let ids: Vec<i32> = variants.iter().map(|v| v.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "Not all variant IDs are unique");
    }

    #[test]
    fn ids_are_positive() {
        let variants = [
            VtEvent::MatchSetAdded,
            VtEvent::AssociationStatusChanged,
            VtEvent::AssociationMarkupStatusChanged,
            VtEvent::MatchAdded,
            VtEvent::MatchDeleted,
            VtEvent::MatchTagChanged,
            VtEvent::AssociationAdded,
            VtEvent::AssociationRemoved,
            VtEvent::MarkupItemStatusChanged,
            VtEvent::MarkupItemDestinationChanged,
            VtEvent::TagAdded,
            VtEvent::TagRemoved,
            VtEvent::VoteCountChanged,
        ];

        for variant in variants.iter() {
            assert!(variant.id() > 0, "Event {:?} has non-positive ID", variant);
        }
    }

    #[test]
    fn same_variant_returns_same_id() {
        let id1 = VtEvent::MatchSetAdded.id();
        let id2 = VtEvent::MatchSetAdded.id();
        assert_eq!(id1, id2, "Same variant should return same ID within a run");
    }

    #[test]
    fn all_13_variants_accounted_for() {
        let _ = [
            VtEvent::MatchSetAdded,
            VtEvent::AssociationStatusChanged,
            VtEvent::AssociationMarkupStatusChanged,
            VtEvent::MatchAdded,
            VtEvent::MatchDeleted,
            VtEvent::MatchTagChanged,
            VtEvent::AssociationAdded,
            VtEvent::AssociationRemoved,
            VtEvent::MarkupItemStatusChanged,
            VtEvent::MarkupItemDestinationChanged,
            VtEvent::TagAdded,
            VtEvent::TagRemoved,
            VtEvent::VoteCountChanged,
        ];
    }
}
