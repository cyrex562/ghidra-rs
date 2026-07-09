use std::collections::HashSet;

use crate::framework::model::{DomainObject, DomainObjectChangeRecord, EventType};

/// An event indicating a [`DomainObject`] has changed. This event is actually a list of
/// [`DomainObjectChangeRecord`]s.
///
/// NOTE: This object is TRANSIENT - it is only valid during the life of calls to all the
/// `DomainObjectListener`s. Listeners who need to retain any of this event information past the
/// listener call should save the `DomainObjectChangeRecord`s, which will remain valid always.
///
/// Port of `ghidra.framework.model.DomainObjectChangedEvent`. Java's `EventObject.source` field
/// (typed `Object`, populated via `super(src)`) is represented here as a borrowed
/// `&'a dyn DomainObject`, matching this event's listener-call-scoped lifetime. Java's
/// `BitSet(255)` used to index event ids is represented as a `HashSet<i32>`, since no Rust bitset
/// type is part of this port yet and a hash set gives the same O(1) `contains` semantics.
pub struct DomainObjectChangedEvent<'a> {
    source: &'a dyn DomainObject,
    sub_events: Vec<DomainObjectChangeRecord>,
    event_bits: HashSet<i32>,
}

impl<'a> DomainObjectChangedEvent<'a> {
    /// Construct a new event.
    ///
    /// # Arguments
    /// * `source` - the object which has changed
    /// * `sub_events` - a list of [`DomainObjectChangeRecord`]s
    pub fn new(source: &'a dyn DomainObject, sub_events: Vec<DomainObjectChangeRecord>) -> Self {
        let event_bits = sub_events
            .iter()
            .map(|record| record.event_type().get_id())
            .collect();
        Self {
            source,
            sub_events,
            event_bits,
        }
    }

    /// Returns the object which has changed.
    pub fn source(&self) -> &dyn DomainObject {
        self.source
    }

    /// Return the number of change records contained within this event.
    pub fn num_records(&self) -> usize {
        self.sub_events.len()
    }

    /// Returns true if this event contains a record with the given event type.
    pub fn contains(&self, event_type: &dyn EventType) -> bool {
        self.event_bits.contains(&event_type.get_id())
    }

    /// Returns true if this event contains a record with any of the given event types.
    pub fn contains_any(&self, types: &[&dyn EventType]) -> bool {
        types.iter().any(|event_type| self.contains(*event_type))
    }

    /// Returns true if this event contains a record with the given event type.
    #[deprecated(
        note = "use `contains` instead. This is here to help transition older code from using \
                integer constants for event types to the new enum way that uses enums instead."
    )]
    pub fn contains_event(&self, event_type: &dyn EventType) -> bool {
        self.contains(event_type)
    }

    /// Get the specified change record within this event.
    ///
    /// # Arguments
    /// * `i` - change record number
    pub fn get_change_record(&self, i: usize) -> &DomainObjectChangeRecord {
        &self.sub_events[i]
    }

    /// Returns an iterator over all sub-events.
    pub fn iter(&self) -> std::slice::Iter<'_, DomainObjectChangeRecord> {
        self.sub_events.iter()
    }

    /// Loops over all records in this event and calls the consumer for each record that matches
    /// the given type.
    pub fn for_each<F>(&self, event_type: &dyn EventType, mut consumer: F)
    where
        F: FnMut(&DomainObjectChangeRecord),
    {
        if !self.contains(event_type) {
            return;
        }
        for record in &self.sub_events {
            if record.event_type().get_id() == event_type.get_id() {
                consumer(record);
            }
        }
    }

    /// Finds the first record with the given event type.
    pub fn find_first(&self, event_type: &dyn EventType) -> Option<&DomainObjectChangeRecord> {
        self.sub_events
            .iter()
            .find(|record| record.event_type().get_id() == event_type.get_id())
    }
}

impl<'a, 'b> IntoIterator for &'b DomainObjectChangedEvent<'a> {
    type Item = &'b DomainObjectChangeRecord;
    type IntoIter = std::slice::Iter<'b, DomainObjectChangeRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.sub_events.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObjectEvent;

    struct MockDomainObject;
    impl DomainObject for MockDomainObject {}

    fn records() -> Vec<DomainObjectChangeRecord> {
        vec![
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved)),
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Renamed)),
            DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Renamed)),
        ]
    }

    #[test]
    fn num_records_matches_sub_events_len() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert_eq!(event.num_records(), 3);
    }

    #[test]
    fn source_returns_the_constructed_source() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert!(std::ptr::eq(
            event.source() as *const dyn DomainObject as *const (),
            &src as *const MockDomainObject as *const (),
        ));
    }

    #[test]
    fn contains_true_for_included_event_type() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert!(event.contains(&DomainObjectEvent::Saved));
        assert!(event.contains(&DomainObjectEvent::Renamed));
    }

    #[test]
    fn contains_false_for_excluded_event_type() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert!(!event.contains(&DomainObjectEvent::Closed));
    }

    #[test]
    fn contains_any_true_if_any_type_matches() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let types: &[&dyn EventType] = &[&DomainObjectEvent::Closed, &DomainObjectEvent::Saved];
        assert!(event.contains_any(types));
    }

    #[test]
    fn contains_any_false_if_no_type_matches() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let types: &[&dyn EventType] = &[&DomainObjectEvent::Closed, &DomainObjectEvent::Error];
        assert!(!event.contains_any(types));
    }

    #[test]
    #[allow(deprecated)]
    fn contains_event_matches_contains() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert_eq!(
            event.contains_event(&DomainObjectEvent::Saved),
            event.contains(&DomainObjectEvent::Saved)
        );
    }

    #[test]
    fn get_change_record_returns_record_at_index() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert_eq!(
            event.get_change_record(1).event_type().get_id(),
            DomainObjectEvent::Renamed.get_id()
        );
    }

    #[test]
    fn iter_visits_all_sub_events_in_order() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let ids: Vec<i32> = event.iter().map(|r| r.event_type().get_id()).collect();
        assert_eq!(
            ids,
            vec![
                DomainObjectEvent::Saved.get_id(),
                DomainObjectEvent::Renamed.get_id(),
                DomainObjectEvent::Renamed.get_id(),
            ]
        );
    }

    #[test]
    fn into_iterator_matches_iter() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let mut count = 0;
        for _ in &event {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn for_each_only_invokes_consumer_for_matching_records() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let mut matched = 0;
        event.for_each(&DomainObjectEvent::Renamed, |_| matched += 1);
        assert_eq!(matched, 2);
    }

    #[test]
    fn for_each_does_nothing_when_type_absent() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let mut matched = 0;
        event.for_each(&DomainObjectEvent::Closed, |_| matched += 1);
        assert_eq!(matched, 0);
    }

    #[test]
    fn find_first_returns_first_matching_record() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        let found = event.find_first(&DomainObjectEvent::Renamed);
        assert!(found.is_some());
        assert_eq!(found.unwrap().event_type().get_id(), DomainObjectEvent::Renamed.get_id());
    }

    #[test]
    fn find_first_returns_none_when_absent() {
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, records());
        assert!(event.find_first(&DomainObjectEvent::Closed).is_none());
    }
}
