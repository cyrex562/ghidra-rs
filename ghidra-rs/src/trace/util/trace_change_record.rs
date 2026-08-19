//! Port of `ghidra.trace.util.TraceChangeRecord`.
//!
//! Java declares this `class TraceChangeRecord<T, U> extends DomainObjectChangeRecord`, with the
//! affected-object type `T` and old/new-value type `U` supplied per event by the (unported)
//! `TraceEvent<T, U>` implementations in `TraceEvents`. Java erases both to `Object` at the
//! bytecode level regardless -- `getAffectedObject()`/`getOldValue()`/`getNewValue()` just cast
//! back to `T`/`U` -- and every consumer in this port so far only ever handles the wildcarded
//! `TraceChangeRecord<?, ?>`, so this port keeps that erasure explicit instead of introducing type
//! parameters nothing needs: the affected object, old value, and new value are all
//! `Box<dyn Any + Send + Sync>`, exactly like [`DomainObjectChangeRecord`]'s own old/new value
//! fields. Callers that know the concrete type downcast with `Any::downcast_ref`, mirroring the
//! Java cast.

use std::any::Any;
use std::sync::Arc;

use crate::framework::model::{DomainObjectChangeRecord, EventType};
use crate::program::model::address::AddressSpace;

/// A change record with type information relevant to traces.
///
/// Port of `ghidra.trace.util.TraceChangeRecord`.
pub struct TraceChangeRecord {
    base: DomainObjectChangeRecord,
    space: Option<Arc<AddressSpace>>,
    affected_object: Option<Box<dyn Any + Send + Sync>>,
    old_known: bool,
}

impl TraceChangeRecord {
    /// Construct a record with a known old value.
    ///
    /// Mirrors `TraceChangeRecord(TraceEvent<T, U>, AddressSpace, T, U, U)`.
    pub fn new(
        event_type: Box<dyn EventType + Send + Sync>,
        space: Option<Arc<AddressSpace>>,
        affected_object: Option<Box<dyn Any + Send + Sync>>,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            base: DomainObjectChangeRecord::with_values(event_type, old_value, new_value),
            space,
            affected_object,
            old_known: true,
        }
    }

    /// Construct a record whose old value is not known, only its new value.
    ///
    /// Mirrors `TraceChangeRecord(TraceEvent<T, U>, AddressSpace, T, U)`.
    pub fn without_old_value(
        event_type: Box<dyn EventType + Send + Sync>,
        space: Option<Arc<AddressSpace>>,
        affected_object: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            base: DomainObjectChangeRecord::with_values(event_type, None, new_value),
            space,
            affected_object,
            old_known: false,
        }
    }

    /// Construct a record that carries no old or new value.
    ///
    /// Mirrors `TraceChangeRecord(TraceEvent<T, U>, AddressSpace, T)`.
    pub fn without_values(
        event_type: Box<dyn EventType + Send + Sync>,
        space: Option<Arc<AddressSpace>>,
        affected_object: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            base: DomainObjectChangeRecord::with_values(event_type, None, None),
            space,
            affected_object,
            old_known: false,
        }
    }

    /// Construct a record with no affected object and no old or new value.
    ///
    /// Mirrors `TraceChangeRecord(TraceEvent<T, U>, AddressSpace)`.
    pub fn without_affected_object(
        event_type: Box<dyn EventType + Send + Sync>,
        space: Option<Arc<AddressSpace>>,
    ) -> Self {
        Self {
            base: DomainObjectChangeRecord::with_values(event_type, None, None),
            space,
            affected_object: None,
            old_known: false,
        }
    }

    /// Returns the event type for this change.
    ///
    /// Mirrors the inherited `DomainObjectChangeRecord.getEventType()`.
    pub fn event_type(&self) -> &dyn EventType {
        self.base.event_type()
    }

    /// The address space affected by this change, or `None` if not applicable.
    ///
    /// Mirrors `getAddressSpace()`.
    pub fn address_space(&self) -> Option<&Arc<AddressSpace>> {
        self.space.as_ref()
    }

    /// The object affected by this change, or `None` if not applicable.
    ///
    /// Mirrors `getAffectedObject()`.
    pub fn affected_object(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.affected_object.as_deref()
    }

    /// Whether the old value is known, i.e., whether this record was constructed with an explicit
    /// old value.
    ///
    /// Mirrors `isOldKnown()`.
    pub fn is_old_known(&self) -> bool {
        self.old_known
    }

    /// The value before the change, or `None` if not applicable or not known.
    ///
    /// Mirrors the overridden `getOldValue()`.
    pub fn old_value(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.base.old_value()
    }

    /// The value after the change, or `None` if not applicable.
    ///
    /// Mirrors the overridden `getNewValue()`.
    pub fn new_value(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.base.new_value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObjectEvent;
    use crate::program::model::address::AddressSpaceType;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn full_constructor_marks_old_known() {
        let record = TraceChangeRecord::new(
            Box::new(DomainObjectEvent::PropertyChanged),
            Some(space()),
            Some(Box::new(7i32)),
            Some(Box::new("old".to_string())),
            Some(Box::new("new".to_string())),
        );
        assert!(record.is_old_known());
        assert_eq!(record.affected_object().unwrap().downcast_ref::<i32>(), Some(&7));
        assert_eq!(
            record.old_value().unwrap().downcast_ref::<String>(),
            Some(&"old".to_string())
        );
        assert_eq!(
            record.new_value().unwrap().downcast_ref::<String>(),
            Some(&"new".to_string())
        );
        assert_eq!(record.address_space().unwrap().name(), "ram");
        assert_eq!(record.event_type().get_id(), DomainObjectEvent::PropertyChanged.get_id());
    }

    #[test]
    fn without_old_value_marks_old_unknown() {
        let record = TraceChangeRecord::without_old_value(
            Box::new(DomainObjectEvent::Renamed),
            None,
            Some(Box::new(1i32)),
            Some(Box::new(2i32)),
        );
        assert!(!record.is_old_known());
        assert!(record.old_value().is_none());
        assert_eq!(record.new_value().unwrap().downcast_ref::<i32>(), Some(&2));
        assert!(record.address_space().is_none());
    }

    #[test]
    fn without_values_carries_only_affected_object() {
        let record = TraceChangeRecord::without_values(
            Box::new(DomainObjectEvent::Saved),
            None,
            Some(Box::new("thread-1".to_string())),
        );
        assert!(!record.is_old_known());
        assert!(record.old_value().is_none());
        assert!(record.new_value().is_none());
        assert_eq!(
            record.affected_object().unwrap().downcast_ref::<String>(),
            Some(&"thread-1".to_string())
        );
    }

    #[test]
    fn without_affected_object_carries_neither_object_nor_values() {
        let record =
            TraceChangeRecord::without_affected_object(Box::new(DomainObjectEvent::Closed), None);
        assert!(!record.is_old_known());
        assert!(record.affected_object().is_none());
        assert!(record.address_space().is_none());
    }
}
