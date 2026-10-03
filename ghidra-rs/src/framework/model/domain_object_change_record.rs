use std::any::Any;
use std::fmt;

use crate::framework::model::EventType;

/// Information about a change that was made to a domain object. The record is delivered as part
/// of the change notification. The event types correspond to variants defined in
/// [`DomainObjectEvent`](crate::framework::model::DomainObjectEvent) and other enums or objects
/// that implement the [`EventType`] trait.
///
/// Each event record contains the event type and optionally an old value and a new value. The old
/// value and new value meaning are determined by the event type.
///
/// Port of `ghidra.framework.model.DomainObjectChangeRecord`. Java's `oldValue`/`newValue` fields
/// are typed `Object`; since `Box<dyn Any>` has no general `Display`, [`fmt::Display`] renders the
/// event type's id in place of Java's `toString()` output for the event type.
pub struct DomainObjectChangeRecord {
    event_type: Box<dyn EventType + Send + Sync>,
    old_value: Option<Box<dyn Any + Send + Sync>>,
    new_value: Option<Box<dyn Any + Send + Sync>>,
}

impl DomainObjectChangeRecord {
    /// Construct a new `DomainObjectChangeRecord` with no old or new value.
    ///
    /// # Arguments
    /// * `event_type` - the type of event
    pub fn new(event_type: Box<dyn EventType + Send + Sync>) -> Self {
        Self::with_values(event_type, None, None)
    }

    /// Construct a new `DomainObjectChangeRecord`.
    ///
    /// # Arguments
    /// * `event_type` - the type of event
    /// * `old_value` - old value
    /// * `new_value` - new value
    pub fn with_values(
        event_type: Box<dyn EventType + Send + Sync>,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            event_type,
            old_value,
            new_value,
        }
    }

    /// Returns the event type for this change.
    pub fn event_type(&self) -> &dyn EventType {
        self.event_type.as_ref()
    }

    /// Return the old value for this event or `None` if not applicable.
    pub fn old_value(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.old_value.as_deref()
    }

    /// Return the new value for this event or `None` if not applicable.
    pub fn new_value(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.new_value.as_deref()
    }
}

impl fmt::Display for DomainObjectChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainObjectChangeRecord: event = {}", self.event_type.get_id())?;
        if self.old_value.is_some() {
            write!(f, ", old = <value>")?;
        }
        if self.new_value.is_some() {
            write!(f, ", new = <value>")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObjectEvent;

    #[test]
    fn new_has_no_old_or_new_value() {
        let record = DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved));
        assert!(record.old_value().is_none());
        assert!(record.new_value().is_none());
        assert_eq!(record.event_type().get_id(), DomainObjectEvent::Saved.get_id());
    }

    #[test]
    fn with_values_stores_old_and_new_value() {
        let record = DomainObjectChangeRecord::with_values(
            Box::new(DomainObjectEvent::PropertyChanged),
            Some(Box::new("old".to_string())),
            Some(Box::new("new".to_string())),
        );

        assert_eq!(
            record.old_value().unwrap().downcast_ref::<String>(),
            Some(&"old".to_string())
        );
        assert_eq!(
            record.new_value().unwrap().downcast_ref::<String>(),
            Some(&"new".to_string())
        );
    }

    #[test]
    fn display_includes_event_id() {
        let record = DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Closed));
        let text = format!("{}", record);
        assert!(text.contains(&DomainObjectEvent::Closed.get_id().to_string()));
        assert!(!text.contains("old ="));
        assert!(!text.contains("new ="));
    }

    #[test]
    fn display_notes_presence_of_values() {
        let record = DomainObjectChangeRecord::with_values(
            Box::new(DomainObjectEvent::Renamed),
            Some(Box::new(1i32)),
            None,
        );
        let text = format!("{}", record);
        assert!(text.contains("old ="));
        assert!(!text.contains("new ="));
    }

    #[test]
    fn old_and_new_value_support_downcast_of_any_type() {
        let record = DomainObjectChangeRecord::with_values(
            Box::new(DomainObjectEvent::FileChanged),
            Some(Box::new(42i32)),
            Some(Box::new(7.5f64)),
        );
        assert_eq!(record.old_value().unwrap().downcast_ref::<i32>(), Some(&42));
        assert_eq!(record.new_value().unwrap().downcast_ref::<f64>(), Some(&7.5));
    }
}
