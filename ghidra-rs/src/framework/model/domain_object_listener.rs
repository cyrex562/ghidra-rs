use crate::framework::model::domain_object_changed_event::DomainObjectChangedEvent;

/// The interface an object must support to be registered with a
/// [`DomainObject`](crate::framework::model::DomainObject) and thus be informed of changes to the
/// object.
///
/// NOTE: The `DomainObjectChangedEvent` is TRANSIENT: it is only valid during the life of calls
/// to all the `DomainObjectListener`s.
///
/// Port of `ghidra.framework.model.DomainObjectListener`.
///
/// This trait was promoted from a minimal placeholder (see `framework::seam_stubs`) that declared
/// no methods, since `DomainObject` only ever registered/unregistered the listener without
/// invoking it. `domain_object_changed` is added here as the real interface's sole method; there
/// is nothing from the placeholder to retain as a superset.
///
/// Java's `EventListener` marker superinterface has no methods of its own and is not represented
/// in Rust.
pub trait DomainObjectListener {
    /// Method called when a change is made to the domain object.
    fn domain_object_changed(&mut self, ev: &DomainObjectChangedEvent<'_>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::{DomainObject, DomainObjectChangeRecord, DomainObjectEvent};

    struct MockDomainObject;
    impl DomainObject for MockDomainObject {}

    struct RecordingListener {
        change_count: usize,
    }

    impl DomainObjectListener for RecordingListener {
        fn domain_object_changed(&mut self, _ev: &DomainObjectChangedEvent<'_>) {
            self.change_count += 1;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener = RecordingListener { change_count: 0 };
        let dyn_listener: &mut dyn DomainObjectListener = &mut listener;
        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved))],
        );
        dyn_listener.domain_object_changed(&event);
        dyn_listener.domain_object_changed(&event);
        assert_eq!(listener.change_count, 2);
    }
}
