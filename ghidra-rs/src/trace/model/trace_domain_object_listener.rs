//! Port of `ghidra.trace.model.TraceDomainObjectListener`.

use crate::framework::model::{DomainObjectChangeRecord, DomainObjectChangedEvent, DomainObjectEvent, DomainObjectListener, EventType};
use crate::trace::util::typed_event_dispatcher::TypedEventDispatcher;

/// A [`TypedEventDispatcher`] that is also a [`DomainObjectListener`], routing every incoming
/// [`DomainObjectChangedEvent`] to the dispatcher's registered handlers.
///
/// Port of `ghidra.trace.model.TraceDomainObjectListener`. Java expresses this as
/// `class TraceDomainObjectListener extends TypedEventDispatcher implements
/// DomainObjectListener`; Java inheritance-for-reuse has no Rust translation, so this embeds the
/// base dispatcher and `Deref`s to it, matching this crate's base-plus-subclass composition
/// convention (see e.g. `FunctionChangeRecord`).
#[derive(Default)]
pub struct TraceDomainObjectListener {
    base: TypedEventDispatcher,
}

impl TraceDomainObjectListener {
    /// Creates a listener with no handlers registered.
    pub fn new() -> Self {
        Self {
            base: TypedEventDispatcher::new(),
        }
    }

    /// Returns a reference to the underlying [`TypedEventDispatcher`].
    pub fn base(&self) -> &TypedEventDispatcher {
        &self.base
    }
}

impl std::ops::Deref for TraceDomainObjectListener {
    type Target = TypedEventDispatcher;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl std::ops::DerefMut for TraceDomainObjectListener {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl DomainObjectListener for TraceDomainObjectListener {
    /// Mirrors `domainObjectChanged(DomainObjectChangedEvent)`.
    ///
    /// If a restored handler is registered and `ev` contains a
    /// [`DomainObjectEvent::Restored`] record, that record alone is dispatched (via
    /// [`TypedEventDispatcher::handle_change_record`], which special-cases restored records
    /// identically to Java's direct `restoredHandler.accept(rec)`) and every other record in `ev`
    /// is skipped, matching Java's early `return`. Otherwise every record is dispatched in order.
    fn domain_object_changed(&mut self, ev: &DomainObjectChangedEvent<'_>) {
        if self.base.has_restored_handler() && ev.contains(&DomainObjectEvent::Restored) {
            for rec in ev.iter() {
                if rec.event_type().get_id() == DomainObjectEvent::Restored.get_id() {
                    self.base.handle_change_record(rec);
                    return;
                }
            }
            unreachable!(
                "DomainObjectChangedEvent::contains(RESTORED) was true but no RESTORED record was found"
            );
        }
        for rec in ev.iter() {
            self.base.handle_change_record(rec);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockDomainObject;
    impl crate::framework::model::DomainObject for MockDomainObject {}

    fn record(event: DomainObjectEvent) -> DomainObjectChangeRecord {
        DomainObjectChangeRecord::new(Box::new(event))
    }

    #[test]
    fn restored_handler_runs_and_skips_other_records() {
        let mut listener = TraceDomainObjectListener::new();
        let restored_calls = Arc::new(Mutex::new(0));
        let restored_calls_clone = Arc::clone(&restored_calls);
        let saved_calls = Arc::new(Mutex::new(0));
        let saved_calls_clone = Arc::clone(&saved_calls);

        listener.listen_for_untyped(
            &DomainObjectEvent::Restored,
            Box::new(move |_rec| {
                *restored_calls_clone.lock().unwrap() += 1;
            }),
        );
        listener.listen_for_untyped(
            &DomainObjectEvent::Saved,
            Box::new(move |_rec| {
                *saved_calls_clone.lock().unwrap() += 1;
            }),
        );

        let src = MockDomainObject;
        // Java's Restored short-circuit fires even when the record precedes other pending
        // records in the same event, so the trailing Saved record must be left unhandled.
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![record(DomainObjectEvent::Restored), record(DomainObjectEvent::Saved)],
        );
        listener.domain_object_changed(&event);

        assert_eq!(*restored_calls.lock().unwrap(), 1);
        assert_eq!(*saved_calls.lock().unwrap(), 0);
    }

    #[test]
    fn dispatches_every_record_when_no_restored_handler_registered() {
        let mut listener = TraceDomainObjectListener::new();
        let saved_calls = Arc::new(Mutex::new(0));
        let saved_calls_clone = Arc::clone(&saved_calls);
        let closed_calls = Arc::new(Mutex::new(0));
        let closed_calls_clone = Arc::clone(&closed_calls);

        listener.listen_for_untyped(
            &DomainObjectEvent::Saved,
            Box::new(move |_rec| {
                *saved_calls_clone.lock().unwrap() += 1;
            }),
        );
        listener.listen_for_untyped(
            &DomainObjectEvent::Closed,
            Box::new(move |_rec| {
                *closed_calls_clone.lock().unwrap() += 1;
            }),
        );

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![record(DomainObjectEvent::Saved), record(DomainObjectEvent::Closed)],
        );
        listener.domain_object_changed(&event);

        assert_eq!(*saved_calls.lock().unwrap(), 1);
        assert_eq!(*closed_calls.lock().unwrap(), 1);
    }

    #[test]
    fn dispatches_every_record_when_restored_absent_even_with_handler_registered() {
        let mut listener = TraceDomainObjectListener::new();
        let saved_calls = Arc::new(Mutex::new(0));
        let saved_calls_clone = Arc::clone(&saved_calls);

        listener.listen_for_untyped(&DomainObjectEvent::Restored, Box::new(move |_rec| {}));
        listener.listen_for_untyped(
            &DomainObjectEvent::Saved,
            Box::new(move |_rec| {
                *saved_calls_clone.lock().unwrap() += 1;
            }),
        );

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(&src, vec![record(DomainObjectEvent::Saved)]);
        listener.domain_object_changed(&event);

        assert_eq!(*saved_calls.lock().unwrap(), 1);
    }
}
