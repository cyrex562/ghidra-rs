//! Port of `ghidra.trace.util.TypedEventDispatcher`.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::framework::model::{DomainObjectChangeRecord, DomainObjectEvent, EventType, RecordConsumer};
use crate::program::model::address::AddressSpace;
use crate::trace::seam_stubs::TraceEvent;
use crate::trace::util::trace_change_record::TraceChangeRecord;

/// A handler for a single [`TraceChangeRecord`], registered against one [`TraceEvent`]. Port of
/// the nested functional interface `TypedEventDispatcher.EventRecordHandler<T, U>`. Java's `T`/`U`
/// type parameters have no counterpart here: [`TraceChangeRecord`] already erases its affected
/// object and old/new value to `dyn Any` (see that type's docs), so a handler that wants a typed
/// view registers through one of the `listen_for_*` adapters below instead, which downcast on the
/// handler's behalf before calling into user code.
pub type EventRecordHandler = Box<dyn Fn(&TraceChangeRecord) + Send + Sync>;

/// Downcasts an erased change-record value to `T`, mirroring the unchecked cast every nested
/// handler interface's default `handle(TraceChangeRecord)` performs in Java. A mismatch here means
/// a handler was registered for the wrong [`TraceEvent`] (its `T`/`U` disagree with what the event
/// actually produces), which Java would also fail on (via `ClassCastException`) the first time the
/// mistyped reference was used -- so this panics rather than silently returning `None`.
fn downcast_ref<T: 'static>(value: Option<&(dyn Any + Send + Sync)>) -> Option<&T> {
    value.map(|v| {
        v.downcast_ref::<T>()
            .expect("TypedEventDispatcher: change record value did not match the registered handler's type")
    })
}

/// Dispatches change records to handlers registered per event type.
///
/// Port of `ghidra.trace.util.TypedEventDispatcher`. A subclass registers handlers -- typically
/// from its constructor -- via [`Self::listen_for`] and its typed `listen_for_*` variants (one per
/// Java's overloaded `listenFor`, since Rust has no method overloading), then forwards incoming
/// change records to [`Self::handle_change_record`].
///
/// Divergence from Java: this port's [`TraceChangeRecord`] does not extend
/// [`DomainObjectChangeRecord`] (it wraps one instead -- see that type's docs), so
/// [`Self::handle_change_record`]'s Java counterpart's `instanceof TraceChangeRecord` branch has no
/// Rust equivalent. In practice this is not a loss:
/// [`DomainObjectChangedEvent`](crate::framework::model::DomainObjectChangedEvent) already carries
/// a concrete `Vec<DomainObjectChangeRecord>`, so no caller can hand `handle_change_record` a
/// record that is "secretly" a `TraceChangeRecord`. Callers that do hold a `TraceChangeRecord` call
/// [`Self::handle_trace_change_record`] directly instead.
pub struct TypedEventDispatcher {
    typed_map: HashMap<i32, EventRecordHandler>,
    untyped_map: HashMap<i32, RecordConsumer>,
    restored_handler: Option<RecordConsumer>,
}

impl Default for TypedEventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl TypedEventDispatcher {
    /// Creates a dispatcher with no handlers registered.
    pub fn new() -> Self {
        Self {
            typed_map: HashMap::new(),
            untyped_map: HashMap::new(),
            restored_handler: None,
        }
    }

    /// Whether a handler for [`DomainObjectEvent::Restored`] has been registered. Mirrors a
    /// subclass's direct read of the protected `restoredHandler` field (e.g.
    /// `TraceDomainObjectListener.domainObjectChanged`, which checks `restoredHandler != null`).
    pub fn has_restored_handler(&self) -> bool {
        self.restored_handler.is_some()
    }

    /// Registers `handler` to run for every [`TraceChangeRecord`] whose event type is `event`.
    /// Mirrors `listenFor(TraceEvent<T, U>, EventRecordHandler<T, U>)`.
    pub fn listen_for(&mut self, event: &dyn TraceEvent, handler: EventRecordHandler) {
        self.typed_map.insert(event.get_id(), handler);
    }

    /// As [`Self::listen_for`], but `handler` receives the address space, affected object, old
    /// value, and new value already downcast to `T`/`U`. Mirrors
    /// `listenFor(TraceEvent<T, U>, FullEventRecordHandler<? super T, ? super U>)`.
    pub fn listen_for_full<T: 'static, U: 'static>(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&Arc<AddressSpace>>, Option<&T>, Option<&U>, Option<&U>) + Send + Sync + 'static,
    ) {
        self.listen_for(
            event,
            Box::new(move |rec| {
                handler(
                    rec.address_space(),
                    downcast_ref(rec.affected_object()),
                    downcast_ref(rec.old_value()),
                    downcast_ref(rec.new_value()),
                )
            }),
        );
    }

    /// As [`Self::listen_for`], but `handler` receives the address space and affected object,
    /// ignoring any old/new value. Mirrors
    /// `listenFor(TraceEvent<T, U>, AffectedObjectHandler<? super T>)`.
    pub fn listen_for_affected_object<T: 'static>(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&Arc<AddressSpace>>, Option<&T>) + Send + Sync + 'static,
    ) {
        self.listen_for(
            event,
            Box::new(move |rec| handler(rec.address_space(), downcast_ref(rec.affected_object()))),
        );
    }

    /// As [`Self::listen_for`], but `handler` receives only the affected object. Mirrors
    /// `listenFor(TraceEvent<T, U>, AffectedObjectOnlyHandler<? super T>)`.
    pub fn listen_for_affected_object_only<T: 'static>(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&T>) + Send + Sync + 'static,
    ) {
        self.listen_for(event, Box::new(move |rec| handler(downcast_ref(rec.affected_object()))));
    }

    /// As [`Self::listen_for`], but `handler` receives the affected object, old value, and new
    /// value, ignoring the address space. Mirrors
    /// `listenFor(TraceEvent<T, U>, AffectedAndValuesOnlyHandler<? super T, ? super U>)`.
    pub fn listen_for_affected_and_values_only<T: 'static, U: 'static>(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&T>, Option<&U>, Option<&U>) + Send + Sync + 'static,
    ) {
        self.listen_for(
            event,
            Box::new(move |rec| {
                handler(
                    downcast_ref(rec.affected_object()),
                    downcast_ref(rec.old_value()),
                    downcast_ref(rec.new_value()),
                )
            }),
        );
    }

    /// As [`Self::listen_for`], but `handler` receives the address space, old value, and new
    /// value, ignoring the affected object. Mirrors
    /// `listenFor(TraceEvent<T, U>, SpaceValuesHandler<? super U>)`.
    pub fn listen_for_space_values<U: 'static>(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&Arc<AddressSpace>>, Option<&U>, Option<&U>) + Send + Sync + 'static,
    ) {
        self.listen_for(
            event,
            Box::new(move |rec| {
                handler(rec.address_space(), downcast_ref(rec.old_value()), downcast_ref(rec.new_value()))
            }),
        );
    }

    /// As [`Self::listen_for`], but `handler` receives only the old and new value. Mirrors
    /// `listenFor(TraceEvent<T, U>, ValuesOnlyHandler<? super U>)`.
    pub fn listen_for_values_only<U: 'static>(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&U>, Option<&U>) + Send + Sync + 'static,
    ) {
        self.listen_for(
            event,
            Box::new(move |rec| handler(downcast_ref(rec.old_value()), downcast_ref(rec.new_value()))),
        );
    }

    /// As [`Self::listen_for`], but `handler` receives only the address space, ignoring the
    /// affected object and both values. Mirrors
    /// `listenFor(TraceEvent<?, ?>, IgnoreValuesHandler)`.
    pub fn listen_for_ignore_values(
        &mut self,
        event: &dyn TraceEvent,
        handler: impl Fn(Option<&Arc<AddressSpace>>) + Send + Sync + 'static,
    ) {
        self.listen_for(event, Box::new(move |rec| handler(rec.address_space())));
    }

    /// As [`Self::listen_for`], but `handler` ignores the record entirely, e.g. to just note that
    /// the event occurred. Mirrors `listenFor(TraceEvent<?, ?>, IgnoreAllHandler)`.
    pub fn listen_for_ignore_all(&mut self, event: &dyn TraceEvent, handler: impl Fn() + Send + Sync + 'static) {
        self.listen_for(event, Box::new(move |_rec| handler()));
    }

    /// Registers `handler` for the untyped `event_type`. `DomainObjectEvent::Restored` is
    /// special-cased into the field backing [`Self::has_restored_handler`] rather than the general
    /// untyped map, matching Java's own carve-out (which lets [`Self::handle_change_record`] check
    /// it before ever consulting `untypedMap`). Mirrors
    /// `listenForUntyped(EventType, Consumer<DomainObjectChangeRecord>)`.
    pub fn listen_for_untyped(&mut self, event_type: &dyn EventType, handler: RecordConsumer) {
        if event_type.get_id() == DomainObjectEvent::Restored.get_id() {
            self.restored_handler = Some(handler);
        } else {
            self.untyped_map.insert(event_type.get_id(), handler);
        }
    }

    /// Dispatches `rec` to its registered handler: the restored handler if `rec` is a restored
    /// event, else the untyped handler registered for its event type, else
    /// [`Self::unhandled`]. Mirrors `handleChangeRecord(DomainObjectChangeRecord)` (see the type
    /// docs for how the Java `instanceof TraceChangeRecord` branch maps here).
    pub fn handle_change_record(&self, rec: &DomainObjectChangeRecord) {
        if rec.event_type().get_id() == DomainObjectEvent::Restored.get_id() {
            if let Some(handler) = &self.restored_handler {
                handler(rec);
                return;
            }
        }
        if let Some(handler) = self.untyped_map.get(&rec.event_type().get_id()) {
            handler(rec);
            return;
        }
        self.unhandled(rec);
    }

    /// Dispatches `rec` to its registered typed handler, if any. Mirrors
    /// `handleTraceChangeRecord(TraceChangeRecord<?, ?>)`.
    pub fn handle_trace_change_record(&self, rec: &TraceChangeRecord) {
        if let Some(handler) = self.typed_map.get(&rec.event_type().get_id()) {
            handler(rec);
        }
    }

    /// Extension point invoked when [`Self::handle_change_record`] finds no handler for `rec`.
    /// Mirrors `unhandled(DomainObjectChangeRecord)`; does nothing by default, as in Java (no
    /// subclass in this codebase overrides it).
    pub fn unhandled(&self, rec: &DomainObjectChangeRecord) {
        let _ = rec;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockTraceEvent(i32);

    impl TraceEvent for MockTraceEvent {
        fn get_id(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn listen_for_full_downcasts_all_four_fields() {
        let mut dispatcher = TypedEventDispatcher::new();
        let event = MockTraceEvent(1);
        let seen: Arc<Mutex<Option<(bool, i32, String, String)>>> = Arc::new(Mutex::new(None));
        let seen_clone = Arc::clone(&seen);

        dispatcher.listen_for_full::<i32, String>(&event, move |space, affected, old, new| {
            *seen_clone.lock().unwrap() = Some((
                space.is_some(),
                *affected.unwrap(),
                old.cloned().unwrap_or_default(),
                new.cloned().unwrap_or_default(),
            ));
        });

        let rec = TraceChangeRecord::new(
            Box::new(MockEventType(1)),
            Some(AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0)),
            Some(Box::new(7i32)),
            Some(Box::new("old".to_string())),
            Some(Box::new("new".to_string())),
        );
        dispatcher.handle_trace_change_record(&rec);

        let seen = seen.lock().unwrap().take().expect("handler should have run");
        assert_eq!(seen, (true, 7, "old".to_string(), "new".to_string()));
    }

    #[test]
    fn handle_trace_change_record_ignores_unregistered_event() {
        let mut dispatcher = TypedEventDispatcher::new();
        let registered = MockTraceEvent(1);
        let calls = Arc::new(Mutex::new(0));
        let calls_clone = Arc::clone(&calls);
        dispatcher.listen_for_ignore_all(&registered, move || {
            *calls_clone.lock().unwrap() += 1;
        });

        let rec =
            TraceChangeRecord::without_affected_object(Box::new(MockEventType(2)), None);
        dispatcher.handle_trace_change_record(&rec);

        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[test]
    fn handle_change_record_prefers_restored_handler_over_untyped_map() {
        let mut dispatcher = TypedEventDispatcher::new();
        let restored_calls = Arc::new(Mutex::new(0));
        let restored_calls_clone = Arc::clone(&restored_calls);
        dispatcher.listen_for_untyped(
            &DomainObjectEvent::Restored,
            Box::new(move |_rec| {
                *restored_calls_clone.lock().unwrap() += 1;
            }),
        );
        assert!(dispatcher.has_restored_handler());

        let untyped_calls = Arc::new(Mutex::new(0));
        let untyped_calls_clone = Arc::clone(&untyped_calls);
        dispatcher.listen_for_untyped(
            &DomainObjectEvent::Saved,
            Box::new(move |_rec| {
                *untyped_calls_clone.lock().unwrap() += 1;
            }),
        );

        dispatcher.handle_change_record(&DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Restored)));
        dispatcher.handle_change_record(&DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved)));

        assert_eq!(*restored_calls.lock().unwrap(), 1);
        assert_eq!(*untyped_calls.lock().unwrap(), 1);
    }

    #[test]
    fn handle_change_record_falls_back_to_unhandled() {
        let dispatcher = TypedEventDispatcher::new();
        // No handler registered for `Closed`; this should not panic, mirroring the Java default
        // `unhandled` no-op.
        dispatcher.handle_change_record(&DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Closed)));
    }

    struct MockEventType(i32);

    impl EventType for MockEventType {
        fn get_id(&self) -> i32 {
            self.0
        }
    }
}
