//! Port of `ghidra.framework.model.DomainObjectListenerBuilder`.
//!
//! The Java class is a thin, concrete subclass of `AbstractDomainObjectListenerBuilder<R, B>`
//! (ported at [`abstract_domain_object_listener_builder`](crate::framework::model::abstract_domain_object_listener_builder))
//! that fixes the CRTP type parameters to `<DomainObjectChangeRecord, DomainObjectListenerBuilder>`
//! and supplies the constructor plus the `self()` hook the base class needs to return `this`
//! typed as the concrete subclass.
//!
//! Per this crate's composition-over-inheritance convention for every Java `extends`, this
//! struct does **not** try to inherit from the base trait/struct; it holds a
//! [`ListenerBuilderState`] (the base's canonical, reusable implementation of
//! [`AbstractDomainObjectListenerBuilder`]) and forwards every trait method to it, exactly as the
//! `MockBuilder` test helper in the base module already demonstrates is possible for an arbitrary
//! wrapper type.
//!
//! Divergences from the Java original:
//! - The `self()` CRTP hook has no Rust equivalent (see the base module's docs); it is simply
//!   omitted here, same as everywhere else in this port.
//! - Java's constructor calls `creator.getClass().getSimpleName()` via runtime reflection. Rust
//!   has no equivalent, so [`DomainObjectListenerBuilder::new`] is generic over the caller's own
//!   type and uses `std::any::type_name::<T>()` (trimmed to its last path segment) as a
//!   compile-time stand-in, preserving the "just pass `self`" call-site ergonomics of
//!   `new DomainObjectListenerBuilder(this)`.

use crate::framework::model::abstract_domain_object_listener_builder::{
    AbstractDomainObjectListenerBuilder, AnyBuilder, BooleanSupplier, EachBuilder, EventConsumer,
    EventTypeList, ListenerBuilderState, RecordConsumer, RecordEventConsumer,
};
use crate::framework::model::domain_object_listener::DomainObjectListener;
use crate::util::function::Callback;

/// Builder for creating a compact and efficient [`DomainObjectListener`] for
/// `DomainObjectChangedEvent`s.
///
/// Port of `ghidra.framework.model.DomainObjectListenerBuilder`. See the module docs for the
/// composition-over-inheritance approach taken here.
pub struct DomainObjectListenerBuilder {
    state: ListenerBuilderState,
}

impl DomainObjectListenerBuilder {
    /// Constructs a new builder, deriving its debug name from the caller's own type.
    ///
    /// Port of `DomainObjectListenerBuilder(Object creator)`, which calls
    /// `super(creator.getClass().getSimpleName(), DomainObjectChangeRecord.class)`. Call this as
    /// `DomainObjectListenerBuilder::new(self)` from within the type that owns the listener, the
    /// same way Java call sites pass `this`; see the module docs for why the type name is
    /// resolved from `T` rather than reflected off a value.
    pub fn new<T: ?Sized>(_creator: &T) -> Self {
        let full = std::any::type_name::<T>();
        let simple_name = full.rsplit("::").next().unwrap_or(full);
        Self {
            state: ListenerBuilderState::new(simple_name),
        }
    }

    /// Constructs a new builder with an explicit debug name, for callers that already have a
    /// name string (or aren't wrapping a specific owning type).
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            state: ListenerBuilderState::new(name),
        }
    }
}

impl AbstractDomainObjectListenerBuilder for DomainObjectListenerBuilder {
    fn name(&self) -> &str {
        self.state.name()
    }

    fn debug(self: Box<Self>, consumer: EventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).debug(consumer)
    }

    fn ignore_when(self: Box<Self>, supplier: BooleanSupplier) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).ignore_when(supplier)
    }

    fn any(self: Box<Self>, event_types: EventTypeList) -> AnyBuilder {
        Box::new(self.state).any(event_types)
    }

    fn each(self: Box<Self>, event_types: EventTypeList) -> EachBuilder {
        Box::new(self.state).each(event_types)
    }

    fn on_any_callback(
        self: Box<Self>,
        event_types: EventTypeList,
        callback: Callback,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).on_any_callback(event_types, callback)
    }

    fn on_any_consumer(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: EventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).on_any_consumer(event_types, consumer)
    }

    fn terminate_callback(
        self: Box<Self>,
        event_types: EventTypeList,
        callback: Callback,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).terminate_callback(event_types, callback)
    }

    fn terminate_consumer(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: EventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).terminate_consumer(event_types, consumer)
    }

    fn on_each(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: RecordConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).on_each(event_types, consumer)
    }

    fn on_each_with_event(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: RecordEventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(self.state).on_each_with_event(event_types, consumer)
    }

    fn build(self: Box<Self>) -> Box<dyn DomainObjectListener> {
        Box::new(self.state).build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::{
        DomainObject, DomainObjectChangeRecord, DomainObjectChangedEvent, DomainObjectEvent, EventType,
    };
    use std::sync::{Arc, Mutex};

    struct MockDomainObject;
    impl DomainObject for MockDomainObject {}

    /// Stand-in for a plugin/provider type that would own a listener built via
    /// `new DomainObjectListenerBuilder(this)` in Java.
    struct SomeOwningWidget;

    #[test]
    fn new_derives_name_from_creators_type() {
        let builder = DomainObjectListenerBuilder::new(&SomeOwningWidget);
        assert_eq!(builder.name(), "SomeOwningWidget");
    }

    #[test]
    fn with_name_uses_the_given_name_directly() {
        let builder = DomainObjectListenerBuilder::with_name("my-explicit-name");
        assert_eq!(builder.name(), "my-explicit-name");
    }

    #[test]
    fn builder_chain_produces_a_working_listener() {
        let calls = Arc::new(Mutex::new(0));
        let calls_clone = Arc::clone(&calls);

        let listener = Box::new(DomainObjectListenerBuilder::new(&SomeOwningWidget))
            .any(vec![Box::new(DomainObjectEvent::Saved)])
            .call_callback(Box::new(move || {
                *calls_clone.lock().unwrap() += 1;
            }))
            .build();
        let mut listener = listener;

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved))],
        );

        listener.domain_object_changed(&event);

        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[test]
    fn each_call_receives_matching_records_only() {
        let seen: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);

        let listener = Box::new(DomainObjectListenerBuilder::new(&SomeOwningWidget))
            .each(vec![Box::new(DomainObjectEvent::Renamed)])
            .call(Box::new(move |record: &DomainObjectChangeRecord| {
                seen_clone.lock().unwrap().push(record.event_type().get_id());
            }))
            .build();
        let mut listener = listener;

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Renamed)),
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Closed)),
            ],
        );

        listener.domain_object_changed(&event);

        assert_eq!(*seen.lock().unwrap(), vec![DomainObjectEvent::Renamed.get_id()]);
    }
}
