use std::collections::HashMap;
use std::sync::Arc;

use crate::framework::model::{DomainObjectChangeRecord, DomainObjectChangedEvent, DomainObjectListener, EventType};
use crate::util::function::Callback;

/// A boolean-valued, no-argument predicate. Port of `java.util.function.BooleanSupplier`.
pub type BooleanSupplier = Box<dyn Fn() -> bool + Send + Sync>;

/// A callback that receives the full change event. Port of
/// `java.util.function.Consumer<DomainObjectChangedEvent>` as used by this builder.
pub type EventConsumer = Box<dyn Fn(&DomainObjectChangedEvent<'_>) + Send + Sync>;

/// A callback that receives a single change record. Port of `java.util.function.Consumer<R>` as
/// used by this builder's `each` handlers.
pub type RecordConsumer = Box<dyn Fn(&DomainObjectChangeRecord) + Send + Sync>;

/// A callback that receives both the change event and a single change record. Port of
/// `java.util.function.BiConsumer<DomainObjectChangedEvent, R>` as used by this builder's `each`
/// handlers.
pub type RecordEventConsumer = Box<dyn Fn(&DomainObjectChangedEvent<'_>, &DomainObjectChangeRecord) + Send + Sync>;

/// A list of event types, as passed to `any(EventType...)` and `each(EventType...)`.
pub type EventTypeList = Vec<Box<dyn EventType + Send + Sync>>;

/// Shared, clonable-handle form of [`RecordEventConsumer`], used internally so the same consumer
/// can be registered under multiple event-type keys in `on_each_map` (mirroring Java's
/// `onEachMap.put(eventType, trc)` inside a loop, where `trc` is the same object reference for
/// every event type in the group).
type SharedRecordConsumer = Arc<dyn Fn(&DomainObjectChangedEvent<'_>, &DomainObjectChangeRecord) + Send + Sync>;

/// Base trait for building a compact and efficient [`DomainObjectListener`]. See
/// `DomainObjectListenerBuilder` (not yet ported) for the concrete, user-facing entry point.
///
/// Port of `ghidra.framework.model.AbstractDomainObjectListenerBuilder<R, B>`. This was selected
/// as a dependency-cycle cut-point, so the Java class's public API is mapped onto a Rust trait
/// rather than a struct, letting other code depend on "some listener builder" without depending
/// on a concrete implementation.
///
/// Divergences from the Java original:
/// - Java's `R extends DomainObjectChangeRecord` / `B extends AbstractDomainObjectListenerBuilder<R, B>`
///   CRTP type parameters have no Rust analog: this port's [`DomainObjectChangeRecord`] is already
///   a single concrete type (not an extensible class hierarchy), so there is only ever one record
///   type in play. Consequently `with(Class<R2>)` (switching the active record type mid-chain) and
///   `TypedRecordConsumer`'s runtime `Class.isInstance` mismatch check (and the
///   `ReflectionUtilities`-based "inception information" it logs on mismatch) are dropped
///   entirely — the mismatch they guarded against cannot occur here.
/// - The `self()` CRTP hook Java subclasses override to return `this` typed as `B` has no Rust
///   equivalent: normal ownership (`self`/`Box<Self>`) already flows through as the correct
///   concrete type.
/// - To remain object-safe (so callers can hold `Box<dyn AbstractDomainObjectListenerBuilder>`
///   without knowing the concrete builder type), chaining methods consume `self: Box<Self>` and
///   return `Box<dyn AbstractDomainObjectListenerBuilder>` rather than `Self`. Java's overloaded
///   `call(Callback)` / `call(Consumer<...>)` pairs become distinctly-named methods since Rust has
///   no overloading.
pub trait AbstractDomainObjectListenerBuilder {
    /// Returns the name that will be associated with the domain object listener. This is for
    /// debugging purposes so that you can tell where this listener came from.
    fn name(&self) -> &str;

    /// Sets a consumer of events intended for clients to add a callback for each event. Useful
    /// for temporarily inspecting events and adding breakpoints.
    fn debug(self: Box<Self>, consumer: EventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Sets a boolean supplier that can be checked to see if the client is in a state where they
    /// don't want events to be processed at this time.
    fn ignore_when(self: Box<Self>, supplier: BooleanSupplier) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Allows for specifying multiple event types that if the event contains any records with any
    /// of the given types, then a callback or callback-with-terminate will be triggered,
    /// depending on which [`AnyBuilder`] method is called next.
    fn any(self: Box<Self>, event_types: EventTypeList) -> AnyBuilder;

    /// Allows for specifying multiple event types that for each record with one of the specified
    /// types, the follow-on consumer will be called.
    fn each(self: Box<Self>, event_types: EventTypeList) -> EachBuilder;

    /// Registers a no-argument callback triggered when the event contains any record with one of
    /// the given types. Used by [`AnyBuilder::call_callback`].
    fn on_any_callback(
        self: Box<Self>,
        event_types: EventTypeList,
        callback: Callback,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Registers an event-consuming callback triggered when the event contains any record with
    /// one of the given types. Used by [`AnyBuilder::call`].
    fn on_any_consumer(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: EventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Registers a no-argument callback triggered (and processing terminated for the event) when
    /// the event contains any record with one of the given types. Used by
    /// [`AnyBuilder::terminate_callback`].
    fn terminate_callback(
        self: Box<Self>,
        event_types: EventTypeList,
        callback: Callback,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Registers an event-consuming callback triggered (and processing terminated for the event)
    /// when the event contains any record with one of the given types. Used by
    /// [`AnyBuilder::terminate`].
    fn terminate_consumer(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: EventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Registers a record-only consumer called for each record matching one of the given event
    /// types. Used by [`EachBuilder::call`].
    fn on_each(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: RecordConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Registers an event-and-record consumer called for each record matching one of the given
    /// event types. Used by [`EachBuilder::call_with_event`].
    fn on_each_with_event(
        self: Box<Self>,
        event_types: EventTypeList,
        consumer: RecordEventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder>;

    /// Builds and returns a new [`DomainObjectListener`] from the accumulated configuration.
    fn build(self: Box<Self>) -> Box<dyn DomainObjectListener>;
}

/// Sub-builder for collecting event types before eventually being associated with a callback or
/// callback with termination.
///
/// Port of `AbstractDomainObjectListenerBuilder.AnyBuilder`.
pub struct AnyBuilder {
    builder: Box<dyn AbstractDomainObjectListenerBuilder>,
    event_types: EventTypeList,
}

impl AnyBuilder {
    /// Provides the no-argument callback to be associated with this collection of event types.
    pub fn call_callback(self, callback: Callback) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.builder.on_any_callback(self.event_types, callback)
    }

    /// Provides the event-consuming callback to be associated with this collection of event
    /// types.
    pub fn call(self, consumer: EventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.builder.on_any_consumer(self.event_types, consumer)
    }

    /// Provides the no-argument callback with termination to be associated with this collection
    /// of event types.
    pub fn terminate_callback(self, callback: Callback) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.builder.terminate_callback(self.event_types, callback)
    }

    /// Provides the event-consuming callback with termination to be associated with this
    /// collection of event types.
    pub fn terminate(self, consumer: EventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.builder.terminate_consumer(self.event_types, consumer)
    }
}

/// Sub-builder for collecting event types before eventually being associated with a consumer for
/// records with those types.
///
/// Port of `AbstractDomainObjectListenerBuilder.EachBuilder`.
pub struct EachBuilder {
    builder: Box<dyn AbstractDomainObjectListenerBuilder>,
    event_types: EventTypeList,
}

impl EachBuilder {
    /// Provides the record-only consumer to be associated with this collection of event types.
    pub fn call(self, consumer: RecordConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.builder.on_each(self.event_types, consumer)
    }

    /// Provides the event-and-record consumer to be associated with this collection of event
    /// types.
    pub fn call_with_event(self, consumer: RecordEventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.builder.on_each_with_event(self.event_types, consumer)
    }
}

/// Holds a group of event types together with the callback that fires when the dispatched event
/// contains a record of any of those types.
///
/// Port of `AbstractDomainObjectListenerBuilder.EventTrigger`.
struct EventTrigger {
    event_types: EventTypeList,
    consumer: EventConsumer,
}

impl EventTrigger {
    fn from_callback(event_types: EventTypeList, callback: Callback) -> Self {
        Self {
            event_types,
            consumer: Box::new(move |_ev: &DomainObjectChangedEvent<'_>| callback()),
        }
    }

    fn from_consumer(event_types: EventTypeList, consumer: EventConsumer) -> Self {
        Self { event_types, consumer }
    }

    fn is_triggered(&self, event: &DomainObjectChangedEvent<'_>) -> bool {
        let refs: Vec<&dyn EventType> =
            self.event_types.iter().map(|t| t.as_ref() as &dyn EventType).collect();
        event.contains_any(&refs)
    }
}

/// The state accumulated by an [`AbstractDomainObjectListenerBuilder`] implementation: the
/// listener's name, its optional ignore/debug hooks, and its registered event triggers.
///
/// Port of the instance fields Java's `AbstractDomainObjectListenerBuilder` declares directly
/// (`name`, `ignoreCheck`, `debugConsumer`, `terminateList`, `onAnyList`, `onEachMap`). Since Rust
/// traits cannot hold fields, this struct is the canonical, reusable implementation of
/// [`AbstractDomainObjectListenerBuilder`]; a future port of the concrete
/// `ghidra.framework.model.DomainObjectListenerBuilder` subclass should wrap or become this type
/// rather than re-implementing this bookkeeping.
pub struct ListenerBuilderState {
    name: String,
    ignore_check: Option<BooleanSupplier>,
    debug_consumer: Option<EventConsumer>,
    terminate_list: Vec<EventTrigger>,
    on_any_list: Vec<EventTrigger>,
    on_each_map: HashMap<i32, SharedRecordConsumer>,
}

impl ListenerBuilderState {
    /// Creates a builder with the given name, mirroring
    /// `AbstractDomainObjectListenerBuilder(String name, Class<R> recordClass)` (minus the record
    /// class, which this port has no use for; see the trait's divergence notes).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ignore_check: None,
            debug_consumer: None,
            terminate_list: Vec::new(),
            on_any_list: Vec::new(),
            on_each_map: HashMap::new(),
        }
    }
}

impl AbstractDomainObjectListenerBuilder for ListenerBuilderState {
    fn name(&self) -> &str {
        &self.name
    }

    fn debug(mut self: Box<Self>, consumer: EventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.debug_consumer = Some(consumer);
        self
    }

    fn ignore_when(mut self: Box<Self>, supplier: BooleanSupplier) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.ignore_check = Some(supplier);
        self
    }

    fn any(self: Box<Self>, event_types: EventTypeList) -> AnyBuilder {
        AnyBuilder { builder: self, event_types }
    }

    fn each(self: Box<Self>, event_types: EventTypeList) -> EachBuilder {
        EachBuilder { builder: self, event_types }
    }

    fn on_any_callback(
        mut self: Box<Self>,
        event_types: EventTypeList,
        callback: Callback,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.on_any_list.push(EventTrigger::from_callback(event_types, callback));
        self
    }

    fn on_any_consumer(
        mut self: Box<Self>,
        event_types: EventTypeList,
        consumer: EventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.on_any_list.push(EventTrigger::from_consumer(event_types, consumer));
        self
    }

    fn terminate_callback(
        mut self: Box<Self>,
        event_types: EventTypeList,
        callback: Callback,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.terminate_list.push(EventTrigger::from_callback(event_types, callback));
        self
    }

    fn terminate_consumer(
        mut self: Box<Self>,
        event_types: EventTypeList,
        consumer: EventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        self.terminate_list.push(EventTrigger::from_consumer(event_types, consumer));
        self
    }

    fn on_each(
        mut self: Box<Self>,
        event_types: EventTypeList,
        consumer: RecordConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        let shared: SharedRecordConsumer =
            Arc::new(move |_ev: &DomainObjectChangedEvent<'_>, rec: &DomainObjectChangeRecord| (consumer)(rec));
        for event_type in &event_types {
            self.on_each_map.insert(event_type.get_id(), Arc::clone(&shared));
        }
        self
    }

    fn on_each_with_event(
        mut self: Box<Self>,
        event_types: EventTypeList,
        consumer: RecordEventConsumer,
    ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        let shared: SharedRecordConsumer = Arc::from(consumer);
        for event_type in &event_types {
            self.on_each_map.insert(event_type.get_id(), Arc::clone(&shared));
        }
        self
    }

    fn build(self: Box<Self>) -> Box<dyn DomainObjectListener> {
        Box::new(BuilderDomainObjectListener {
            ignore_check: self.ignore_check.unwrap_or_else(|| Box::new(|| false)),
            debug_consumer: self.debug_consumer.unwrap_or_else(|| Box::new(|_ev| {})),
            terminate_list: self.terminate_list,
            on_any_list: self.on_any_list,
            on_each_map: self.on_each_map,
        })
    }
}

/// The [`DomainObjectListener`] produced by [`AbstractDomainObjectListenerBuilder::build`].
///
/// Port of `AbstractDomainObjectListenerBuilder.BuilderDomainObjectListener`. The Java class's
/// `eachEventTypes` fast-path (skip the per-record loop when the event has more records than
/// there are "each" handlers and none of the handled types are present) is a pure micro-
/// optimization that does not change observable behavior, so it is omitted here in favor of
/// always looping when `on_each_map` is non-empty.
struct BuilderDomainObjectListener {
    ignore_check: BooleanSupplier,
    debug_consumer: EventConsumer,
    terminate_list: Vec<EventTrigger>,
    on_any_list: Vec<EventTrigger>,
    on_each_map: HashMap<i32, SharedRecordConsumer>,
}

impl DomainObjectListener for BuilderDomainObjectListener {
    fn domain_object_changed(&mut self, event: &DomainObjectChangedEvent<'_>) {
        // A way for clients to add conditional debug, print statements and breakpoints.
        (self.debug_consumer)(event);

        if (self.ignore_check)() {
            return;
        }

        for trigger in &self.terminate_list {
            if trigger.is_triggered(event) {
                (trigger.consumer)(event);
                return;
            }
        }

        for trigger in &self.on_any_list {
            if trigger.is_triggered(event) {
                (trigger.consumer)(event);
            }
        }

        if !self.on_each_map.is_empty() {
            for record in event {
                if let Some(consumer) = self.on_each_map.get(&record.event_type().get_id()) {
                    consumer(event, record);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::{DomainObject, DomainObjectEvent};
    use std::sync::Mutex;

    struct MockDomainObject;
    impl DomainObject for MockDomainObject {}

    /// Thin wrapper that forwards every call to a [`ListenerBuilderState`], proving that an
    /// arbitrary type (not just the canonical implementation) can implement
    /// [`AbstractDomainObjectListenerBuilder`] and be driven entirely through
    /// `Box<dyn AbstractDomainObjectListenerBuilder>`.
    struct MockBuilder(ListenerBuilderState);

    impl AbstractDomainObjectListenerBuilder for MockBuilder {
        fn name(&self) -> &str {
            self.0.name()
        }
        fn debug(self: Box<Self>, consumer: EventConsumer) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).debug(consumer)
        }
        fn ignore_when(self: Box<Self>, supplier: BooleanSupplier) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).ignore_when(supplier)
        }
        fn any(self: Box<Self>, event_types: EventTypeList) -> AnyBuilder {
            Box::new(self.0).any(event_types)
        }
        fn each(self: Box<Self>, event_types: EventTypeList) -> EachBuilder {
            Box::new(self.0).each(event_types)
        }
        fn on_any_callback(
            self: Box<Self>,
            event_types: EventTypeList,
            callback: Callback,
        ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).on_any_callback(event_types, callback)
        }
        fn on_any_consumer(
            self: Box<Self>,
            event_types: EventTypeList,
            consumer: EventConsumer,
        ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).on_any_consumer(event_types, consumer)
        }
        fn terminate_callback(
            self: Box<Self>,
            event_types: EventTypeList,
            callback: Callback,
        ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).terminate_callback(event_types, callback)
        }
        fn terminate_consumer(
            self: Box<Self>,
            event_types: EventTypeList,
            consumer: EventConsumer,
        ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).terminate_consumer(event_types, consumer)
        }
        fn on_each(
            self: Box<Self>,
            event_types: EventTypeList,
            consumer: RecordConsumer,
        ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).on_each(event_types, consumer)
        }
        fn on_each_with_event(
            self: Box<Self>,
            event_types: EventTypeList,
            consumer: RecordEventConsumer,
        ) -> Box<dyn AbstractDomainObjectListenerBuilder> {
            Box::new(self.0).on_each_with_event(event_types, consumer)
        }
        fn build(self: Box<Self>) -> Box<dyn DomainObjectListener> {
            Box::new(self.0).build()
        }
    }

    fn boxed_builder(name: &str) -> Box<dyn AbstractDomainObjectListenerBuilder> {
        Box::new(MockBuilder(ListenerBuilderState::new(name)))
    }

    #[test]
    fn any_and_each_dispatch_through_dyn_trait_object() {
        let any_calls = Arc::new(Mutex::new(0));
        let any_calls_clone = Arc::clone(&any_calls);
        let each_records: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let each_records_clone = Arc::clone(&each_records);

        let listener = boxed_builder("test-listener")
            .any(vec![Box::new(DomainObjectEvent::Saved)])
            .call_callback(Box::new(move || {
                *any_calls_clone.lock().unwrap() += 1;
            }))
            .each(vec![Box::new(DomainObjectEvent::Renamed)])
            .call(Box::new(move |record: &DomainObjectChangeRecord| {
                each_records_clone.lock().unwrap().push(record.event_type().get_id());
            }))
            .build();
        let mut listener = listener;

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved)),
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Renamed)),
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Closed)),
            ],
        );

        listener.domain_object_changed(&event);

        assert_eq!(*any_calls.lock().unwrap(), 1);
        assert_eq!(*each_records.lock().unwrap(), vec![DomainObjectEvent::Renamed.get_id()]);
    }

    #[test]
    fn terminate_short_circuits_on_any_processing() {
        let any_calls = Arc::new(Mutex::new(0));
        let any_calls_clone = Arc::clone(&any_calls);
        let terminate_calls = Arc::new(Mutex::new(0));
        let terminate_calls_clone = Arc::clone(&terminate_calls);

        let listener = boxed_builder("terminating")
            .any(vec![Box::new(DomainObjectEvent::Closed)])
            .call_callback(Box::new(move || {
                *any_calls_clone.lock().unwrap() += 1;
            }))
            .any(vec![Box::new(DomainObjectEvent::Error)])
            .terminate_callback(Box::new(move || {
                *terminate_calls_clone.lock().unwrap() += 1;
            }))
            .build();
        let mut listener = listener;

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Error)),
                DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Closed)),
            ],
        );

        listener.domain_object_changed(&event);

        assert_eq!(*terminate_calls.lock().unwrap(), 1);
        assert_eq!(*any_calls.lock().unwrap(), 0, "terminate should short-circuit before onAny processing");
    }

    #[test]
    fn ignore_when_true_suppresses_all_processing_but_debug_still_fires() {
        let debug_calls = Arc::new(Mutex::new(0));
        let debug_calls_clone = Arc::clone(&debug_calls);
        let any_calls = Arc::new(Mutex::new(0));
        let any_calls_clone = Arc::clone(&any_calls);

        let listener = boxed_builder("ignored")
            .debug(Box::new(move |_ev| {
                *debug_calls_clone.lock().unwrap() += 1;
            }))
            .ignore_when(Box::new(|| true))
            .any(vec![Box::new(DomainObjectEvent::Saved)])
            .call_callback(Box::new(move || {
                *any_calls_clone.lock().unwrap() += 1;
            }))
            .build();
        let mut listener = listener;

        let src = MockDomainObject;
        let event = DomainObjectChangedEvent::new(
            &src,
            vec![DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved))],
        );

        listener.domain_object_changed(&event);

        assert_eq!(*debug_calls.lock().unwrap(), 1, "debug consumer runs even when ignoring");
        assert_eq!(*any_calls.lock().unwrap(), 0, "ignoreWhen should suppress all other processing");
    }

    #[test]
    fn name_is_preserved_through_the_chain() {
        let builder = boxed_builder("my-listener");
        assert_eq!(builder.name(), "my-listener");
    }
}
