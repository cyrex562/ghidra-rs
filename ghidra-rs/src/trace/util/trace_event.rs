//! Port of `ghidra.trace.util.TraceEvent`.

use crate::framework::model::EventType;

/// A sub-type for events specific to traces.
///
/// Port of `ghidra.trace.util.TraceEvent<T, U>`.
///
/// For the various defined events, see `TraceEvents` (its 53 nested enums each `implements
/// TraceEvent<T, U>` in Java, e.g. `TraceObjectEvent implements TraceEvent<TraceObject, Void>`).
///
/// Two divergences from the Java interface, both already established elsewhere in this port:
/// - Java's `TraceEvent<T, U>` introduces the affected-object type `T` and the old/new-value type
///   `U`. Every consumer already ported ([`TraceChangeRecord`](crate::trace::util::trace_change_record::TraceChangeRecord),
///   [`TypedEventDispatcher`](crate::trace::util::typed_event_dispatcher::TypedEventDispatcher))
///   erases both to `Box<dyn Any + Send + Sync>` rather than carrying the type parameters (see
///   `TraceChangeRecord`'s doc comment), so this trait needs no `<T, U>` of its own: nothing here
///   is actually generic over them.
/// - The Java default method `cast(DomainObjectChangeRecord)` is an unchecked generic cast
///   (`@SuppressWarnings("unchecked")`) from an untyped record to a `TraceChangeRecord<T, U>`. It
///   is omitted here for the same reason
///   [`TraceObjectValue::get_value`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
///   Java `castValue()` sibling is omitted: there is no equivalent unchecked cast for an
///   unconstrained type parameter on an object-safe trait. Callers use `TraceChangeRecord`'s own
///   `Any`-downcasting accessors instead.
///
/// With both dropped, Java's `TraceEvent<T, U> extends EventType` (which itself declares zero
/// abstract methods of its own -- `getId()` is inherited) reduces to a plain marker supertrait.
/// `Send + Sync` is required so `&dyn TraceEvent` can be passed across the handler closures
/// [`TypedEventDispatcher`](crate::trace::util::typed_event_dispatcher::TypedEventDispatcher)
/// registers.
pub trait TraceEvent: EventType + Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedIdEvent(i32);

    impl EventType for FixedIdEvent {
        fn get_id(&self) -> i32 {
            self.0
        }
    }

    impl TraceEvent for FixedIdEvent {}

    #[test]
    fn trace_event_inherits_get_id_from_event_type() {
        let event = FixedIdEvent(42);
        // Callable directly...
        assert_eq!(event.get_id(), 42);
        // ...and through a `dyn TraceEvent`, exactly as `TypedEventDispatcher` needs.
        let dyn_event: &dyn TraceEvent = &event;
        assert_eq!(dyn_event.get_id(), 42);
    }

    #[test]
    fn distinct_trace_events_keep_distinct_ids() {
        let a = FixedIdEvent(1);
        let b = FixedIdEvent(2);
        let events: Vec<&dyn TraceEvent> = vec![&a, &b];
        let ids: Vec<i32> = events.iter().map(|e| e.get_id()).collect();
        assert_eq!(ids, vec![1, 2]);
    }
}
