/// Trait for objects that represent event types.
///
/// This trait provides a single method for obtaining a unique, compact id that can be used
/// as an index into a bit set. The id is assigned by [`DomainObjectEventIdGenerator::next()`]
/// to ensure coordination and minimal values.
///
/// Port of `ghidra.framework.model.EventType`.
pub trait EventType {
    /// Returns the unique id assigned to this event type.
    /// The value is guaranteed to be constant for any given run of the application,
    /// but can vary from run to run.
    fn get_id(&self) -> i32;
}
