//! An object-based implementation of another trace-manager interface, e.g. `TraceThread`.
//!
//! Java source: `ghidra.trace.database.target.DBTraceObjectInterface`.
//!
//! Ported as a trait because it was selected as a cycle cut-point.
//!
//! Two pieces of the Java type are intentionally not reproduced here, each because it depends on
//! machinery that cannot be represented without an unported static factory (the same class of
//! omission already established by
//! [`ImmutableTraceAddressSnapRange`](crate::trace::model::immutable_trace_address_snap_range)):
//!
//! - The nested `Translator<T>` helper class. It depends on the generic trace-event framework
//!   (`TraceEvent<T, U>`, the `TraceEvents` constant table, and a generic `TraceChangeRecord<T,
//!   U>` with `getEventType()`/`cast()`), none of which exists in the Rust port yet.
//!   Implementors of [`DBTraceObjectInterface::translate_event`] must reimplement that
//!   translation logic directly until `Translator` and its dependencies are ported.
//! - The static `spaceForValue(TraceObject, long, String)` and its default `spaceForValue(long,
//!   String)` overload. Both bottom out in `DBTraceObject.spaceForValue(Object)`, a *static*
//!   utility on the not-yet-ported concrete `DBTraceObject` class. Rust has no way to invoke a
//!   trait's static-like associated function without already knowing a concrete implementing
//!   type, so there is no object-safe way to call through to it from here.
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::seam_stubs::ObjectKey;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::util::trace_change_record::TraceChangeRecord;

/// A [`TraceObject`]-backed implementation of another trace-manager interface.
///
/// Port of `ghidra.trace.database.target.DBTraceObjectInterface`.
pub trait DBTraceObjectInterface: TraceObjectInterface + TraceUniqueObject {

    /// Translate an object event into the interface-specific event.
    ///
    /// Both the object event and the interface-specific event, if applicable, should be emitted.
    /// If multiple events need to be emitted, an implementation may emit them directly via its
    /// object's trace. If exactly one event needs to be emitted, this method should return the
    /// translated record. If no translation applies, or the translated event(s) were emitted
    /// directly, this returns `None`.
    fn translate_event(&self, rec: &TraceChangeRecord) -> Option<TraceChangeRecord>;

    /// A default implementation of `TraceUniqueObject.getObjectKey()`.
    ///
    /// Mirrors `DBTraceObjectInterface.getObjectKey()`. Rust has no way for one trait to supply a
    /// default body for a *different* (super)trait's abstract method, so this isn't a literal
    /// override; implementors' own `TraceUniqueObject::get_object_key` impl should delegate to
    /// this.
    fn default_object_key(&self) -> Box<dyn ObjectKey> {
        self.get_object().get_object_key()
    }

    /// A default implementation of `TraceUniqueObject.isDeleted()`.
    ///
    /// Mirrors `DBTraceObjectInterface.isDeleted()`. See [`Self::default_object_key`] for why
    /// this isn't a literal trait-method override.
    fn default_is_deleted(&self) -> bool {
        self.get_object().get_life().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::tracermi::SchemaName;
    use crate::framework::model::DomainObjectEvent;
    use crate::trace::seam_stubs::{LifeSet, TraceObjectSchema};

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockSchema;

    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> SchemaName {
            SchemaName::new("Thread")
        }

        fn to_string(&self) -> String {
            "Thread".to_string()
        }
    }

    struct MockLifeSet {
        empty: bool,
    }

    impl LifeSet for MockLifeSet {
        fn is_empty(&self) -> bool {
            self.empty
        }
    }

    struct MockObject {
        key: i32,
        life_empty: bool,
    }

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(self.key))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema)
        }


        fn get_life(&self) -> Box<dyn LifeSet> {
            Box::new(MockLifeSet {
                empty: self.life_empty,
            })
        }

        fn get_canonical_path(&self) -> crate::trace::model::target::path::key_path::KeyPath {
            crate::trace::model::target::path::key_path::KeyPath::root()
        }

        crate::trace::model::target::trace_object::unimplemented_trace_object_members!();
    }

    /// A minimal implementor proving the trait is object-safe and that its defaults delegate
    /// correctly through [`DBTraceObjectInterface::get_object`].
    struct MockThread {
        object: MockObject,
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn TraceObject> {
            Box::new(MockObject {
                key: self.object.key,
                life_empty: self.object.life_empty,
            })
        }
    }

    impl DBTraceObjectInterface for MockThread {
        fn translate_event(&self, _rec: &TraceChangeRecord) -> Option<TraceChangeRecord> {
            None
        }
    }

    impl TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            self.default_object_key()
        }

        fn is_deleted(&self) -> bool {
            self.default_is_deleted()
        }
    }

    #[test]
    fn default_object_key_delegates_to_backing_object() {
        let thread = MockThread {
            object: MockObject {
                key: 42,
                life_empty: false,
            },
        };
        assert_eq!(thread.default_object_key().hash_code(), 42);
        assert_eq!(
            TraceUniqueObject::get_object_key(&thread).hash_code(),
            42
        );
    }

    #[test]
    fn default_is_deleted_reflects_empty_life() {
        let alive = MockThread {
            object: MockObject {
                key: 1,
                life_empty: false,
            },
        };
        let dead = MockThread {
            object: MockObject {
                key: 2,
                life_empty: true,
            },
        };
        assert!(!alive.default_is_deleted());
        assert!(dead.default_is_deleted());
        assert!(!TraceUniqueObject::is_deleted(&alive));
        assert!(TraceUniqueObject::is_deleted(&dead));
    }

    #[test]
    fn trait_object_is_object_safe() {
        let thread: Box<dyn DBTraceObjectInterface> = Box::new(MockThread {
            object: MockObject {
                key: 7,
                life_empty: true,
            },
        });
        assert!(thread.default_is_deleted());
        assert_eq!(thread.get_object().get_object_key().hash_code(), 7);
        assert!(thread.translate_event(&mock_change_record()).is_none());
    }

    fn mock_change_record() -> TraceChangeRecord {
        TraceChangeRecord::without_affected_object(Box::new(DomainObjectEvent::Saved), None)
    }
}
