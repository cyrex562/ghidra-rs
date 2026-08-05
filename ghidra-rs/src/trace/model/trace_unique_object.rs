use crate::trace::seam_stubs::ObjectKey;

/// A trace object with an immutable-hash opaque identity, independent of its mutable content.
///
/// Java source: `ghidra.trace.model.TraceUniqueObject`.
pub trait TraceUniqueObject {
    /// Get an opaque unique id for this object, whose hash is immutable.
    fn get_object_key(&self) -> Box<dyn ObjectKey>;

    /// Check if this object is deleted.
    fn is_deleted(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

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

    struct MockUniqueObject {
        key: i32,
        deleted: bool,
    }

    impl TraceUniqueObject for MockUniqueObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(self.key))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    #[test]
    fn object_key_is_stable_and_comparable() {
        let obj = MockUniqueObject {
            key: 7,
            deleted: false,
        };
        let key_a = obj.get_object_key();
        let key_b = obj.get_object_key();
        assert_eq!(key_a.hash_code(), key_b.hash_code());
        assert_eq!(key_a.compare_to(key_b.as_ref()), 0);
        assert!(key_a.equals(&MockObjectKey(7)));
    }

    #[test]
    fn is_deleted_reflects_state() {
        let live = MockUniqueObject {
            key: 1,
            deleted: false,
        };
        let dead = MockUniqueObject {
            key: 2,
            deleted: true,
        };
        assert!(!live.is_deleted());
        assert!(dead.is_deleted());
    }

    #[test]
    fn trait_object_is_object_safe() {
        let obj: Box<dyn TraceUniqueObject> = Box::new(MockUniqueObject {
            key: 3,
            deleted: true,
        });
        assert!(obj.is_deleted());
        assert_eq!(obj.get_object_key().hash_code(), 3);
    }
}
