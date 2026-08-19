/// Base trait for objects which have keys, e.g. [`crate::util::graph::Vertex`] and `Edge`.
///
/// Port of `ghidra.util.graph.KeyedObject` (deprecated since Ghidra 10.2).
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait KeyedObject: Send + Sync {
    /// Returns the key for this `KeyedObject`.
    fn key(&self) -> i64;
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    struct MockKeyedObject {
        key: i64,
    }

    impl KeyedObject for MockKeyedObject {
        fn key(&self) -> i64 {
            self.key
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let obj: Box<dyn KeyedObject> = Box::new(MockKeyedObject { key: 42 });
        assert_eq!(obj.key(), 42);
    }
}
