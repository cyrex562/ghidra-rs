use crate::util::graph::keyed_object::KeyedObject;
use crate::util::seam_stubs::AttributeLike;

/// Use this string as the attribute type to create an integer attribute.
pub const INTEGER_TYPE: &str = "INTEGER_TYPE";
/// Use this string as the attribute type to create a long attribute.
pub const LONG_TYPE: &str = "LONG_TYPE";
/// Use this string as the attribute type to create a double attribute.
pub const DOUBLE_TYPE: &str = "DOUBLE_TYPE";
/// Use this string as the attribute type to create a string attribute.
pub const STRING_TYPE: &str = "STRING_TYPE";
/// Use this string as the attribute type to create an object attribute.
pub const OBJECT_TYPE: &str = "OBJECT_TYPE";

/// Creates and keeps track of attributes defined for a single `KeyIndexableSet`.
///
/// Port of `ghidra.util.graph.attributes.AttributeManager` (deprecated since Ghidra 10.2), cut to
/// a trait to break a dependency cycle at this node in the port graph.
/// `ghidra.util.graph.attributes.Attribute` is not yet ported, so attribute accessors return the
/// boxed [`AttributeLike`] placeholder from `seam_stubs` instead.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait AttributeManager<T: KeyedObject> {
    /// Creates a new attribute of the given `attribute_type` (one of the `*_TYPE` constants) and
    /// registers it under `attribute_name`. Returns `None` if `attribute_type` is unrecognized.
    fn create_attribute(
        &mut self,
        attribute_name: &str,
        attribute_type: &str,
    ) -> Option<Box<dyn AttributeLike<T>>>;

    /// Removes the attribute with the specified name from this `AttributeManager`.
    fn remove_attribute(&mut self, attribute_name: &str);

    /// Returns true if there is an attribute with the specified name managed by this
    /// `AttributeManager`.
    fn has_attribute_named(&self, attribute_name: &str) -> bool;

    /// Returns the attribute with the specified name, or `None` if there is no attribute with
    /// that name.
    fn get_attribute(&self, attribute_name: &str) -> Option<&dyn AttributeLike<T>>;

    /// Returns the names of all attributes managed by this `AttributeManager`.
    fn get_attribute_names(&self) -> Vec<String>;

    /// Clears all of the attributes managed by this `AttributeManager` while leaving the
    /// attributes defined.
    fn clear(&mut self);
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockKeyedObject {
        key: i64,
    }

    impl KeyedObject for MockKeyedObject {
        fn key(&self) -> i64 {
            self.key
        }
    }

    struct MockAttribute {
        cleared: bool,
    }

    impl AttributeLike<MockKeyedObject> for MockAttribute {
        fn clear(&mut self) {
            self.cleared = true;
        }
    }

    struct MockAttributeManager {
        attributes: HashMap<String, Box<dyn AttributeLike<MockKeyedObject>>>,
    }

    impl AttributeManager<MockKeyedObject> for MockAttributeManager {
        fn create_attribute(
            &mut self,
            attribute_name: &str,
            attribute_type: &str,
        ) -> Option<Box<dyn AttributeLike<MockKeyedObject>>> {
            if attribute_type != INTEGER_TYPE {
                return None;
            }
            self.attributes
                .insert(attribute_name.to_string(), Box::new(MockAttribute { cleared: false }));
            None
        }

        fn remove_attribute(&mut self, attribute_name: &str) {
            self.attributes.remove(attribute_name);
        }

        fn has_attribute_named(&self, attribute_name: &str) -> bool {
            self.attributes.contains_key(attribute_name)
        }

        fn get_attribute(&self, attribute_name: &str) -> Option<&dyn AttributeLike<MockKeyedObject>> {
            self.attributes.get(attribute_name).map(|a| a.as_ref())
        }

        fn get_attribute_names(&self) -> Vec<String> {
            self.attributes.keys().cloned().collect()
        }

        fn clear(&mut self) {
            for attr in self.attributes.values_mut() {
                attr.clear();
            }
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut manager: Box<dyn AttributeManager<MockKeyedObject>> =
            Box::new(MockAttributeManager { attributes: HashMap::new() });

        manager.create_attribute("weight", INTEGER_TYPE);
        assert!(manager.has_attribute_named("weight"));
        assert!(manager.create_attribute("bogus", "NOT_A_TYPE").is_none());
        assert_eq!(manager.get_attribute_names(), vec!["weight".to_string()]);

        manager.clear();
        assert!(manager.get_attribute("weight").is_some());

        manager.remove_attribute("weight");
        assert!(!manager.has_attribute_named("weight"));
    }
}
