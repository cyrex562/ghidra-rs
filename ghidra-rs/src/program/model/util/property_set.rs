use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// A named collection of properties, each backed by a type-specific property map.
///
/// Port of `ghidra.program.model.util.PropertySet`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here. All methods have default,
/// no-properties-defined implementations so that existing implementors (which previously
/// implemented the empty placeholder trait) continue to compile unchanged.
///
/// The Java `setProperty`/`getXxxProperty` overloads are split into distinctly-named methods
/// here since Rust does not support overloading on parameter/return type.
pub trait PropertySet {
    /// Set the named property with the given [`Saveable`] value.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `IllegalArgumentException`/`TypeMismatchException`)
    /// if a property map named `name` already exists but is not an object property map, or if
    /// `value`'s type is inconsistent with the named map.
    fn set_object_property(&mut self, name: &str, value: Box<dyn Saveable>) {
        let _ = (name, value);
    }

    /// Set the named string property with the given value.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` already exists but is not a string property map.
    fn set_string_property(&mut self, name: &str, value: &str) {
        let _ = (name, value);
    }

    /// Set the named integer property with the given value.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` already exists but is not an int property map.
    fn set_int_property(&mut self, name: &str, value: i32) {
        let _ = (name, value);
    }

    /// Set the named property. Used for "void" properties: the property is either set or not
    /// set, and there is no associated value.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` already exists but is not a void property map.
    fn set_void_property(&mut self, name: &str) {
        let _ = name;
    }

    /// Get the object property for `name`; returns `None` if there is no `name` property.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` exists but is not an object property map.
    fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        let _ = name;
        None
    }

    /// Get the string property for `name`; returns `None` if there is no `name` property.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` exists but is not a string property map.
    fn get_string_property(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }

    /// Get the int property for `name`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if there is no `name` property.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` exists but is not an int property map.
    fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        Err(NoValueException::with_message(format!(
            "no int property named '{name}'"
        )))
    }

    /// Returns true if this property set has the given property defined. Works for all property
    /// map types.
    fn has_property(&self, name: &str) -> bool {
        let _ = name;
        false
    }

    /// Returns whether this property set is marked as having the named void property.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a property map named
    /// `name` exists but is not a void property map.
    fn get_void_property(&self, name: &str) -> bool {
        let _ = name;
        false
    }

    /// Get an iterator over the property names which have values applied.
    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(std::iter::empty())
    }

    /// Remove the property value associated with the given name.
    fn remove_property(&mut self, name: &str) {
        let _ = name;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::saveable::ObjectStorageFieldType;
    use crate::util::ObjectStorage;
    use std::collections::HashMap;

    #[derive(Clone)]
    struct MockSaveable(i32);

    impl Saveable for MockSaveable {
        fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
            vec![ObjectStorageFieldType::Int]
        }
        fn save(&self, obj_storage: &mut dyn ObjectStorage) {
            obj_storage.put_int(self.0);
        }
        fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
            self.0 = obj_storage.get_int();
        }
        fn get_schema_version(&self) -> i32 {
            1
        }
        fn is_upgradeable(&self, _old_schema_version: i32) -> bool {
            false
        }
        fn upgrade(
            &mut self,
            _old_obj_storage: &mut dyn ObjectStorage,
            _old_schema_version: i32,
            _current_obj_storage: &mut dyn ObjectStorage,
        ) -> bool {
            false
        }
        fn is_private(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct MockPropertySet {
        strings: HashMap<String, String>,
        ints: HashMap<String, i32>,
        voids: HashMap<String, bool>,
    }

    impl PropertySet for MockPropertySet {
        fn set_string_property(&mut self, name: &str, value: &str) {
            self.strings.insert(name.to_string(), value.to_string());
        }

        fn set_int_property(&mut self, name: &str, value: i32) {
            self.ints.insert(name.to_string(), value);
        }

        fn set_void_property(&mut self, name: &str) {
            self.voids.insert(name.to_string(), true);
        }

        fn get_string_property(&self, name: &str) -> Option<String> {
            self.strings.get(name).cloned()
        }

        fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
            self.ints
                .get(name)
                .copied()
                .ok_or_else(|| NoValueException::with_message(format!("no value for '{name}'")))
        }

        fn has_property(&self, name: &str) -> bool {
            self.strings.contains_key(name) || self.ints.contains_key(name) || self.voids.contains_key(name)
        }

        fn get_void_property(&self, name: &str) -> bool {
            self.voids.contains_key(name)
        }

        fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
            Box::new(
                self.strings
                    .keys()
                    .chain(self.ints.keys())
                    .chain(self.voids.keys())
                    .cloned(),
            )
        }

        fn remove_property(&mut self, name: &str) {
            self.strings.remove(name);
            self.ints.remove(name);
            self.voids.remove(name);
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut props: Box<dyn PropertySet> = Box::new(MockPropertySet::default());
        props.set_string_property("name", "foo");
        props.set_int_property("count", 42);
        props.set_void_property("marker");

        assert_eq!(props.get_string_property("name"), Some("foo".to_string()));
        assert_eq!(props.get_int_property("count"), Ok(42));
        assert!(props.get_void_property("marker"));
        assert!(props.has_property("name"));
        assert!(!props.has_property("missing"));

        assert!(props.get_int_property("missing").is_err());

        props.remove_property("name");
        assert!(!props.has_property("name"));
    }

    #[test]
    fn default_impls_report_no_properties() {
        struct EmptyPropertySet;
        impl PropertySet for EmptyPropertySet {}

        let props = EmptyPropertySet;
        assert!(!props.has_property("anything"));
        assert!(props.get_string_property("anything").is_none());
        assert!(props.get_int_property("anything").is_err());
        assert_eq!(props.property_names().count(), 0);
    }

    #[test]
    fn object_property_default_impl_is_object_safe() {
        struct ObjectOnly(Option<MockSaveable>);
        impl PropertySet for ObjectOnly {
            fn set_object_property(&mut self, _name: &str, value: Box<dyn Saveable>) {
                let mut restored = MockSaveable(0);
                let fields = value.get_object_storage_fields();
                assert_eq!(fields, vec![ObjectStorageFieldType::Int]);
                self.0 = Some(restored.clone());
                let _ = restored.is_private();
            }
            fn get_object_property(&self, _name: &str) -> Option<Box<dyn Saveable>> {
                self.0.clone().map(|s| Box::new(s) as Box<dyn Saveable>)
            }
        }

        let mut props: Box<dyn PropertySet> = Box::new(ObjectOnly(None));
        props.set_object_property("obj", Box::new(MockSaveable(7)));
        assert!(props.get_object_property("obj").is_some());
    }
}
