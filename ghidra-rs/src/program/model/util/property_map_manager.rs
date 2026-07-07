use crate::program::model::address::Address;
use crate::program::util::{
    IntPropertyMap, LongPropertyMap, ObjectPropertyMap, StringPropertyMap, VoidPropertyMap,
};
use crate::program::model::util::PropertyMap;
use crate::util::exception::CancelledException;
use crate::util::exception::DuplicateNameException;
use crate::util::task::TaskMonitor;

/// Manager for a set of PropertyMaps.
///
/// Port of `ghidra.program.model.util.PropertyMapManager`.
pub trait PropertyMapManager {
    /// Creates a new IntPropertyMap with the given name.
    ///
    /// # Errors
    /// Returns `DuplicateNameException` if a PropertyMap already exists with that name.
    fn create_int_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn IntPropertyMap>, DuplicateNameException>;

    /// Creates a new LongPropertyMap with the given name.
    ///
    /// # Errors
    /// Returns `DuplicateNameException` if a PropertyMap already exists with that name.
    fn create_long_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn LongPropertyMap>, DuplicateNameException>;

    /// Creates a new StringPropertyMap with the given name.
    ///
    /// # Errors
    /// Returns `DuplicateNameException` if a PropertyMap already exists with that name.
    fn create_string_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn StringPropertyMap>, DuplicateNameException>;

    /// Creates a new ObjectPropertyMap with the given name.
    ///
    /// # Errors
    /// Returns `DuplicateNameException` if a PropertyMap already exists with that name.
    fn create_object_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException>;

    /// Creates a new VoidPropertyMap with the given name.
    ///
    /// # Errors
    /// Returns `DuplicateNameException` if a PropertyMap already exists with that name.
    fn create_void_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn VoidPropertyMap>, DuplicateNameException>;

    /// Returns the PropertyMap with the given name or None if no PropertyMap exists with that name.
    fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>>;

    /// Returns the IntPropertyMap associated with the given name.
    ///
    /// # Returns
    /// `None` if not found.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a propertyMap named
    /// `property_name` exists but is not an IntPropertyMap.
    fn get_int_property_map(&self, property_name: &str) -> Option<Box<dyn IntPropertyMap>>;

    /// Returns the LongPropertyMap associated with the given name.
    ///
    /// # Returns
    /// `None` if not found.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a propertyMap named
    /// `property_name` exists but is not a LongPropertyMap.
    fn get_long_property_map(&self, property_name: &str) -> Option<Box<dyn LongPropertyMap>>;

    /// Returns the StringPropertyMap associated with the given name.
    ///
    /// # Returns
    /// `None` if not found.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a propertyMap named
    /// `property_name` exists but is not a StringPropertyMap.
    fn get_string_property_map(&self, property_name: &str) -> Option<Box<dyn StringPropertyMap>>;

    /// Returns the ObjectPropertyMap associated with the given name.
    ///
    /// # Returns
    /// `None` if not found.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a propertyMap named
    /// `property_name` exists but is not an ObjectPropertyMap.
    fn get_object_property_map(&self, property_name: &str) -> Option<Box<dyn ObjectPropertyMap>>;

    /// Returns the VoidPropertyMap associated with the given name.
    ///
    /// # Returns
    /// `None` if not found.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `TypeMismatchException`) if a propertyMap named
    /// `property_name` exists but is not a VoidPropertyMap.
    fn get_void_property_map(&self, property_name: &str) -> Option<Box<dyn VoidPropertyMap>>;

    /// Removes the PropertyMap with the given name.
    ///
    /// # Returns
    /// `true` if a PropertyMap with that name was found (and removed), `false` otherwise.
    fn remove_property_map(&mut self, property_name: &str) -> bool;

    /// Returns an iterator over the names of all existing PropertyMaps sorted by name.
    fn property_managers(&self) -> Box<dyn Iterator<Item = String> + '_>;

    /// Removes any property at the given address from all defined PropertyMaps.
    fn remove_all(&mut self, addr: &Address);

    /// Removes all properties in the given range from all user defined PropertyMaps.
    /// The specified start and end addresses must form a valid range within a single AddressSpace.
    ///
    /// # Errors
    /// Returns `CancelledException` if the user cancelled the operation.
    fn remove_all_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockPropertyMapManager {
        maps: std::collections::BTreeMap<String, String>,
    }

    impl PropertyMapManager for MockPropertyMapManager {
        fn create_int_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn IntPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                Err(DuplicateNameException::default())
            } else {
                self.maps.insert(property_name.to_string(), "int".to_string());
                Err(DuplicateNameException::default())
            }
        }

        fn create_long_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn LongPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                Err(DuplicateNameException::default())
            } else {
                self.maps.insert(property_name.to_string(), "long".to_string());
                Err(DuplicateNameException::default())
            }
        }

        fn create_string_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn StringPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                Err(DuplicateNameException::default())
            } else {
                self.maps.insert(property_name.to_string(), "string".to_string());
                Err(DuplicateNameException::default())
            }
        }

        fn create_object_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                Err(DuplicateNameException::default())
            } else {
                self.maps.insert(property_name.to_string(), "object".to_string());
                Err(DuplicateNameException::default())
            }
        }

        fn create_void_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn VoidPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                Err(DuplicateNameException::default())
            } else {
                self.maps.insert(property_name.to_string(), "void".to_string());
                Err(DuplicateNameException::default())
            }
        }

        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
            None
        }

        fn get_int_property_map(&self, _property_name: &str) -> Option<Box<dyn IntPropertyMap>> {
            None
        }

        fn get_long_property_map(&self, _property_name: &str) -> Option<Box<dyn LongPropertyMap>> {
            None
        }

        fn get_string_property_map(
            &self,
            _property_name: &str,
        ) -> Option<Box<dyn StringPropertyMap>> {
            None
        }

        fn get_object_property_map(
            &self,
            _property_name: &str,
        ) -> Option<Box<dyn ObjectPropertyMap>> {
            None
        }

        fn get_void_property_map(
            &self,
            _property_name: &str,
        ) -> Option<Box<dyn VoidPropertyMap>> {
            None
        }

        fn remove_property_map(&mut self, property_name: &str) -> bool {
            self.maps.remove(property_name).is_some()
        }

        fn property_managers(&self) -> Box<dyn Iterator<Item = String> + '_> {
            Box::new(self.maps.keys().cloned())
        }

        fn remove_all(&mut self, _addr: &Address) {}

        fn remove_all_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    #[test]
    fn test_create_int_property_map_duplicate() {
        let mut manager = MockPropertyMapManager {
            maps: std::collections::BTreeMap::new(),
        };
        let result1 = manager.create_int_property_map("test_map");
        assert!(result1.is_err());

        let result2 = manager.create_int_property_map("test_map");
        assert!(result2.is_err());
    }

    #[test]
    fn test_remove_property_map() {
        let mut manager = MockPropertyMapManager {
            maps: std::collections::BTreeMap::new(),
        };
        manager.maps.insert("test".to_string(), "int".to_string());
        assert!(manager.remove_property_map("test"));
        assert!(!manager.remove_property_map("test"));
    }

    #[test]
    fn test_property_managers() {
        let mut manager = MockPropertyMapManager {
            maps: std::collections::BTreeMap::new(),
        };
        manager.maps.insert("a".to_string(), "int".to_string());
        manager.maps.insert("b".to_string(), "long".to_string());
        manager.maps.insert("c".to_string(), "string".to_string());

        let names: Vec<_> = manager.property_managers().collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
