use std::collections::HashSet;

use crate::framework::model::UserData;
use crate::framework::options::Options;
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::Transaction;
use crate::program::util::{
    IntPropertyMap, LongPropertyMap, ObjectPropertyMap, StringPropertyMap, VoidPropertyMap,
};
use crate::util::exception::PropertyTypeMismatchException;

/// Storage for arbitrary, non-undoable user data associated with a program (e.g. per-plugin
/// options and property maps that should not be shared/saved with the program itself).
///
/// Port of `ghidra.program.model.listing.ProgramUserData`.
///
/// The Java interface overloads `getStringProperty` for two unrelated purposes: retrieving an
/// address-based [`StringPropertyMap`] (`owner`, `propertyName`, `create`), and retrieving a
/// simple named string value (`propertyName`, `defaultValue`). Rust does not support overloading,
/// so the map-returning accessors below are named `get_*_property_map`, matching the convention
/// already used by [`PropertyMapManager`](crate::program::model::util::PropertyMapManager), while
/// the simple string accessor keeps the `get_string_property`/`set_string_property` names.
///
/// `getObjectProperty`'s `Class<T> saveableObjectClass` parameter is dropped: this crate's
/// [`ObjectPropertyMap`] is already type-erased (see its doc comment), so there is nothing for the
/// class token to select.
pub trait ProgramUserData: UserData {
    /// Open new transaction. This should generally be dropped once the associated changes have
    /// been made, releasing the transaction.
    ///
    /// # Panics
    /// May panic if this `ProgramUserData` has already been closed.
    fn open_transaction(&self) -> Box<dyn Transaction>;

    /// Start a transaction prior to changing any properties.
    ///
    /// Returns the transaction ID needed for [`ProgramUserData::end_transaction`].
    fn start_transaction(&self) -> i32;

    /// End a previously started transaction.
    fn end_transaction(&self, transaction_id: i32);

    /// Get an address-based String property map.
    ///
    /// # Errors
    /// Returns `PropertyTypeMismatchException` if a conflicting map definition was found.
    fn get_string_property_map(
        &mut self,
        owner: &str,
        property_name: &str,
        create: bool,
    ) -> Result<Box<dyn StringPropertyMap>, PropertyTypeMismatchException>;

    /// Get an address-based Long property map.
    ///
    /// # Errors
    /// Returns `PropertyTypeMismatchException` if a conflicting map definition was found.
    fn get_long_property_map(
        &mut self,
        owner: &str,
        property_name: &str,
        create: bool,
    ) -> Result<Box<dyn LongPropertyMap>, PropertyTypeMismatchException>;

    /// Get an address-based Integer property map.
    ///
    /// # Errors
    /// Returns `PropertyTypeMismatchException` if a conflicting map definition was found.
    fn get_int_property_map(
        &mut self,
        owner: &str,
        property_name: &str,
        create: bool,
    ) -> Result<Box<dyn IntPropertyMap>, PropertyTypeMismatchException>;

    /// Get an address-based Boolean property map.
    ///
    /// # Errors
    /// Returns `PropertyTypeMismatchException` if a conflicting map definition was found.
    fn get_boolean_property_map(
        &mut self,
        owner: &str,
        property_name: &str,
        create: bool,
    ) -> Result<Box<dyn VoidPropertyMap>, PropertyTypeMismatchException>;

    /// Get an address-based Saveable-object property map.
    ///
    /// # Errors
    /// Returns `PropertyTypeMismatchException` if a conflicting map definition was found.
    fn get_object_property_map(
        &mut self,
        owner: &str,
        property_name: &str,
        create: bool,
    ) -> Result<Box<dyn ObjectPropertyMap>, PropertyTypeMismatchException>;

    /// Get all property maps associated with a specific owner.
    fn get_properties(&self, owner: &str) -> Vec<Box<dyn PropertyMap>>;

    /// Returns the names of all property owners for which property maps have been defined.
    fn get_property_owners(&self) -> Vec<String>;

    /// Returns the names of all the Options objects stored in the user data.
    fn get_options_names(&self) -> Vec<String>;

    /// Get the Options for the given `options_name`.
    fn get_options(&self, options_name: &str) -> Box<dyn Options>;

    /// Sets the given String property.
    fn set_string_property(&mut self, property_name: &str, value: &str);

    /// Gets the value for the given property name, or `default_value` if there is no saved value
    /// for the given name.
    fn get_string_property(&self, property_name: &str, default_value: &str) -> String;

    /// Removes the String property with the given name.
    ///
    /// Returns the value of the property that was removed, or `None` if the property doesn't
    /// exist.
    fn remove_string_property(&mut self, property_name: &str) -> Option<String>;

    /// Returns the set of all String property names that have been set on this
    /// `ProgramUserData`.
    fn get_string_property_names(&self) -> HashSet<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockTransaction;
    impl Transaction for MockTransaction {}

    struct MockOptions;
    impl Options for MockOptions {}

    #[derive(Default)]
    struct MockProgramUserData {
        string_properties: HashMap<String, String>,
    }

    impl UserData for MockProgramUserData {}

    impl ProgramUserData for MockProgramUserData {
        fn open_transaction(&self) -> Box<dyn Transaction> {
            Box::new(MockTransaction)
        }

        fn start_transaction(&self) -> i32 {
            1
        }

        fn end_transaction(&self, _transaction_id: i32) {}

        fn get_string_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn StringPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_long_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn LongPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_int_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn IntPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_boolean_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn VoidPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_object_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn ObjectPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_properties(&self, _owner: &str) -> Vec<Box<dyn PropertyMap>> {
            Vec::new()
        }

        fn get_property_owners(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_options_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_options(&self, _options_name: &str) -> Box<dyn Options> {
            Box::new(MockOptions)
        }

        fn set_string_property(&mut self, property_name: &str, value: &str) {
            self.string_properties
                .insert(property_name.to_string(), value.to_string());
        }

        fn get_string_property(&self, property_name: &str, default_value: &str) -> String {
            self.string_properties
                .get(property_name)
                .cloned()
                .unwrap_or_else(|| default_value.to_string())
        }

        fn remove_string_property(&mut self, property_name: &str) -> Option<String> {
            self.string_properties.remove(property_name)
        }

        fn get_string_property_names(&self) -> HashSet<String> {
            self.string_properties.keys().cloned().collect()
        }
    }

    #[test]
    fn program_user_data_usable_as_trait_object() {
        let mut pud: Box<dyn ProgramUserData> = Box::new(MockProgramUserData::default());

        assert_eq!(
            pud.get_string_property("missing", "default"),
            "default".to_string()
        );

        pud.set_string_property("foo", "bar");
        assert_eq!(pud.get_string_property("foo", "default"), "bar".to_string());
        assert!(pud.get_string_property_names().contains("foo"));

        assert_eq!(pud.remove_string_property("foo"), Some("bar".to_string()));
        assert!(pud.get_string_property_names().is_empty());

        let _tx = pud.open_transaction();
        let id = pud.start_transaction();
        pud.end_transaction(id);

        let _opts = pud.get_options("some-options");
    }

    #[test]
    fn program_user_data_is_user_data() {
        let _as_user_data: Box<dyn UserData> = Box::new(MockProgramUserData::default());
    }
}
