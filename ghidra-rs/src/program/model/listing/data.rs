use std::any::{Any, TypeId};

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::seam_stubs::{CodeUnit, RefType, Reference, Settings};

/// Interface for interacting with data at an address in a program.
///
/// Port of `ghidra.program.model.listing.Data`.
pub trait Data: CodeUnit + Settings {
    /// Returns the value of this data as determined by the corresponding [`DataType`].
    /// The value may be an [`Address`], a `Scalar`, a datatype-defined object, or `None`
    /// if there is no value.
    fn get_value(&self) -> Option<Box<dyn Any>>;

    /// Get the type used to express the value of this data, or `None` if a consistent
    /// value type is not utilized.
    ///
    /// NOTE: This determination is made based upon data type and settings only and does not
    /// examine memory bytes which are used to construct the data value object.
    fn get_value_class(&self) -> Option<TypeId>;

    /// Mirrors the `Data` override of `Settings.isImmutableSettings()`, which always
    /// returns `true` (we could check to see if any editable Settings are defined).
    fn is_immutable_settings(&self) -> bool {
        true
    }

    /// Returns true if this data corresponds to string data. This is determined
    /// by the corresponding data type producing a String value.
    fn has_string_value(&self) -> bool;

    /// Determine if this data has explicitly been marked as constant.
    /// NOTE: This is based upon explicit `Data` and `DataType` mutability settings
    /// and does not reflect independent memory block or processor specification settings.
    fn is_constant(&self) -> bool;

    /// Determine if this data has explicitly been marked as writable.
    /// NOTE: This is based upon explicit `Data` and `DataType` mutability settings
    /// and does not reflect independent memory block or processor specification settings.
    fn is_writable(&self) -> bool;

    /// Determine if this data has explicitly been marked as volatile.
    /// NOTE: This is based upon explicit `Data` and `DataType` mutability settings
    /// and does not reflect independent memory block or processor specification settings.
    fn is_volatile(&self) -> bool;

    /// Returns true if the data type is defined. Any address that has not been defined to be
    /// code or data is treated as undefined data.
    fn is_defined(&self) -> bool;

    /// Get the Data type for the data.
    fn get_data_type(&self) -> Box<dyn DataType>;

    /// If the dataType is a typeDef, then the typeDef's base type is returned, otherwise, the
    /// dataType is returned.
    fn get_base_data_type(&self) -> Box<dyn DataType>;

    /// Get the references for the value.
    fn get_value_references(&self) -> Vec<Box<dyn Reference>>;

    /// Add a memory reference to the value.
    ///
    /// # Arguments
    /// * `ref_addr` - address referenced.
    /// * `ref_type` - the type of reference to be added.
    fn add_value_reference(&mut self, ref_addr: Address, ref_type: Box<dyn RefType>);

    /// Remove a reference to the value.
    ///
    /// # Arguments
    /// * `ref_addr` - address of reference to be removed.
    fn remove_value_reference(&mut self, ref_addr: Address);

    /// Get the field name of this data item if it is "inside" another data item, otherwise
    /// return `None`.
    fn get_field_name(&self) -> Option<String>;

    /// Returns the full path name (dot notation) for this field. This includes the symbol name
    /// at this address.
    fn get_path_name(&self) -> String;

    /// Returns the component path name (dot notation) for this field.
    fn get_component_path_name(&self) -> String;

    /// Returns true if this is a pointer, which implies `get_value` will return a value that is
    /// an `Address`.
    fn is_pointer(&self) -> bool;

    /// Returns true if this data item is a Union.
    fn is_union(&self) -> bool;

    /// Returns true if this data item is a Structure.
    fn is_structure(&self) -> bool;

    /// Returns true if this data item is an Array of DataTypes.
    fn is_array(&self) -> bool;

    /// Returns true if this data item is a dynamic DataType.
    fn is_dynamic(&self) -> bool;

    /// Get the immediate parent data item of this data item, or `None` if this data item is not
    /// contained in another data item.
    fn get_parent(&self) -> Option<Box<dyn Data>>;

    /// Get the highest level Data item in a hierarchy of structures containing this component.
    fn get_root(&self) -> Box<dyn Data>;

    /// Get the offset of this Data item from the start of the root data item of some hierarchy
    /// of structures.
    fn get_root_offset(&self) -> i32;

    /// Get the offset of this Data item from the start of its immediate parent.
    fn get_parent_offset(&self) -> i32;

    /// Returns the immediate n'th component or `None` if none exists.
    ///
    /// # Arguments
    /// * `index` - the index of the component to get.
    fn get_component(&self, index: i32) -> Option<Box<dyn Data>>;

    /// Get a data item given the index path. Each integer in the array represents an index into
    /// the data item at that level. Mirrors the overload `Data.getComponent(int[])`.
    ///
    /// # Arguments
    /// * `component_path` - the array of indexes to use to find the requested data item.
    fn get_component_by_path(&self, component_path: &[i32]) -> Option<Box<dyn Data>>;

    /// Get the component path if this is a component. The component path is an array of
    /// integers that represent each index in the tree of data items. Top level data items have
    /// an empty array for their component path.
    fn get_component_path(&self) -> Vec<i32>;

    /// Return the number of components that make up this data item.
    /// If this is an Array, return the number of elements in the array.
    fn get_num_components(&self) -> i32;

    /// Return the first immediate child component that contains the byte at the given offset.
    ///
    /// # Deprecated
    /// method name has been changed to better reflect behavior. [`Data::get_component_containing`]
    /// should be used instead.
    #[deprecated(note = "use get_component_containing instead")]
    fn get_component_at(&self, offset: i32) -> Option<Box<dyn Data>>;

    /// Return the first immediate child component that contains the byte at the given offset.
    /// It is important to note that with certain datatypes there may be more than one component
    /// containing the specified offset (see [`Data::get_components_containing`]).
    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn Data>>;

    /// Returns a list of all the immediate child components that contain the byte at the given
    /// offset, or `None` if offset is out of bounds.
    ///
    /// For a union, this will return all the components (if the offset is 0). The presence of
    /// bit-fields or zero-length components may cause multiple components to be returned.
    fn get_components_containing(&self, offset: i32) -> Option<Vec<Box<dyn Data>>>;

    /// Returns the primitive component containing this offset (i.e., one that does not have
    /// sub-components). This is useful for data items which are made up of multiple layers of
    /// other data items. This method immediately goes to the lowest level data item. If the
    /// minimum offset of a component is specified, only the first component containing the
    /// offset will be considered (e.g., 0-element array).
    fn get_primitive_at(&self, offset: i32) -> Option<Box<dyn Data>>;

    /// Get the index of this component in its parent, or -1 if this data item is not a
    /// component of another data item.
    fn get_component_index(&self) -> i32;

    /// Get this data's component level in its hierarchy of components, with 0 being the level
    /// of top level data items.
    fn get_component_level(&self) -> i32;

    /// Returns a string that represents the data value without markup.
    fn get_default_value_representation(&self) -> String;

    /// Returns the appropriate string to use as the default label prefix, or `None` if it has
    /// no preferred default label prefix.
    fn get_default_label_prefix(&self, options: &dyn DataTypeDisplayOptions) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type_display_options::DEFAULT;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockRefType;
    impl RefType for MockRefType {}

    struct MockReference;
    impl Reference for MockReference {}

    struct MockData {
        value: i32,
        constant: bool,
    }

    impl CodeUnit for MockData {}
    impl Settings for MockData {}

    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            Some(Box::new(self.value))
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<i32>())
        }

        fn has_string_value(&self) -> bool {
            false
        }

        fn is_constant(&self) -> bool {
            self.constant
        }

        fn is_writable(&self) -> bool {
            !self.constant
        }

        fn is_volatile(&self) -> bool {
            false
        }

        fn is_defined(&self) -> bool {
            true
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            vec![Box::new(MockReference)]
        }

        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}

        fn remove_value_reference(&mut self, _ref_addr: Address) {}

        fn get_field_name(&self) -> Option<String> {
            None
        }

        fn get_path_name(&self) -> String {
            "mock".to_string()
        }

        fn get_component_path_name(&self) -> String {
            String::new()
        }

        fn is_pointer(&self) -> bool {
            false
        }

        fn is_union(&self) -> bool {
            false
        }

        fn is_structure(&self) -> bool {
            false
        }

        fn is_array(&self) -> bool {
            false
        }

        fn is_dynamic(&self) -> bool {
            false
        }

        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }

        fn get_root(&self) -> Box<dyn Data> {
            Box::new(MockData {
                value: self.value,
                constant: self.constant,
            })
        }

        fn get_root_offset(&self) -> i32 {
            0
        }

        fn get_parent_offset(&self) -> i32 {
            0
        }

        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }

        fn get_num_components(&self) -> i32 {
            0
        }

        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }

        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_index(&self) -> i32 {
            -1
        }

        fn get_component_level(&self) -> i32 {
            0
        }

        fn get_default_value_representation(&self) -> String {
            self.value.to_string()
        }

        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let data = MockData {
            value: 42,
            constant: true,
        };
        let dyn_data: &dyn Data = &data;
        assert_eq!(
            dyn_data.get_value().and_then(|v| v.downcast::<i32>().ok()),
            Some(Box::new(42))
        );
        assert!(dyn_data.is_immutable_settings());
        assert!(dyn_data.is_constant());
        assert!(!dyn_data.is_writable());
        assert_eq!(
            dyn_data.get_default_label_prefix(&DEFAULT),
            None
        );
    }
}
