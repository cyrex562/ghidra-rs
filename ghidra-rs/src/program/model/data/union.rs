use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::seam_stubs::{Composite, DataTypeManager};

/// The union interface.
///
/// NOTE: The use of bitfields within all unions assumes a default packing where bit
/// allocation always starts with byte-0 of the union. Bit allocation order is dictated
/// by data organization endianness (byte-0 msb allocated first for big-endian, while
/// byte-0 lsb allocated first for little-endian).
///
/// Port of `ghidra.program.model.data.Union`.
pub trait Union: Composite {
    /// Returns a copy of this union, associated with the given data type manager.
    /// Mirrors the covariant override of `Composite.clone(DataTypeManager)`.
    fn clone_union(&self, dtm: &dyn DataTypeManager) -> Box<dyn Union>;

    /// Inserts a new bitfield at the specified ordinal position in this union.
    ///
    /// For all Unions, a bitfield starts at bit-0 (lsb) of the first byte for
    /// little-endian, and at bit-7 (msb) of the first byte for big-endian. This is the
    /// default behavior for most compilers. Insertion behavior may not work as expected
    /// if packing rules differ from this.
    ///
    /// # Arguments
    /// * `ordinal` - the ordinal where the new datatype is to be inserted (numbering
    ///   starts at 0).
    /// * `base_data_type` - the bitfield base datatype (certain restrictions apply).
    /// * `bit_size` - the declared bitfield size in bits. The effective bit size may be
    ///   adjusted based upon the specified `base_data_type`.
    /// * `component_name` - the field name to associate with this component (`None` for
    ///   no name). The name may be sanitized to convert all whitespace characters to an
    ///   underscore.
    /// * `comment` - the comment to associate with this component.
    ///
    /// # Errors
    /// Returns `Err` if `base_data_type` is not a valid base type for bitfields (mirrors
    /// `InvalidDataTypeException`), or if `ordinal` is less than 0 or greater than the
    /// current number of components (mirrors `IndexOutOfBoundsException`).
    fn insert_bit_field(
        &mut self,
        ordinal: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockDataTypeComponent;
    impl DataTypeComponent for MockDataTypeComponent {}

    struct MockUnion {
        components: Vec<i32>,
    }

    impl Composite for MockUnion {}

    impl Union for MockUnion {
        fn clone_union(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Union> {
            Box::new(MockUnion {
                components: self.components.clone(),
            })
        }

        fn insert_bit_field(
            &mut self,
            ordinal: i32,
            _base_data_type: Box<dyn DataType>,
            _bit_size: i32,
            _component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            if ordinal < 0 || ordinal as usize > self.components.len() {
                return Err(
                    "IndexOutOfBoundsException: ordinal out of bounds".to_string()
                );
            }
            self.components.insert(ordinal as usize, ordinal);
            Ok(Box::new(MockDataTypeComponent))
        }
    }

    fn sample() -> MockUnion {
        MockUnion {
            components: Vec::new(),
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut u = sample();
        let base = Box::new(MockDataType);
        u.insert_bit_field(0, base, 8, Some("flag".to_string()), None)
            .unwrap();
        let dyn_union: &dyn Union = &u;
        let dtm = MockDataTypeManager;
        let mut cloned = dyn_union.clone_union(&dtm);

        // The clone carries over the one component inserted above, so ordinal 2 is
        // out of bounds but ordinal 1 (appending) is not.
        assert!(cloned
            .insert_bit_field(2, Box::new(MockDataType), 8, None, None)
            .is_err());
        assert!(cloned
            .insert_bit_field(1, Box::new(MockDataType), 8, None, None)
            .is_ok());
    }

    #[test]
    fn insert_bit_field_rejects_out_of_bounds_ordinal() {
        let mut u = sample();
        let base = Box::new(MockDataType);
        let result = u.insert_bit_field(5, base, 8, Some("flag".to_string()), None);
        assert!(result.is_err());
    }

    #[test]
    fn insert_bit_field_inserts_at_ordinal() {
        let mut u = sample();
        let base = Box::new(MockDataType);
        let result = u.insert_bit_field(0, base, 8, Some("flag".to_string()), None);
        assert!(result.is_ok());
        assert_eq!(u.components.len(), 1);
    }
}
