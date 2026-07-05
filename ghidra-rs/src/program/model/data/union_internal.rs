use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::union::Union;
use crate::program::seam_stubs::CompositeInternal;

/// Marker trait for `Union` implementations that are internal to the data type
/// manager (as opposed to externally-supplied implementations).
///
/// Port of `ghidra.program.model.data.UnionInternal`.
pub trait UnionInternal: Union + CompositeInternal {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeComponent;
    impl DataTypeComponent for MockDataTypeComponent {}

    struct MockUnion;

    impl DataType for MockUnion {}
    impl Composite for MockUnion {}
    impl Union for MockUnion {
        fn clone_union(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Union> {
            Box::new(MockUnion)
        }

        fn insert_bit_field(
            &mut self,
            _ordinal: i32,
            _base_data_type: Box<dyn DataType>,
            _bit_size: i32,
            _component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Ok(Box::new(MockDataTypeComponent))
        }
    }
    impl CompositeInternal for MockUnion {}
    impl UnionInternal for MockUnion {}

    #[test]
    fn usable_as_trait_object() {
        let u = MockUnion;
        let _dyn_union: &dyn UnionInternal = &u;
    }
}
