use crate::app::util::bin::struct_converter::StructConverter;

/// Trait representing a type lookup table used in Android OAT format.
///
/// Port of `ghidra.file.formats.android.oat.tlt.TypeLookupTable`.
///
/// References:
/// - [Android Oreo Release](https://android.googlesource.com/platform/art/+/oreo-release/runtime/type_lookup_table.h#161)
/// - [Android Oreo M2 Release](https://android.googlesource.com/platform/art/+/oreo-m2-release/runtime/type_lookup_table.h#161)
pub trait TypeLookupTable: StructConverter {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockTypeLookupTable;

    impl StructConverter for MockTypeLookupTable {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl TypeLookupTable for MockTypeLookupTable {}

    #[test]
    fn trait_is_object_safe() {
        let mock = MockTypeLookupTable;
        let boxed: Box<dyn TypeLookupTable> = Box::new(mock);
        assert!(boxed.to_data_type().is_ok());
    }

    #[test]
    fn to_data_type_returns_success() {
        let mock = MockTypeLookupTable;
        assert!(mock.to_data_type().is_ok());
    }
}
