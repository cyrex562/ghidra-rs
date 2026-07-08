use crate::app::util::bin::struct_converter::StructConverter;

/// A marker trait for COFF symbol auxiliary records.
///
/// Port of `ghidra.app.util.bin.format.coff.CoffSymbolAux`.
/// This trait serves as a type marker for implementations that provide
/// auxiliary data for COFF symbol table entries.
pub trait CoffSymbolAux: StructConverter {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCoffSymbolAux;

    impl StructConverter for MockCoffSymbolAux {
        fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            struct MockDataType;
            impl crate::program::model::data::data_type::DataType for MockDataType {}
            Ok(Box::new(MockDataType))
        }
    }

    impl CoffSymbolAux for MockCoffSymbolAux {}

    #[test]
    fn trait_can_be_implemented() {
        let _aux: &dyn CoffSymbolAux = &MockCoffSymbolAux;
    }

    #[test]
    fn trait_is_object_safe() {
        fn _use_trait_object(_: &dyn CoffSymbolAux) {}
        _use_trait_object(&MockCoffSymbolAux);
    }
}
