use crate::app::util::bin::struct_converter::StructConverter;

/// Base class to represent an FBPT (Facebook Package) entry.
///
/// Port of `ghidra.file.formats.android.fbpk.FBPT_Entry`.
pub trait FbptEntry: StructConverter {
    /// Returns the name of this FBPT entry.
    ///
    /// # Returns
    /// The entry name
    fn get_name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockFbptEntry;

    impl StructConverter for MockFbptEntry {
        fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl FbptEntry for MockFbptEntry {
        fn get_name(&self) -> &str {
            "test_entry"
        }
    }

    #[test]
    fn fbpt_entry_trait_is_object_safe() {
        let entry: Box<dyn FbptEntry> = Box::new(MockFbptEntry);
        assert_eq!(entry.get_name(), "test_entry");
    }

    #[test]
    fn fbpt_entry_implements_struct_converter() {
        let entry: Box<dyn StructConverter> = Box::new(MockFbptEntry);
        assert!(entry.to_data_type().is_ok());
    }
}
