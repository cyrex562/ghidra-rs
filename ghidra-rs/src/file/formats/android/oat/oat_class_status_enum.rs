use crate::app::util::bin::struct_converter::StructConverter;

/// Trait for OAT class status information based on Android version.
///
/// Port of `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum`.
pub trait OatClassStatusEnum: StructConverter {
    /// Returns the OatClassStatusEnum instance for the given status value.
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockStatusEnum {
        value: i16,
    }

    impl MockStatusEnum {
        fn new(value: i16) -> Self {
            Self { value }
        }
    }

    impl StructConverter for MockStatusEnum {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl OatClassStatusEnum for MockStatusEnum {
        fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
            if value == self.value {
                Some(Box::new(MockStatusEnum::new(value)))
            } else {
                None
            }
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let mock = MockStatusEnum::new(1);
        let boxed: Box<dyn OatClassStatusEnum> = Box::new(mock);
        assert!(boxed.get(1).is_some());
    }

    #[test]
    fn get_matching_value_returns_some() {
        let mock = MockStatusEnum::new(5);
        assert!(mock.get(5).is_some());
    }

    #[test]
    fn get_non_matching_value_returns_none() {
        let mock = MockStatusEnum::new(5);
        assert!(mock.get(3).is_none());
    }
}
