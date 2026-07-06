use crate::program::model::data::data_type::DataType;

/// Provides the ability to wrap a [`DataType`] with additional information not conveyed
/// by the datatype on its own.
///
/// Port of `ghidra.app.util.bin.format.pdb.WrappedDataType`.
///
/// Note that a `BitFieldDataType` instance may be specified as the datatype in order to
/// convey bitfield related information.
pub struct WrappedDataType {
    is_zero_length_array: bool,
    is_no_type: bool,
    data_type: Box<dyn DataType>,
}

impl WrappedDataType {
    /// Constructs a wrapped datatype.
    ///
    /// `is_zero_length_array` is true if the datatype corresponds to a zero-length array
    /// which can not directly be represented as an Array datatype, else false for all other
    /// cases.
    ///
    /// `is_no_type` is true if the wrapped type corresponds to NoType as used by PDB forced
    /// to have a size of 1-byte.
    pub fn new(data_type: Box<dyn DataType>, is_zero_length_array: bool, is_no_type: bool) -> Self {
        Self {
            data_type,
            is_zero_length_array,
            is_no_type,
        }
    }

    /// Returns the wrapped datatype.
    pub fn data_type(&self) -> &dyn DataType {
        self.data_type.as_ref()
    }

    /// Returns true if the datatype corresponds to a zero-length array which can not
    /// directly be represented as an Array datatype, else false for all other cases.
    ///
    /// NOTE: zero-length arrays are only supported as a trailing flex-array within a
    /// structure. If such zero-length arrays exist within unions or within the body of a
    /// structure the composite reconstruction will produce unpredictable results or fail.
    pub fn is_zero_length_array(&self) -> bool {
        self.is_zero_length_array
    }

    /// Returns true if the wrapped type corresponds to NoType as used by PDB forced to have
    /// a size of 1-byte.
    pub fn is_no_type(&self) -> bool {
        self.is_no_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubDataType {
        name: &'static str,
    }

    impl DataType for StubDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
    }

    #[test]
    fn stores_data_type_and_flags() {
        let wrapped = WrappedDataType::new(Box::new(StubDataType { name: "int" }), false, false);
        assert_eq!(wrapped.data_type().get_name(), "int");
        assert!(!wrapped.is_zero_length_array());
        assert!(!wrapped.is_no_type());
    }

    #[test]
    fn reports_zero_length_array() {
        let wrapped = WrappedDataType::new(Box::new(StubDataType { name: "flex" }), true, false);
        assert!(wrapped.is_zero_length_array());
        assert!(!wrapped.is_no_type());
    }

    #[test]
    fn reports_no_type() {
        let wrapped = WrappedDataType::new(Box::new(StubDataType { name: "NoType" }), false, true);
        assert!(!wrapped.is_zero_length_array());
        assert!(wrapped.is_no_type());
    }
}
