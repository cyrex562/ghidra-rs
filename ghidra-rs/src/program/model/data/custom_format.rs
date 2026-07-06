use crate::program::model::data::data_type::DataType;

/// Container object for a DataType and a byte array that is the format for the data type.
///
/// Port of `ghidra.program.model.data.CustomFormat`.
pub struct CustomFormat {
    data_type: Box<dyn DataType>,
    format: Vec<u8>,
}

impl CustomFormat {
    /// Creates a new CustomFormat with the given data type and format bytes.
    pub fn new(data_type: Box<dyn DataType>, format: Vec<u8>) -> Self {
        CustomFormat { data_type, format }
    }

    /// Gets the data type associated with this format.
    pub fn get_data_type(&self) -> &dyn DataType {
        &*self.data_type
    }

    /// Gets the bytes that define this format.
    pub fn get_bytes(&self) -> &[u8] {
        &self.format
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    #[test]
    fn new_creates_instance() {
        let dt = Box::new(MockDataType);
        let format = vec![1, 2, 3, 4];
        let custom = CustomFormat::new(dt, format.clone());
        assert_eq!(custom.get_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn get_data_type_returns_reference() {
        let dt = Box::new(MockDataType);
        let format = vec![];
        let custom = CustomFormat::new(dt, format);
        let _dt_ref = custom.get_data_type();
    }

    #[test]
    fn get_bytes_returns_empty_array() {
        let dt = Box::new(MockDataType);
        let custom = CustomFormat::new(dt, vec![]);
        assert_eq!(custom.get_bytes().len(), 0);
    }

    #[test]
    fn get_bytes_returns_correct_values() {
        let dt = Box::new(MockDataType);
        let expected = vec![0x10, 0x20, 0x30];
        let custom = CustomFormat::new(dt, expected.clone());
        assert_eq!(custom.get_bytes(), &expected[..]);
    }

    #[test]
    fn preserves_multiple_format_bytes() {
        let dt = Box::new(MockDataType);
        let large_format = vec![1; 256];
        let custom = CustomFormat::new(dt, large_format.clone());
        assert_eq!(custom.get_bytes().len(), 256);
        assert!(custom.get_bytes().iter().all(|&b| b == 1));
    }
}
