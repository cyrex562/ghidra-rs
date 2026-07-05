use crate::program::seam_stubs::DataTypeComponent;

/// Interface for objects that can provide new instances of dataTypes.
///
/// Port of `ghidra.program.model.lang.DataTypeProviderContext`.
pub trait DataTypeProviderContext {
    /// Get a unique name for a data type given a prefix name.
    ///
    /// # Arguments
    /// * `base_name` - prefix for unique name
    ///
    /// # Returns
    /// A unique data type name
    fn get_unique_name(&self, base_name: &str) -> String;

    /// Get one data type from buffer at the current position plus offset.
    ///
    /// # Arguments
    /// * `offset` - the displacement from the current position
    ///
    /// # Returns
    /// The data type at offset from the current position
    ///
    /// # Errors
    /// Returns `Err` if offset is negative (mirrors `IndexOutOfBoundsException`)
    fn get_data_type_component(&self, offset: i32) -> Result<Option<Box<dyn DataTypeComponent>>, String>;

    /// Get an array of DataTypeComponents that begin at start or before end.
    ///
    /// DataTypes that begin before start are not returned.
    /// DataTypes that begin before end, but terminate after end ARE returned.
    ///
    /// # Arguments
    /// * `start` - start offset
    /// * `end` - end offset
    ///
    /// # Returns
    /// Array of DataTypes that exist between start and end
    fn get_data_type_components(&self, start: i32, end: i32) -> Vec<Box<dyn DataTypeComponent>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataTypeComponent;

    impl DataTypeComponent for MockDataTypeComponent {}

    struct MockDataTypeProviderContext {
        unique_names: Vec<String>,
        components: Vec<Box<dyn DataTypeComponent>>,
    }

    impl MockDataTypeProviderContext {
        fn new() -> Self {
            Self {
                unique_names: vec![],
                components: vec![],
            }
        }

        fn with_component(mut self, component: Box<dyn DataTypeComponent>) -> Self {
            self.components.push(component);
            self
        }
    }

    impl DataTypeProviderContext for MockDataTypeProviderContext {
        fn get_unique_name(&self, base_name: &str) -> String {
            format!("{}_unique", base_name)
        }

        fn get_data_type_component(&self, offset: i32) -> Result<Option<Box<dyn DataTypeComponent>>, String> {
            if offset < 0 {
                return Err("IndexOutOfBoundsException: offset must not be negative".to_string());
            }
            Ok(None)
        }

        fn get_data_type_components(&self, _start: i32, _end: i32) -> Vec<Box<dyn DataTypeComponent>> {
            vec![]
        }
    }

    #[test]
    fn get_unique_name() {
        let ctx = MockDataTypeProviderContext::new();
        assert_eq!(ctx.get_unique_name("test"), "test_unique");
        assert_eq!(ctx.get_unique_name("Type"), "Type_unique");
    }

    #[test]
    fn get_data_type_component_negative_offset_error() {
        let ctx = MockDataTypeProviderContext::new();
        let result = ctx.get_data_type_component(-1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "IndexOutOfBoundsException: offset must not be negative");
    }

    #[test]
    fn get_data_type_component_zero_offset() {
        let ctx = MockDataTypeProviderContext::new();
        let result = ctx.get_data_type_component(0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn get_data_type_component_positive_offset() {
        let ctx = MockDataTypeProviderContext::new();
        let result = ctx.get_data_type_component(10);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn get_data_type_components_empty() {
        let ctx = MockDataTypeProviderContext::new();
        let components = ctx.get_data_type_components(0, 10);
        assert!(components.is_empty());
    }

    #[test]
    fn get_data_type_components_with_range() {
        let ctx = MockDataTypeProviderContext::new();
        let components = ctx.get_data_type_components(5, 15);
        assert!(components.is_empty());
    }
}
