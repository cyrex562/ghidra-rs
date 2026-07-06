use std::io::Write;

use serde_json::{json, Value as JsonValue};

use crate::util::task::TaskMonitor;
use crate::util::exception::CancelledException;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Exports function information in ISF (JSON) format for SARIF documents.
///
/// Mirrors `ExtFunctionWriter` from Ghidra's `sarif.export.func` package.
/// Generates function data as JSON objects that can be serialized and included
/// in SARIF export output.
pub struct ExtFunctionWriter {
    data: JsonValue,
}

impl ExtFunctionWriter {
    /// Creates a new `ExtFunctionWriter` with the given data type manager and output writer.
    ///
    /// # Arguments
    ///
    /// * `_dtm` - The data type manager (not currently used in the base implementation)
    /// * `_base_writer` - Optional output writer for serialization (not currently used in the base implementation)
    ///
    /// Initializes the writer with an empty JSON object for data generation.
    pub fn new(_dtm: Box<dyn DataTypeManager>, _base_writer: Option<Box<dyn Write>>) -> Self {
        Self {
            data: json!({}),
        }
    }

    /// Exports all root types as ISF JSON.
    ///
    /// Generates function data and returns the resultant JSON object.
    ///
    /// # Arguments
    ///
    /// * `monitor` - The task monitor for progress reporting
    ///
    /// # Returns
    ///
    /// A JSON object containing the exported function data
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the operation is cancelled by the user.
    pub fn get_root_object(&mut self, monitor: &dyn TaskMonitor) -> Result<JsonValue, CancelledException> {
        self.gen_functions(monitor)?;
        Ok(self.data.clone())
    }

    fn gen_functions(&mut self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        // Initialize data to an empty object
        // Subclasses would override this to generate actual function data
        self.data = json!({});
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_root_object_returns_empty_json_object() {
        let mut writer = ExtFunctionWriter {
            data: json!({}),
        };
        let dummy_monitor = crate::util::task::DummyMonitor;

        let result = writer.get_root_object(&dummy_monitor);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));
    }

    #[test]
    fn multiple_calls_to_get_root_object_return_consistent_result() {
        let mut writer = ExtFunctionWriter {
            data: json!({}),
        };
        let dummy_monitor = crate::util::task::DummyMonitor;

        let result1 = writer.get_root_object(&dummy_monitor);
        let result2 = writer.get_root_object(&dummy_monitor);

        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn gen_functions_initializes_data_to_empty_object() {
        let mut writer = ExtFunctionWriter {
            data: json!({"old": "data"}),
        };
        let dummy_monitor = crate::util::task::DummyMonitor;

        let result = writer.gen_functions(&dummy_monitor);

        assert!(result.is_ok());
        assert_eq!(writer.data, json!({}));
    }
}
