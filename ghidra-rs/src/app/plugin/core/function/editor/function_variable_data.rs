use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::variable_storage::VariableStorage;

/// Backing data for a single row (parameter or the return variable) in the function-editor
/// model.
///
/// Port of `ghidra.app.plugin.core.function.editor.FunctionVariableData`. The Java interface has
/// package-private (default) access, reflecting that it is an internal collaborator of the
/// function editor model; this port keeps it `pub` since Rust has no package-private visibility
/// tier narrower than the crate.
pub trait FunctionVariableData {
    /// Returns the parameter ordinal, or `None` for the return variable. Mirrors `getIndex()`.
    fn get_index(&self) -> Option<i32>;

    /// Sets the variable's storage. Mirrors `setStorage(VariableStorage)`.
    fn set_storage(&mut self, storage: Box<dyn VariableStorage>);

    /// Sets the variable's name. Mirrors `setName(String)`.
    fn set_name(&mut self, name: &str);

    /// Sets the variable's formal (declared) data type, returning whether the change was
    /// applied. Mirrors `setFormalDataType(DataType)`.
    fn set_formal_data_type(&mut self, data_type: Box<dyn DataType>) -> bool;

    /// Returns the variable's storage. Mirrors `getStorage()`.
    fn get_storage(&self) -> Box<dyn VariableStorage>;

    /// Returns the variable's name. Mirrors `getName()`.
    fn get_name(&self) -> String;

    /// Returns the variable's formal (declared) data type. Mirrors `getFormalDataType()`.
    fn get_formal_data_type(&self) -> Box<dyn DataType>;

    /// Returns whether this variable's storage conflicts with another variable's storage.
    /// Mirrors `hasStorageConflict()`.
    fn has_storage_conflict(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal test double proving the trait's shape: a row that tracks a name and an index,
    /// with `set_formal_data_type` reporting `false` (rejected) once a conflict flag is set --
    /// enough to exercise every method without needing real `DataType`/`VariableStorage`
    /// implementors.
    struct RowData {
        index: Option<i32>,
        name: String,
        storage_conflict: bool,
        reject_data_type_changes: bool,
    }

    impl FunctionVariableData for RowData {
        fn get_index(&self) -> Option<i32> {
            self.index
        }

        fn set_storage(&mut self, _storage: Box<dyn VariableStorage>) {
            // Test double: storage isn't tracked, only that the call is accepted.
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn set_formal_data_type(&mut self, _data_type: Box<dyn DataType>) -> bool {
            !self.reject_data_type_changes
        }

        fn get_storage(&self) -> Box<dyn VariableStorage> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_storage_conflict(&self) -> bool {
            self.storage_conflict
        }
    }

    fn parameter_row() -> RowData {
        RowData {
            index: Some(0),
            name: "param0".to_string(),
            storage_conflict: false,
            reject_data_type_changes: false,
        }
    }

    fn return_row() -> RowData {
        RowData {
            index: None,
            name: "return".to_string(),
            storage_conflict: false,
            reject_data_type_changes: false,
        }
    }

    #[test]
    fn get_index_distinguishes_parameter_from_return_variable() {
        assert_eq!(parameter_row().get_index(), Some(0));
        assert_eq!(return_row().get_index(), None);
    }

    #[test]
    fn set_name_and_get_name_round_trip() {
        let mut row = parameter_row();
        row.set_name("newName");
        assert_eq!(row.get_name(), "newName");
    }

    #[test]
    fn has_storage_conflict_reflects_flag() {
        let mut row = parameter_row();
        assert!(!row.has_storage_conflict());
        row.storage_conflict = true;
        assert!(row.has_storage_conflict());
    }

    /// A `DataType` every one of whose methods is defaulted; used purely as a value to pass
    /// through `set_formal_data_type`'s trait-object parameter.
    struct StubDataType;
    impl DataType for StubDataType {}

    #[test]
    fn set_formal_data_type_returns_acceptance() {
        let mut row = parameter_row();
        assert!(row.set_formal_data_type(Box::new(StubDataType)));

        row.reject_data_type_changes = true;
        assert!(!row.set_formal_data_type(Box::new(StubDataType)));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let row: Box<dyn FunctionVariableData> = Box::new(parameter_row());
        assert_eq!(row.get_index(), Some(0));
        assert_eq!(row.get_name(), "param0");
    }
}
