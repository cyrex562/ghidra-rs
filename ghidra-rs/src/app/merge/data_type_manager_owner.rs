use crate::program::model::data::data_type_manager::DataTypeManager;

/// Trait for objects that own or manage a data type manager.
///
/// Port of `ghidra.app.merge.DataTypeManagerOwner`.
pub trait DataTypeManagerOwner {
    /// Gets the associated data type manager.
    fn get_data_type_manager(&self) -> &dyn DataTypeManager;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataTypeManager;

    impl DataTypeManager for MockDataTypeManager {}

    struct TestOwner {
        manager: MockDataTypeManager,
    }

    impl DataTypeManagerOwner for TestOwner {
        fn get_data_type_manager(&self) -> &dyn DataTypeManager {
            &self.manager
        }
    }

    #[test]
    fn returns_data_type_manager() {
        let owner = TestOwner {
            manager: MockDataTypeManager,
        };
        let manager = owner.get_data_type_manager();
        assert_eq!(manager.get_universal_id().value(), 0);
    }

    #[test]
    fn usable_as_trait_object() {
        let owner = TestOwner {
            manager: MockDataTypeManager,
        };
        let dyn_owner: &dyn DataTypeManagerOwner = &owner;
        let manager = dyn_owner.get_data_type_manager();
        assert_eq!(manager.get_universal_id().value(), 0);
    }
}
