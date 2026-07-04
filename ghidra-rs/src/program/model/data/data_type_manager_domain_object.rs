use crate::program::seam_stubs::{DataTypeManagerOwner, DomainObject};

/// Marker trait for a domain object that also owns a data type manager.
///
/// Port of `ghidra.program.model.data.DataTypeManagerDomainObject`.
pub trait DataTypeManagerDomainObject: DomainObject + DataTypeManagerOwner {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::seam_stubs::DataTypeManager;

    struct MockDataTypeManager;

    impl DataTypeManager for MockDataTypeManager {}

    struct MockDomainObject;

    impl DomainObject for MockDomainObject {}

    impl DataTypeManagerOwner for MockDomainObject {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockDomainObject {}

    #[test]
    fn usable_as_trait_object() {
        let obj = MockDomainObject;
        let dyn_obj: &dyn DataTypeManagerDomainObject = &obj;
        let _mgr = dyn_obj.get_data_type_manager();
    }
}
