use crate::docking::settings::settings::Settings;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::listing::program::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::util::table::field::program_location_table_column::ProgramLocationTableColumn;

/// A convenience trait that allows implementors to signal that they implement
/// [`ProgramLocationTableColumn`], but they do not want to be [`ExtensionPoint`](crate::util::classfinder::extension_point::ExtensionPoint)s.
/// For those wishing to be ExtensionPoints, see a separate extension point type.
///
/// This trait provides a concrete anchor point for implementations that wish to supply custom
/// column rendering for program-aware table cells that can also provide a [`ProgramLocation`]
/// for navigation, without being registered as an extension point.
///
/// Port of `ghidra.util.table.field.AbstractProgramLocationTableColumn`.
pub trait AbstractProgramLocationTableColumn<ROW_TYPE, COLUMN_TYPE>:
    ProgramLocationTableColumn<ROW_TYPE, COLUMN_TYPE>
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {
        fn is_immutable_settings(&self) -> bool {
            false
        }
    }

    struct MockServiceProvider;
    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn add_service_listener(&mut self, _listener: Box<dyn crate::framework::plugintool::ServiceListener>) {
        }
        fn remove_service_listener(&mut self, _listener: Box<dyn crate::framework::plugintool::ServiceListener>) {
        }
    }

    struct MockProgramLocation {
        address: crate::program::model::address::Address,
    }

    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> crate::program::model::address::Address {
            self.address.clone()
        }
    }

    struct ConcreteColumn;
    impl crate::util::table::field::program_based_dynamic_table_column::ProgramBasedDynamicTableColumn
        for ConcreteColumn
    {
    }
    impl ProgramLocationTableColumn<String, String> for ConcreteColumn {
        fn get_program_location(
            &self,
            _row_object: &String,
            _settings: &dyn Settings,
            _program: &dyn Program,
            _service_provider: &dyn ServiceProvider,
        ) -> Box<dyn ProgramLocation> {
            let ram = crate::program::model::address::AddressSpace::new(
                "ram",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                0,
            );
            let addr = crate::program::model::address::Address::new(ram, 0x1000);
            Box::new(MockProgramLocation { address: addr })
        }
    }
    impl AbstractProgramLocationTableColumn<String, String> for ConcreteColumn {}

    #[test]
    fn abstract_trait_can_be_implemented() {
        let col = ConcreteColumn;
        let program = MockProgram;
        let settings = MockSettings;
        let provider = MockServiceProvider;

        let row = "test_row".to_string();
        let location = col.get_program_location(&row, &settings, &program, &provider);

        assert_eq!(location.get_address().space().name(), "ram");
        assert_eq!(location.get_address().offset(), 0x1000);
    }

    #[test]
    fn multiple_implementations_can_coexist() {
        struct ColumnA;
        impl crate::util::table::field::program_based_dynamic_table_column::ProgramBasedDynamicTableColumn
            for ColumnA
        {
        }
        impl ProgramLocationTableColumn<i32, String> for ColumnA {
            fn get_program_location(
                &self,
                _row_object: &i32,
                _settings: &dyn Settings,
                _program: &dyn Program,
                _service_provider: &dyn ServiceProvider,
            ) -> Box<dyn ProgramLocation> {
                let ram = crate::program::model::address::AddressSpace::new(
                    "ram",
                    32,
                    1,
                    crate::program::model::address::AddressSpaceType::Ram,
                    0,
                );
                let addr = crate::program::model::address::Address::new(ram, 0x2000);
                Box::new(MockProgramLocation { address: addr })
            }
        }
        impl AbstractProgramLocationTableColumn<i32, String> for ColumnA {}

        struct ColumnB;
        impl crate::util::table::field::program_based_dynamic_table_column::ProgramBasedDynamicTableColumn
            for ColumnB
        {
        }
        impl ProgramLocationTableColumn<String, i32> for ColumnB {
            fn get_program_location(
                &self,
                _row_object: &String,
                _settings: &dyn Settings,
                _program: &dyn Program,
                _service_provider: &dyn ServiceProvider,
            ) -> Box<dyn ProgramLocation> {
                let ram = crate::program::model::address::AddressSpace::new(
                    "ram",
                    32,
                    1,
                    crate::program::model::address::AddressSpaceType::Ram,
                    0,
                );
                let addr = crate::program::model::address::Address::new(ram, 0x3000);
                Box::new(MockProgramLocation { address: addr })
            }
        }
        impl AbstractProgramLocationTableColumn<String, i32> for ColumnB {}

        let col_a = ColumnA;
        let col_b = ColumnB;
        let program = MockProgram;
        let settings = MockSettings;
        let provider = MockServiceProvider;

        let loc_a = col_a.get_program_location(&42, &settings, &program, &provider);
        let loc_b = col_b.get_program_location(&"test".to_string(), &settings, &program, &provider);

        assert_eq!(loc_a.get_address().offset(), 0x2000);
        assert_eq!(loc_b.get_address().offset(), 0x3000);
    }
}
