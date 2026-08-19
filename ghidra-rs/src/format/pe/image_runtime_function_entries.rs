use crate::program::model::listing::program::Program;
use crate::program::model::address::Address;
use crate::format::seam_stubs::MessageLog;

/// Interface for working with function table entries used for exception handling,
/// which are found in the .pdata section. The actual implementations are
/// architecture-specific.
///
/// Port of `ghidra.app.util.bin.format.pe.ImageRuntimeFunctionEntries`.
pub trait ImageRuntimeFunctionEntries: Send + Sync {
    /// Marks up an ImageRuntimeFunctionEntries.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to mark up
    /// * `start` - The start address
    /// * `log` - The message log for recording operations and errors
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An I/O error occurs
    /// - A duplicate name exception occurs
    /// - A code unit insertion exception occurs
    fn markup(
        &self,
        program: &dyn Program,
        start: Address,
        log: &dyn MessageLog,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::framework::model::DomainObject;

    struct MockProgram;

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "TestProgram".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:32:default".to_string()
        }
        fn get_language(&self) -> Option<Arc<dyn crate::program::model::lang::Language>> {
            None
        }
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            None
        }
        fn get_loaded_and_initialized_address_set(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn get_all_initialized_address_set(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            None
        }
        fn get_memory(&self) -> Option<Arc<dyn crate::program::model::mem::Memory>> {
            None
        }
        fn get_global_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
        fn get_reference_manager(
            &mut self,
        ) -> Option<&mut dyn crate::program::model::symbol::ReferenceManager> {
            None
        }
        fn get_equate_table(
            &mut self,
        ) -> Option<&mut dyn crate::program::model::symbol::EquateTable> {
            None
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn crate::program::model::symbol::SymbolTable> {
            None
        }
        fn get_external_manager(
            &mut self,
        ) -> Option<&mut dyn crate::program::model::symbol::ExternalManager> {
            None
        }
        fn get_function_manager(
            &mut self,
        ) -> Option<&mut dyn crate::program::model::listing::FunctionManager> {
            None
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn crate::program::model::data::data_type_manager::DataTypeManager>> {
            None
        }
        fn get_executable_path(&self) -> String {
            "test.exe".to_string()
        }
        fn get_executable_format(&self) -> String {
            "PE".to_string()
        }
        fn get_compiler(&self) -> String {
            "unknown".to_string()
        }
        fn get_compiler_spec_id(
            &self,
        ) -> Option<crate::program::model::lang::CompilerSpecID> {
            None
        }
        fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_register_at(&self, _address: &crate::program::model::address::Address) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_compiler_spec(&self) -> Option<Box<dyn crate::program::model::lang::CompilerSpec>> {
            None
        }
        fn get_program_context(
            &mut self,
        ) -> Option<&mut dyn crate::program::model::listing::ProgramContext> {
            None
        }
        fn get_image_base(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn get_address_map(&self) -> Option<Arc<dyn crate::program::database::map::address_map::AddressMap>> {
            None
        }
    }

    struct MockMessageLog;

    impl MessageLog for MockMessageLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, _message: &str) {}
        fn append_exception(&self, _t: &dyn crate::format::seam_stubs::Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            false
        }
        fn clear(&self) {}
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            String::new()
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    struct TestRuntimeEntries;

    impl ImageRuntimeFunctionEntries for TestRuntimeEntries {
        fn markup(
            &self,
            _program: &dyn Program,
            _start: Address,
            _log: &dyn MessageLog,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let entries: Box<dyn ImageRuntimeFunctionEntries> = Box::new(TestRuntimeEntries);
        let program = MockProgram;
        let log = MockMessageLog;

        // Need to create an Address - let's use the default address space
        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0x1000);

        let result = entries.markup(&program, start, &log);
        assert!(result.is_ok());
    }

    #[test]
    fn markup_returns_ok() {
        let entries = TestRuntimeEntries;
        let program = MockProgram;
        let log = MockMessageLog;

        let space = crate::program::model::address::AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0x2000);

        let result = entries.markup(&program, start, &log);
        assert!(result.is_ok());
    }
}
