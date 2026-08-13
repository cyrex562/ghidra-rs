use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;
use crate::format::seam_stubs::{NTHeader, MessageLog};

/// Common interface for standardizing the markup of a PE structure.
///
/// Port of `ghidra.app.util.bin.format.pe.PeMarkupable`. Types implementing this trait
/// can annotate a program with PE-specific metadata and structures.
pub trait PeMarkupable: Send + Sync {
    /// Marks up a PE structure.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to markup
    /// * `is_binary` - True if the program is binary; otherwise, false
    /// * `monitor` - The task monitor for progress tracking
    /// * `log` - The message log for recording operations and errors
    /// * `nt_header` - The PE's NT Header structure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A duplicate name exception occurs during markup
    /// - A code unit insertion exception occurs
    /// - An I/O error occurs
    /// - A memory access exception occurs
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
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

    struct MockTaskMonitor;
    impl TaskMonitor for MockTaskMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            false
        }
        fn clear_cancelled(&self) {}
    }

    struct MockMessageLog {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl MockMessageLog {
        fn new() -> Self {
            Self {
                messages: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl MessageLog for MockMessageLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn append_exception(&self, _t: &dyn crate::format::seam_stubs::Throwable) {}
        fn error(&self, _originator: &str, message: &str) {
            self.messages.lock().unwrap().push(format!("ERROR: {}", message));
        }
        fn has_messages(&self) -> bool {
            !self.messages.lock().unwrap().is_empty()
        }
        fn clear(&self) {
            self.messages.lock().unwrap().clear();
        }
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            self.messages
                .lock()
                .unwrap()
                .join("\n")
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    struct MockNTHeader;

    impl NTHeader for MockNTHeader {
        fn get_name(&self) -> String {
            "NT Header".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> Box<dyn crate::format::seam_stubs::FileHeader> {
            unimplemented!()
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
            unimplemented!()
        }
        fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Not implemented",
            ))
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, _rva: i64) -> bool {
            true
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    struct TestMarkupable;

    impl PeMarkupable for TestMarkupable {
        fn markup(
            &self,
            _program: &dyn Program,
            is_binary: bool,
            _monitor: &dyn TaskMonitor,
            log: &dyn MessageLog,
            _nt_header: &dyn NTHeader,
        ) -> Result<(), Box<dyn std::error::Error>> {
            log.append_msg(&format!("Markup: binary={}", is_binary));
            Ok(())
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let markupable: Box<dyn PeMarkupable> = Box::new(TestMarkupable);
        let program = MockProgram;
        let monitor = MockTaskMonitor;
        let log = MockMessageLog::new();
        let nt_header = MockNTHeader;

        let result = markupable.markup(&program, true, &monitor, &log, &nt_header);
        assert!(result.is_ok());
        assert!(log.has_messages());
    }

    #[test]
    fn markup_with_binary_true() {
        let markupable = TestMarkupable;
        let program = MockProgram;
        let monitor = MockTaskMonitor;
        let log = MockMessageLog::new();
        let nt_header = MockNTHeader;

        let result = markupable.markup(&program, true, &monitor, &log, &nt_header);
        assert!(result.is_ok());
        let log_str = log.to_string();
        assert!(log_str.contains("binary=true"));
    }

    #[test]
    fn markup_with_binary_false() {
        let markupable = TestMarkupable;
        let program = MockProgram;
        let monitor = MockTaskMonitor;
        let log = MockMessageLog::new();
        let nt_header = MockNTHeader;

        let result = markupable.markup(&program, false, &monitor, &log, &nt_header);
        assert!(result.is_ok());
        let log_str = log.to_string();
        assert!(log_str.contains("binary=false"));
    }
}
