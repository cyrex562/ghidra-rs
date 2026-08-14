//! Port of `ghidra.app.util.bin.format.elf.info.ElfInfoProducer`.
//!
//! Something that adds nice-to-have markup and program info to Elf binaries.
//!
//! Classes that implement this ExtensionPoint must have names that end with "ElfInfoProducer" for
//! the class searcher to find them.
//!
//! Instances are created for each Elf binary that is being loaded.

use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::util::classfinder::extension_point::ExtensionPoint;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Port of `ElfInfoProducer`.
///
/// Something that adds nice-to-have markup and program info to Elf binaries.
pub trait ElfInfoProducer: ExtensionPoint + Send + Sync {
    /// Initializes this instance.
    fn init(&self, elf_load_helper: &dyn ElfLoadHelper);

    /// Called by the Elf loader to give this ElfInfoProducer the opportunity to markup the Elf
    /// binary.
    fn markup_elf_info(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;
}

/// Returns a sorted list of new and initialized ElfInfoProducer instances.
///
/// Port of the static method `ElfInfoProducer.getElfInfoProducers(ElfLoadHelper)`.
/// This is a placeholder that uses the ClassSearcher stub to discover implementations.
pub fn get_elf_info_producers(elf_load_helper: &dyn ElfLoadHelper) -> Vec<Arc<dyn ElfInfoProducer>> {
    let mut result = crate::format::seam_stubs::ClassSearcher::get_elf_info_producer_instances();
    for producer in &result {
        producer.init(elf_load_helper);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestElfInfoProducer {
        init_called: Arc<Mutex<Vec<String>>>,
        markup_called: Arc<Mutex<Vec<String>>>,
    }

    impl ExtensionPoint for TestElfInfoProducer {}

    impl ElfInfoProducer for TestElfInfoProducer {
        fn init(&self, _elf_load_helper: &dyn ElfLoadHelper) {
            self.init_called.lock().unwrap().push("init_called".to_string());
        }

        fn markup_elf_info(&self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            self.markup_called.lock().unwrap().push("markup_called".to_string());
            Ok(())
        }
    }

    #[test]
    fn elf_info_producer_trait_is_implementable() {
        let init_log = Arc::new(Mutex::new(Vec::new()));
        let markup_log = Arc::new(Mutex::new(Vec::new()));

        let producer = TestElfInfoProducer {
            init_called: Arc::clone(&init_log),
            markup_called: Arc::clone(&markup_log),
        };

        // Test that we can create a trait object
        let _boxed: Box<dyn ElfInfoProducer> = Box::new(TestElfInfoProducer {
            init_called: Arc::clone(&init_log),
            markup_called: Arc::clone(&markup_log),
        });

        assert!(init_log.lock().unwrap().is_empty());
        assert!(markup_log.lock().unwrap().is_empty());
    }

    #[test]
    fn elf_info_producer_implements_init_method() {
        let init_log = Arc::new(Mutex::new(Vec::new()));
        let markup_log = Arc::new(Mutex::new(Vec::new()));

        let producer = TestElfInfoProducer {
            init_called: Arc::clone(&init_log),
            markup_called: Arc::clone(&markup_log),
        };

        // Mock ElfLoadHelper
        struct MockLoadHelper;
        impl ElfLoadHelper for MockLoadHelper {
            fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
                unimplemented!()
            }
            fn get_option_bool(&self, _: &str, default: bool) -> bool {
                default
            }
            fn get_option_string(&self, _: &str, default: std::option::Option<String>) -> std::option::Option<String> {
                default
            }
            fn get_option_i32(&self, _: &str, default: i32) -> i32 {
                default
            }
            fn get_elf_header(&self) -> Arc<dyn crate::format::seam_stubs::ElfHeader> {
                unimplemented!()
            }
            fn get_log(&self) -> Arc<dyn crate::format::seam_stubs::MessageLog> {
                unimplemented!()
            }
            fn log(&self, _: &str) {}
            fn log_exception(&self, _: &dyn std::error::Error) {}
            fn mark_as_code(&self, _: crate::program::model::address::Address) {}
            fn create_one_byte_function(
                &self,
                _: std::option::Option<&str>,
                _: crate::program::model::address::Address,
                _: bool,
            ) -> Arc<dyn crate::program::model::listing::function::Function> {
                unimplemented!()
            }
            fn create_external_function_linkage(
                &self,
                _: &str,
                _: crate::program::model::address::Address,
                _: std::option::Option<crate::program::model::address::Address>,
            ) -> std::option::Option<Arc<dyn crate::program::model::listing::function::Function>> {
                None
            }
            fn create_undefined_data(
                &self,
                _: crate::program::model::address::Address,
                _: i32,
            ) -> std::option::Option<Arc<dyn crate::program::model::listing::data::Data>> {
                None
            }
            fn create_data(
                &self,
                _: crate::program::model::address::Address,
                _: Box<dyn crate::program::model::data::data_type::DataType>,
            ) -> std::option::Option<Arc<dyn crate::program::model::listing::data::Data>> {
                None
            }
            fn set_elf_symbol_address(
                &self,
                _: &crate::format::elf::elf_symbol::ElfSymbol,
                _: std::option::Option<crate::program::model::address::Address>,
            ) {
            }
            fn get_elf_symbol_address(
                &self,
                _: &crate::format::elf::elf_symbol::ElfSymbol,
            ) -> std::option::Option<crate::program::model::address::Address> {
                None
            }
            fn create_symbol(
                &self,
                _: crate::program::model::address::Address,
                _: &str,
                _: bool,
                _: bool,
                _: std::option::Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
            ) -> Result<Arc<dyn crate::program::model::symbol::Symbol>, crate::util::exception::InvalidInputException> {
                unimplemented!()
            }
            fn find_load_address(
                &self,
                _: &dyn crate::format::memory_loadable::MemoryLoadable,
                _: i64,
            ) -> std::option::Option<crate::program::model::address::Address> {
                None
            }
            fn get_default_address(&self, _: i64) -> crate::program::model::address::Address {
                unimplemented!()
            }
            fn get_image_base_word_adjustment_offset(&self) -> i64 {
                0
            }
            fn get_got_value(&self) -> std::option::Option<i64> {
                None
            }
            fn allocate_linkage_block(
                &self,
                _: i32,
                _: i32,
                _: &str,
            ) -> std::option::Option<crate::program::model::address::range::AddressRange> {
                None
            }
            fn get_original_value(
                &self,
                _: crate::program::model::address::Address,
                _: bool,
            ) -> Result<i64, crate::program::model::mem::memory_access_exception::MemoryAccessException> {
                unimplemented!()
            }
            fn add_artificial_reloc_table_entry(&self, _: crate::program::model::address::Address, _: i32) -> bool {
                false
            }
        }

        let helper = MockLoadHelper;
        producer.init(&helper);

        assert_eq!(*init_log.lock().unwrap(), vec!["init_called"]);
    }

    #[test]
    fn elf_info_producer_implements_markup_elf_info_method() {
        let init_log = Arc::new(Mutex::new(Vec::new()));
        let markup_log = Arc::new(Mutex::new(Vec::new()));

        let producer = TestElfInfoProducer {
            init_called: Arc::clone(&init_log),
            markup_called: Arc::clone(&markup_log),
        };

        // Mock TaskMonitor
        struct MockTaskMonitor;
        impl crate::util::task::TaskMonitor for MockTaskMonitor {
            fn is_cancelled(&self) -> bool {
                false
            }
            fn set_show_progress_value(&self, _: bool) {}
            fn set_message(&self, _: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _: i64) {}
            fn initialize(&self, _: i64) {}
            fn set_maximum(&self, _: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Ok(())
            }
            fn increment_progress(&self, _: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                false
            }
            fn clear_cancelled(&self) {}
        }

        let monitor = MockTaskMonitor;
        let result = producer.markup_elf_info(&monitor);

        assert!(result.is_ok());
        assert_eq!(*markup_log.lock().unwrap(), vec!["markup_called"]);
    }
}
