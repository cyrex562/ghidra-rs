use crate::app::emulator::memory::EmulatorLoadData;
use crate::pcode::memstate::MemoryFaultHandler;
use crate::program::model::lang::Language;
use std::sync::Arc;

/// Provides the configuration for creating and operating an emulator.
///
/// This interface supplies the language definition, memory/register state, and
/// memory fault handling behavior needed to initialize and run an emulator.
///
/// Corresponds to `ghidra.app.emulator.EmulatorConfiguration`.
///
/// # Deprecation
/// Deprecated since Ghidra 12.1 and scheduled for removal.
#[deprecated(since = "12.1", note = "for removal")]
pub trait EmulatorConfiguration {
    /// Returns the language model for this emulator configuration.
    fn get_language(&self) -> Arc<dyn Language>;

    /// Returns the initial memory and register load data for the emulator.
    fn get_load_data(&self) -> Box<dyn EmulatorLoadData>;

    /// Returns the memory fault handler for this emulator configuration.
    fn get_memory_fault_handler(&self) -> Box<dyn MemoryFaultHandler>;

    /// Returns whether write-back of emulated memory changes is enabled.
    ///
    /// # Default
    /// Returns `false`.
    fn is_write_back_enabled(&self) -> bool {
        false
    }

    /// Returns the preferred memory page size in bytes for this emulator configuration.
    ///
    /// # Default
    /// Returns `0x1000` (4096 bytes).
    fn get_preferred_memory_page_size(&self) -> i32 {
        0x1000
    }

    /// Returns the name of the program counter register for this language.
    ///
    /// Retrieves the program counter register from the language and returns its name.
    /// If no program counter is defined, this panics with a descriptive error message.
    ///
    /// # Panics
    /// If the language has not defined a program counter register.
    fn get_program_counter_name(&self) -> String {
        let lang = self.get_language();
        match lang.get_program_counter() {
            Some(pc_reg) => {
                let pc = pc_reg.borrow();
                pc.name().to_string()
            }
            None => {
                let lang_id = lang.get_language_id();
                panic!(
                    "Language has not defined Program Counter Register: {}",
                    lang_id
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::emulator::memory::MemoryLoadImage;
    use crate::app::emulator::state::RegisterState;
    use crate::pcode::load_image::LoadImage;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::{LanguageID};
    use std::collections::{HashMap, HashSet};

    struct TestMemoryLoadImage {
        data: Vec<u8>,
    }

    impl TestMemoryLoadImage {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl LoadImage for TestMemoryLoadImage {
        fn load_fill(
            &self,
            buf: &mut [u8],
            size: i32,
            _addr: &Address,
            buf_offset: i32,
            _generate_initialized_mask: bool,
        ) -> Option<Vec<u8>> {
            let offset = buf_offset as usize;
            let len = (size as usize)
                .min(buf.len().saturating_sub(offset))
                .min(self.data.len());
            if len > 0 {
                buf[offset..offset + len].copy_from_slice(&self.data[..len]);
            }
            None
        }
    }

    impl MemoryLoadImage for TestMemoryLoadImage {
        fn write_back(&mut self, _bytes: &[u8], _size: i32, _addr: &Address, _offset: i32) {}

        fn dispose(&mut self) {
            self.data.clear();
        }
    }

    struct TestRegisterState {
        vals: HashMap<String, Vec<u8>>,
        initialized: HashMap<String, bool>,
    }

    impl TestRegisterState {
        fn new() -> Self {
            Self {
                vals: HashMap::new(),
                initialized: HashMap::new(),
            }
        }
    }

    impl RegisterState for TestRegisterState {
        fn keys(&self) -> HashSet<String> {
            self.vals.keys().cloned().collect()
        }

        fn vals(&self, key: &str) -> Option<Vec<u8>> {
            self.vals.get(key).cloned()
        }

        fn is_initialized(&self, key: &str) -> Option<bool> {
            self.initialized.get(key).copied()
        }

        fn set_vals(&mut self, key: &str, vals: &[u8], set_initialized: bool) {
            self.vals.insert(key.to_string(), vals.to_vec());
            if set_initialized {
                self.initialized.insert(key.to_string(), true);
            }
        }

        fn set_vals_long(&mut self, key: &str, val: i64, size: usize, set_initialized: bool) {
            let bytes = val.to_be_bytes();
            let start = bytes.len().saturating_sub(size);
            self.set_vals(key, &bytes[start..], set_initialized);
        }

        fn dispose(&mut self) {
            self.vals.clear();
            self.initialized.clear();
        }
    }

    struct TestMemoryFaultHandler;

    #[allow(deprecated)]
    impl MemoryFaultHandler for TestMemoryFaultHandler {
        fn uninitialized_read(
            &self,
            _address: &Address,
            _size: i32,
            _buf: &mut [u8],
            _buf_offset: i32,
        ) -> bool {
            false
        }

        fn unknown_address(&self, _address: &Address, _write: bool) -> bool {
            false
        }
    }

    struct TestLanguage {
        pc_register: Option<crate::program::model::lang::register::RegisterRef>,
    }

    impl TestLanguage {
        fn new(pc_register: Option<crate::program::model::lang::register::RegisterRef>) -> Self {
            Self { pc_register }
        }
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86", "64", "default", 1, 0)
        }

        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::LanguageDescription> {
            todo!()
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::seam_stubs::ParallelInstructionLanguageHelper>> {
            None
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            todo!()
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            todo!()
        }

        fn get_default_space(&self) -> Arc<AddressSpace> {
            Arc::new(AddressSpace::new("RAM", 64, 1, AddressSpaceType::Ram, 0))
        }

        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.get_default_space()
        }

        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_instruction_alignment(&self) -> i32 {
            1
        }

        fn supports_pcode(&self) -> bool {
            true
        }

        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }

        fn parse(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn crate::program::model::lang::InstructionPrototype>, crate::program::model::lang::ParseError>
        {
            todo!()
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }

        fn get_registers_at(&self, _address: &Address) -> Vec<crate::program::model::lang::register::RegisterRef> {
            vec![]
        }

        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            if let Some(ref pc) = self.pc_register {
                vec![pc.clone()]
            } else {
                vec![]
            }
        }

        fn get_register_names(&self) -> Vec<String> {
            if let Some(ref pc) = self.pc_register {
                vec![pc.borrow().name().to_string()]
            } else {
                vec![]
            }
        }

        fn get_register_by_name(&self, name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
            if let Some(ref pc) = self.pc_register {
                if pc.borrow().name() == name {
                    return Some(pc.clone());
                }
            }
            None
        }

        fn get_register_at(
            &self,
            _addr: &Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            self.pc_register.clone()
        }

        fn get_context_base_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            vec![]
        }

        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::program::seam_stubs::MemoryBlockDefinition>> {
            vec![]
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            vec![]
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            todo!()
        }

        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {
        }

        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::seam_stubs::CompilerSpecDescription>> {
            vec![]
        }

        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::seam_stubs::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::CompilerSpec>,
            crate::program::model::lang::CompilerSpecNotFoundException,
        > {
            todo!()
        }

        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            todo!()
        }

        fn has_property(&self, _key: &str) -> bool {
            false
        }

        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }

        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }

        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
    }

    struct TestEmulatorConfiguration {
        language: Arc<dyn Language>,
    }

    impl TestEmulatorConfiguration {
        fn new(language: Arc<dyn Language>) -> Self {
            Self { language }
        }
    }

    #[allow(deprecated)]
    impl EmulatorConfiguration for TestEmulatorConfiguration {
        fn get_language(&self) -> Arc<dyn Language> {
            self.language.clone()
        }

        fn get_load_data(&self) -> Box<dyn EmulatorLoadData> {
            Box::new(TestEmulatorLoadData)
        }

        fn get_memory_fault_handler(&self) -> Box<dyn MemoryFaultHandler> {
            Box::new(TestMemoryFaultHandler)
        }
    }

    struct TestEmulatorLoadData;

    impl EmulatorLoadData for TestEmulatorLoadData {
        fn get_memory_load_image(&self) -> Box<dyn MemoryLoadImage> {
            Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]))
        }

        fn get_initial_register_state(&self) -> Box<dyn RegisterState> {
            Box::new(TestRegisterState::new())
        }
    }

    #[test]
    fn test_is_write_back_enabled_default() {
        let lang = Arc::new(TestLanguage::new(None));
        let config = TestEmulatorConfiguration::new(lang);
        assert!(!config.is_write_back_enabled());
    }

    #[test]
    fn test_get_preferred_memory_page_size_default() {
        let lang = Arc::new(TestLanguage::new(None));
        let config = TestEmulatorConfiguration::new(lang);
        assert_eq!(config.get_preferred_memory_page_size(), 0x1000);
    }

    #[test]
    fn test_get_program_counter_name_success() {
        let ram = Arc::new(AddressSpace::new("RAM", 64, 1, AddressSpaceType::Ram, 0));
        let pc_addr = Address::new(ram, 0x0);
        let pc_register = Register::new("rip", "Instruction Pointer", pc_addr, 8, false, 4);

        let lang = Arc::new(TestLanguage::new(Some(pc_register)));
        let config = TestEmulatorConfiguration::new(lang);

        assert_eq!(config.get_program_counter_name(), "rip");
    }

    #[test]
    #[should_panic(expected = "Language has not defined Program Counter Register")]
    fn test_get_program_counter_name_panic_no_pc() {
        let lang = Arc::new(TestLanguage::new(None));
        let config = TestEmulatorConfiguration::new(lang);
        config.get_program_counter_name();
    }

    #[test]
    fn test_get_load_data() {
        let lang = Arc::new(TestLanguage::new(None));
        let config = TestEmulatorConfiguration::new(lang);
        let _load_data = config.get_load_data();
    }

    #[test]
    fn test_get_memory_fault_handler() {
        let lang = Arc::new(TestLanguage::new(None));
        let config = TestEmulatorConfiguration::new(lang);
        let _handler = config.get_memory_fault_handler();
    }
}
