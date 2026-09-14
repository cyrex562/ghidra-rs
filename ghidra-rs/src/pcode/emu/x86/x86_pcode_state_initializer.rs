//! Port of `ghidra.pcode.emu.x86.X86PcodeStateInitializer`.

use crate::pcode::emu::pcode_state_initializer::PcodeStateInitializer;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::program::model::lang::Language;
use crate::util::classfinder::ExtensionPoint;
use crate::util::msg::Msg;

/// Would-be initializer for x86's `FS_OFFSET`/`GS_OFFSET` segment-base pseudo-registers.
///
/// Port of `ghidra.pcode.emu.x86.X86PcodeStateInitializer`. Java's `isApplicable` has its real
/// body -- `LANG_IDS.contains(language.getLanguageID())`, checking for `x86:LE:32:default` /
/// `x86:LE:64:default` -- commented out in favor of a bare `return false;`, so in the real Java
/// class this initializer never actually applies to any language, x86 included.
/// [`Self::is_applicable`] reproduces that faithfully rather than "fixing" it: see
/// [`is_applicable_always_returns_false_even_for_x86`](tests::is_applicable_always_returns_false_even_for_x86).
#[derive(Default)]
pub struct X86PcodeStateInitializer;

impl X86PcodeStateInitializer {
    pub fn new() -> Self {
        Self
    }
}

impl ExtensionPoint for X86PcodeStateInitializer {}

impl PcodeStateInitializer for X86PcodeStateInitializer {
    /// `X86PcodeStateInitializer.isApplicable(Language)`. Always `false` -- see the struct doc.
    fn is_applicable(&self, _language: &dyn Language) -> bool {
        false
    }

    /// `X86PcodeStateInitializer.initializeThread(PcodeThread<T>)`.
    ///
    /// Java logs the warning below unconditionally, then compiles `FS_OFFSET = 0; GS_OFFSET =
    /// 0;` as a Sleigh initializer and executes it against the thread's userop library. This
    /// crate's [`ErasedPcodeThread`] -- the type-erased stand-in Rust needs since Java's
    /// `initializeThread` is generic over `T` (see [`PcodeStateInitializer`]'s own doc comment)
    /// -- only exposes the stepping methods `StepKind` needs so far, not
    /// `getMachine().compileSleigh(...)`/`getExecutor().execute(...)`. In practice this method is
    /// unreachable anyway, since [`Self::is_applicable`] always returns `false`; the warning --
    /// the one side effect Java performs before touching either the machine or the executor -- is
    /// preserved here regardless.
    fn initialize_thread(&self, _thread: &dyn ErasedPcodeThread) {
        Msg::warn(
            "X86PcodeStateInitializer",
            &"Segmentation is not emulated. Initializing FS_OFFSET and FS_OFFSET to 0.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
    use crate::util::error_logger::ErrorLogger;
    use std::fmt::Display;
    use std::sync::{Arc, Mutex};

    struct MockLanguage {
        language_id: crate::program::model::lang::LanguageID,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            self.language_id.clone()
        }

        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::LanguageDescription> {
            unimplemented!("test should not call this")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>>
        {
            unimplemented!("test should not call this")
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("test should not call this")
        }

        fn get_version(&self) -> i32 {
            unimplemented!("test should not call this")
        }

        fn get_minor_version(&self) -> i32 {
            unimplemented!("test should not call this")
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory>
        {
            unimplemented!("test should not call this")
        }

        fn get_default_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("test should not call this")
        }

        fn get_default_data_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("test should not call this")
        }

        fn is_big_endian(&self) -> bool {
            unimplemented!("test should not call this")
        }

        fn get_instruction_alignment(&self) -> i32 {
            unimplemented!("test should not call this")
        }

        fn supports_pcode(&self) -> bool {
            unimplemented!("test should not call this")
        }

        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            unimplemented!("test should not call this")
        }

        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn crate::program::model::lang::InstructionPrototype>, crate::program::model::lang::ParseError>
        {
            unimplemented!("test should not call this")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            unimplemented!("test should not call this")
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            unimplemented!("test should not call this")
        }

        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_register_in_space(
            &self,
            _addrspc: &Arc<crate::program::model::address::AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_register_names(&self) -> Vec<String> {
            unimplemented!("test should not call this")
        }

        fn get_register_by_name(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_program_counter(&self) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_context_base_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_context_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            unimplemented!("test should not call this")
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            unimplemented!("test should not call this")
        }

        fn get_segmented_space(&self) -> String {
            unimplemented!("test should not call this")
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView>
        {
            unimplemented!("test should not call this")
        }

        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext) {
            unimplemented!("test should not call this")
        }

        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            unimplemented!("test should not call this")
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            unimplemented!("test should not call this")
        }

        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<Box<dyn crate::program::model::lang::CompilerSpec>, crate::program::model::lang::CompilerSpecNotFoundException>
        {
            unimplemented!("test should not call this")
        }

        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("test should not call this")
        }

        fn has_property(&self, _key: &str) -> bool {
            unimplemented!("test should not call this")
        }

        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unimplemented!("test should not call this")
        }

        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unimplemented!("test should not call this")
        }

        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unimplemented!("test should not call this")
        }

        fn get_property(&self, _key: &str) -> Option<String> {
            unimplemented!("test should not call this")
        }

        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("test should not call this")
        }

        fn has_manual(&self) -> bool {
            unimplemented!("test should not call this")
        }

        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry>
        {
            unimplemented!("test should not call this")
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("test should not call this")
        }

        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            unimplemented!("test should not call this")
        }

        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView>
        {
            unimplemented!("test should not call this")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unimplemented!("test should not call this")
        }
    }

    struct MockPcodeThread;

    impl ErasedPcodeThread for MockPcodeThread {}

    #[test]
    fn is_applicable_always_returns_false_even_for_x86() {
        let initializer = X86PcodeStateInitializer::new();
        let x86_32 = MockLanguage {
            language_id: crate::program::model::lang::LanguageID::new("x86:LE:32:default").unwrap(),
        };
        let x86_64 = MockLanguage {
            language_id: crate::program::model::lang::LanguageID::new("x86:LE:64:default").unwrap(),
        };
        let arm = MockLanguage {
            language_id: crate::program::model::lang::LanguageID::new("ARM:LE:32:v8").unwrap(),
        };

        assert!(!initializer.is_applicable(&x86_32));
        assert!(!initializer.is_applicable(&x86_64));
        assert!(!initializer.is_applicable(&arm));
    }

    struct RecordingLogger {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl ErrorLogger for RecordingLogger {
        fn trace(&self, _originator: &str, _message: &dyn Display) {}
        fn trace_with_error(&self, _originator: &str, _message: &dyn Display, _error: &dyn std::error::Error) {}
        fn debug(&self, _originator: &str, _message: &dyn Display) {}
        fn debug_with_error(&self, _originator: &str, _message: &dyn Display, _error: &dyn std::error::Error) {}
        fn info(&self, _originator: &str, _message: &dyn Display) {}
        fn info_with_error(&self, _originator: &str, _message: &dyn Display, _error: &dyn std::error::Error) {}
        fn warn(&self, _originator: &str, message: &dyn Display) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn warn_with_error(&self, _originator: &str, _message: &dyn Display, _error: &dyn std::error::Error) {}
        fn error(&self, _originator: &str, _message: &dyn Display) {}
        fn error_with_error(&self, _originator: &str, _message: &dyn Display, _error: &dyn std::error::Error) {}
    }

    #[test]
    fn initialize_thread_logs_segmentation_warning() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        Msg::set_error_logger(Box::new(RecordingLogger { messages: messages.clone() }));

        let initializer = X86PcodeStateInitializer::new();
        initializer.initialize_thread(&MockPcodeThread);

        let logged = messages.lock().unwrap();
        assert_eq!(
            logged.last().map(String::as_str),
            Some("Segmentation is not emulated. Initializing FS_OFFSET and FS_OFFSET to 0.")
        );
    }

    #[test]
    fn extension_point_object_safety() {
        let initializer = X86PcodeStateInitializer::new();
        let _boxed: Box<dyn PcodeStateInitializer> = Box::new(initializer);
    }
}
