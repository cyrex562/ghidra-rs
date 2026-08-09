use crate::program::model::lang::Language;
use crate::pcode::emu::pcode_machine::ErasedPcodeMachine;
use crate::pcode::seam_stubs::PcodeThread;
use crate::util::classfinder::ExtensionPoint;
use std::sync::Arc;

/// An extension for preparing execution state for sleigh emulation.
///
/// As much as possible, it's highly-recommended to use Sleigh execution to perform any
/// modifications. This will help it remain agnostic to various state types.
///
/// Corresponds to `ghidra.pcode.emu.PcodeStateInitializer`.
pub trait PcodeStateInitializer: ExtensionPoint + Send + Sync {
    /// Check if this initializer applies to the given language.
    ///
    /// # Arguments
    /// * `language` - the language to check
    ///
    /// # Returns
    /// true if it applies, false otherwise
    fn is_applicable(&self, language: &dyn Language) -> bool;

    /// The machine's memory state has just been initialized, and additional initialization is
    /// needed for Sleigh execution.
    ///
    /// There's probably not much preparation of memory.
    ///
    /// # Arguments
    /// * `machine` - the newly-initialized machine
    ///
    /// Java declares this as a *generic* method, `<T> void initializeMachine(PcodeMachine<T>)`.
    /// A generic method would cost this trait its object safety, which an extension point cannot
    /// afford, so the machine arrives type-erased. See
    /// [`ErasedPcodeMachine`](crate::pcode::emu::pcode_machine::ErasedPcodeMachine).
    fn initialize_machine(&self, machine: &dyn ErasedPcodeMachine) {}

    /// The thread's register state has just been initialized, and additional initialization is
    /// needed for Sleigh execution.
    ///
    /// Initialization generally consists of setting "virtual" registers using data from the real
    /// ones. Virtual registers are those specified in the Sleigh, but which don't actually exist on
    /// the target processor. Often, they exist to simplify static analysis, but unfortunately cause
    /// a minor headache for dynamic execution.
    ///
    /// # Arguments
    /// * `thread` - the newly-initialized thread
    fn initialize_thread(&self, thread: &dyn PcodeThread) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine};
    use crate::pcode::seam_stubs::PcodeThread;

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            unimplemented!("test should not call this")
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

    struct MockPcodeMachine;

    impl ErasedPcodeMachine for MockPcodeMachine {}

    struct MockPcodeThread;

    impl PcodeThread for MockPcodeThread {}

    struct TestInitializer;

    impl ExtensionPoint for TestInitializer {}

    impl PcodeStateInitializer for TestInitializer {
        fn is_applicable(&self, _language: &dyn Language) -> bool {
            true
        }

        fn initialize_machine(&self, _machine: &dyn ErasedPcodeMachine) {
            // Test implementation
        }

        fn initialize_thread(&self, _thread: &dyn PcodeThread) {
            // Test implementation
        }
    }

    #[test]
    fn pcode_state_initializer_is_implementable() {
        let initializer = TestInitializer;
        assert!(initializer.is_applicable(&MockLanguage));
    }

    #[test]
    fn pcode_state_initializer_is_object_safe() {
        let initializer = TestInitializer;
        let _boxed: Box<dyn PcodeStateInitializer> = Box::new(initializer);
    }

    #[test]
    fn pcode_state_initializer_default_methods() {
        let initializer = TestInitializer;
        let machine = MockPcodeMachine;
        let thread = MockPcodeThread;

        // These should not panic
        initializer.initialize_machine(&machine);
        initializer.initialize_thread(&thread);
    }

    #[test]
    fn pcode_state_initializer_machine_traps() {
        // The `traps_read`/`traps_write` predicates the placeholder machine carried belong, in
        // Java, to `PcodeMachine.AccessKind`, not to the machine itself.
        assert!(AccessKind::R.traps_read());
        assert!(!AccessKind::R.traps_write());
    }
}
