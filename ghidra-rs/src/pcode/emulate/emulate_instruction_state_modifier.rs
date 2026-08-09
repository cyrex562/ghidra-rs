use std::collections::HashMap;

use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::opbehavior::OpBehaviorOther;
use crate::pcode::seam_stubs::{Emulate, RegisterValue};
use crate::program::model::address::Address;
use crate::program::model::lang::Language;
use crate::program::model::pcode::PcodeOp;

/// The shared state and concrete behavior of a language-specific emulation state modifier.
///
/// Java's `EmulateInstructionStateModifier` is an abstract class carrying the `emu`/`language`
/// fields and the CALLOTHER dispatch table (`pcodeOpMap`), plus the `final` methods that operate
/// on them. Rust has no field inheritance, so this struct holds that state; a concrete modifier
/// embeds it and implements [`EmulateInstructionStateModifier`] for the two overridable callbacks.
///
/// Corresponds to `ghidra.pcode.emulate.EmulateInstructionStateModifier`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal; use `PcodeUseropLibrary` or
/// `AnnotatedPcodeUseropLibrary` instead.
#[deprecated(since = "12.1", note = "use PcodeUseropLibrary or AnnotatedPcodeUseropLibrary instead")]
pub struct EmulateInstructionStateModifierBase {
    emu: Box<dyn Emulate>,
    language: Box<dyn Language>,
    pcode_op_map: HashMap<i32, Box<dyn OpBehaviorOther>>,
}

#[allow(deprecated)]
impl EmulateInstructionStateModifierBase {
    /// Port of the protected constructor `EmulateInstructionStateModifier(Emulate emu)`.
    pub fn new(emu: Box<dyn Emulate>) -> Self {
        let language = emu.get_language();
        Self {
            emu,
            language,
            pcode_op_map: HashMap::new(),
        }
    }

    /// The emulator this modifier is attached to. Port of the protected `emu` field.
    pub fn emu(&self) -> &dyn Emulate {
        self.emu.as_ref()
    }

    /// The language of the associated emulator. Port of the protected `language` field.
    pub fn language(&self) -> &dyn Language {
        self.language.as_ref()
    }

    /// Register a pcodeop behavior corresponding to a CALLOTHER opcode.
    ///
    /// Port of `registerPcodeOpBehavior(String, OpBehaviorOther)`.
    ///
    /// # Arguments
    /// * `op_name` - name as defined within language via "define pcodeop"
    /// * `pcode_op_behavior` - the behavior to invoke for this pcodeop
    ///
    /// # Errors
    /// Returns a [`LowlevelError`] if `op_name` is not a user-defined op name of this language.
    pub fn register_pcode_op_behavior(
        &mut self,
        op_name: &str,
        pcode_op_behavior: Box<dyn OpBehaviorOther>,
    ) -> Result<(), LowlevelError> {
        let num_user_ops = self.language.get_number_of_user_defined_op_names();
        for i in 0..num_user_ops {
            if self.language.get_user_defined_op_name(i).as_deref() == Some(op_name) {
                self.pcode_op_map.insert(i, pcode_op_behavior);
                return Ok(());
            }
        }
        Err(LowlevelError::with_message(format!(
            "Undefined pcodeop name: {op_name}"
        )))
    }

    /// Execute a CALLOTHER op.
    ///
    /// Port of `executeCallOther(PcodeOp)`.
    ///
    /// # Returns
    /// `true` if a corresponding pcodeop was registered and emulation support was performed, or
    /// `false` if the corresponding pcodeop is not supported by this modifier.
    pub fn execute_call_other(&self, op: &PcodeOp) -> bool {
        if self.pcode_op_map.is_empty() {
            return false;
        }
        let index = op.inputs[0].get_offset() as i32;
        let Some(op_behavior_other) = self.pcode_op_map.get(&index) else {
            return false;
        };

        // Strip off the first input before passing inputs to OpBehaviorOther.
        let call_other_inputs = &op.inputs[1..];
        op_behavior_other.evaluate(self.emu.as_ref(), op.output.as_ref(), call_other_inputs);
        true
    }

    /// Get the map of registered pcode userop behaviors, keyed by userop index.
    ///
    /// Port of `getPcodeOpMap()`.
    pub fn get_pcode_op_map(&self) -> &HashMap<i32, Box<dyn OpBehaviorOther>> {
        &self.pcode_op_map
    }
}

/// The overridable emulation callbacks of an
/// [`EmulateInstructionStateModifierBase`]-backed language-specific state modifier.
///
/// Java gives both callbacks empty default bodies, meant to be overridden by language-specific
/// subclasses; this trait's default methods do the same.
///
/// Corresponds to `ghidra.pcode.emulate.EmulateInstructionStateModifier`.
#[allow(deprecated)]
pub trait EmulateInstructionStateModifier {
    /// Emulation callback immediately before the first instruction is executed. This callback
    /// permits any language specific initializations to be performed.
    ///
    /// Port of `initialExecuteCallback(Emulate, Address, RegisterValue)`.
    ///
    /// # Arguments
    /// * `emulate` - the emulator
    /// * `current_address` - initial execute address
    /// * `context_register_value` - initial context value, or `None` if not applicable or unknown
    fn initial_execute_callback(
        &self,
        _emulate: &dyn Emulate,
        _current_address: &Address,
        _context_register_value: Option<&dyn RegisterValue>,
    ) -> Result<(), LowlevelError> {
        // no default implementation
        Ok(())
    }

    /// Emulation callback immediately following execution of the last-executed address. One use
    /// of this callback is to modify the flowing/future context state.
    ///
    /// Port of `postExecuteCallback(Emulate, Address, PcodeOp[], int, Address)`.
    ///
    /// # Arguments
    /// * `emulate` - the emulator
    /// * `last_execute_address` - the address of the last-executed instruction
    /// * `last_execute_pcode` - the pcode of the last-executed instruction
    /// * `last_pcode_index` - pcode index of the last op, or -1 if no pcode or fall-through
    ///   occurred
    /// * `current_address` - the current execute address
    fn post_execute_callback(
        &self,
        _emulate: &dyn Emulate,
        _last_execute_address: &Address,
        _last_execute_pcode: &[PcodeOp],
        _last_pcode_index: i32,
        _current_address: &Address,
    ) -> Result<(), LowlevelError> {
        // no default implementation
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};
    use std::sync::{Arc, Mutex};

    struct MockLanguage {
        user_defined_op_names: Vec<&'static str>,
    }

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
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("test should not call this")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("test should not call this")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
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
        fn is_volatile(&self, _addr: &Address) -> bool {
            unimplemented!("test should not call this")
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::InstructionPrototype>,
            crate::program::model::lang::ParseError,
        > {
            unimplemented!("test should not call this")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            self.user_defined_op_names.len() as i32
        }
        fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
            self.user_defined_op_names
                .get(index as usize)
                .map(|s| s.to_string())
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
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
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<crate::program::model::lang::RegisterRef> {
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
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("test should not call this")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext,
        ) {
            unimplemented!("test should not call this")
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
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
        ) -> Result<
            Box<dyn crate::program::model::lang::CompilerSpec>,
            crate::program::model::lang::CompilerSpecNotFoundException,
        > {
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
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
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
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("test should not call this")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unimplemented!("test should not call this")
        }
    }

    struct MockEmulate {
        user_defined_op_names: Vec<&'static str>,
    }

    impl Emulate for MockEmulate {
        fn dispose(&self) {}

        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage {
                user_defined_op_names: self.user_defined_op_names.clone(),
            })
        }
    }

    struct RecordingBehavior {
        calls: Arc<Mutex<Vec<(Option<Varnode>, Vec<Varnode>)>>>,
    }

    impl OpBehaviorOther for RecordingBehavior {
        fn evaluate(&self, _emu: &dyn Emulate, out: Option<&Varnode>, inputs: &[Varnode]) {
            self.calls
                .lock()
                .unwrap()
                .push((out.cloned(), inputs.to_vec()));
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(crate::program::model::address::Address::new(ram(), offset), size)
    }

    fn modifier_with_ops(names: Vec<&'static str>) -> EmulateInstructionStateModifierBase {
        let emu = Box::new(MockEmulate { user_defined_op_names: names });
        EmulateInstructionStateModifierBase::new(emu)
    }

    #[test]
    fn new_resolves_language_from_emulate() {
        // Java: `this.language = emu.getLanguage();` in the constructor.
        let modifier = modifier_with_ops(vec!["myop"]);
        assert_eq!(modifier.language().get_number_of_user_defined_op_names(), 1);
    }

    #[test]
    fn get_pcode_op_map_starts_empty() {
        // Java: `getPcodeOpMap()` returns `Map.of()` when nothing has been registered.
        let modifier = modifier_with_ops(vec![]);
        assert!(modifier.get_pcode_op_map().is_empty());
    }

    #[test]
    fn register_pcode_op_behavior_finds_op_by_name() {
        let mut modifier = modifier_with_ops(vec!["foo", "myop", "bar"]);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let behavior = Box::new(RecordingBehavior { calls: Arc::clone(&calls) });

        modifier
            .register_pcode_op_behavior("myop", behavior)
            .expect("myop is a defined userop name");

        // Registered under index 1, matching its position in getUserDefinedOpName.
        assert!(modifier.get_pcode_op_map().contains_key(&1));
    }

    #[test]
    fn register_pcode_op_behavior_rejects_unknown_name() {
        // Java: `throw new LowlevelError("Undefined pcodeop name: " + opName);`
        let mut modifier = modifier_with_ops(vec!["foo"]);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let behavior = Box::new(RecordingBehavior { calls });

        let err = modifier
            .register_pcode_op_behavior("nope", behavior)
            .unwrap_err();
        assert_eq!(err.message(), "Undefined pcodeop name: nope");
    }

    #[test]
    fn execute_call_other_returns_false_when_nothing_registered() {
        let modifier = modifier_with_ops(vec![]);
        let op = PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(ram().address(0), 0),
            vec![varnode(0, 4)],
            None,
        );
        assert!(!modifier.execute_call_other(&op));
    }

    #[test]
    fn execute_call_other_returns_false_for_unregistered_index() {
        let mut modifier = modifier_with_ops(vec!["myop"]);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let behavior = Box::new(RecordingBehavior { calls: Arc::clone(&calls) });
        modifier.register_pcode_op_behavior("myop", behavior).unwrap();

        // Index 0 is registered; call with index 5 instead.
        let op = PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(ram().address(0), 0),
            vec![varnode(5, 4)],
            None,
        );
        assert!(!modifier.execute_call_other(&op));
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn execute_call_other_strips_the_index_input_and_invokes_the_behavior() {
        let mut modifier = modifier_with_ops(vec!["myop"]);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let behavior = Box::new(RecordingBehavior { calls: Arc::clone(&calls) });
        modifier.register_pcode_op_behavior("myop", behavior).unwrap();

        let out = varnode(0x2000, 4);
        let in1 = varnode(0x1000, 4);
        let in2 = varnode(0x1004, 4);
        let op = PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(ram().address(0), 0),
            // Index 0 selects the registered behavior; only in1/in2 should reach it.
            vec![varnode(0, 4), in1.clone(), in2.clone()],
            Some(out.clone()),
        );

        assert!(modifier.execute_call_other(&op));

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let (recorded_out, recorded_inputs) = &recorded[0];
        assert_eq!(recorded_out.as_ref(), Some(&out));
        assert_eq!(recorded_inputs, &vec![in1, in2]);
    }

    struct DefaultModifier;
    impl EmulateInstructionStateModifier for DefaultModifier {}

    #[test]
    fn default_callbacks_are_no_ops() {
        // Java: both callbacks have empty default bodies, meant to be overridden by subclasses.
        let modifier = DefaultModifier;
        let emu = MockEmulate { user_defined_op_names: vec![] };
        let addr = ram().address(0);

        assert!(modifier.initial_execute_callback(&emu, &addr, None).is_ok());
        assert!(modifier
            .post_execute_callback(&emu, &addr, &[], -1, &addr)
            .is_ok());
    }
}
