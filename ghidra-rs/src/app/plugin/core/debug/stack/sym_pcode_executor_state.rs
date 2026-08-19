//! A symbolic state for stack unwind analysis.
//!
//! Port of `ghidra.app.plugin.core.debug.stack.SymPcodeExecutorState`.

use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::plugin::core::debug::stack::stack_unwind_warning::StackUnwindWarning;
use crate::app::plugin::core::debug::stack::sym::Sym;
use crate::app::seam_stubs::{SymPcodeArithmetic, SymStateSpace};
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::Program;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::seam_stubs::DumbMemBufferImpl;
use crate::util::msg::Msg;

/// A symbolic state for stack unwind analysis.
///
/// This state can store symbols in stack, register, and unique spaces. It ignores physical memory,
/// since that is not typically used as temporary storage when moving values between registers and
/// stack. When an address is read that does not have an entry, the state will generate a fresh
/// symbol representing that address, if applicable.
pub struct SymPcodeExecutorState {
    program: Arc<dyn Program>,
    c_spec: Arc<dyn CompilerSpec>,
    language: Arc<dyn Language>,
    arithmetic: Arc<SymPcodeArithmetic>,

    stack_space: SymStateSpace,
    register_space: SymStateSpace,
    unique_space: SymStateSpace,

    /// Warnings accumulated while unwinding. Java declares this package-private and only ever
    /// reads and appends to it from siblings such as `SymPcodeExecutor`; it is a
    /// `LinkedHashSet`, so insertion order is significant.
    pub warnings: Vec<Arc<dyn StackUnwindWarning>>,
}

impl SymPcodeExecutorState {
    /// Construct a new state for the given program.
    ///
    /// # Panics
    ///
    /// Panics if the program declares no compiler specification; Java dereferences
    /// `program.getCompilerSpec()` unconditionally.
    pub fn new(program: Arc<dyn Program>) -> Self {
        Self::with_spaces(
            program,
            SymStateSpace::new(),
            SymStateSpace::new(),
            SymStateSpace::new(),
        )
    }

    /// Construct a state over the given (typically forked) spaces.
    ///
    /// Stands in for the `protected SymPcodeExecutorState(Program, SymPcodeArithmetic,
    /// SymStateSpace, SymStateSpace, SymStateSpace)` constructor. Java's `arithmetic` parameter is
    /// dead -- that constructor builds a fresh `SymPcodeArithmetic` from the program's compiler
    /// spec and drops the argument -- so it is not carried over here.
    pub(crate) fn with_spaces(
        program: Arc<dyn Program>,
        stack_space: SymStateSpace,
        register_space: SymStateSpace,
        unique_space: SymStateSpace,
    ) -> Self {
        let c_spec: Arc<dyn CompilerSpec> = Arc::from(
            program
                .get_compiler_spec()
                .expect("program has no compiler spec"),
        );
        let language: Arc<dyn Language> = Arc::from(c_spec.get_language());
        let arithmetic = Arc::new(SymPcodeArithmetic::new(Arc::clone(&c_spec)));
        SymPcodeExecutorState {
            program,
            c_spec,
            language,
            arithmetic,
            stack_space,
            register_space,
            unique_space,
            warnings: Vec::new(),
        }
    }

    /// The language defining this state's address spaces.
    ///
    /// [`PcodeExecutorStatePiece::get_language`] returns an owned `Box<dyn Language>`, which this
    /// state (which shares one language with its arithmetic) cannot produce; use this instead.
    pub fn language(&self) -> &Arc<dyn Language> {
        &self.language
    }

    /// The compiler specification of the program under analysis.
    pub fn compiler_spec(&self) -> &Arc<dyn CompilerSpec> {
        &self.c_spec
    }

    /// Create a new state whose registers are forked from those of this state.
    ///
    /// Port of `forkRegs()`. The stack and unique spaces start empty.
    pub fn fork_regs(&self) -> SymPcodeExecutorState {
        SymPcodeExecutorState::with_spaces(
            Arc::clone(&self.program),
            SymStateSpace::new(),
            self.register_space.fork(),
            SymStateSpace::new(),
        )
    }

    /// Port of `dump()`, which writes to standard error.
    pub fn dump(&self) {
        eprintln!("Registers: ");
        self.register_space.dump("  ", &*self.language);
        eprintln!("Unique: ");
        self.unique_space.dump("  ", &*self.language);
        eprintln!("Stack: ");
        self.stack_space.dump("  ", &*self.language);
    }

    /// Examine this state's SP for the overall change in stack depth.
    ///
    /// There are two cases:
    ///
    /// * `SP:Register(reg==SP)` => depth is 0
    /// * `SP:Offset` => depth is `SP.offset`
    ///
    /// If SP has any other form, the depth is unknown (`None`, where Java returns `null`).
    pub fn compute_stack_depth(&self) -> Option<i64> {
        let sp = self.c_spec.get_stack_pointer()?;
        match self.get_var_register(&sp, Reason::Inspect) {
            Sym::Register { register, .. } if same_register(&register, &sp) => Some(0),
            Sym::StackOffset { offset } => Some(offset),
            _ => None,
        }
    }

    /// Examine this state's PC for the location of the return address.
    ///
    /// There are two cases:
    ///
    /// * `PC:Register` => location is `PC.reg.address`
    /// * `PC:Deref` => location is `[Stack]:PC.offset`
    pub fn compute_address_of_return(&self) -> Option<Address> {
        let pc = self.language.get_program_counter()?;
        match self.get_var_register(&pc, Reason::Inspect) {
            Sym::StackDeref { offset, .. } => Some(self.c_spec.get_stack_space().address(offset)),
            Sym::Register { register, .. } => Some(register.borrow().address().clone()),
            _ => None,
        }
    }

    /// Examine this state's PC to determine how the return address is masked.
    ///
    /// This is only applicable in cases where [`compute_address_of_return`](Self::
    /// compute_address_of_return) returns an address. This is to handle architectures where the
    /// low bits indicate an ISA mode, and the higher bits form the actual address. Often, the
    /// sleigh specifications for these processors will mask off those low bits when setting the
    /// PC. If that has happened, and the symbolic expression stored in the PC is otherwise
    /// understood to come from the stack or a register, this will return that mask. Most often,
    /// this will return -1, indicating that all bits are relevant to the actual address. If the
    /// symbolic expression does not indicate the stack or a register, this still returns -1.
    pub fn compute_mask_of_return(&self) -> i64 {
        let Some(pc) = self.language.get_program_counter() else {
            return -1;
        };
        match self.get_var_register(&pc, Reason::Inspect) {
            Sym::StackDeref { mask, .. } => mask,
            Sym::Register { mask, .. } => mask,
            _ => -1,
        }
    }

    /// Compute the map of (saved) registers.
    ///
    /// Any entry of the form `(addr, v:Register)` is collected as `(v.register, addr)`. Note that
    /// the size of the stack entry is implied by the size of the register.
    ///
    /// Returns pairs rather than a map, since [`RegisterRef`] is `Rc<RefCell<Register>>` and so
    /// cannot be a hash key.
    pub fn compute_map_using_stack(&self) -> Vec<(RegisterRef, Address)> {
        let mut result = Vec::new();
        for ent in self.stack_space.entries() {
            if ent.is_truncated() {
                continue;
            }
            let Sym::Register { register, .. } = ent.sym() else {
                continue;
            };
            result.push((Rc::clone(register), ent.ent_range().min_address().clone()));
        }
        result
    }

    /// Compute the map of (restored) registers.
    ///
    /// Any entry of the form `(reg, v:Deref)` is collected as `(reg, [Stack]:v.offset)`. Note that
    /// the size of the stack entry is implied by the size of the register.
    pub fn compute_map_using_registers(&self) -> Vec<(RegisterRef, Address)> {
        let mut result = Vec::new();
        for ent in self.register_space.entries() {
            if ent.is_truncated() {
                continue;
            }
            let Sym::StackDeref { offset, .. } = ent.sym() else {
                continue;
            };
            let Some(register) = ent.get_register(&*self.language) else {
                continue;
            };
            result.push((register, self.c_spec.get_stack_space().address(*offset)));
        }
        result
    }
}

/// Java compares a symbol's register against `cSpec.getStackPointer()` by reference; registers are
/// shared through the language, so pointer identity is checked first, falling back to the
/// register's own equality (name, size, and location).
fn same_register(a: &RegisterRef, b: &RegisterRef) -> bool {
    Rc::ptr_eq(a, b) || *a.borrow() == *b.borrow()
}

impl fmt::Display for SymPcodeExecutorState {
    /// Port of `toString()`. Java renders `cSpec` itself; `CompilerSpec` has no `Display` here, so
    /// its ID stands in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let language = Some(&*self.language);
        writeln!(f, "SymPcodeExecutorState[")?;
        writeln!(
            f,
            "  cSpec={}",
            self.c_spec.get_compiler_spec_id().get_id_as_string()
        )?;
        writeln!(f, "  stack={}", self.stack_space.display("  ", language))?;
        writeln!(
            f,
            "  registers={}",
            self.register_space.display("  ", language)
        )?;
        writeln!(f, "  unique={}", self.unique_space.display("  ", language))?;
        writeln!(f, "]")
    }
}

impl ErasedPcodeExecutorStatePiece for SymPcodeExecutorState {}

impl PcodeExecutorStatePiece<Sym, Sym> for SymPcodeExecutorState {
    /// Java returns the cached language; this state shares one [`Language`] with its arithmetic
    /// and cannot hand out an owned `Box`. Use [`language`](SymPcodeExecutorState::language).
    fn get_language(&self) -> Box<dyn Language> {
        unimplemented!("SymPcodeExecutorState::get_language: use SymPcodeExecutorState::language")
    }

    /// Java inherits `PcodeExecutorState`'s default, which delegates to `getArithmetic()`.
    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Sym>> {
        self.get_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Sym>> {
        Arc::clone(&self.arithmetic) as Arc<dyn PcodeArithmetic<Sym>>
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        vec![self]
    }

    fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self {
        SymPcodeExecutorState::with_spaces(
            Arc::clone(&self.program),
            self.stack_space.fork(),
            self.register_space.fork(),
            self.unique_space.fork(),
        )
    }

    /// # Panics
    ///
    /// Panics where Java throws `IllegalArgumentException`, i.e. when the offset resolves into the
    /// constant space.
    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Sym,
        size: i32,
        _quantize: bool,
        val: &Sym,
    ) {
        let address = offset.address_in(space, &*self.c_spec);
        if address.is_register_address() {
            self.register_space.set(&address, size, val.clone());
        } else if address.is_unique_address() {
            self.unique_space.set(&address, size, val.clone());
        } else if address.is_constant_address() {
            panic!("IllegalArgumentException: cannot set a variable in the constant space");
        } else if address.is_stack_address() {
            self.stack_space.set(&address, size, val.clone());
        } else {
            Msg::trace(
                "SymPcodeExecutorState",
                &format!(
                    "Ignoring set: space={},offset={offset:?},size={size},val={val:?}",
                    space.name()
                ),
            );
        }
    }

    fn set_var_internal_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Sym,
        size: i32,
        val: &Sym,
    ) {
        self.set_var_abstract(space, offset, size, false, val);
    }

    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Sym,
        size: i32,
        _quantize: bool,
        _reason: Reason,
    ) -> Sym {
        let address = offset.address_in(space, &*self.c_spec);
        if address.is_register_address() {
            self.register_space
                .get(&address, size, &self.arithmetic, &*self.language)
        } else if address.is_unique_address() {
            self.unique_space
                .get(&address, size, &self.arithmetic, &*self.language)
        } else if address.is_constant_address() {
            offset.clone()
        } else if address.is_stack_address() {
            self.stack_space
                .get(&address, size, &self.arithmetic, &*self.language)
        } else {
            Sym::opaque()
        }
    }

    fn get_var_internal_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Sym,
        size: i32,
        reason: Reason,
    ) -> Sym {
        self.get_var_abstract(space, offset, size, false, reason)
    }

    /// Java returns `Map.of()`.
    fn get_register_values(&self) -> Vec<(RegisterRef, Sym)> {
        Vec::new()
    }

    fn get_concrete_buffer(&self, address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
        // Java constructs a `MemoryBufferImpl`; `DumbMemBufferImpl` is the unported-class stand-in
        // for it, differing only in that it does not cache reads.
        Box::new(DumbMemBufferImpl::new(
            self.program.get_memory(),
            address.clone(),
        ))
    }

    /// Note that Java deliberately leaves the unique space alone.
    fn clear(&mut self) {
        self.register_space.clear();
        self.stack_space.clear();
    }
}

impl PcodeExecutorState<Sym> for SymPcodeExecutorState {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::address::{AddressSet, AddressSetView, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::Encoder;
    use crate::program::seam_stubs::{AddressLabelInfo, PcodeInjectLibrary, Processor};
    use crate::util::task::TaskMonitor;

    /// The register file shared by the test language and compiler spec: a stack pointer, a
    /// callee-saved register, and a program counter.
    fn test_registers(register_space: &Arc<AddressSpace>) -> Vec<RegisterRef> {
        vec![
            Register::new(
                "SP",
                "stack pointer",
                register_space.address(0x10),
                8,
                true,
                Register::TYPE_SP,
            ),
            Register::new(
                "RBX",
                "callee saved",
                register_space.address(0x20),
                8,
                true,
                Register::TYPE_NONE,
            ),
            Register::new(
                "PC",
                "program counter",
                register_space.address(0x30),
                8,
                true,
                Register::TYPE_PC,
            ),
        ]
    }

    struct TestLanguage {
        registers: Vec<RegisterRef>,
    }

    impl TestLanguage {
        fn new(register_space: &Arc<AddressSpace>) -> Self {
            TestLanguage {
                registers: test_registers(register_space),
            }
        }
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
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
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(
                UnknownInstructionException::new(),
            ))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
            self.registers
                .iter()
                .filter(|r| r.borrow().address() == address)
                .cloned()
                .collect()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.clone()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers
                .iter()
                .map(|r| r.borrow().name().to_string())
                .collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers
                .iter()
                .find(|r| r.borrow().name() == name)
                .cloned()
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
            self.registers
                .iter()
                .find(|r| {
                    let r = r.borrow();
                    r.address() == addr && (size == 0 || r.minimum_byte_size() == size)
                })
                .cloned()
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            self.get_register_by_name("PC")
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
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
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// The address spaces every test double shares. `AddressSpace::new` mints a fresh space per
    /// call, and [`Address`] equality includes the space, so they must be built once and cloned.
    #[derive(Clone)]
    struct TestSpaces {
        register: Arc<AddressSpace>,
        stack: Arc<AddressSpace>,
        ram: Arc<AddressSpace>,
        constant: Arc<AddressSpace>,
        unique: Arc<AddressSpace>,
    }

    impl TestSpaces {
        fn new() -> Self {
            TestSpaces {
                register: AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1),
                stack: AddressSpace::new("stack", 64, 1, AddressSpaceType::Stack, 2),
                ram: AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 3),
                constant: AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 4),
                unique: AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 5),
            }
        }
    }

    struct TestCompilerSpec {
        spaces: TestSpaces,
        registers: Vec<RegisterRef>,
    }

    impl TestCompilerSpec {
        fn new(spaces: TestSpaces) -> Self {
            let registers = test_registers(&spaces.register);
            TestCompilerSpec { spaces, registers }
        }

        fn register(&self, name: &str) -> RegisterRef {
            self.registers
                .iter()
                .find(|r| r.borrow().name() == name)
                .cloned()
                .expect("no such test register")
        }
    }

    impl CompilerSpec for TestCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(TestLanguage::new(&self.spaces.register))
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("default"))
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            Some(self.register("SP"))
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.spaces.stack)
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.spaces.ram)
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            unimplemented!("not exercised by these tests")
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            false
        }
        fn get_data_organization(
            &self,
        ) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            unimplemented!("not exercised by these tests")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            unimplemented!("not exercised by these tests")
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn Parameter],
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
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
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            false
        }
    }

    struct TestProgram {
        spaces: TestSpaces,
    }

    impl crate::framework::model::DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }

        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }

        fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
            Some(Box::new(TestCompilerSpec::new(self.spaces.clone())))
        }
    }

    /// A state plus the doubles the assertions need. `TestProgram` mints a fresh compiler spec
    /// (and hence fresh `Rc` registers) per call, exactly as Ghidra hands out shared ones, so the
    /// spec kept here is only for naming registers and spaces in assertions.
    struct Fixture {
        state: SymPcodeExecutorState,
        c_spec: TestCompilerSpec,
        spaces: TestSpaces,
    }

    impl Fixture {
        fn new() -> Self {
            let spaces = TestSpaces::new();
            let program = Arc::new(TestProgram {
                spaces: spaces.clone(),
            });
            Fixture {
                state: SymPcodeExecutorState::new(program),
                c_spec: TestCompilerSpec::new(spaces.clone()),
                spaces,
            }
        }
    }

    #[test]
    fn a_fresh_state_reads_registers_as_themselves_so_the_depth_is_zero() {
        let f = Fixture::new();

        // Java: an unset register reads back as RegisterSym(reg, -1), so SP:Register(reg==SP).
        let sp = f.c_spec.register("SP");
        assert_eq!(
            f.state.get_var_register(&sp, Reason::Inspect),
            Sym::Register {
                register: Rc::clone(&sp),
                mask: -1
            }
        );
        assert_eq!(f.state.compute_stack_depth(), Some(0));
        // Nothing is saved or restored yet.
        assert!(f.state.compute_map_using_stack().is_empty());
        assert!(f.state.compute_map_using_registers().is_empty());
    }

    #[test]
    fn writing_a_stack_offset_to_sp_sets_the_stack_depth() {
        let mut f = Fixture::new();
        let sp = f.c_spec.register("SP");

        f.state
            .set_var_register(&sp, &Sym::StackOffset { offset: -0x18 });

        assert_eq!(f.state.compute_stack_depth(), Some(-0x18));
        // An opaque SP means the depth is not known.
        f.state.set_var_register(&sp, &Sym::opaque());
        assert_eq!(f.state.compute_stack_depth(), None);
    }

    #[test]
    fn a_register_stored_through_the_stack_pointer_is_collected_as_saved() {
        let mut f = Fixture::new();
        let rbx = f.c_spec.register("RBX");

        // Java: `*(SP - 8) = RBX`. The offset symbol resolves into the stack space via the
        // compiler spec's stack base space.
        f.state.set_var_abstract(
            &f.spaces.ram,
            &Sym::StackOffset { offset: -8 },
            8,
            false,
            &Sym::Register {
                register: Rc::clone(&rbx),
                mask: -1,
            },
        );

        let saved = f.state.compute_map_using_stack();
        assert_eq!(saved.len(), 1);
        assert_eq!(*saved[0].0.borrow(), *rbx.borrow());
        assert_eq!(saved[0].1, f.spaces.stack.address(-8));

        // Reading it back yields the very symbol that was stored.
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.ram,
                &Sym::StackOffset { offset: -8 },
                8,
                false,
                Reason::Inspect
            ),
            Sym::Register {
                register: rbx,
                mask: -1
            }
        );
    }

    #[test]
    fn an_unwritten_stack_slot_reads_as_a_fresh_dereference() {
        let f = Fixture::new();

        // Java: SymStateSpace.get generates StackDerefSym(offset, -1, size) for stack addresses.
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.ram,
                &Sym::StackOffset { offset: -0x10 },
                8,
                false,
                Reason::Inspect
            ),
            Sym::StackDeref {
                offset: -0x10,
                mask: -1,
                size: 8
            }
        );
    }

    #[test]
    fn a_register_holding_a_stack_dereference_is_collected_as_restored() {
        let mut f = Fixture::new();
        let rbx = f.c_spec.register("RBX");

        f.state.set_var_register(
            &rbx,
            &Sym::StackDeref {
                offset: -8,
                mask: -1,
                size: 8,
            },
        );

        let restored = f.state.compute_map_using_registers();
        assert_eq!(restored.len(), 1);
        assert_eq!(*restored[0].0.borrow(), *rbx.borrow());
        assert_eq!(restored[0].1, f.spaces.stack.address(-8));
    }

    #[test]
    fn the_return_address_location_and_mask_come_from_the_program_counter() {
        let mut f = Fixture::new();
        let pc = f.c_spec.register("PC");
        let lr = f.c_spec.register("RBX");

        // Untouched, the PC reads as itself: the return address lives in the PC register.
        assert_eq!(
            f.state.compute_address_of_return(),
            Some(pc.borrow().address().clone())
        );
        assert_eq!(f.state.compute_mask_of_return(), -1);

        // PC:Deref => the return address is on the stack, at that offset.
        f.state.set_var_register(
            &pc,
            &Sym::StackDeref {
                offset: 8,
                mask: -2,
                size: 8,
            },
        );
        assert_eq!(
            f.state.compute_address_of_return(),
            Some(f.spaces.stack.address(8))
        );
        assert_eq!(f.state.compute_mask_of_return(), -2);

        // PC:Register => the return address is in that register, keeping its mask.
        f.state.set_var_register(
            &pc,
            &Sym::Register {
                register: Rc::clone(&lr),
                mask: -4,
            },
        );
        assert_eq!(
            f.state.compute_address_of_return(),
            Some(lr.borrow().address().clone())
        );
        assert_eq!(f.state.compute_mask_of_return(), -4);

        // Anything else is not understood.
        f.state.set_var_register(&pc, &Sym::opaque());
        assert_eq!(f.state.compute_address_of_return(), None);
        assert_eq!(f.state.compute_mask_of_return(), -1);
    }

    #[test]
    fn a_constant_offset_reads_back_as_itself() {
        let f = Fixture::new();

        // Java: an address in the constant space returns the offset symbol unchanged.
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.constant,
                &Sym::constant(0x1234),
                8,
                false,
                Reason::Inspect
            ),
            Sym::Const {
                value: 0x1234,
                size: 8
            }
        );
    }

    #[test]
    #[should_panic(expected = "IllegalArgumentException")]
    fn writing_the_constant_space_is_rejected() {
        let mut f = Fixture::new();
        f.state.set_var_abstract(
            &f.spaces.constant,
            &Sym::constant(0x10),
            8,
            false,
            &Sym::opaque(),
        );
    }

    #[test]
    fn memory_writes_are_ignored_but_unique_writes_are_kept() {
        let mut f = Fixture::new();

        // A plain RAM offset resolves to no address, so the write is dropped and reads are opaque.
        f.state.set_var_abstract(
            &f.spaces.ram,
            &Sym::constant(0x4000),
            8,
            false,
            &Sym::constant(7),
        );
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.ram,
                &Sym::constant(0x4000),
                8,
                false,
                Reason::Inspect
            ),
            Sym::Opaque
        );

        // The unique space, by contrast, stores and returns the symbol.
        f.state.set_var_abstract(
            &f.spaces.unique,
            &Sym::constant(0x80),
            8,
            false,
            &Sym::constant(7),
        );
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.unique,
                &Sym::constant(0x80),
                8,
                false,
                Reason::Inspect
            ),
            Sym::Const { value: 7, size: 8 }
        );
    }

    #[test]
    fn clear_erases_registers_and_stack_but_leaves_unique_alone() {
        let mut f = Fixture::new();
        let sp = f.c_spec.register("SP");

        f.state
            .set_var_register(&sp, &Sym::StackOffset { offset: -0x20 });
        f.state.set_var_abstract(
            &f.spaces.ram,
            &Sym::StackOffset { offset: -8 },
            8,
            false,
            &Sym::constant(1),
        );
        f.state.set_var_abstract(
            &f.spaces.unique,
            &Sym::constant(0x80),
            8,
            false,
            &Sym::constant(2),
        );

        f.state.clear();

        assert_eq!(f.state.compute_stack_depth(), Some(0));
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.ram,
                &Sym::StackOffset { offset: -8 },
                8,
                false,
                Reason::Inspect
            ),
            Sym::StackDeref {
                offset: -8,
                mask: -1,
                size: 8
            }
        );
        // Java's clear() deliberately skips the unique space.
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.unique,
                &Sym::constant(0x80),
                8,
                false,
                Reason::Inspect
            ),
            Sym::Const { value: 2, size: 8 }
        );
    }

    #[test]
    fn fork_regs_keeps_the_registers_and_drops_the_stack() {
        let mut f = Fixture::new();
        let sp = f.c_spec.register("SP");
        let rbx = f.c_spec.register("RBX");

        f.state
            .set_var_register(&sp, &Sym::StackOffset { offset: -0x20 });
        f.state.set_var_abstract(
            &f.spaces.ram,
            &Sym::StackOffset { offset: -8 },
            8,
            false,
            &Sym::Register {
                register: Rc::clone(&rbx),
                mask: -1,
            },
        );

        let forked = f.state.fork_regs();
        assert_eq!(forked.compute_stack_depth(), Some(-0x20));
        assert!(forked.compute_map_using_stack().is_empty());

        // Writing the fork's SP leaves the original alone.
        let mut forked = forked;
        forked.set_var_register(&sp, &Sym::StackOffset { offset: -0x30 });
        assert_eq!(forked.compute_stack_depth(), Some(-0x30));
        assert_eq!(f.state.compute_stack_depth(), Some(-0x20));
        assert_eq!(f.state.compute_map_using_stack().len(), 1);
    }

    #[test]
    fn an_overlapping_write_truncates_the_entry_it_covers() {
        let mut f = Fixture::new();
        let rbx = f.c_spec.register("RBX");

        // Save RBX at [Stack:-8, Stack:-1], then clobber its low half.
        f.state.set_var_abstract(
            &f.spaces.ram,
            &Sym::StackOffset { offset: -8 },
            8,
            false,
            &Sym::Register {
                register: rbx,
                mask: -1,
            },
        );
        f.state.set_var_abstract(
            &f.spaces.ram,
            &Sym::StackOffset { offset: -8 },
            4,
            false,
            &Sym::constant(0),
        );

        // Java: the truncated remainder is skipped by computeMapUsingStack.
        assert!(f.state.compute_map_using_stack().is_empty());
        // And the original 8-byte read no longer matches a single entry, so it is opaque.
        assert_eq!(
            f.state.get_var_abstract(
                &f.spaces.ram,
                &Sym::StackOffset { offset: -8 },
                8,
                false,
                Reason::Inspect
            ),
            Sym::Opaque
        );
    }

    #[test]
    fn the_arithmetic_folds_symbols_the_way_sym_does() {
        let f = Fixture::new();
        let arithmetic = f.state.get_arithmetic();
        let sp = f.c_spec.register("SP");

        // Java's SymPcodeArithmetic: INT_ADD/INT_SUB/INT_AND defer to Sym; everything else is
        // opaque, and COPY passes its input through.
        assert_eq!(
            arithmetic.binary_op(
                crate::program::model::pcode::OpCode::IntAdd,
                8,
                8,
                &Sym::Register {
                    register: sp,
                    mask: -1
                },
                8,
                &Sym::constant(-0x20)
            ),
            Sym::StackOffset { offset: -0x20 }
        );
        assert_eq!(
            arithmetic.unary_op(
                crate::program::model::pcode::OpCode::Copy,
                8,
                8,
                &Sym::constant(5)
            ),
            Sym::Const { value: 5, size: 8 }
        );
        assert_eq!(
            arithmetic.unary_op(
                crate::program::model::pcode::OpCode::IntNegate,
                8,
                8,
                &Sym::constant(5)
            ),
            Sym::Opaque
        );
        // fromConst reads little-endian bytes back into a constant of the same size.
        assert_eq!(
            arithmetic.from_const_bytes(&[0x34, 0x12]),
            Sym::Const {
                value: 0x1234,
                size: 2
            }
        );
        assert_eq!(arithmetic.size_of(&Sym::constant(1)), 8);
    }
}
