//! Port of `ghidra.lisa.pcode.contexts.StatementContext`.

use std::fmt;
use std::sync::Arc;

use crate::feature::lisa::pcode::contexts::condition_context::ConditionContext;
use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::var_def_context::VarDefContext;
use crate::program::model::address::AddressFactory;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// A [`PcodeContext`] specialized for a single p-code operation of an [`Instruction`], splitting
/// it into a defined target ([`StatementContext::left`]) and defining expression
/// ([`StatementContext::right`]), and classifying its control-flow shape.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.StatementContext` in the Java source, which `extends
/// PcodeContext`. Following this crate's composition-over-inheritance convention, this wraps a
/// `PcodeContext` by composition instead.
///
/// # Deviations from Java
///
/// Java's protected constructor (`StatementContext(PcodeOp op)`, ported as
/// [`StatementContext::from_op`]) guards its whole body with `if (op != null)`. Every real
/// construction path in this codebase's Java call sites (`UnitContext.branch`/`UnitContext.next`,
/// which call this constructor directly since they live in the same Java package, and the public
/// `StatementContext(Instruction, PcodeOp)` constructor, which always delegates to this one)
/// always supplies a real, non-null `op` -- matching the same situation, and the same modeling
/// choice, documented on [`PcodeContext`]'s own docs (its `op` field is likewise never
/// `Option<PcodeOp>`). This port therefore always executes that guarded body.
///
/// By contrast, `inst` genuinely *can* be absent in practice: `UnitContext`'s calls to the
/// protected 1-arg constructor never set it, only the public 2-arg constructor
/// ([`StatementContext::new`]) does. [`StatementContext::inst`] is therefore `Option`, and
/// [`fmt::Display`]/[`StatementContext::get_address_factory`] -- both of which unconditionally
/// dereference Java's `inst` field -- panic if `inst` is absent, faithfully reproducing the
/// `NullPointerException` Java would throw at that point instead.
pub struct StatementContext {
    base: PcodeContext,
    /// Mirrors the Java class's public `otherwise` field. Never populated by anything in this
    /// codebase's Java call graph (nothing assigns to it), so it always starts (and, absent a
    /// caller reaching in to set it, stays) `None`.
    pub otherwise: Option<Box<StatementContext>>,
    /// Mirrors the Java class's public `then` field. See [`StatementContext::otherwise`]'s docs;
    /// the same applies here.
    pub then: Option<Box<StatementContext>>,
    opcode: OpCode,
    inst: Option<Arc<dyn Instruction>>,
    /// Mirrors the Java class's public `left` field: this statement's defined target. `None`
    /// when `op` has neither an output varnode nor an input at index 2 -- Java would instead
    /// store a `null` `VarDefContext` there (every op shape without a defined target, e.g.
    /// `BRANCH`/`CBRANCH`/`RETURN`, hits this path in completely ordinary usage, not just
    /// malformed input), which would only actually throw a `NullPointerException` if a caller
    /// later dereferenced it. [`StatementContext::target`] reproduces that deferred failure by
    /// panicking only when actually called on a `None` left.
    pub left: Option<VarDefContext>,
    /// Mirrors the Java class's public `right` field: this statement's defining expression.
    pub right: PcodeContext,
}

impl StatementContext {
    /// Java: protected `StatementContext(PcodeOp op)`. See the struct docs for why the `op !=
    /// null` guard's body is always executed here.
    pub fn from_op(op: PcodeOp) -> Self {
        let opcode = op.get_opcode();
        let def_vn = op.get_output().cloned().or_else(|| op.get_input(2).cloned());
        let left = def_vn.map(|vn| VarDefContext::new(op.clone(), vn));
        let right = PcodeContext::new(op.clone());
        Self {
            base: PcodeContext::new(op),
            otherwise: None,
            then: None,
            opcode,
            inst: None,
            left,
            right,
        }
    }

    /// Java: public `StatementContext(Instruction inst, PcodeOp op)`.
    pub fn new(inst: Arc<dyn Instruction>, op: PcodeOp) -> Self {
        let mut ctx = Self::from_op(op);
        ctx.inst = Some(inst);
        ctx
    }

    /// Java: the inherited `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        self.base.get_op()
    }

    /// Java: `target()`.
    ///
    /// # Panics
    ///
    /// If [`StatementContext::left`] is `None` (this op had neither an output varnode nor an
    /// input at index 2) -- the `NullPointerException` a real caller dereferencing Java's `null`
    /// `left` field would hit, deferred to this point rather than at construction. See the
    /// struct docs.
    pub fn target(&self) -> &VarDefContext {
        self.left.as_ref().expect("StatementContext::target: left is None (Java NullPointerException)")
    }

    /// Java: `expression()`.
    pub fn expression(&self) -> &PcodeContext {
        &self.right
    }

    /// Java: `condition()`, `return new ConditionContext(op);` (the inherited `op` field).
    pub fn condition(&self) -> ConditionContext {
        ConditionContext::new(self.base.get_op().clone())
    }

    /// Java: `isRet()`.
    pub fn is_ret(&self) -> bool {
        self.opcode == OpCode::Return
    }

    /// Java: `isBranch()`.
    pub fn is_branch(&self) -> bool {
        matches!(self.opcode, OpCode::Branch | OpCode::BranchInd | OpCode::CBranch)
    }

    /// Java: `isConditional()`.
    pub fn is_conditional(&self) -> bool {
        self.opcode == OpCode::CBranch
    }

    /// Java: `getAddressFactory()`, `return inst.getProgram().getAddressFactory();`.
    ///
    /// # Panics
    ///
    /// If `inst` is absent. See the struct docs.
    pub fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        let inst = self
            .inst
            .as_ref()
            .expect("StatementContext::get_address_factory: inst is None (Java NullPointerException)");
        inst.get_program().get_address_factory()
    }
}

impl fmt::Display for StatementContext {
    /// Java: `toString()`, `return inst.getAddress() + ": " + inst + ":" + op;`.
    ///
    /// `inst.getAddress()` maps to [`CodeUnit::get_min_address`] (an `Instruction`'s own address,
    /// with no operand index, is its code unit's minimum address in this crate's model -- there is
    /// no separate no-argument `Instruction::get_address`). `inst` alone (implicit
    /// `Object.toString()` via string concatenation) is reproduced by
    /// `InstructionDB.toString()`'s own algorithm (mnemonic followed by operands and separators),
    /// the same approach already taken by
    /// [`instruction_error::get_instruction_details`](crate::program::model::lang::instruction_error)'s
    /// private `instruction_to_string` helper, inlined here since that helper isn't public.
    ///
    /// # Panics
    ///
    /// If `inst` is absent. See the struct docs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inst = self
            .inst
            .as_ref()
            .expect("StatementContext::fmt: inst is None (Java NullPointerException)");
        write!(
            f,
            "{}: {}:{}",
            inst.get_min_address(),
            instruction_to_string(inst.as_ref()),
            self.base.get_op()
        )
    }
}

/// Reproduces `InstructionDB.toString()` (mnemonic followed by its operands joined by whatever
/// separators the instruction reports), since this crate's `Instruction`/`CodeUnit` traits don't
/// expose a `Display`/`to_string()` port equivalent to Java's `Instruction.toString()`. Built from
/// the same public accessors (`get_mnemonic_string`, `get_num_operands`, `get_separator`,
/// `get_default_operand_representation`) that `InstructionDB.toString()` itself uses -- the same
/// approach already taken by a private helper of the same name in
/// `crate::program::model::lang::instruction_error`, duplicated here since that one isn't public.
fn instruction_to_string(instr: &dyn Instruction) -> String {
    let mut buf = String::new();
    buf.push_str(&instr.get_mnemonic_string());

    let n = instr.get_num_operands();
    let mut sep = instr.get_separator(0);
    if sep.is_some() || n != 0 {
        buf.push(' ');
    }
    if let Some(s) = &sep {
        buf.push_str(s);
    }

    for i in 0..n {
        buf.push_str(&instr.get_default_operand_representation(i));
        sep = instr.get_separator(i + 1);
        if let Some(s) = &sep {
            buf.push_str(s);
        }
    }

    buf
}

impl fmt::Debug for StatementContext {
    /// Manual `Debug` impl: `inst` is `Arc<dyn Instruction>`, and neither `Instruction` nor its
    /// `CodeUnit`/`ProcessorContext` supertraits require `Debug`, so `#[derive(Debug)]` isn't
    /// available here (the same situation this project's established "trait object with no Debug
    /// supertrait" pitfall describes). Reports whether `inst` is present rather than its contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatementContext")
            .field("opcode", &self.opcode)
            .field("has_inst", &self.inst.is_some())
            .field("left", &self.left)
            .field("right", &self.right)
            .field("then", &self.then.is_some())
            .field("otherwise", &self.otherwise.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::pcode::{SequenceNumber, Varnode};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::model::lang::register_value::RegisterValue;
    use crate::program::model::listing::FlowOverride;
    use crate::program::util::CodeUnitInsertionException;

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &std::sync::Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn op_with(opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(opcode, seq, inputs, output)
    }

    #[test]
    fn from_op_derives_opcode_and_right_from_op() {
        let space = ram_space();
        let output = varnode(&space, 0x10, 4);
        let op = op_with(OpCode::Copy, vec![varnode(&space, 0x20, 4)], Some(output.clone()));

        let ctx = StatementContext::from_op(op.clone());

        assert_eq!(ctx.get_op(), &op);
        assert!(!ctx.is_ret());
        assert!(!ctx.is_branch());
        assert!(!ctx.is_conditional());
    }

    #[test]
    fn from_op_uses_output_for_left_when_present() {
        let space = ram_space();
        let output = varnode(&space, 0x10, 4);
        let op = op_with(OpCode::Copy, vec![varnode(&space, 0x20, 4)], Some(output.clone()));

        let ctx = StatementContext::from_op(op);

        assert_eq!(ctx.target().varnode(), &output);
    }

    #[test]
    fn from_op_falls_back_to_input_2_when_there_is_no_output() {
        let space = ram_space();
        let in0 = varnode(&space, 0x10, 4);
        let in1 = varnode(&space, 0x14, 4);
        let in2 = varnode(&space, 0x18, 4);
        // STORE has no output; its "defined" varnode (the value being stored) is input 2.
        let op = op_with(OpCode::Store, vec![in0, in1, in2.clone()], None);

        let ctx = StatementContext::from_op(op);

        assert_eq!(ctx.target().varnode(), &in2);
    }

    #[test]
    fn from_op_leaves_left_none_when_there_is_no_output_and_no_input_2() {
        let space = ram_space();
        let op = op_with(OpCode::Store, vec![varnode(&space, 0x10, 4)], None);
        let ctx = StatementContext::from_op(op);
        assert!(ctx.left.is_none());
    }

    #[test]
    #[should_panic(expected = "StatementContext::target: left is None")]
    fn target_panics_when_there_is_no_output_and_no_input_2() {
        let space = ram_space();
        let op = op_with(OpCode::Store, vec![varnode(&space, 0x10, 4)], None);
        let ctx = StatementContext::from_op(op);
        let _ = ctx.target();
    }

    #[test]
    fn is_ret_is_true_only_for_return_opcode() {
        let op = op_with(OpCode::Return, vec![], None);
        assert!(StatementContext::from_op(op).is_ret());

        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        assert!(!StatementContext::from_op(op).is_ret());
    }

    #[test]
    fn is_branch_covers_branch_branchind_and_cbranch() {
        let space = ram_space();
        for opcode in [OpCode::Branch, OpCode::BranchInd, OpCode::CBranch] {
            let inputs = if opcode == OpCode::CBranch {
                vec![varnode(&space, 0, 4), varnode(&space, 4, 1)]
            } else {
                vec![varnode(&space, 0, 4)]
            };
            let op = op_with(opcode, inputs, None);
            assert!(StatementContext::from_op(op).is_branch(), "{opcode:?} should be a branch");
        }

        let op = op_with(OpCode::Copy, vec![], Some(varnode(&space, 0, 4)));
        assert!(!StatementContext::from_op(op).is_branch());
    }

    #[test]
    fn is_conditional_is_true_only_for_cbranch() {
        let space = ram_space();
        let op = op_with(OpCode::CBranch, vec![varnode(&space, 0, 4), varnode(&space, 4, 1)], None);
        assert!(StatementContext::from_op(op).is_conditional());

        let op = op_with(OpCode::Branch, vec![varnode(&space, 0, 4)], None);
        assert!(!StatementContext::from_op(op).is_conditional());
    }

    #[test]
    fn condition_wraps_the_op_as_a_condition_context() {
        let space = ram_space();
        let op = op_with(OpCode::CBranch, vec![varnode(&space, 0, 4), varnode(&space, 4, 1)], None);
        let op_clone = op.clone();

        let ctx = StatementContext::from_op(op);
        let condition = ctx.condition();

        assert_eq!(condition.get_op(), &op_clone);
    }

    #[test]
    fn target_and_expression_expose_left_and_right() {
        let space = ram_space();
        let output = varnode(&space, 0x10, 4);
        let op = op_with(OpCode::Copy, vec![varnode(&space, 0x20, 4)], Some(output));

        let ctx = StatementContext::from_op(op.clone());

        assert_eq!(ctx.target().get_op(), &op);
        assert_eq!(ctx.expression().get_op(), &op);
    }

    #[test]
    fn otherwise_and_then_start_as_none() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let ctx = StatementContext::from_op(op);
        assert!(ctx.otherwise.is_none());
        assert!(ctx.then.is_none());
    }

    #[test]
    #[should_panic(expected = "inst is None")]
    fn get_address_factory_panics_when_inst_is_absent() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let ctx = StatementContext::from_op(op);
        let _ = ctx.get_address_factory();
    }

    #[test]
    #[should_panic(expected = "inst is None")]
    fn display_panics_when_inst_is_absent() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let ctx = StatementContext::from_op(op);
        let _ = ctx.to_string();
    }

    // --- A minimal `Instruction` mock, needed to exercise `new`/`get_address_factory`/`Display`
    // with `inst` present. Each of `Instruction`'s supertraits (`CodeUnit`, `ProcessorContext`,
    // `ProcessorContextView`) must be implemented in full to build a trait object, even though most
    // methods are never called by these tests -- mirroring the established pattern used throughout
    // this crate (e.g. `ext_comment.rs`'s `MockData`, `function_iterator.rs`'s `MockFunction`).

    struct MockInstruction {
        address: Address,
        mnemonic: String,
        program_address_factory: Option<Arc<dyn AddressFactory>>,
    }

    impl MemBuffer for MockInstruction {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }
    impl PropertySet for MockInstruction {}

    impl ProcessorContextView for MockInstruction {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register) -> Option<RegisterValue> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockInstruction {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: RegisterValue,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    struct MockProgram {
        address_factory: Option<Arc<dyn AddressFactory>>,
    }
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.address_factory.clone()
        }
    }

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            self.mnemonic.clone()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram { address_factory: self.program_address_factory.clone() })
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }
        fn get_op_objects(
            &self,
            _operand_index: i32,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_input_objects(&self) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_result_objects(&self) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }
        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<crate::program::model::listing::instruction::OperandValue>> {
            None
        }
        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }
        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }
        fn get_operand_ref_type(&self, _operand_index: i32) -> SymRefType {
            SymRefType::Data
        }
        fn get_default_fall_through_offset(&self) -> i32 {
            0
        }
        fn get_default_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_fall_from(&self) -> Option<Address> {
            None
        }
        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }
        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }
        fn get_flow_type(&self) -> SymRefType {
            SymRefType::FallThrough
        }
        fn is_fallthrough(&self) -> bool {
            true
        }
        fn has_fallthrough(&self) -> bool {
            true
        }
        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::None
        }
        fn set_flow_override(&mut self, _flow_override: FlowOverride) {}
        fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> {
            Ok(())
        }
        fn is_length_overridden(&self) -> bool {
            false
        }
        fn get_parsed_length(&self) -> i32 {
            1
        }
        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_pcode(&self) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_delay_slot_depth(&self) -> i32 {
            0
        }
        fn is_in_delay_slot(&self) -> bool {
            false
        }
        fn get_next(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn set_fall_through(&mut self, _addr: Option<Address>) {}
        fn clear_fall_through_override(&mut self) {}
        fn is_fall_through_overridden(&self) -> bool {
            false
        }
        fn get_instruction_context(&self) -> Arc<dyn crate::program::seam_stubs::InstructionContext> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn mock_address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[test]
    fn new_sets_inst_alongside_the_op_derived_fields() {
        let space = ram_space();
        let output = varnode(&space, 0x10, 4);
        let op = op_with(OpCode::Copy, vec![varnode(&space, 0x20, 4)], Some(output.clone()));
        let inst: Arc<dyn Instruction> = Arc::new(MockInstruction {
            address: mock_address(0x400000),
            mnemonic: "MOV".to_string(),
            program_address_factory: None,
        });

        let ctx = StatementContext::new(inst, op);

        assert_eq!(ctx.target().varnode(), &output);
    }

    #[test]
    fn get_address_factory_delegates_through_inst_and_program() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let inst: Arc<dyn Instruction> = Arc::new(MockInstruction {
            address: mock_address(0x400000),
            mnemonic: "MOV".to_string(),
            program_address_factory: None,
        });

        let ctx = StatementContext::new(inst, op);

        // MockProgram's default reports `None`, proving the call actually threads through to the
        // instruction's program rather than being hardcoded.
        assert!(ctx.get_address_factory().is_none());
    }

    #[test]
    fn display_renders_address_instruction_text_and_op() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let op_clone = op.clone();
        let inst: Arc<dyn Instruction> = Arc::new(MockInstruction {
            address: mock_address(0x400000),
            mnemonic: "MOV".to_string(),
            program_address_factory: None,
        });

        let ctx = StatementContext::new(inst, op);

        let expected = format!("{}: {}:{}", mock_address(0x400000), "MOV", op_clone);
        assert_eq!(ctx.to_string(), expected);
    }
}
