use super::sleigh_exception::SleighException;
use super::sleigh_parser_context::SleighParserContext;
use super::unique_layout::UniqueLayout;
use super::varnode_data::VarnodeData;
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
use crate::program::model::lang::instruction_context::InstructionContext;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::sleigh::constructor::Constructor;
use crate::program::model::lang::sleigh::symbol::SleighSymbol;
use crate::program::model::lang::sleigh::template::const_tpl::CALC_MASK;
use crate::program::model::lang::sleigh::template::{
    ConstTpl, ConstTplSelect, ConstTplType, ConstructTpl, OpTpl, VarnodeTpl,
};
use crate::program::model::lang::sleigh::{ParserWalker, SleighLanguage};
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::seam_stubs::FlowOverride;
use std::sync::Arc;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::PcodeOverride;
use crate::program::model::symbol::RefType;
use std::fmt;
use std::io;

/// Error produced by [`PcodeEmit::build`].
///
/// Mirrors the `UnknownInstructionException`/`MemoryAccessException`/`IOException` triple that
/// `PcodeEmit.build(ConstructTpl, int)` declares, folded into one `Result` error the way
/// [`InjectPayloadError`](crate::program::model::lang::inject_payload::InjectPayloadError) folds
/// the same triple (plus a fourth variant that doesn't apply here) for `InjectPayload::inject`.
#[derive(Debug)]
pub enum PcodeEmitBuildError {
    /// There is no underlying instruction being built (e.g. an unresolvable delay-slot or
    /// crossbuild target).
    UnknownInstruction(UnknownInstructionException),
    /// A problem reading memory while resolving a referenced instruction.
    MemoryAccess(MemoryAccessException),
    /// A problem emitting the built p-code.
    Io(io::Error),
    /// The specification was used in a way it does not support (Java `SleighException`, e.g.
    /// delay-slot or crossbuild recursion, or a template constant that cannot be evaluated).
    Sleigh(SleighException),
    /// The instruction has no semantics (Java `NotYetImplementedException`).
    NotYetImplemented(String),
}

impl From<SleighException> for PcodeEmitBuildError {
    fn from(err: SleighException) -> Self {
        PcodeEmitBuildError::Sleigh(err)
    }
}

impl From<crate::program::model::lang::sleigh::walker::SleighError> for PcodeEmitBuildError {
    fn from(err: crate::program::model::lang::sleigh::walker::SleighError) -> Self {
        use crate::program::model::lang::sleigh::walker::SleighError;
        match err {
            SleighError::UnknownInstruction(e) => PcodeEmitBuildError::UnknownInstruction(e),
            SleighError::MemoryAccess(e) => PcodeEmitBuildError::MemoryAccess(e),
            SleighError::Sleigh(e) => PcodeEmitBuildError::Sleigh(e),
        }
    }
}

impl From<UnknownInstructionException> for PcodeEmitBuildError {
    fn from(err: UnknownInstructionException) -> Self {
        PcodeEmitBuildError::UnknownInstruction(err)
    }
}

impl From<MemoryAccessException> for PcodeEmitBuildError {
    fn from(err: MemoryAccessException) -> Self {
        PcodeEmitBuildError::MemoryAccess(err)
    }
}

impl From<io::Error> for PcodeEmitBuildError {
    fn from(err: io::Error) -> Self {
        PcodeEmitBuildError::Io(err)
    }
}

impl fmt::Display for PcodeEmitBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcodeEmitBuildError::UnknownInstruction(err) => write!(f, "{err}"),
            PcodeEmitBuildError::MemoryAccess(err) => write!(f, "{err}"),
            PcodeEmitBuildError::Io(err) => write!(f, "{err}"),
            PcodeEmitBuildError::Sleigh(err) => write!(f, "{}", err.message()),
            PcodeEmitBuildError::NotYetImplemented(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for PcodeEmitBuildError {}

/// Class for converting a `ConstructTpl` into p-code ops for a particular instruction context.
///
/// Port of the interface of `ghidra.app.plugin.processors.sleigh.PcodeEmit`, the abstract base
/// class both `PcodeEmitPacked` and `PcodeEmitObjects` extend. Java's class carries both state
/// and behaviour; its port is split: [`PcodeEmitBase`] holds the shared fields and the concrete
/// template-walking driver (`build` and its private helpers), and this trait is the emitter's
/// public contract -- the accessors, the abstract operations ([`dump`](Self::dump),
/// [`resolve_relatives`](Self::resolve_relatives), [`add_label_ref`](Self::add_label_ref)) and
/// [`build`](Self::build), which a concrete emitter implements by running the driver (see
/// [`PcodeEmitObjects`](super::pcode_emit_objects::PcodeEmitObjects)).
/// [`check_overrides`](Self::check_overrides) (`checkOverrides`) and
/// [`resolve_final_fallthrough`](Self::resolve_final_fallthrough) (`resolveFinalFallthrough`) are
/// default methods over the accessors.
pub trait PcodeEmit {
    /// Stands in for `PcodeEmit.getStartAddress()`: the address of the instruction whose p-code
    /// is being emitted.
    fn start_address(&self) -> Address;

    /// Stands in for `PcodeEmit.getFallOffset()`: the default instruction fall offset (i.e.
    /// instruction length including delay-slotted instructions), possibly already adjusted for a
    /// fall-through override.
    fn fall_offset(&self) -> i32;

    /// Stands in for `PcodeEmit.getWalker()`: the parser tree walk state used to weave together
    /// p-code for the instruction.
    fn walker(&self) -> &ParserWalker<'_>;

    /// Stands in for the base `PcodeEmit.override` field: the p-code override in effect for this
    /// instruction, if any (a `null` override in Java disables all override checks).
    fn pcode_override(&self) -> Option<&dyn PcodeOverride>;

    /// Stands in for the base `PcodeEmit.fallOverride` field, computed once in the Java
    /// constructor from `override.getFallThroughOverride()`.
    fn fall_override(&self) -> Option<Address>;

    /// Stands in for the base `PcodeEmit.defaultFallAddress` field, computed once in the Java
    /// constructor as `instrAddr.addNoWrap(fallOffset)` (using the *pre-override* fall offset),
    /// alongside [`fall_override`](Self::fall_override).
    fn default_fall_address(&self) -> Option<Address>;

    /// Make a note of a reference to a label within a `BRANCH` or `CBRANCH` op, so it can later
    /// be resolved to a full relative address. Mirrors the abstract `PcodeEmit.addLabelRef()`.
    fn add_label_ref(&mut self);

    /// Now that every label template and reference has been seen, convert the collected
    /// references into full relative addresses. Mirrors the abstract
    /// `PcodeEmit.resolveRelatives()`.
    fn resolve_relatives(&mut self) -> Result<(), SleighException>;

    /// Emits one p-code operation. Mirrors the abstract
    /// `PcodeEmit.dump(Address, int, VarnodeData[], int, VarnodeData)`.
    fn dump(
        &mut self,
        instr_addr: Address,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()>;

    /// Walks a constructor's p-code template, dispatching `BUILD`/delay-slot/label/`CROSSBUILD`
    /// directives and emitting every other op (via [`dump`](Self::dump), after resolving its
    /// `VarnodeTpl` operands and applying any flow override) in order.
    ///
    /// Mirrors the public `PcodeEmit.build(ConstructTpl, int)`; see [`PcodeEmitBase::build`].
    fn build(&mut self, construct: &ConstructTpl, secnum: i32) -> Result<(), PcodeEmitBuildError>;

    /// Applies opcode-specific call/jump overrides, rewriting `in_[0]` in place to the override
    /// destination when one applies and returning the (possibly rewritten) opcode.
    ///
    /// Mirrors the package-private `PcodeEmit.checkOverrides(int, VarnodeData[])`. Returns
    /// `opcode` unchanged if there is no [`pcode_override`](Self::pcode_override).
    fn check_overrides(&self, opcode: OpCode, in_: &mut [VarnodeData]) -> OpCode {
        check_overrides(
            self.pcode_override(),
            self.fall_override(),
            self.default_fall_address(),
            opcode,
            in_,
        )
    }

    /// Now that all p-code has been generated, including special overrides and injections,
    /// ensures that a fall-through override adds a final branch so execution doesn't drop out
    /// the bottom (covering both the last-op-has-fallthrough and
    /// internal-label-branches-past-the-end cases).
    ///
    /// Mirrors the package-private `PcodeEmit.resolveFinalFallthrough()`. A no-op when there is
    /// no [`fall_override`](Self::fall_override).
    fn resolve_final_fallthrough(&mut self) -> io::Result<()> {
        let Some(fall_override) = self.fall_override() else {
            return Ok(());
        };
        let mut dest = VarnodeData::new(
            fall_override.space().clone(),
            fall_override.offset(),
            fall_override.space().pointer_size(),
        );
        let start_address = self.start_address();
        self.dump(
            start_address,
            OpCode::CpuiBranch,
            std::slice::from_mut(&mut dest),
            1,
            None,
        )
    }
}

/// The body of `PcodeEmit.checkOverrides(int, VarnodeData[])`, over the override state it
/// reads: applies opcode-specific call/jump overrides, rewriting `in_[0]` in place to the
/// override destination when one applies, and returns the (possibly rewritten) opcode.
pub fn check_overrides(
pcode_override: Option<&dyn PcodeOverride>,
fall_override: Option<Address>,
default_fall_address: Option<Address>,
opcode: OpCode,
in_: &mut [VarnodeData],
) -> OpCode {
    let Some(over) = pcode_override else {
        return opcode;
    };

    // An overriding call reference on an indirect call turns it into a direct call, unless a
    // call override has already been applied at this instruction.
    if opcode == OpCode::CpuiCallind && !over.is_call_override_ref_applied() {
        if let Some(call_ref) = over.get_overriding_reference(RefType::CallOverrideUnconditional)
        {
            apply_destination(&mut in_[0], &call_ref);
            over.set_call_override_ref_applied();
            return OpCode::CpuiCall;
        }
    }

    // CALLOTHER ops can be overridden with CALLOTHER_OVERRIDE_CALL or
    // CALLOTHER_OVERRIDE_JUMP; call overrides take precedence over jump overrides. Override
    // at most one CALLOTHER p-code op per native instruction.
    let call_other_override_applied = over.is_call_other_call_override_ref_applied()
        || over.is_call_other_jump_override_applied();
    if opcode == OpCode::CpuiCallother && !call_other_override_applied {
        if let Some(override_ref) =
            over.get_overriding_reference(RefType::CallOtherOverrideCall)
        {
            apply_destination(&mut in_[0], &override_ref);
            over.set_call_other_call_override_ref_applied();
            return OpCode::CpuiCall;
        }
        if let Some(override_ref) =
            over.get_overriding_reference(RefType::CallOtherOverrideJump)
        {
            apply_destination(&mut in_[0], &override_ref);
            over.set_call_other_jump_override_ref_applied();
            return OpCode::CpuiBranch;
        }
    }

    // Simple call reference override: grab the destination from the appropriate reference.
    // Only perform the override if the destination function does not have a call-fixup.
    if opcode == OpCode::CpuiCall
        && !over.is_call_override_ref_applied()
        && !over.has_call_fixup(in_[0].space.address(in_[0].offset))
    {
        #[allow(deprecated)]
        let mut call_ref = over.get_primary_call_reference();
        let mut overriding_ref = false;
        if call_ref.is_none() {
            call_ref = over.get_overriding_reference(RefType::CallOverrideUnconditional);
            overriding_ref = true;
        }
        if let Some(call_ref) = call_ref {
            if overriding_ref || actual_override(&in_[0], &call_ref) {
                apply_destination(&mut in_[0], &call_ref);
                over.set_call_override_ref_applied();
                return OpCode::CpuiCall;
            }
        }
    }

    // Fall-through override: alter a branch to the next instruction.
    if let (Some(fall_override), Some(default_fall_address)) =
        (fall_override, default_fall_address)
    {
        if opcode == OpCode::CpuiCbranch || opcode == OpCode::CpuiBranch {
            // Don't apply fall-through overrides into the constant space.
            if in_[0].space.space_type() == AddressSpaceType::Constant {
                return opcode;
            }
            if default_fall_address.offset() == in_[0].offset {
                apply_destination(&mut in_[0], &fall_override);
                return opcode;
            }
        }
    }

    // An overriding jump reference changes a conditional jump into an unconditional jump
    // targeting the reference.
    if (opcode == OpCode::CpuiBranch || opcode == OpCode::CpuiCbranch)
        && !over.is_jump_override_ref_applied()
    {
        // If the destination varnode is in the constant space, it's a p-code-relative
        // branch; these should not be overridden.
        if in_[0].space.space_type() == AddressSpaceType::Constant {
            return opcode;
        }
        if let Some(override_ref) =
            over.get_overriding_reference(RefType::JumpOverrideUnconditional)
        {
            apply_destination(&mut in_[0], &override_ref);
            over.set_jump_override_ref_applied();
            return OpCode::CpuiBranch;
        }
    }

    opcode
}

/// The shared state of `ghidra.app.plugin.processors.sleigh.PcodeEmit` -- the Java abstract
/// class's fields -- together with its concrete template-walking driver ([`build`]).
///
/// Java's `PcodeEmit` is an abstract class with instance state and two subclasses, so its port
/// is split: this struct holds the fields and concrete methods, and a [`PcodeEmitSink`] supplies
/// the abstract operations (`dump`, `addLabelRef`) of the concrete emitter
/// ([`PcodeEmitObjects`](super::pcode_emit_objects::PcodeEmitObjects)). The walker is passed to
/// the driver rather than stored, since delay-slot and crossbuild directives build other
/// instructions' templates with walkers over those instructions' parser contexts.
///
/// [`build`]: PcodeEmitBase::build
pub struct PcodeEmitBase<'a> {
    pcode_override: Option<&'a dyn PcodeOverride>,
    instcontext: Option<&'a dyn InstructionContext>,
    flow_override: Option<FlowOverride>,
    start_address: Address,
    default_fall_address: Option<Address>,
    fall_override: Option<Address>,
    fall_offset: i32,
    language: Option<Arc<SleighLanguage>>,
    const_space: Arc<AddressSpace>,
    uniq_space: Option<Arc<AddressSpace>>,
    uniquemask: i64,
    uniqueoffset: i64,
    /// Op index of each label, by label id (`labeldef`).
    labeldef: Vec<Option<i32>>,
    /// Number of p-code ops generated so far (`numOps`).
    num_ops: i32,
    labelbase: i32,
    labelcount: i32,
    /// Are we currently emitting delay slot p-code (`inDelaySlot`).
    in_delay_slot: bool,
}

/// The abstract operations of `PcodeEmit` that a concrete emitter supplies to
/// [`PcodeEmitBase`]'s driver.
pub trait PcodeEmitSink {
    /// Make a note of a reference to a label within a `BRANCH` or `CBRANCH` op, which is about
    /// to be emitted as op number `num_ops`. Port of the abstract `PcodeEmit.addLabelRef()`.
    fn add_label_ref(&mut self, num_ops: i32);

    /// Emits one p-code operation; `base` supplies the override state `checkOverrides` reads.
    /// Port of the abstract `PcodeEmit.dump(Address, int, VarnodeData[], int, VarnodeData)`.
    fn dump(
        &mut self,
        base: &PcodeEmitBase<'_>,
        instr_addr: Address,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> io::Result<()>;
}

fn const_real(val: i64) -> ConstTpl {
    ConstTpl {
        tp: ConstTplType::Real,
        value_real: val as u64,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    }
}

fn const_space_id(space: Arc<AddressSpace>) -> ConstTpl {
    ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: Some(space),
        handle_index: 0,
        select: None,
    }
}

fn op_tpl(opc: OpCode, out: Option<VarnodeTpl>, inputs: &[VarnodeTpl]) -> OpTpl {
    let mut op = OpTpl::with_opcode(opc);
    if let Some(out) = out {
        op.set_output(out);
    }
    for i in inputs {
        op.add_input(i.clone());
    }
    op
}

fn same_space(a: &AddressSpace, b: Option<&Arc<AddressSpace>>) -> bool {
    b.is_some_and(|b| *a == **b)
}

impl<'a> PcodeEmitBase<'a> {
    /// Port of `PcodeEmit(ParserWalker, InstructionContext, int, PcodeOverride)`: `walker` is
    /// the tree walk that will be passed to [`PcodeEmitBase::build`], `ictx` resolves delay-slot
    /// and crossbuild directives, `fall_offset` is the default instruction fall offset (the
    /// length including delay-slotted instructions) and `pcode_override` steers overrides.
    pub fn new(
        walker: &ParserWalker<'_>,
        ictx: Option<&'a dyn InstructionContext>,
        fall_offset: i32,
        pcode_override: Option<&'a dyn PcodeOverride>,
    ) -> Self {
        let parsercontext = walker.get_parser_context();
        let start_address = parsercontext.get_addr();
        let language = parsercontext
            .get_sleigh_prototype()
            .map(|p| p.language().clone());
        // A snippet (e.g. a call-fixup) has no prototype, and its temporaries are not patched
        let (uniq_space, uniquemask) = match &language {
            Some(language) => (
                language.get_address_factory().get_unique_space(),
                language.get_unique_allocation_mask() as i64,
            ),
            None => (None, 0),
        };
        let uniqueoffset = (start_address.offset() & uniquemask).wrapping_shl(8);
        let mut base = Self {
            pcode_override,
            instcontext: ictx,
            flow_override: None,
            const_space: walker.get_const_space(),
            start_address,
            default_fall_address: None,
            fall_override: None,
            fall_offset,
            language,
            uniq_space,
            uniquemask,
            uniqueoffset,
            labeldef: Vec::new(),
            num_ops: 0,
            labelbase: 0,
            labelcount: 0,
            in_delay_slot: false,
        };
        if let Some(over) = pcode_override {
            let flow = over.get_flow_override();
            base.flow_override = (flow != FlowOverride::None).then_some(flow);
            if let Some(fall) = over.get_fall_through_override() {
                let instr_addr = over.get_instruction_start();
                match instr_addr.add_no_wrap(fall_offset as i64) {
                    Ok(default_fall) => {
                        base.default_fall_address = Some(default_fall);
                        base.fall_offset = fall.subtract(&instr_addr) as i32;
                        base.fall_override = Some(fall);
                    }
                    Err(_) => {
                        base.fall_override = None;
                        base.default_fall_address = None;
                    }
                }
            }
        }
        base
    }

    /// Port of `getStartAddress()`.
    pub fn get_start_address(&self) -> Address {
        self.start_address.clone()
    }

    /// Port of `getFallOffset()`.
    pub fn get_fall_offset(&self) -> i32 {
        self.fall_offset
    }

    /// The p-code override in effect, if any.
    pub fn pcode_override(&self) -> Option<&'a dyn PcodeOverride> {
        self.pcode_override
    }

    /// The fall-through override address, if any (`fallOverride`).
    pub fn fall_override(&self) -> Option<Address> {
        self.fall_override.clone()
    }

    /// The default fall-through address, set alongside a fall-through override
    /// (`defaultFallAddress`).
    pub fn default_fall_address(&self) -> Option<Address> {
        self.default_fall_address.clone()
    }

    /// Op index of label `label_index`, if defined (`labeldef.get(labelIndex)`).
    pub fn label_def(&self, label_index: i32) -> Option<i32> {
        if label_index < 0 {
            return None;
        }
        self.labeldef.get(label_index as usize).copied().flatten()
    }

    /// Port of `checkOverrides(int, VarnodeData[])`.
    pub fn check_overrides(&self, opcode: OpCode, in_: &mut [VarnodeData]) -> OpCode {
        check_overrides(
            self.pcode_override,
            self.fall_override.clone(),
            self.default_fall_address.clone(),
            opcode,
            in_,
        )
    }

    fn set_unique_offset(&mut self, addr: &Address) {
        self.uniqueoffset = (addr.offset() & self.uniquemask).wrapping_shl(8);
    }

    fn unique_offset_of(&self, layout: UniqueLayout) -> i64 {
        layout.get_offset(self.language.as_deref()) as i64
    }

    fn uniq_space(&self) -> Result<Arc<AddressSpace>, PcodeEmitBuildError> {
        self.uniq_space.clone().ok_or_else(|| {
            SleighException::with_message("no unique space to hold a runtime temporary").into()
        })
    }

    /// Note the current op index as the definition of the label in `op` (a `PTRADD` label
    /// directive). Port of the private `setLabel(OpTpl)`.
    fn set_label(&mut self, op: &OpTpl) {
        let labelindex = (op.get_in(0).offset.get_real() as i32 + self.labelbase) as usize;
        if self.labeldef.len() <= labelindex {
            self.labeldef.resize(labelindex + 1, None);
        }
        self.labeldef[labelindex] = Some(self.num_ops);
    }

    /// Port of `resolveFinalFallthrough()`: with a fall-through override, a final branch keeps
    /// flow from dropping out the bottom.
    ///
    /// # Errors
    /// Whatever the sink reports.
    pub fn resolve_final_fallthrough(&self, sink: &mut dyn PcodeEmitSink) -> io::Result<()> {
        let Some(fall_override) = self.fall_override.clone() else {
            // handles both length-override and fallthrough override cases
            return Ok(());
        };
        let mut dest = VarnodeData::new(
            fall_override.space().clone(),
            fall_override.offset(),
            fall_override.space().pointer_size(),
        );
        sink.dump(
            self,
            self.start_address.clone(),
            OpCode::CpuiBranch,
            std::slice::from_mut(&mut dest),
            1,
            None,
        )
    }

    fn emit(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        opcode: OpCode,
        in_: &mut [VarnodeData],
        isize: usize,
        out: Option<&VarnodeData>,
    ) -> Result<(), PcodeEmitBuildError> {
        let start = self.start_address.clone();
        sink.dump(self, start, opcode, in_, isize, out)?;
        self.num_ops += 1;
        Ok(())
    }

    fn dump_branch_override(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
        opt: &OpTpl,
    ) -> Result<bool, PcodeEmitBuildError> {
        let opcode = opt.get_opcode();
        if opcode == OpCode::CpuiCall {
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiBranch, None, &opt.input))?;
            self.flow_override = None;
            return Ok(true);
        } else if opcode == OpCode::CpuiCallind || opcode == OpCode::CpuiReturn {
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiBranchind, None, &opt.input))?;
            self.flow_override = None;
            return Ok(true);
        }
        Ok(false)
    }

    fn dump_null_return(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
    ) -> Result<(), PcodeEmitBuildError> {
        let null_addr = VarnodeTpl::with_fields(
            const_space_id(self.const_space.clone()),
            const_real(0),
            const_real(self.const_space.pointer_size() as i64),
        );
        self.dump_op(sink, walker, &op_tpl(OpCode::CpuiReturn, None, &[null_addr]))
    }

    fn is_local_branch_target(tp: ConstTplType) -> bool {
        matches!(
            tp,
            ConstTplType::JRelative | ConstTplType::JStart | ConstTplType::JNext | ConstTplType::JNext2
        )
    }

    fn relative_label(&mut self) -> VarnodeTpl {
        let label_index = self.labelcount;
        self.labelcount += 1;
        VarnodeTpl::with_fields(
            const_space_id(self.const_space.clone()),
            ConstTpl {
                tp: ConstTplType::JRelative,
                value_real: label_index as u64,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            const_real(8),
        )
    }

    fn dump_call_override(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
        opt: &OpTpl,
        return_after_call: bool,
    ) -> Result<bool, PcodeEmitBuildError> {
        let opcode = opt.get_opcode();
        let inputs = &opt.input;
        if opcode == OpCode::CpuiBranch {
            if Self::is_local_branch_target(inputs[0].offset.tp) {
                return Ok(false);
            }
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCall, None, inputs))?;
            if return_after_call {
                self.dump_null_return(sink, walker)?;
            }
            self.flow_override = None;
            return Ok(true);
        } else if opcode == OpCode::CpuiBranchind || opcode == OpCode::CpuiReturn {
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCallind, None, inputs))?;
            if return_after_call {
                self.dump_null_return(sink, walker)?;
            }
            self.flow_override = None;
            return Ok(true);
        } else if opcode == OpCode::CpuiCbranch {
            if Self::is_local_branch_target(inputs[0].offset.tp) {
                return Ok(false);
            }
            //   CBRANCH <dest>,<cond>
            // -- maps to --
            //   tmp = BOOL_NEGATE <cond>
            //   CBRANCH <label>,tmp
            //   CALL <dest>
            //   <label>
            let tmp = VarnodeTpl::with_fields(
                const_space_id(self.uniq_space()?),
                const_real(self.unique_offset_of(UniqueLayout::RuntimeBooleanInvert)),
                inputs[1].size.clone(),
            );
            let label = self.relative_label();
            let dest = inputs[0].clone();
            let cond = inputs[1].clone();
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiBoolNegate, Some(tmp.clone()), &[cond]))?;
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCbranch, None, &[label.clone(), tmp]))?;
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCall, None, &[dest]))?;
            if return_after_call {
                self.dump_null_return(sink, walker)?;
            }
            self.set_label(&op_tpl(OpCode::CpuiPtradd, None, &[label]));
            self.flow_override = None;
            return Ok(true);
        } else if (opcode == OpCode::CpuiCall || opcode == OpCode::CpuiCallind) && return_after_call
        {
            self.dump_op(sink, walker, opt)?; // dump original call
            self.dump_null_return(sink, walker)?;
            self.flow_override = None;
            return Ok(true);
        }
        Ok(false)
    }

    fn dump_return_override(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
        opt: &OpTpl,
    ) -> Result<bool, PcodeEmitBuildError> {
        let opcode = opt.get_opcode();
        let inputs = &opt.input;
        if opcode == OpCode::CpuiBranch || opcode == OpCode::CpuiCall {
            if Self::is_local_branch_target(inputs[0].offset.tp) {
                return Ok(false);
            }
            let ptr_size = walker.get_cur_space().pointer_size() as i64;
            //   BRANCH <dest>  (or CALL)
            // -- maps to --
            //   tmp = COPY &<dest>
            //   RETURN tmp
            let tmp = VarnodeTpl::with_fields(
                const_space_id(self.uniq_space()?),
                const_real(self.unique_offset_of(UniqueLayout::RuntimeReturnLocation)),
                const_real(ptr_size),
            );
            let dest_addr = VarnodeTpl::with_fields(
                const_space_id(self.const_space.clone()),
                inputs[0].offset.clone(),
                const_real(ptr_size),
            );
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCopy, Some(tmp.clone()), &[dest_addr]))?;
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiReturn, None, &[tmp]))?;
            self.flow_override = None;
            return Ok(true);
        } else if opcode == OpCode::CpuiBranchind || opcode == OpCode::CpuiCallind {
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiReturn, None, inputs))?;
            self.flow_override = None;
            return Ok(true);
        } else if opcode == OpCode::CpuiCbranch {
            if Self::is_local_branch_target(inputs[0].offset.tp) {
                return Ok(false);
            }
            let ptr_size = walker.get_cur_space().pointer_size() as i64;
            //   CBRANCH <dest>,<cond>
            // -- maps to --
            //   tmp = BOOL_NEGATE <cond>
            //   CBRANCH <label>,tmp
            //   tmp2 = COPY &<dest>
            //   RETURN <dest>
            //   <label>
            let tmp = VarnodeTpl::with_fields(
                const_space_id(self.uniq_space()?),
                const_real(self.unique_offset_of(UniqueLayout::RuntimeBooleanInvert)),
                inputs[1].size.clone(),
            );
            let tmp2 = VarnodeTpl::with_fields(
                const_space_id(self.uniq_space()?),
                const_real(self.unique_offset_of(UniqueLayout::RuntimeReturnLocation)),
                const_real(ptr_size),
            );
            let dest_addr = VarnodeTpl::with_fields(
                const_space_id(self.const_space.clone()),
                inputs[0].offset.clone(),
                const_real(ptr_size),
            );
            let label = self.relative_label();
            let cond = inputs[1].clone();
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiBoolNegate, Some(tmp.clone()), &[cond]))?;
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCbranch, None, &[label.clone(), tmp]))?;
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiCopy, Some(tmp2.clone()), &[dest_addr]))?;
            self.dump_op(sink, walker, &op_tpl(OpCode::CpuiReturn, None, &[tmp2]))?;
            self.set_label(&op_tpl(OpCode::CpuiPtradd, None, &[label]));
            self.flow_override = None;
            return Ok(true);
        }
        Ok(false)
    }

    fn dump_flow_override(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
        opt: &OpTpl,
    ) -> Result<bool, PcodeEmitBuildError> {
        if opt.get_out().is_some() {
            return Ok(false); // only call, branch and return instructions can be affected
        }
        match self.flow_override {
            Some(FlowOverride::Branch) => self.dump_branch_override(sink, walker, opt),
            Some(FlowOverride::Call) => self.dump_call_override(sink, walker, opt, false),
            Some(FlowOverride::CallReturn) => self.dump_call_override(sink, walker, opt, true),
            Some(FlowOverride::Return) => self.dump_return_override(sink, walker, opt),
            _ => Ok(false),
        }
    }

    /// Convert a varnode template into a concrete varnode. Port of the private
    /// `generateLocation(VarnodeTpl, VarnodeData)`.
    fn generate_location(
        &self,
        walker: &ParserWalker<'_>,
        vntpl: &VarnodeTpl,
    ) -> Result<VarnodeData, PcodeEmitBuildError> {
        let space = vntpl.space.fix_space(walker)?;
        let size = vntpl.size.fix(walker)? as i32;
        let fixed = vntpl.offset.fix(walker)?;
        let offset = if *space == *self.const_space {
            (fixed as u64 & CALC_MASK[size.clamp(0, 8) as usize]) as i64
        } else if same_space(&space, self.uniq_space.as_ref()) {
            fixed | self.uniqueoffset
        } else {
            space.truncate_offset(fixed)
        };
        Ok(VarnodeData::new(space, offset, size))
    }

    /// Generate a concrete pointer varnode for a dynamic varnode template, returning it with
    /// the space into which the pointer points. Port of the private
    /// `generatePointer(VarnodeTpl, VarnodeData)`.
    fn generate_pointer(
        &self,
        walker: &ParserWalker<'_>,
        vntpl: &VarnodeTpl,
    ) -> Result<(VarnodeData, Arc<AddressSpace>), PcodeEmitBuildError> {
        let hand = walker.get_fixed_handle(vntpl.offset.handle_index as usize);
        let missing = || SleighException::with_message("dynamic handle is missing a space");
        let space = hand.offset_space.clone().ok_or_else(missing)?;
        let size = hand.offset_size;
        let offset = if *space == *self.const_space {
            (hand.offset_offset as u64 & CALC_MASK[size.clamp(0, 8) as usize]) as i64
        } else if same_space(&space, self.uniq_space.as_ref()) {
            hand.offset_offset | self.uniqueoffset
        } else {
            space.truncate_offset(hand.offset_offset)
        };
        Ok((VarnodeData::new(space, offset, size), hand.space.ok_or_else(missing)?))
    }

    /// Adjust the dynamic pointer in `dyncache[1]` for a `V_OFFSET_PLUS` in `vn`, emitting the
    /// `INT_ADD`. Port of the private `generatePointerAdd(VarnodeData[], VarnodeTpl)`.
    fn generate_pointer_add(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        dyncache: &mut [VarnodeData; 3],
        vn: &VarnodeTpl,
    ) -> Result<(), PcodeEmitBuildError> {
        let offset_plus = vn.offset.get_real() & 0xffff;
        if offset_plus == 0 {
            return Ok(());
        }
        dyncache.swap(0, 1);
        dyncache[1] = VarnodeData::new(self.const_space.clone(), offset_plus, dyncache[0].size);
        dyncache[2] = VarnodeData::new(
            self.uniq_space()?,
            self.unique_offset_of(UniqueLayout::RuntimeBitrangeEa),
            dyncache[0].size,
        );
        let out = dyncache[2].clone();
        self.emit(sink, OpCode::CpuiIntAdd, &mut dyncache[..], 2, Some(&out))?;
        dyncache.swap(1, 2);
        Ok(())
    }

    /// Emits one template op, resolving its operands (and any dynamic loads/stores they
    /// imply). Port of the private `dump(OpTpl)`.
    fn dump_op(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
        opt: &OpTpl,
    ) -> Result<(), PcodeEmitBuildError> {
        let isize = opt.input.len();
        let mut incache: Vec<VarnodeData> = Vec::with_capacity(isize);
        let const_space = self.const_space.clone();
        let placeholder = || VarnodeData::new(const_space.clone(), 0, 0);

        // First build all the inputs
        for vn in &opt.input {
            if vn.is_dynamic(walker) {
                let loc = self.generate_location(walker, vn)?; // Temporary storage
                let (ptr, spc) = self.generate_pointer(walker, vn)?;
                let mut dyncache = [placeholder(), ptr, placeholder()];
                if vn.offset.select == Some(ConstTplSelect::VOffsetPlus) {
                    self.generate_pointer_add(sink, &mut dyncache, vn)?;
                }
                dyncache[0] = VarnodeData::new(self.const_space.clone(), spc.space_id() as i64, 4);
                dyncache[2] = loc.clone();
                let out = dyncache[2].clone();
                self.emit(sink, OpCode::CpuiLoad, &mut dyncache[..], 2, Some(&out))?;
                incache.push(loc);
            } else {
                incache.push(self.generate_location(walker, vn)?);
            }
        }
        if isize > 0 && opt.input[0].is_relative() {
            incache[0].offset += self.labelbase as i64;
            sink.add_label_ref(self.num_ops);
        }
        match opt.get_out() {
            Some(outvn) if outvn.is_dynamic(walker) => {
                let outcache = self.generate_location(walker, outvn)?; // Temporary storage
                self.emit(sink, opt.get_opcode(), &mut incache, isize, Some(&outcache))?;
                let (ptr, spc) = self.generate_pointer(walker, outvn)?;
                let mut dyncache = [placeholder(), ptr, placeholder()];
                if outvn.offset.select == Some(ConstTplSelect::VOffsetPlus) {
                    self.generate_pointer_add(sink, &mut dyncache, outvn)?;
                }
                dyncache[0] = VarnodeData::new(self.const_space.clone(), spc.space_id() as i64, 4);
                dyncache[2] = outcache;
                self.emit(sink, OpCode::CpuiStore, &mut dyncache[..], 3, None)?;
            }
            Some(outvn) => {
                let outcache = self.generate_location(walker, outvn)?;
                self.emit(sink, opt.get_opcode(), &mut incache, isize, Some(&outcache))?;
            }
            None => self.emit(sink, opt.get_opcode(), &mut incache, isize, None)?,
        }
        Ok(())
    }

    /// Follows a BUILD directive into the subtable operand it names. Port of the private
    /// `appendBuild(OpTpl, int)`.
    fn append_build(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &mut ParserWalker<'_>,
        bld: &OpTpl,
        secnum: i32,
    ) -> Result<(), PcodeEmitBuildError> {
        // Recover operand index from build statement
        let index = bld.get_in(0).offset.get_real() as usize;
        if !Self::operand_is_subtable(walker, index) {
            return Ok(());
        }
        walker.push_operand(index);
        let res = self.build_current(sink, walker, secnum);
        walker.pop_operand();
        res
    }

    /// Builds the template of the constructor at the walker's position: its section `secnum`
    /// (or the implied BUILD list of an empty section), or its main template for `-1`.
    fn build_current(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &mut ParserWalker<'_>,
        secnum: i32,
    ) -> Result<(), PcodeEmitBuildError> {
        let ct = walker
            .get_constructor()
            .ok_or_else(|| SleighException::with_message("unresolved subtable operand"))?;
        if secnum >= 0 {
            match ct.get_named_templ(secnum) {
                None => self.build_empty(sink, walker, &ct, secnum),
                Some(construct) => self.build(sink, walker, Some(construct), secnum),
            }
        } else {
            self.build(sink, walker, ct.get_templ(), -1)
        }
    }

    fn operand_is_subtable(walker: &ParserWalker<'_>, index: usize) -> bool {
        let (Some(ct), Some(table)) = (walker.get_constructor(), walker.symbol_table()) else {
            return false;
        };
        matches!(
            ct.get_operand(table, index)
                .and_then(|op| op.get_defining_symbol(table)),
            Some(SleighSymbol::Subtable(_))
        )
    }

    /// The parser context of the instruction at `addr`, from the instruction context. Java
    /// casts the returned `ParserContext` to `SleighParserContext` without checking.
    fn parser_context_at(
        &self,
        addr: &Address,
        what: &str,
    ) -> Result<Box<dyn ParserContext>, PcodeEmitBuildError> {
        let ictx = self.instcontext.ok_or_else(|| {
            UnknownInstructionException::with_message(format!(
                "Could not find cached {what} parser context"
            ))
        })?;
        let ctx = ictx.get_parser_context_at(addr.clone()).map_err(|_| {
            UnknownInstructionException::with_message(format!(
                "Could not find cached {what} parser context"
            ))
        })?;
        if ctx
            .as_any()
            .and_then(|a| a.downcast_ref::<SleighParserContext>())
            .is_none()
        {
            return Err(UnknownInstructionException::with_message(format!(
                "Could not find cached {what} parser context"
            ))
            .into());
        }
        Ok(ctx)
    }

    /// Insert the p-code of the instruction(s) in the delay slot at this point. Port of the
    /// private `delaySlot(OpTpl)`.
    fn delay_slot(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
    ) -> Result<(), PcodeEmitBuildError> {
        if self.in_delay_slot {
            return Err(SleighException::with_message(format!(
                "Delay Slot recursion problem for Instruction at {}",
                walker.get_addr()
            ))
            .into());
        }
        self.in_delay_slot = true;
        let parsercontext = walker.get_parser_context();
        let baseaddr = parsercontext.get_addr();
        let proto = parsercontext
            .get_sleigh_prototype()
            .ok_or_else(|| SleighException::with_message("delay slot outside an instruction"))?;
        let mut falloffset = proto.get_length();
        let delay_slot_byte_cnt = proto.get_delay_slot_byte_count();
        let olduniqueoffset = self.uniqueoffset;
        let mut bytecount = 0;
        let res = (|| {
            loop {
                let addr = baseaddr
                    .add(falloffset as i64)
                    .map_err(|e| SleighException::with_message(e.to_string()))?;
                self.set_unique_offset(&addr);
                let delay_box = self.parser_context_at(&addr, "delayslot")?;
                let delay = delay_box
                    .as_any()
                    .and_then(|a| a.downcast_ref::<SleighParserContext>())
                    .expect("checked by parser_context_at");
                let len = delay
                    .get_sleigh_prototype()
                    .map_or(0, |p| p.get_length());
                let mut delay_walker = ParserWalker::new(delay);
                delay_walker.base_state();
                let ct = delay_walker.get_constructor();
                self.build(
                    sink,
                    &mut delay_walker,
                    ct.as_ref().and_then(|c| c.get_templ()),
                    -1,
                )?;
                falloffset += len;
                bytecount += len;
                if bytecount >= delay_slot_byte_cnt {
                    break;
                }
            }
            Ok(())
        })();
        self.uniqueoffset = olduniqueoffset;
        self.in_delay_slot = false;
        res
    }

    /// Inject the p-code for a different instruction at this point. Port of the private
    /// `appendCrossBuild(OpTpl, int)`.
    fn append_cross_build(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &ParserWalker<'_>,
        bld: &OpTpl,
        secnum: i32,
    ) -> Result<(), PcodeEmitBuildError> {
        if secnum >= 0 {
            return Err(SleighException::with_message(format!(
                "CROSSBUILD recursion problem for instruction at {}",
                walker.get_addr()
            ))
            .into());
        }
        let secnum = bld.get_in(1).offset.get_real() as i32;
        let vn = bld.get_in(0);
        let spc = vn.space.fix_space(walker)?;
        let addr = Address::new(spc.clone(), spc.truncate_offset(vn.offset.fix(walker)?));
        let olduniqueoffset = self.uniqueoffset;
        self.set_unique_offset(&addr);
        let res = (|| {
            let cross_box = self.parser_context_at(&addr, "crossbuild")?;
            let cross = cross_box
                .as_any()
                .and_then(|a| a.downcast_ref::<SleighParserContext>())
                .expect("checked by parser_context_at");
            let mut cross_walker =
                ParserWalker::with_cross_context(cross, walker.get_parser_context());
            cross_walker.base_state();
            let ct = cross_walker
                .get_constructor()
                .ok_or_else(|| SleighException::with_message("unresolved crossbuild target"))?;
            match ct.get_named_templ(secnum) {
                None => self.build_empty(sink, &mut cross_walker, &ct, secnum),
                Some(construct) => self.build(sink, &mut cross_walker, Some(construct), secnum),
            }
        })();
        self.uniqueoffset = olduniqueoffset;
        res
    }

    /// Walks a constructor's p-code template, dispatching BUILD, delay-slot, label and
    /// CROSSBUILD directives and emitting every other op. Port of
    /// `PcodeEmit.build(ConstructTpl, int)`.
    ///
    /// # Errors
    /// [`PcodeEmitBuildError::NotYetImplemented`] for a constructor without semantics, or any
    /// failure resolving the template or a referenced instruction.
    pub fn build(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &mut ParserWalker<'_>,
        construct: Option<&ConstructTpl>,
        secnum: i32,
    ) -> Result<(), PcodeEmitBuildError> {
        let Some(construct) = construct else {
            return Err(PcodeEmitBuildError::NotYetImplemented(
                "Semantics for this instruction are not implemented".to_string(),
            ));
        };

        let oldbase = self.labelbase; // Recursively save old labelbase
        self.labelbase = self.labelcount;
        self.labelcount += construct.num_labels;

        for op in &construct.vec {
            match op.get_opcode() {
                OpCode::CpuiMultiequal => self.append_build(sink, walker, op, secnum)?, // Build placeholder
                OpCode::CpuiIndirect => self.delay_slot(sink, walker)?, // Delay slot placeholder
                OpCode::CpuiPtradd => self.set_label(op),               // Label placeholder
                OpCode::CpuiPtrsub => self.append_cross_build(sink, walker, op, secnum)?, // Crossbuild placeholder
                _ => {
                    if self.in_delay_slot
                        || self.flow_override.is_none()
                        || !self.dump_flow_override(sink, walker, op)?
                    {
                        self.dump_op(sink, walker, op)?;
                    }
                }
            }
        }
        self.labelbase = oldbase; // Restore old labelbase
        Ok(())
    }

    /// Build a named p-code section of a constructor that contains only implied BUILD
    /// directives. Port of the private `buildEmpty(Constructor, int)`.
    fn build_empty(
        &mut self,
        sink: &mut dyn PcodeEmitSink,
        walker: &mut ParserWalker<'_>,
        ct: &Constructor,
        secnum: i32,
    ) -> Result<(), PcodeEmitBuildError> {
        let numops = ct.get_num_operands();
        for i in 0..numops {
            let is_subtable = walker.symbol_table().is_some_and(|table| {
                matches!(
                    ct.get_operand(table, i)
                        .and_then(|op| op.get_defining_symbol(table)),
                    Some(SleighSymbol::Subtable(_))
                )
            });
            if !is_subtable {
                continue;
            }
            walker.push_operand(i);
            let res = self.build_current(sink, walker, secnum);
            walker.pop_operand();
            res?;
        }
        Ok(())
    }
}

/// Rewrites `dest` to point at `addr`, mirroring the repeated
/// `dest.space = ...; dest.offset = ...; dest.size = dest.space.getPointerSize();` pattern in
/// `PcodeEmit.checkOverrides`.
fn apply_destination(dest: &mut VarnodeData, addr: &Address) {
    dest.space = addr.space().clone();
    dest.offset = addr.offset();
    dest.size = dest.space.pointer_size();
}

/// Checks whether an overriding reference actually changes the call destination.
///
/// Mirrors the private `PcodeEmit.actualOverride(VarnodeData, Address)`.
fn actual_override(data: &VarnodeData, addr: &Address) -> bool {
    Address::new(data.space.clone(), data.offset) != *addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
    use crate::program::model::lang::InjectPayload;
    use crate::program::seam_stubs::FlowOverride;
    use std::cell::Cell;
    use std::sync::Arc;

    fn make_walker(addr: Address) -> ParserWalker<'static> {
        // The mock owns its walker, so the (tiny) context it walks is leaked for the test.
        let context: &'static SleighParserContext = Box::leak(Box::new(
            SleighParserContext::for_snippet(addr.clone(), Some(addr), None, None, None),
        ));
        ParserWalker::new(context)
    }

    /// A configurable [`PcodeOverride`] mock, proving `check_overrides`/
    /// `resolve_final_fallthrough`'s object-safety through `&self` interior mutability, matching
    /// the real port's own test convention (see `PcodeOverride`'s `MockOverride`).
    #[derive(Default)]
    struct TestOverride {
        instruction_start: Option<Address>,
        call_override_ref: Option<Address>,
        jump_override_ref: Option<Address>,
        call_override_applied: Cell<bool>,
        jump_override_applied: Cell<bool>,
        call_other_call_applied: Cell<bool>,
        call_other_jump_applied: Cell<bool>,
    }

    impl PcodeOverride for TestOverride {
        fn get_instruction_start(&self) -> Address {
            self.instruction_start.clone().expect("instruction_start")
        }
        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::None
        }
        fn get_overriding_reference(&self, ref_type: RefType) -> Option<Address> {
            match ref_type {
                RefType::CallOverrideUnconditional => self.call_override_ref.clone(),
                RefType::JumpOverrideUnconditional => self.jump_override_ref.clone(),
                _ => None,
            }
        }
        fn get_fall_through_override(&self) -> Option<Address> {
            None
        }
        fn has_call_fixup(&self, _call_dest_addr: Address) -> bool {
            false
        }
        fn get_call_fixup(&self, _call_dest_addr: Address) -> Option<Box<dyn InjectPayload>> {
            None
        }
        fn set_call_override_ref_applied(&self) {
            self.call_override_applied.set(true);
        }
        fn is_call_override_ref_applied(&self) -> bool {
            self.call_override_applied.get()
        }
        fn set_jump_override_ref_applied(&self) {
            self.jump_override_applied.set(true);
        }
        fn is_jump_override_ref_applied(&self) -> bool {
            self.jump_override_applied.get()
        }
        fn set_call_other_call_override_ref_applied(&self) {
            self.call_other_call_applied.set(true);
        }
        fn is_call_other_call_override_ref_applied(&self) -> bool {
            self.call_other_call_applied.get()
        }
        fn set_call_other_jump_override_ref_applied(&self) {
            self.call_other_jump_applied.set(true);
        }
        fn is_call_other_jump_override_applied(&self) -> bool {
            self.call_other_jump_applied.get()
        }
        fn has_potential_override(&self) -> bool {
            self.call_override_ref.is_some() || self.jump_override_ref.is_some()
        }
        #[allow(deprecated)]
        fn get_primary_call_reference(&self) -> Option<Address> {
            None
        }
    }

    struct MockEmit {
        start_address: Address,
        fall_offset: i32,
        walker: ParserWalker<'static>,
        over: Option<TestOverride>,
        fall_override: Option<Address>,
        default_fall_address: Option<Address>,
        dumped: Vec<(OpCode, Vec<VarnodeData>)>,
    }

    impl MockEmit {
        fn new(start_address: Address) -> Self {
            Self {
                walker: make_walker(start_address.clone()),
                start_address,
                fall_offset: 4,
                over: None,
                fall_override: None,
                default_fall_address: None,
                dumped: Vec::new(),
            }
        }
    }

    impl PcodeEmit for MockEmit {
        fn start_address(&self) -> Address {
            self.start_address.clone()
        }
        fn fall_offset(&self) -> i32 {
            self.fall_offset
        }
        fn walker(&self) -> &ParserWalker<'_> {
            &self.walker
        }
        fn pcode_override(&self) -> Option<&dyn PcodeOverride> {
            self.over.as_ref().map(|o| o as &dyn PcodeOverride)
        }
        fn fall_override(&self) -> Option<Address> {
            self.fall_override.clone()
        }
        fn default_fall_address(&self) -> Option<Address> {
            self.default_fall_address.clone()
        }
        fn add_label_ref(&mut self) {}
        fn resolve_relatives(&mut self) -> Result<(), SleighException> {
            Ok(())
        }
        fn dump(
            &mut self,
            _instr_addr: Address,
            opcode: OpCode,
            in_: &mut [VarnodeData],
            isize: usize,
            _out: Option<&VarnodeData>,
        ) -> io::Result<()> {
            self.dumped.push((opcode, in_[..isize].to_vec()));
            Ok(())
        }
        fn build(
            &mut self,
            _construct: &ConstructTpl,
            _secnum: i32,
        ) -> Result<(), PcodeEmitBuildError> {
            Ok(())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    #[test]
    fn check_overrides_converts_indirect_call_to_direct() {
        let space = ram_space();
        let mut emit = MockEmit::new(addr(&space, 0x1000));
        emit.over = Some(TestOverride {
            instruction_start: Some(addr(&space, 0x1000)),
            call_override_ref: Some(addr(&space, 0x9999)),
            ..Default::default()
        });

        let mut inputs = [VarnodeData::new(space.clone(), 0x2000, 4)];
        let result = emit.check_overrides(OpCode::CpuiCallind, &mut inputs);

        assert_eq!(result, OpCode::CpuiCall);
        assert_eq!(inputs[0].offset, 0x9999);
        assert!(emit.over.as_ref().unwrap().is_call_override_ref_applied());
    }

    #[test]
    fn check_overrides_applies_call_reference_override() {
        let space = ram_space();
        let mut emit = MockEmit::new(addr(&space, 0x1000));
        emit.over = Some(TestOverride {
            instruction_start: Some(addr(&space, 0x1000)),
            call_override_ref: Some(addr(&space, 0x5000)),
            ..Default::default()
        });

        let mut inputs = [VarnodeData::new(space.clone(), 0x2000, 4)];
        let result = emit.check_overrides(OpCode::CpuiCall, &mut inputs);

        assert_eq!(result, OpCode::CpuiCall);
        assert_eq!(inputs[0].offset, 0x5000);
        assert!(emit.over.as_ref().unwrap().is_call_override_ref_applied());
    }

    #[test]
    fn check_overrides_leaves_opcode_unchanged_without_override() {
        let space = ram_space();
        let mut emit = MockEmit::new(addr(&space, 0x1000));
        let mut inputs = [VarnodeData::new(space.clone(), 0x2000, 4)];

        let result = emit.check_overrides(OpCode::CpuiCall, &mut inputs);

        assert_eq!(result, OpCode::CpuiCall);
        assert_eq!(inputs[0].offset, 0x2000);
    }

    #[test]
    fn resolve_final_fallthrough_emits_branch_to_fall_override() {
        let space = ram_space();
        let mut emit = MockEmit::new(addr(&space, 0x1000));
        emit.fall_override = Some(addr(&space, 0x1010));

        emit.resolve_final_fallthrough().unwrap();

        assert_eq!(emit.dumped.len(), 1);
        let (opcode, inputs) = &emit.dumped[0];
        assert_eq!(*opcode, OpCode::CpuiBranch);
        assert_eq!(inputs[0].offset, 0x1010);
    }

    #[test]
    fn resolve_final_fallthrough_is_a_no_op_without_fall_override() {
        let space = ram_space();
        let mut emit = MockEmit::new(addr(&space, 0x1000));

        emit.resolve_final_fallthrough().unwrap();

        assert!(emit.dumped.is_empty());
    }

    /// Proves `dyn PcodeEmit` is object safe and usable through a trait object.
    #[test]
    fn is_object_safe() {
        let space = ram_space();
        let mut emit: Box<dyn PcodeEmit> = Box::new(MockEmit::new(addr(&space, 0x1000)));
        assert!(emit.resolve_relatives().is_ok());
        assert!(emit.build(&ConstructTpl::new(), -1).is_ok());
        emit.add_label_ref();
    }
}
