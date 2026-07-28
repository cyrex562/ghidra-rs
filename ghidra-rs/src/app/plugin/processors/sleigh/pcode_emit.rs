use super::sleigh_exception::SleighException;
use super::varnode_data::VarnodeData;
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::{Address, AddressSpaceType};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::ParserWalker;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
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
        }
    }
}

impl std::error::Error for PcodeEmitBuildError {}

/// Class for converting a `ConstructTpl` into p-code ops for a particular instruction context.
///
/// Port of `ghidra.app.plugin.processors.sleigh.PcodeEmit`. In Java this is the abstract base
/// class both `PcodeEmitPacked` and `PcodeEmitObjects` extend, but as those two ports already
/// note, most of its value is a large template-walking driver
/// ([`build`](Self::build) and its private helpers `dump(OpTpl)`, `appendBuild`, `delaySlot`,
/// `appendCrossBuild`, `buildEmpty`, `generateLocation`, `generatePointer`,
/// `generatePointerAdd`, and the `dumpFlowOverride` family) that resolves `VarnodeTpl`s against a
/// live `ParserWalker` via `ConstTpl.fix`/`VarnodeTpl.fixSpace` -- neither of which is ported yet
/// -- and recurses into delay-slot/crossbuild instruction contexts via `InstructionContext`. That
/// machinery is left as a required (bodyless) [`build`](Self::build) method for a future port,
/// mirroring the precedent set by
/// [`AbstractAssemblyTreeResolver::resolve_root_recursion`](
/// crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver::resolve_root_recursion).
///
/// The three Java-abstract extension points ([`dump`](Self::dump),
/// [`resolve_relatives`](Self::resolve_relatives), [`add_label_ref`](Self::add_label_ref)) and the
/// public accessors ([`start_address`](Self::start_address), [`fall_offset`](Self::fall_offset),
/// [`walker`](Self::walker)) are declared as required methods, matching the abstract class's own
/// contract. What *is* ported as real default-method logic -- because it only needs types already
/// real in this crate (`VarnodeData`, `Address`, `RefType`, [`PcodeOverride`]) -- is
/// [`check_overrides`](Self::check_overrides) (`checkOverrides`) and
/// [`resolve_final_fallthrough`](Self::resolve_final_fallthrough) (`resolveFinalFallthrough`).
/// The constructor is dropped, like the sibling ports' constructors: a concrete implementor is
/// expected to compute [`fall_override`](Self::fall_override)/
/// [`default_fall_address`](Self::default_fall_address) once (mirroring the Java constructor's
/// `fallOverride`/`defaultFallAddress` field setup) and expose them via those accessors.
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
    fn walker(&self) -> &ParserWalker;

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
    /// Mirrors the public `PcodeEmit.build(ConstructTpl, int)`. Left as a required method: its
    /// Java body resolves each op's `VarnodeTpl` operands into concrete `VarnodeData` via
    /// `ConstTpl.fix(ParserWalker)`/`VarnodeTpl.fixSpace(ParserWalker)` (neither ported yet),
    /// recurses into subtable operands and delay-slot/crossbuild instruction contexts via
    /// `ParserWalker.pushOperand`/`InstructionContext.getParserContext`, and threads through
    /// label bookkeeping via [`add_label_ref`](Self::add_label_ref) -- see this trait's own docs
    /// for the full list of not-yet-ported collaborators.
    fn build(&mut self, construct: &ConstructTpl, secnum: i32) -> Result<(), PcodeEmitBuildError>;

    /// Applies opcode-specific call/jump overrides, rewriting `in_[0]` in place to the override
    /// destination when one applies and returning the (possibly rewritten) opcode.
    ///
    /// Mirrors the package-private `PcodeEmit.checkOverrides(int, VarnodeData[])`. Returns
    /// `opcode` unchanged if there is no [`pcode_override`](Self::pcode_override).
    fn check_overrides(&self, opcode: OpCode, in_: &mut [VarnodeData]) -> OpCode {
        let Some(over) = self.pcode_override() else {
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
            (self.fall_override(), self.default_fall_address())
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
    use crate::program::model::lang::sleigh::walker::{MemBuffer, ParserContext};
    use crate::program::model::lang::InjectPayload;
    use crate::program::seam_stubs::FlowOverride;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct DummyMemBuffer(Address);

    impl MemBuffer for DummyMemBuffer {
        fn get_address(&self) -> Address {
            self.0.clone()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, buf: &mut [u8], _offset: i32) -> usize {
            buf.fill(0);
            buf.len()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }

    fn make_walker(addr: Address) -> ParserWalker {
        let context = Arc::new(ParserContext {
            addr: addr.clone(),
            naddr: addr.clone(),
            n2addr: addr.clone(),
            context: Vec::new(),
            mem_buffer: Arc::new(DummyMemBuffer(addr)),
            handle_map: HashMap::new(),
        });
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
        walker: ParserWalker,
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
        fn walker(&self) -> &ParserWalker {
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
