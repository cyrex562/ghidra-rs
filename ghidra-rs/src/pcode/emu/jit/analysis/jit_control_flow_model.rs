//! Control flow analysis for JIT-accelerated emulation.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitControlFlowModel`.
//!
//! This implements the Control Flow Analysis phase of the JIT compiler. Some rudimentary analysis
//! is performed during passage decoding -- note [`BlockSplitter`] is exported for use in
//! [`DecoderExecutor`](crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor). This is
//! necessary to evaluate whether an instruction (especially an inject-instrumented instruction) has
//! fall-through. Without that information, the decoder cannot know whether it has reached the end of
//! its stride. Note that the decoder records all the branches it encounters and includes them as
//! metadata in the passage. Because branches need to record the source and target p-code op, the
//! decoder is well suited. Additionally, it has to compute these anyway, and we'd rather avoid
//! duplicative work by this analyzer.
//!
//! The decoded passage contains a good deal of information, but the primary inputs at this point are
//! the ordered list of p-code ops and the branches. This model's primary responsibility is to break
//! the passage down into basic blocks at the p-code level. Even though the p-code ops have all been
//! concatenated together when constructing the passage, we know, by definition, that each stride
//! will end with an unconditional branch (or else a synthesized exit op). Note also that a passage
//! only records the non-fall-through branches, because these are all that are recorded by the
//! decoder. Thus, it is also this model's responsibility to create the fall-through branches. These
//! will occur to represent the "false" case of any conditional branches, and to represent
//! "unconditional fall through."
//!
//! **NOTE:** It is technically possible for a userop to branch, but this analysis does not consider
//! that. Instead, the emulator will decide how to handle those.
//!
//! # Divergences from Java
//!
//! * **Blocks are handles; their contents live in a [`BlockTable`].** Java's `JitBlock` extends
//!   `PcodeProgram` and owns its ops, its branches, and -- crucially -- the [`BlockFlow`]s that
//!   connect it to *other blocks*. Modelling that directly in Rust would require every block to hold
//!   strong references to its neighbors, and a passage's flow graph has cycles (any loop), so those
//!   references would leak. Instead [`JitBlock`] is a `Copy` identity handle, exactly as Java's
//!   reference identity behaves, and one [`BlockTable`] owns the [`JitBlockData`] of every block
//!   produced by one analysis. Every `JitBlock` method in Java is therefore a `JitBlockData` method
//!   (for the block's own contents) or a [`BlockTable`] method (for anything that resolves another
//!   block or another block's branch).
//! * **The passage constructor.** Java's `JitControlFlowModel(JitAnalysisContext)` reads the
//!   passage's ops and branches off the context. `JitPassage` is not ported yet (see
//!   [`JitPassage`](crate::pcode::seam_stubs::JitPassage)), so [`JitControlFlowModel::analyze`]
//!   takes those two inputs -- the [`PcodeProgram`] and its branches -- directly.
//! * **The branch types.** Java's splitter is written against the `Branch`/`IntBranch` interfaces,
//!   so the model instantiates its fall-through branches as `RIntBranch(from, to, true,
//!   WITHOUT_CTXMOD)` while the decoder instantiates `SIntBranch`. This crate's branch enums are
//!   split by analysis stage instead ([`SBranch`] has an `Int` variant, [`PBranch`] does not: a
//!   passage keeps its internal branches in a separate map), so the splitter works in terms of
//!   [`SBranch`]/[`SIntBranch`], and a branch is upgraded with
//!   [`SIntBranch::with_reach`] when the passage records it. `Reachability::WithoutCtxmod` is the
//!   reach Java attaches to the model's synthesized fall-throughs.
//!
//! [`PBranch`]: crate::pcode::seam_stubs::PBranch

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::seam_stubs::{JitPassage, SBranch, SIntBranch};
use crate::program::model::address::Address;
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::{PcodeOp, SequenceNumber};

/// An exception thrown when control flow might run off the edge of the passage.
///
/// By definition a passage is a collection of strides, and each stride is terminated by some op
/// without fall through (or else a synthesized exit op). In particular, the last stride cannot end
/// in fall through. If it did, there would be no op for it to fall through to. While this should
/// never happen, it is easy in the course of development to allow it by accident. The control flow
/// analysis detects this as it finishes splitting the passage into blocks. If the final block has
/// fall through, the passage is said to have "unterminated flow," and this is reported. We do not
/// wait until execution of the passage to report it. It is reported during translation, as it
/// represents an assertion failure in the translation process. That is, the decoder produced an
/// unsound passage.
///
/// Java's `UnterminatedFlowException extends IllegalArgumentException`, i.e. it is unchecked; here
/// it is the error type of [`BlockSplitter::split_blocks`], since a caller that has already ensured
/// termination (as the decoder does, with its probe op) can simply unwrap it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnterminatedFlowException;

impl fmt::Display for UnterminatedFlowException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Final block cannot fall through")
    }
}

impl std::error::Error for UnterminatedFlowException {}

/// A basic block of p-code.
///
/// This follows the formal definition of a basic block, but at the p-code level. All flows into the
/// block enter at its first op, and all flows out of the block exit at its last op.
///
/// This type is the block's *identity* -- Java's object reference. Its contents are the
/// [`JitBlockData`] held for it by the [`BlockTable`] that produced it; see this module's
/// divergences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitBlock {
    id: u64,
}

impl JitBlock {
    /// A block distinct from every other, standing in for Java reference identity.
    ///
    /// The block has no contents until a [`BlockTable`] gives it some. Analysis creates its blocks
    /// through [`BlockSplitter`]; this is for callers (and tests) that only need the identity, such
    /// as a [`JitPhiOp`](crate::pcode::emu::jit::op::JitPhiOp)'s owning block.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self { id: NEXT_ID.fetch_add(1, Ordering::Relaxed) }
    }
}

impl Default for JitBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// A reference to one internal branch leaving a block, i.e. an element of that block's
/// [`branches_from`](JitBlockData::branches_from).
///
/// Java's [`BlockFlow`] record holds the `IntBranch` itself; a branch owns two [`PcodeOp`]s, so
/// holding one by value would cost `BlockFlow` its `Copy`. Resolve it with
/// [`BlockTable::branch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BranchRef {
    block: JitBlock,
    index: u32,
}

impl BranchRef {
    /// The block the branch leaves, i.e. the block whose `branches_from` holds it.
    pub fn block(&self) -> JitBlock {
        self.block
    }

    /// The branch's position in that block's [`branches_from`](JitBlockData::branches_from).
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// A flow from one block to another.
///
/// This is just a wrapper around an internal branch that allows us to quickly identify what two
/// blocks it connects. Note that to connect two blocks in the passage, the branch must by definition
/// be internal.
///
/// If this flow represents entry into the passage, then [`from`](Self::from) and
/// [`branch`](Self::branch) are `None`.
///
/// Port of the record `BlockFlow(JitBlock from, JitBlock to, IntBranch branch)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockFlow {
    /// The block from which execution flows. In the case of a non-fall-through branch, the block
    /// ends with the branching p-code op. For conditional fall-through, it ends with the
    /// `CBRANCH` op. For unconditional fall-through, it can end with any op having fall through.
    pub from: Option<JitBlock>,
    /// The block to which execution flows. The block starts with the target op of the branch.
    pub to: JitBlock,
    /// The branch effecting the flow of execution.
    pub branch: Option<BranchRef>,
}

impl BlockFlow {
    /// Create a flow along the given branch.
    ///
    /// Port of the canonical constructor `new BlockFlow(JitBlock, JitBlock, IntBranch)`.
    pub fn new(from: JitBlock, to: JitBlock, branch: BranchRef) -> Self {
        Self { from: Some(from), to, branch: Some(branch) }
    }

    /// Create an entry flow to the given block.
    ///
    /// Port of `BlockFlow.entry(JitBlock)`.
    pub fn entry(to: JitBlock) -> Self {
        Self { from: None, to, branch: None }
    }
}

/// The contents of one basic block: Java's `JitBlock` fields, less its identity.
///
/// Java's class extends `PcodeProgram`; here the block's ops are held in a [`PcodeProgram`] of their
/// own, built from the passage, which is also what supplies [`format`](Self::format) and
/// [`get_userop_name`](Self::get_userop_name).
pub struct JitBlockData {
    /// The block's ops, as a program derived from the passage. `None` for a block registered with
    /// [`JitControlFlowModel::new`], which builds a flow graph over blocks that carry no p-code.
    program: Option<PcodeProgram>,
    instructions: i32,
    trailing_ops: i32,
    branches_from: Vec<SIntBranch>,
    branches_to: Vec<SIntBranch>,
    branches_out: Vec<SBranch>,
    flows_from: Vec<BlockFlow>,
    flows_to: Vec<BlockFlow>,
}

/// Check whether an op is the first produced by a decoded instruction.
///
/// Port of `JitPassage.DecodedPcodeOp.isInstructionStart()`, which is `seq.getTime() == 0 &&
/// seq.getTarget().equals(at.address)`. This crate models `DecodedPcodeOp` as a plain [`PcodeOp`]
/// (see
/// [`DecoderExecutor`](crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor)), so
/// there is no `at` to compare against -- but the decoder builds every op's sequence number at
/// exactly that address, so the time is the whole test.
fn is_instruction_start(op: &PcodeOp) -> bool {
    op.seqnum.uniq == 0
}

impl JitBlockData {
    /// Construct the contents of a block over the given ops.
    ///
    /// Port of `new JitBlock(PcodeProgram, List<PcodeOp>)`, whose constructor also counts the
    /// instructions and trailing ops. Java counts only ops that are `DecodedPcodeOp`s, skipping
    /// synthetic ops such as `ExitPcodeOp`; this crate has one op type, so a synthetic op counts as
    /// a trailing op (or, if its sequence time is 0, as an instruction start).
    fn new(passage: &PcodeProgram, code: Vec<PcodeOp>) -> Self {
        let mut instructions = 0;
        let mut trailing_ops = 0;
        for op in &code {
            if is_instruction_start(op) {
                instructions += 1;
                trailing_ops = 0;
            } else {
                trailing_ops += 1;
            }
        }
        Self {
            program: Some(PcodeProgram::from_program(passage, code)),
            instructions,
            trailing_ops,
            ..Self::empty()
        }
    }

    /// Contents for a block with no p-code, as [`JitControlFlowModel::new`] registers.
    fn empty() -> Self {
        Self {
            program: None,
            instructions: 0,
            trailing_ops: 0,
            branches_from: Vec::new(),
            branches_to: Vec::new(),
            branches_out: Vec::new(),
            flows_from: Vec::new(),
            flows_to: Vec::new(),
        }
    }

    /// The subset of the passage's ops, in execution order, comprising this block.
    ///
    /// Port of the inherited `PcodeProgram.getCode()`.
    pub fn code(&self) -> &[PcodeOp] {
        self.program.as_ref().map_or(&[], PcodeProgram::code)
    }

    /// Get the first p-code op in this block.
    ///
    /// Port of `JitBlock.first()`. `None` only for a block carrying no p-code; a block the analysis
    /// produced is never empty.
    pub fn first(&self) -> Option<&PcodeOp> {
        self.code().first()
    }

    /// Get the sequence number of the first op.
    ///
    /// This is used for display and testing purposes only. Port of `JitBlock.start()`.
    pub fn start(&self) -> Option<&SequenceNumber> {
        self.first().map(|op| &op.seqnum)
    }

    /// Get the sequence number of the last op.
    ///
    /// This is used for display and testing purposes only. Port of `JitBlock.end()`.
    pub fn end(&self) -> Option<&SequenceNumber> {
        self.code().last().map(|op| &op.seqnum)
    }

    /// Get internal branches leaving this block.
    ///
    /// Port of `JitBlock.branchesFrom()`.
    pub fn branches_from(&self) -> &[SIntBranch] {
        &self.branches_from
    }

    /// Get internal branches entering this block.
    ///
    /// Port of `JitBlock.branchesTo()`. Java's list holds the very same branch objects as the
    /// source blocks' [`branches_from`](Self::branches_from); these are clones of them.
    pub fn branches_to(&self) -> &[SIntBranch] {
        &self.branches_to
    }

    /// Get branches leaving the passage from this block.
    ///
    /// Port of `JitBlock.branchesOut()`.
    pub fn branches_out(&self) -> &[SBranch] {
        &self.branches_out
    }

    /// Get (internal) flows leaving this block.
    ///
    /// Port of `JitBlock.flowsFrom()`. Java keys the flows by the branch producing each; nothing
    /// looks a flow up by its branch (Java's call sites take `.values()`), and each flow carries its
    /// [`BranchRef`] anyway, so this is a list.
    pub fn flows_from(&self) -> &[BlockFlow] {
        &self.flows_from
    }

    /// Get (internal) flows entering this block.
    ///
    /// Port of `JitBlock.flowsTo()`. See [`flows_from`](Self::flows_from).
    pub fn flows_to(&self) -> &[BlockFlow] {
        &self.flows_to
    }

    /// Get the number of instructions represented in this block.
    ///
    /// This may get dicey as blocks are not necessarily split on instruction boundaries.
    /// Nevertheless, we seek to count the number of instructions executed at runtime, so that we can
    /// replay an execution, step in reverse, etc. What we actually do here is count the number of
    /// ops which are the first op produced by a decoded instruction.
    ///
    /// Port of `JitBlock.instructionCount()`.
    pub fn instruction_count(&self) -> i32 {
        self.instructions
    }

    /// Get the number of trailing ops in this block.
    ///
    /// It is possible a block represents only partial execution of an instruction. Though
    /// [`instruction_count`](Self::instruction_count) will count this partial instruction, we can
    /// tell how far we got into it by examining this value.
    ///
    /// Port of `JitBlock.trailingOpCount()`.
    pub fn trailing_op_count(&self) -> i32 {
        self.trailing_ops
    }

    /// Get the name of the userop for the given number.
    ///
    /// Port of the inherited `PcodeProgram.getUseropName(int)`.
    pub fn get_userop_name(&self, op_no: i32) -> Option<String> {
        self.program.as_ref().and_then(|p| p.get_userop_name(op_no))
    }

    /// Format this block's p-code ops, optionally numbering each.
    ///
    /// Port of the inherited `PcodeProgram.format(boolean)`.
    pub fn format(&self, number_ops: bool) -> String {
        self.program.as_ref().map_or_else(String::new, |p| p.format(number_ops))
    }

    /// The display header for this block.
    ///
    /// Port of `JitBlock.getHead()` (and so of its `toString()`), which appends the block's start
    /// sequence number to `PcodeProgram`'s header.
    pub fn head(&self) -> String {
        match self.start() {
            Some(seq) => format!("<JitBlock[start={}]", format_seqnum(seq)),
            None => "<JitBlock[start=none]".to_string(),
        }
    }
}

/// Format a sequence number as Java's `SequenceNumber.toString()` does.
fn format_seqnum(seq: &SequenceNumber) -> String {
    format!(
        "({}, 0x{:x}, {}, {})",
        seq.pc.space().name(),
        seq.pc.offset(),
        seq.uniq,
        seq.order
    )
}

/// The blocks produced by one control flow analysis, and their contents.
///
/// Java has no counterpart: its `BlockSplitter.splitBlocks()` returns a `SequencedMap<PcodeOp,
/// JitBlock>` and each block owns its own contents. See this module's divergences for why the
/// contents live here instead.
#[derive(Default)]
pub struct BlockTable {
    order: Vec<JitBlock>,
    by_first_op: HashMap<PcodeOp, JitBlock>,
    data: HashMap<JitBlock, JitBlockData>,
}

impl BlockTable {
    /// The blocks, in the order their first ops appear in the passage.
    ///
    /// Port of the key set of `BlockSplitter.splitBlocks()`, which is a `SequencedMap`.
    pub fn blocks(&self) -> &[JitBlock] {
        &self.order
    }

    /// The block starting with the given op, i.e. Java's lookup into that same map.
    pub fn get(&self, first_op: &PcodeOp) -> Option<JitBlock> {
        self.by_first_op.get(first_op).copied()
    }

    /// The contents of the given block.
    ///
    /// # Panics
    ///
    /// If the block was not produced by (or registered with) this table.
    pub fn block(&self, block: JitBlock) -> &JitBlockData {
        self.try_block(block).expect("block does not belong to this analysis")
    }

    /// The contents of the given block, or `None` if it does not belong to this table.
    pub fn try_block(&self, block: JitBlock) -> Option<&JitBlockData> {
        self.data.get(&block)
    }

    /// Resolve the branch a [`BlockFlow`] refers to.
    ///
    /// # Panics
    ///
    /// If the reference does not belong to this table.
    pub fn branch(&self, branch: BranchRef) -> &SIntBranch {
        &self.block(branch.block).branches_from[branch.index()]
    }

    /// If the given block has fall through, find the block into which it falls.
    ///
    /// Port of `JitBlock.getFallFrom()`.
    pub fn get_fall_from(&self, block: JitBlock) -> Option<JitBlock> {
        self.block(block)
            .flows_from()
            .iter()
            .find(|flow| flow.branch.is_some_and(|b| self.branch(b).is_fall))
            .map(|flow| flow.to)
    }

    /// Check if there is an internal non-fall-through branch to the given block.
    ///
    /// This is used by the code generator to determine whether or not a block's bytecode needs to be
    /// labeled. Port of `JitBlock.hasJumpTo()`.
    pub fn has_jump_to(&self, block: JitBlock) -> bool {
        self.block(block)
            .flows_to()
            .iter()
            .any(|flow| flow.branch.is_some_and(|b| !self.branch(b).is_fall))
    }

    /// Get the target block for the given internal branch.
    ///
    /// Port of `JitBlock.getTargetBlock(IntBranch)`, whose receiver is the block the branch leaves,
    /// i.e. [`BranchRef::block`].
    pub fn get_target_block(&self, branch: BranchRef) -> Option<JitBlock> {
        self.block(branch.block)
            .flows_from()
            .iter()
            .find(|flow| flow.branch == Some(branch))
            .map(|flow| flow.to)
    }

    /// Consume the table, yielding each block and its contents in program order.
    pub fn into_blocks(mut self) -> impl Iterator<Item = (JitBlock, JitBlockData)> {
        let order = std::mem::take(&mut self.order);
        order.into_iter().filter_map(move |block| self.data.remove(&block).map(|data| (block, data)))
    }
}

/// A class that splits a sequence of ops and associated branches into basic blocks.
///
/// This is the kernel of control flow analysis. It first indexes the branches by source and target
/// op. Note that only non-fall-through branches are known at this point. Then, it traverses the list
/// of ops. A split occurs following an op that is a branch source and/or preceding an op that is a
/// branch target. A block is constructed when such a split point is encountered. In the case of a
/// branch source, the branch is added to the newly constructed block. As traversal proceeds to the
/// next op, it checks if the immediately-preceding block should have fall through (conditional or
/// unconditional) by examining its last op. It adds a new fall-through branch if so. The end of the
/// p-code op list is presumed a split point. If that final block "should have" fall through, an
/// [`UnterminatedFlowException`] is reported.
///
/// Once all the splitting is done, we have the blocks and all the branches (internal or external)
/// that leave each block. We then compute all the branches (internal) that enter each block and the
/// associated flows in both directions.
///
/// Java's `newFallthroughIntBranch` is an abstract method the client overrides (both
/// `JitControlFlowModel` and the decoder subclass the splitter anonymously); Rust has no subclass
/// override, so it is supplied to the constructor instead.
pub struct BlockSplitter {
    program: PcodeProgram,
    new_fallthrough_int_branch: fn(&PcodeOp, &PcodeOp) -> SIntBranch,

    /// Java's `Map<PcodeOp, Branch> branches`, keyed by source op. Java keys by object identity;
    /// [`PcodeOp`] hashes by value here, so two indistinguishable ops in one program would share an
    /// entry. Each op consumes its branch as the walk reaches it, so the first such op wins.
    branches: HashMap<PcodeOp, SBranch>,
    /// Java's `Map<PcodeOp, IntBranch> branchesByTarget`. Only its key set is ever consulted (the
    /// walk asks whether an op is a branch target), so the branches themselves are not repeated.
    branch_targets: HashSet<PcodeOp>,

    order: Vec<JitBlock>,
    by_first_op: HashMap<PcodeOp, JitBlock>,
    data: HashMap<JitBlock, JitBlockData>,

    partial_block: Vec<PcodeOp>,
    last_block: Option<JitBlock>,
}

impl BlockSplitter {
    /// Construct a new block splitter to process the given program.
    ///
    /// No analysis is performed in the constructor. The client must call
    /// [`add_branches`](Self::add_branches) and then [`split_blocks`](Self::split_blocks).
    ///
    /// Port of `new BlockSplitter(PcodeProgram)`, plus the `newFallthroughIntBranch` override.
    pub fn new(
        program: PcodeProgram,
        new_fallthrough_int_branch: fn(&PcodeOp, &PcodeOp) -> SIntBranch,
    ) -> Self {
        Self {
            program,
            new_fallthrough_int_branch,
            branches: HashMap::new(),
            branch_targets: HashSet::new(),
            order: Vec::new(),
            by_first_op: HashMap::new(),
            data: HashMap::new(),
            partial_block: Vec::new(),
            last_block: None,
        }
    }

    /// Notify the splitter of the given branches before analysis.
    ///
    /// The splitter immediately indexes the given branches by source and target op.
    ///
    /// Port of `BlockSplitter.addBranches(Collection)`.
    pub fn add_branches(&mut self, branches: impl IntoIterator<Item = SBranch>) {
        for branch in branches {
            if let SBranch::Int(ib) = &branch {
                self.branch_targets.insert(ib.to.clone());
            }
            self.branches.insert(branch.from().clone(), branch);
        }
    }

    /// Port of `BlockSplitter.makeBlock()`. Returns `None`, leaving the last block alone, when
    /// there are no accumulated ops to make a block of.
    fn make_block(&mut self) -> Option<JitBlock> {
        if self.partial_block.is_empty() {
            return None;
        }
        let code = std::mem::take(&mut self.partial_block);
        let data = JitBlockData::new(&self.program, code);
        let block = JitBlock::new();
        self.by_first_op
            .insert(data.first().expect("a block is made only of accumulated ops").clone(), block);
        self.order.push(block);
        self.data.insert(block, data);
        self.last_block = Some(block);
        Some(block)
    }

    /// Port of `BlockSplitter.needsFallthrough(JitBlock)`.
    fn needs_fallthrough(&self, block: JitBlock) -> bool {
        let data = &self.data[&block];
        if data.branches_from.is_empty() && data.branches_out.is_empty() {
            return true;
        }
        if data.branches_from.len() == 1 {
            return JitPassage::has_fallthrough(&data.branches_from[0].from);
        }
        if data.branches_out.len() == 1 {
            return JitPassage::has_fallthrough(data.branches_out[0].from());
        }
        // Java: `throw new AssertionError()`. A block is cut at its first branch, so it can leave
        // by at most one.
        panic!("a block cannot have more than one branch leaving it")
    }

    /// Port of `BlockSplitter.checkForFallthrough(PcodeOp)`, where `op` is the op following the
    /// block made on the previous iteration.
    fn check_for_fallthrough(&mut self, op: &PcodeOp) {
        let Some(last) = self.last_block.take() else {
            return;
        };
        if self.needs_fallthrough(last) {
            let from = self.data[&last]
                .code()
                .last()
                .expect("a block always has at least one op")
                .clone();
            let branch = (self.new_fallthrough_int_branch)(&from, op);
            self.data.get_mut(&last).expect("just read above").branches_from.push(branch);
        }
    }

    /// Port of `BlockSplitter.fillFlows()`.
    fn fill_flows(&mut self) {
        for index in 0..self.order.len() {
            let from = self.order[index];
            let targets: Vec<(u32, PcodeOp)> = self.data[&from]
                .branches_from
                .iter()
                .enumerate()
                .map(|(i, branch)| (i as u32, branch.to.clone()))
                .collect();
            for (i, target_op) in targets {
                let to = self
                    .by_first_op
                    .get(&target_op)
                    .copied()
                    .expect("an internal branch must target the start of some block");
                let branch = BranchRef { block: from, index: i };
                let flow = BlockFlow::new(from, to, branch);
                let entering = self.data[&from].branches_from[i as usize].clone();
                let to_data = self.data.get_mut(&to).expect("target block was just resolved");
                to_data.branches_to.push(entering);
                to_data.flows_to.push(flow);
                self.data.get_mut(&from).expect("source block").flows_from.push(flow);
            }
        }
    }

    /// Port of `BlockSplitter.doWork()`. Java's `cook()` -- which replaces each block's collections
    /// with unmodifiable views -- has no counterpart: the accessors already hand out shared slices.
    ///
    /// # Panics
    ///
    /// If the program has no code, as Java throws `IllegalArgumentException("No code to analyze")`.
    fn do_work(&mut self) -> Result<(), UnterminatedFlowException> {
        assert!(!self.program.code().is_empty(), "No code to analyze");

        for op in self.program.code().to_vec() {
            // This op would be after the block from the last iteration
            self.check_for_fallthrough(&op);
            if self.branch_targets.contains(&op) {
                self.make_block();
                // This op would be after the block we just made
                self.check_for_fallthrough(&op);
            }
            self.partial_block.push(op.clone());
            if let Some(branch_from) = self.branches.remove(&op) {
                // NB. the block cannot be missing, we just added the op
                let block = self.make_block().expect("the op was just accumulated");
                let data = self.data.get_mut(&block).expect("the block was just made");
                match branch_from {
                    SBranch::Int(ib) => data.branches_from.push(ib),
                    other => data.branches_out.push(other),
                }
                // Do not check_for_fallthrough, because the current op is already in the block
            }
        }

        self.make_block();
        let last = self.last_block.expect("the program has code, so it has a last block");
        if self.needs_fallthrough(last) {
            // The decoder is responsible for providing a sane program. We can catch missing control
            // flow at the very end, but we cannot do so at the end of other blocks. If they have
            // fall-through, they'll (perhaps erroneously) fall through to the next block that
            // happens to be there. Thus, if the decoder decodes any incomplete strides, it must
            // synthesize the appropriate control-flow ops.
            return Err(UnterminatedFlowException);
        }

        self.fill_flows();
        Ok(())
    }

    /// Perform the actual analysis.
    ///
    /// Port of `BlockSplitter.splitBlocks()`, which returns the blocks keyed by their first op.
    pub fn split_blocks(&mut self) -> Result<BlockTable, UnterminatedFlowException> {
        self.do_work()?;
        Ok(BlockTable {
            order: std::mem::take(&mut self.order),
            by_first_op: std::mem::take(&mut self.by_first_op),
            data: std::mem::take(&mut self.data),
        })
    }
}

/// The control flow analysis for JIT-accelerated emulation.
///
/// See the module documentation.
#[derive(Default)]
pub struct JitControlFlowModel {
    blocks: BlockTable,
    language: Option<Arc<dyn Language>>,
}

impl JitControlFlowModel {
    /// Construct the control flow model, performing the analysis.
    ///
    /// Port of `new JitControlFlowModel(JitAnalysisContext)` together with its `analyze()`: Java
    /// reads `context.getPassage()` and hands the passage and `passage.getBranches().values()` to a
    /// [`BlockSplitter`]. See this module's divergences for why those two are passed directly here.
    pub fn analyze(
        passage: PcodeProgram,
        branches: impl IntoIterator<Item = SBranch>,
    ) -> Result<Self, UnterminatedFlowException> {
        let mut splitter = BlockSplitter::new(passage, |from, to| {
            // The decoder should already have inserted fall-through protectors.
            SIntBranch::new(from.clone(), to.clone(), true)
        });
        splitter.add_branches(branches);
        Ok(Self::from_blocks(splitter.split_blocks()?))
    }

    /// Build the model over an already-split passage.
    pub fn from_blocks(blocks: BlockTable) -> Self {
        Self { blocks, language: None }
    }

    /// Build a model over the given blocks and flows, with no p-code.
    ///
    /// Only the flow graph is modelled -- the blocks carry no ops, so nothing that reads a block's
    /// code, branches, or counts will report anything. For the real analysis, use
    /// [`analyze`](Self::analyze). This exists for the downstream phases (such as
    /// [`JitVarScopeModel`](crate::pcode::emu::jit::analysis::JitVarScopeModel)) that consume only
    /// the graph, and for their tests, which state a control-flow shape directly rather than
    /// decoding a passage that produces it.
    pub fn new(blocks: Vec<JitBlock>, flows: impl IntoIterator<Item = BlockFlow>) -> Self {
        let mut table = BlockTable::default();
        for block in blocks {
            table.order.push(block);
            table.data.insert(block, JitBlockData::empty());
        }
        for flow in flows {
            if let Some(from) = flow.from {
                if let Some(data) = table.data.get_mut(&from) {
                    data.flows_from.push(flow);
                }
            }
            if let Some(data) = table.data.get_mut(&flow.to) {
                data.flows_to.push(flow);
            }
        }
        Self::from_blocks(table)
    }

    /// Attach the passage's language, used by [`get_register_name`](Self::get_register_name).
    ///
    /// Java reads the language off the block, which extends `PcodeProgram`; blocks built by
    /// [`analyze`](Self::analyze) carry it already, but those registered through
    /// [`new`](Self::new) have no program to read it from.
    pub fn with_language(mut self, language: Arc<dyn Language>) -> Self {
        self.language = Some(language);
        self
    }

    /// Get the basic blocks.
    ///
    /// Port of `JitControlFlowModel.getBlocks()`.
    pub fn get_blocks(&self) -> &[JitBlock] {
        self.blocks.blocks()
    }

    /// Get the blocks' contents.
    ///
    /// Java reads these off each `JitBlock`; see this module's divergences.
    pub fn blocks(&self) -> &BlockTable {
        &self.blocks
    }

    /// The flows leaving `block`. Port of `JitBlock.flowsFrom()`.
    ///
    /// Unlike [`BlockTable::block`], an unknown block is empty rather than a panic: the downstream
    /// phases walk flows for blocks they were handed, and Java's `Map.values()` on a block from
    /// another model is likewise empty rather than an error.
    pub fn flows_from(&self, block: JitBlock) -> &[BlockFlow] {
        self.blocks.try_block(block).map_or(&[], JitBlockData::flows_from)
    }

    /// The flows entering `block`. Port of `JitBlock.flowsTo()`. See [`flows_from`](Self::flows_from).
    pub fn flows_to(&self, block: JitBlock) -> &[BlockFlow] {
        self.blocks.try_block(block).map_or(&[], JitBlockData::flows_to)
    }

    /// The name of the register at the given location, if any.
    ///
    /// Stands in for `block.getLanguage().getRegister(address, size).getName()`, the only use any
    /// call site makes of a block's language. Returns `None` when no language is available or no
    /// register covers exactly that location, matching Java's null return.
    pub fn get_register_name(
        &self,
        block: JitBlock,
        address: &Address,
        size: i32,
    ) -> Option<String> {
        let language = self
            .blocks
            .try_block(block)
            .and_then(|data| data.program.as_ref())
            .map(PcodeProgram::get_language)
            .or_else(|| self.language.clone())?;
        let register = language.get_register_at(address, size)?;
        let name = register.borrow().name().to_owned();
        Some(name)
    }

    /// For diagnostics: dump the results to stderr.
    ///
    /// See `JitCompiler.Diag.PRINT_CFM`. Port of `JitControlFlowModel.dumpResult()`.
    pub fn dump_result(&self) {
        eprintln!("STAGE: ControlFlow");
        for &block in self.get_blocks() {
            let data = self.blocks.block(block);
            eprintln!();
            eprintln!("Block: {}", data.head());
            eprintln!("Branches to:");
            for branch in data.branches_to() {
                eprintln!("  {} -> {}", branch.from, branch.to);
            }
            eprintln!("Flows to:");
            for flow in data.flows_to() {
                eprintln!("  {flow:?}");
            }
            if data.program.is_some() {
                eprintln!("{}", data.format(true));
            }
            eprintln!("Branches from:");
            for branch in data.branches_from() {
                eprintln!("  {} -> {}", branch.from, branch.to);
            }
            eprintln!("Flows from:");
            for flow in data.flows_from() {
                eprintln!("  {flow:?}");
            }
            eprintln!("Branches out:");
            for branch in data.branches_out() {
                eprintln!("  {}", branch.from());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_program::testing::NullLanguage;
    use crate::pcode::seam_stubs::{AddrCtx, SExtBranch};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, Varnode};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    /// An op at `offset`, `uniq` steps into that instruction. `uniq == 0` marks an instruction
    /// start, as `DecodedPcodeOp.isInstructionStart()` does.
    fn op(space: &Arc<AddressSpace>, offset: i64, uniq: i32, opcode: OpCode) -> PcodeOp {
        PcodeOp::new(
            opcode,
            SequenceNumber::new(Address::new(Arc::clone(space), offset), uniq),
            vec![Varnode::new(Address::new(Arc::clone(space), offset), 1)],
            None,
        )
    }

    fn passage(code: Vec<PcodeOp>) -> PcodeProgram {
        PcodeProgram::new(Arc::new(NullLanguage), code, HashMap::new())
    }

    /// The worked example: one instruction at 0x00 that conditionally branches over its own tail,
    /// and one at 0x04 that branches back to the top.
    ///
    /// ```text
    /// 0x00,0  COPY                (instruction start)
    /// 0x00,1  CBRANCH -> 0x04,0
    /// 0x00,2  COPY
    /// 0x04,0  BRANCH   -> 0x00,0  (instruction start)
    /// ```
    ///
    /// Java splits this into three blocks: `[0x00,0 .. 0x00,1]`, `[0x00,2]`, and `[0x04,0]`, and
    /// synthesizes the two fall-through branches the decoder never recorded.
    fn worked_example() -> (PcodeProgram, Vec<SBranch>, Vec<PcodeOp>) {
        let space = ram();
        let ops = vec![
            op(&space, 0x00, 0, OpCode::Copy),
            op(&space, 0x00, 1, OpCode::CBranch),
            op(&space, 0x00, 2, OpCode::Copy),
            op(&space, 0x04, 0, OpCode::Branch),
        ];
        let branches = vec![
            SBranch::Int(SIntBranch::new(ops[1].clone(), ops[3].clone(), false)),
            SBranch::Int(SIntBranch::new(ops[3].clone(), ops[0].clone(), false)),
        ];
        (passage(ops.clone()), branches, ops)
    }

    #[test]
    fn splits_at_branch_sources_and_targets() {
        let (program, branches, ops) = worked_example();
        let model = JitControlFlowModel::analyze(program, branches).expect("flow is terminated");

        let blocks = model.get_blocks();
        assert_eq!(blocks.len(), 3);

        let table = model.blocks();
        assert_eq!(table.block(blocks[0]).code(), &ops[0..2]);
        assert_eq!(table.block(blocks[1]).code(), &ops[2..3]);
        assert_eq!(table.block(blocks[2]).code(), &ops[3..4]);

        // start()/end() are the first and last ops' sequence numbers.
        assert_eq!(table.block(blocks[0]).start(), Some(&ops[0].seqnum));
        assert_eq!(table.block(blocks[0]).end(), Some(&ops[1].seqnum));

        // Each block is keyed by its first op, as Java's SequencedMap is.
        assert_eq!(table.get(&ops[2]), Some(blocks[1]));
        assert_eq!(table.get(&ops[1]), None);
    }

    #[test]
    fn synthesizes_the_fall_through_branches_the_decoder_did_not_record() {
        let (program, branches, ops) = worked_example();
        let model = JitControlFlowModel::analyze(program, branches).expect("flow is terminated");
        let (table, blocks) = (model.blocks(), model.get_blocks());

        // The CBRANCH block leaves by its recorded branch to 0x04 *and* a synthesized fall-through
        // to 0x00,2 -- the "false" case Java's model adds.
        let from_first = table.block(blocks[0]).branches_from();
        assert_eq!(from_first.len(), 2);
        assert!(!from_first[0].is_fall);
        assert_eq!(from_first[0].to, ops[3]);
        assert!(from_first[1].is_fall);
        assert_eq!(from_first[1].from, ops[1]);
        assert_eq!(from_first[1].to, ops[2]);

        // The middle block ends in no branch at all, so it falls through unconditionally.
        let from_middle = table.block(blocks[1]).branches_from();
        assert_eq!(from_middle.len(), 1);
        assert!(from_middle[0].is_fall);
        assert_eq!(from_middle[0].to, ops[3]);

        // The BRANCH block has no fall through, which is what terminates the passage.
        let from_last = table.block(blocks[2]).branches_from();
        assert_eq!(from_last.len(), 1);
        assert!(!from_last[0].is_fall);
    }

    #[test]
    fn flows_connect_the_blocks_in_both_directions() {
        let (program, branches, _ops) = worked_example();
        let model = JitControlFlowModel::analyze(program, branches).expect("flow is terminated");
        let (table, blocks) = (model.blocks(), model.get_blocks());
        let (head, middle, tail) = (blocks[0], blocks[1], blocks[2]);

        let targets: Vec<JitBlock> = model.flows_from(head).iter().map(|f| f.to).collect();
        assert_eq!(targets, vec![tail, middle]);
        assert_eq!(model.flows_from(middle).iter().map(|f| f.to).collect::<Vec<_>>(), vec![tail]);
        // The back edge: the last block flows to the first.
        assert_eq!(model.flows_from(tail).iter().map(|f| f.to).collect::<Vec<_>>(), vec![head]);

        let sources: Vec<Option<JitBlock>> = model.flows_to(tail).iter().map(|f| f.from).collect();
        assert_eq!(sources, vec![Some(head), Some(middle)]);
        assert_eq!(table.block(tail).branches_to().len(), 2);

        // Fall through goes to the *next* block; the branch target does not.
        assert_eq!(table.get_fall_from(head), Some(middle));
        assert_eq!(table.get_fall_from(middle), Some(tail));
        assert_eq!(table.get_fall_from(tail), None);

        // Only blocks entered by a non-fall-through branch need a label.
        assert!(table.has_jump_to(tail));
        assert!(table.has_jump_to(head));
        assert!(!table.has_jump_to(middle));

        // getTargetBlock resolves the branch back to the block it reaches.
        let branch = model.flows_from(head)[0].branch.expect("an internal flow has a branch");
        assert_eq!(table.get_target_block(branch), Some(tail));
        assert_eq!(branch.block(), head);
    }

    #[test]
    fn counts_instruction_starts_and_trailing_ops() {
        let (program, branches, _ops) = worked_example();
        let model = JitControlFlowModel::analyze(program, branches).expect("flow is terminated");
        let (table, blocks) = (model.blocks(), model.get_blocks());

        // [0x00,0 (start); 0x00,1] -- one instruction, one op into it.
        assert_eq!(table.block(blocks[0]).instruction_count(), 1);
        assert_eq!(table.block(blocks[0]).trailing_op_count(), 1);
        // [0x00,2] -- the tail of an instruction that started in another block.
        assert_eq!(table.block(blocks[1]).instruction_count(), 0);
        assert_eq!(table.block(blocks[1]).trailing_op_count(), 1);
        // [0x04,0 (start)] -- a whole instruction, nothing trailing.
        assert_eq!(table.block(blocks[2]).instruction_count(), 1);
        assert_eq!(table.block(blocks[2]).trailing_op_count(), 0);
    }

    #[test]
    fn a_final_block_with_fall_through_is_unterminated() {
        let space = ram();
        // A lone COPY has fall through, and there is no op to fall through to.
        let program = passage(vec![op(&space, 0x00, 0, OpCode::Copy)]);
        assert_eq!(
            JitControlFlowModel::analyze(program, []).map(|_| ()),
            Err(UnterminatedFlowException)
        );
        assert_eq!(UnterminatedFlowException.to_string(), "Final block cannot fall through");

        // A block that leaves the passage by a recorded external branch is terminated, because the
        // op it leaves by -- BRANCH -- has no fall through. Note the opcode alone is not enough:
        // Java's first test is whether the block leaves by *any* branch at all, so a BRANCH the
        // decoder never recorded still reads as unterminated, exactly as above.
        let ops = vec![op(&space, 0x00, 0, OpCode::Copy), op(&space, 0x00, 1, OpCode::Branch)];
        let out = SBranch::Ext(SExtBranch::new(ops[1].clone(), AddrCtx::nowhere()));
        let model = JitControlFlowModel::analyze(passage(ops.clone()), [out])
            .expect("an external branch off a BRANCH terminates flow");
        assert_eq!(model.get_blocks().len(), 1);
        assert_eq!(model.blocks().block(model.get_blocks()[0]).branches_out().len(), 1);

        assert_eq!(
            JitControlFlowModel::analyze(passage(ops), []).map(|_| ()),
            Err(UnterminatedFlowException)
        );
    }

    #[test]
    fn graph_only_blocks_carry_flows_but_no_code() {
        let head = JitBlock::new();
        let tail = JitBlock::new();
        let model = JitControlFlowModel::new(
            vec![head, tail],
            [BlockFlow { from: Some(head), to: tail, branch: None }, BlockFlow::entry(head)],
        );

        assert_eq!(model.get_blocks(), [head, tail].as_slice());
        assert_eq!(model.flows_from(head).len(), 1);
        assert_eq!(model.flows_from(head)[0].to, tail);
        // The entry flow enters `head` from outside the passage.
        assert_eq!(model.flows_to(head), [BlockFlow::entry(head)].as_slice());
        assert_eq!(model.flows_to(tail).len(), 1);
        assert!(model.blocks().block(head).code().is_empty());
        // A block from another analysis has no flows at all, rather than panicking.
        assert!(model.flows_from(JitBlock::new()).is_empty());
    }
}
