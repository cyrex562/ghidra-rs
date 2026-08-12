//! Variable scope analysis.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitVarScopeModel`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::pcode::seam_stubs::{JitBlock, JitControlFlowModel, JitDataFlowModel};
use crate::program::model::address::Address;
use crate::program::model::pcode::Varnode;
use crate::util::math_utilities::MathUtilities;

/// The variable scope analysis of JIT-accelerated emulation.
///
/// This implements the Variable Scope Analysis phase of the JIT compiler. The result provides the
/// set of in-scope (alive) varnodes for each basic block. The design of this analysis, and the
/// shortcuts we take, are informed by the design of downstream phases. In particular, we do not
/// intend to allocate each SSA variable. There are often many, many such variables, and attempting
/// to allocate them to as few target resources as possible is *probably* a complicated and
/// expensive algorithm. Instead, we just allocate by varnode. To do that, though, we still have to
/// consider that some varnodes overlap and otherwise alias others.
///
/// To handle the aliasing, we coalesce overlapping varnodes. For example, `EAX` will get coalesced
/// with `RAX`, but `BH` *will not* get coalesced with `BL`, assuming no other part of `RBX` is
/// accessed. The data flow model records all varnodes accessed in the course of its intra-block
/// analysis. Only those actually accessed are considered. We then compute scope in terms of these
/// coalesced varnodes. For example, if both `RAX` and `EAX` are used by a passage, then an access
/// of `EAX` causes `RAX` to remain in scope.
///
/// The decision to compute scope on a block-by-block basis instead of op-by-op is for simplicity.
/// We intend to birth and retire variables along block transitions by considering what variables
/// are coming into or leaving scope on the flow edge. *Birthing* is just reading a variable's value
/// from the run-time executor state into its allocated local. Conversely, *retiring* is writing the
/// value back out to the state.
///
/// The algorithm defines two sets for each block: the upward view and the downward view. The first
/// corresponds to all varnodes that could be accessed before entering this block or while in it.
/// The second corresponds to all varnodes that could be accessed while in this block or after
/// leaving it. The upward view is computed by initializing each set to the varnodes accessed by its
/// block, then "pushing" each set upward by adding its elements into the set for each block that
/// flows into this one, until the sets converge. The downward sets are computed the same way,
/// independently. The result is the intersection of these sets, per block. Essentially, if we are
/// between two accesses of a varnode, then that varnode is alive. This also prevents retirement and
/// rebirth of a variable that is merely untouched in the middle of its live range.
///
/// One notable effect of this algorithm is that all blocks in a loop will have the same variables
/// in scope.
pub struct JitVarScopeModel {
    cfm: Arc<JitControlFlowModel>,
    dfm: Arc<dyn JitDataFlowModel>,

    /// Java's `NavigableMap<Address, Varnode> coalesced`, keyed by each coalesced varnode's min
    /// address. A [`BTreeMap`] gives the `floorEntry`/`subMap` navigation the coalescing needs.
    coalesced: BTreeMap<Address, Varnode>,

    infos: HashMap<JitBlock, ScopeInfo>,
}

/// Encapsulates set movement when computing the upward and downward views.
///
/// Java models this as an enum with abstract per-constant methods selecting a direction's flows and
/// sets; here the selection is done by matching on the variant, since the "methods" only pick which
/// of a [`ScopeInfo`]'s four sets (or which of a block's two flow lists) to operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    /// Set movement for the upward view.
    Up,
    /// Set movement for the downward view.
    Down,
}

/// Encapsulates the (intermediate) analytic result for each block.
struct ScopeInfo {
    live_up: HashSet<Varnode>,
    live_dn: HashSet<Varnode>,

    queued_up: HashSet<Varnode>,
    queued_dn: HashSet<Varnode>,

    /// Java's `liveVars`, a `LinkedHashSet` filled in address order and then intersected with
    /// `liveDn`. Since its contents are unique and its iteration order is exactly that address
    /// order, a sorted [`Vec`] captures it without a second set type.
    live_vars: Vec<Varnode>,
}

impl ScopeInfo {
    /// The current set for the given view.
    fn live(&self, which: Which) -> &HashSet<Varnode> {
        match which {
            Which::Up => &self.live_up,
            Which::Down => &self.live_dn,
        }
    }

    fn live_mut(&mut self, which: Which) -> &mut HashSet<Varnode> {
        match which {
            Which::Up => &mut self.live_up,
            Which::Down => &mut self.live_dn,
        }
    }

    /// The varnodes queued for addition into this block's set for the given view.
    fn queued(&self, which: Which) -> &HashSet<Varnode> {
        match which {
            Which::Up => &self.queued_up,
            Which::Down => &self.queued_dn,
        }
    }

    fn queued_mut(&mut self, which: Which) -> &mut HashSet<Varnode> {
        match which {
            Which::Up => &mut self.queued_up,
            Which::Down => &mut self.queued_dn,
        }
    }

    /// Finish the analytic computation for this block.
    ///
    /// If a block contains an access to a variable, that variable is alive in that block. If a
    /// block is between (in terms of possible control-flow paths) two others that access a
    /// variable, that variable is alive in the block.
    fn finish(&mut self) {
        let mut sorted_live_up: Vec<Varnode> = self.live_up.iter().cloned().collect();
        sorted_live_up.sort_by(|a, b| a.get_address().cmp(b.get_address()));
        sorted_live_up.retain(|vn| self.live_dn.contains(vn));
        self.live_vars = sorted_live_up;
    }
}

/// An insertion-ordered set of blocks, standing in for Java's `SequencedSet<ScopeInfo>` worklist.
/// Re-adding a block already queued leaves its position alone, as `LinkedHashSet.add` does.
#[derive(Default)]
struct BlockQueue {
    order: VecDeque<JitBlock>,
    members: HashSet<JitBlock>,
}

impl BlockQueue {
    fn add(&mut self, block: JitBlock) {
        if self.members.insert(block) {
            self.order.push_back(block);
        }
    }

    fn remove_first(&mut self) -> Option<JitBlock> {
        let block = self.order.pop_front()?;
        self.members.remove(&block);
        Some(block)
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl JitVarScopeModel {
    /// Construct the model, performing the analysis.
    pub fn new(cfm: Arc<JitControlFlowModel>, dfm: Arc<dyn JitDataFlowModel>) -> Self {
        let mut model =
            Self { cfm, dfm, coalesced: BTreeMap::new(), infos: HashMap::new() };
        model.analyze();
        model
    }

    /// Get the maximum address (inclusive) in the varnode.
    ///
    /// Panics if the varnode runs off the end of its address space, standing in for the
    /// `AddressOutOfBoundsException` Java's `Address.add` throws.
    pub fn max_addr(varnode: &Varnode) -> Address {
        varnode
            .get_address()
            .add(i64::from(varnode.get_size() - 1))
            .expect("varnode extends past the end of its address space")
    }

    /// Check for overlap when one varnode is known to be to the left of the other.
    ///
    /// `left` is the varnode having the lower address, `right` the higher. Returns true if they
    /// overlap, not counting abutting.
    pub fn overlaps_left(left: &Varnode, right: &Varnode) -> bool {
        // max is inclusive, so use >=, not just >
        Self::max_addr(left) >= *right.get_address()
    }

    /// The entry of `coalesced` with the greatest key `<= key`, i.e. Java's `floorEntry`.
    fn floor_entry(&self, key: &Address) -> Option<(&Address, &Varnode)> {
        self.coalesced.range(..=key).next_back()
    }

    fn coalesce_varnode(&mut self, varnode: &Varnode) {
        let mut min = varnode.get_address().clone();
        let mut max = Self::max_addr(varnode);

        let left_entry = self
            .floor_entry(&min)
            .filter(|(_, existing)| Self::overlaps_left(existing, varnode))
            .map(|(key, existing)| (key.clone(), existing.clone()));
        if let Some((key, _)) = &left_entry {
            min = key.clone();
        }
        let right_entry = self.floor_entry(&max).map(|(key, existing)| (key.clone(), existing.clone()));
        if let Some((_, existing)) = &right_entry {
            max = MathUtilities::cmax(max, Self::max_addr(existing));
        }

        // Java compares the two entries' *values* by reference; entries of one map are identical
        // exactly when they are the same entry, so compare the keys.
        if let (Some((left_key, left_vn)), Some((right_key, _))) = (&left_entry, &right_entry) {
            if left_key == right_key
                && *left_vn.get_address() == min
                && Self::max_addr(left_vn) == max
            {
                return; // no change
            }
        }

        // Clear [min, maxAddr(varnode)] -- note Java clears up to the *original* varnode's max,
        // not the possibly-extended `max`, since anything beyond it was already coalesced into the
        // entry we are about to widen.
        let doomed: Vec<Address> = self
            .coalesced
            .range(min.clone()..=Self::max_addr(varnode))
            .map(|(key, _)| key.clone())
            .collect();
        for key in doomed {
            self.coalesced.remove(&key);
        }

        let size = (max.subtract(&min) + 1) as i32;
        self.coalesced.insert(min.clone(), Varnode::new(min, size));
    }

    fn coalesce_varnodes(&mut self) {
        let mut all_varnodes = HashSet::new();
        for block in self.cfm.get_blocks() {
            let analyzer = self.dfm.get_analyzer(*block);
            all_varnodes.extend(analyzer.get_varnodes_read());
            all_varnodes.extend(analyzer.get_varnodes_written());
        }
        // Java iterates a `HashSet`, whose order does not affect the fixed point but does affect
        // nothing observable here; sort by address so the coalescing is reproducible.
        let mut all_varnodes: Vec<Varnode> = all_varnodes.into_iter().collect();
        all_varnodes.sort_by(|a, b| {
            a.get_address().cmp(b.get_address()).then(a.get_size().cmp(&b.get_size()))
        });
        for varnode in all_varnodes {
            if !varnode.is_address() {
                self.coalesce_varnode(&varnode);
            }
        }
    }

    /// Get the varnode into which the given varnode was coalesced.
    ///
    /// In many cases, the result is the same varnode.
    pub fn get_coalesced(&self, part: &Varnode) -> Varnode {
        if part.is_address() {
            return part.clone();
        }
        let (_, whole) = self
            .floor_entry(part.get_address())
            .expect("no coalesced varnode covers the given part");
        debug_assert!(Self::overlaps_left(whole, part));
        whole.clone()
    }

    /// Build the initial (intermediate) result for a block: everything it reads or writes, in
    /// coalesced form, queued for both views.
    fn make_scope_info(&self, block: JitBlock) -> ScopeInfo {
        let analyzer = self.dfm.get_analyzer(block);
        let mut queued = HashSet::new();
        for vn in analyzer.get_varnodes_read().iter().chain(analyzer.get_varnodes_written().iter()) {
            if !vn.is_address() {
                queued.insert(self.get_coalesced(vn));
            }
        }
        ScopeInfo {
            live_up: HashSet::new(),
            live_dn: HashSet::new(),
            queued_up: queued.clone(),
            queued_dn: queued,
            live_vars: Vec::new(),
        }
    }

    /// Get the blocks toward which the given block's set will be pushed for the given view.
    ///
    /// Upward, that is each block flowing *into* this one; downward, each block this one flows
    /// *to*. Flows without a source block (passage entries) have nothing upward to push into and
    /// are skipped.
    fn flows(&self, block: JitBlock, which: Which) -> Vec<JitBlock> {
        match which {
            Which::Up => self.cfm.flows_to(block).iter().filter_map(|flow| flow.from).collect(),
            Which::Down => self.cfm.flows_from(block).iter().map(|flow| flow.to).collect(),
        }
    }

    /// Push the given block's queue for the given view.
    ///
    /// Any block whose set was affected by this push is added to the queue of blocks to be
    /// processed again.
    fn push(&mut self, block: JitBlock, which: Which, block_queue: &mut BlockQueue) {
        let queued = self.infos[&block].queued(which).clone();
        if queued.is_empty() {
            return;
        }
        for other in self.flows(block, which) {
            let Some(that) = self.infos.get_mut(&other)
            else {
                continue;
            };
            let to_queue: Vec<Varnode> = queued
                .iter()
                .filter(|vn| !that.live(which).contains(*vn))
                .cloned()
                .collect();
            let mut changed = false;
            for vn in to_queue {
                changed |= that.queued_mut(which).insert(vn);
            }
            if changed {
                block_queue.add(other);
            }
        }
        let info = self.infos.get_mut(&block).expect("block was just read above");
        info.live_mut(which).extend(queued);
        info.queued_mut(which).clear();
    }

    /// Perform a push for the given direction for the next block in the queue.
    ///
    /// Any block whose varnode queue was affected is added back into the block queue. Returns true
    /// if there remains at least one block in the queue.
    fn push_next(&mut self, which: Which, block_queue: &mut BlockQueue) -> bool {
        let Some(block) = block_queue.remove_first()
        else {
            return false;
        };
        self.push(block, which, block_queue);
        !block_queue.is_empty()
    }

    /// Perform the analysis.
    ///
    /// This starts with the upward set, which is computed by pushing queued blocks' varnodes
    /// upward until the queue is empty. All blocks are queued initially. When a block's set is
    /// affected, it's re-added to the queue, so we know we've converged when the queue is empty.
    /// The downward set is then computed in the same fashion.
    fn analyze(&mut self) {
        self.coalesce_varnodes();

        let blocks: Vec<JitBlock> = self.cfm.get_blocks().to_vec();
        let mut block_queue = BlockQueue::default();
        for block in &blocks {
            let info = self.make_scope_info(*block);
            self.infos.insert(*block, info);
            block_queue.add(*block);
        }
        while self.push_next(Which::Up, &mut block_queue) {}

        // Java re-queues `infos.values()`, i.e. in hash order; the fixed point does not depend on
        // the order, so use the control flow model's block order for reproducibility.
        for block in &blocks {
            block_queue.add(*block);
        }
        while self.push_next(Which::Down, &mut block_queue) {}

        for info in self.infos.values_mut() {
            info.finish();
        }
    }

    /// Get all coalesced varnodes, in address order.
    pub fn coalesced_varnodes(&self) -> impl Iterator<Item = &Varnode> {
        self.coalesced.values()
    }

    /// Get the live varnodes for the given block, in address order.
    ///
    /// Java returns an unmodifiable `Set`; the elements are unique and the iteration order is
    /// exactly this address order, so a shared slice carries the same guarantees.
    pub fn get_live_vars(&self, block: JitBlock) -> &[Varnode] {
        self.infos.get(&block).map_or(&[], |info| info.live_vars.as_slice())
    }

    /// For diagnostics: dump the analysis result to stderr.
    ///
    /// See `JitCompiler.Diag.PRINT_VSM`.
    pub fn dump_result(&self) {
        eprintln!("STAGE: VarLiveness");
        for block in self.cfm.get_blocks() {
            eprintln!("  Block: {block:?}");
            let mut live_names = BTreeSet::new();
            for vn in self.get_live_vars(*block) {
                if let Some(name) = self.cfm.get_register_name(*block, vn.get_address(), vn.get_size())
                {
                    live_names.insert(name);
                }
                else if vn.is_unique() {
                    live_names.insert(format!("$U{:x}:{}", vn.get_offset(), vn.get_size()));
                }
                else {
                    // Java's format string here is `"%s:%x:4"` -- a literal 4 where the varnode's
                    // size belongs, with the size passed as an ignored extra argument. Kept as-is
                    // so the diagnostic output matches upstream.
                    live_names.insert(format!(
                        "{}:{:x}:4",
                        vn.get_address().space().name(),
                        vn.get_offset()
                    ));
                }
            }
            let names: Vec<&String> = live_names.iter().collect();
            eprintln!("    Live: {names:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic;
    use crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer;
    use crate::pcode::emu::jit::op::JitPhiOp;
    use crate::pcode::seam_stubs::{
        BlockFlow, JitAnalysisContext, JitDataFlowUseropLibrary, JitLocalOutVar, JitOp, JitOutVar,
    };
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 64, 1, AddressSpaceType::Register, 0)
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1)
    }

    fn vn(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    /// Never-called model, held by [`JitDataFlowArithmetic`] instances the tests do not exercise.
    struct NoopDfm;
    impl JitDataFlowModel for NoopDfm {
        fn generate_out_var(&self, _out: &Varnode) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
        fn notify_op(&self, _op: Arc<dyn JitOp>) {
            unimplemented!()
        }
    }

    /// A data flow model whose per-block analyzers report exactly the varnodes each test declares
    /// as accessed -- everything `JitVarScopeModel` asks of a `JitDataFlowModel`.
    #[derive(Default)]
    struct MockDfm {
        next_id: AtomicI32,
        analyzers: Mutex<HashMap<JitBlock, Arc<JitDataFlowBlockAnalyzer>>>,
        phi_queue: Mutex<Vec<Arc<JitPhiOp>>>,
    }

    impl JitDataFlowModel for MockDfm {
        fn generate_out_var(&self, out: &Varnode) -> Arc<dyn JitOutVar> {
            Arc::new(JitLocalOutVar::new(self.next_id.fetch_add(1, Ordering::Relaxed), out.clone()))
        }

        fn notify_op(&self, op: Arc<dyn JitOp>) {
            op.link();
        }

        fn get_arithmetic(&self) -> JitDataFlowArithmetic {
            let context = JitAnalysisContext::new(Endian::Little);
            JitDataFlowArithmetic::new(&context, Arc::new(NoopDfm) as Arc<dyn JitDataFlowModel>)
        }

        fn get_library(&self) -> JitDataFlowUseropLibrary {
            JitDataFlowUseropLibrary
        }

        fn get_or_create_analyzer(&self, block: JitBlock) -> Arc<JitDataFlowBlockAnalyzer> {
            Arc::clone(
                self.analyzers.lock().unwrap().get(&block).expect("test: analyzer not registered"),
            )
        }

        fn phi_queue_add(&self, phi: Arc<JitPhiOp>) {
            self.phi_queue.lock().unwrap().push(phi);
        }
    }

    /// Register a block with the model, whose analyzer accesses `accessed`.
    ///
    /// Each access goes through `get_var`, which is what the real intra-block interpreter calls;
    /// on a first access that both records the varnode as read and -- via the def-state's
    /// missing-var-to-phi substitution -- records it as written. `JitVarScopeModel` unions the two
    /// catalogs anyway, so a single list of accessed varnodes drives its whole input.
    fn register_block(dfm: &Arc<MockDfm>, block: JitBlock, accessed: &[Varnode]) {
        let context = JitAnalysisContext::new(Endian::Little);
        let analyzer = Arc::new(JitDataFlowBlockAnalyzer::new(
            context,
            Arc::clone(dfm) as Arc<dyn JitDataFlowModel>,
            block,
        ));
        dfm.analyzers.lock().unwrap().insert(block, Arc::clone(&analyzer));
        for varnode in accessed {
            analyzer.get_var(varnode);
        }
    }

    // Java: `maxAddr` is inclusive -- a 4-byte varnode at 0x10 ends at 0x13 -- and `overlapsLeft`
    // uses `>=` so that abutting varnodes (0x10:4 then 0x14:4) do *not* count as overlapping.
    #[test]
    fn max_addr_is_inclusive_and_abutting_varnodes_do_not_overlap() {
        let space = register_space();
        let a = vn(&space, 0x10, 4);
        let b = vn(&space, 0x14, 4);
        let c = vn(&space, 0x12, 4);

        assert_eq!(JitVarScopeModel::max_addr(&a), Address::new(Arc::clone(&space), 0x13));
        assert!(!JitVarScopeModel::overlaps_left(&a, &b));
        assert!(JitVarScopeModel::overlaps_left(&a, &c));
    }

    // Java: overlapping varnodes are coalesced into their union (EAX into RAX), while disjoint
    // ones -- even in the same register, like BH and BL -- stay separate. Memory (`isAddress`)
    // varnodes are never coalesced at all.
    #[test]
    fn overlapping_varnodes_coalesce_and_disjoint_ones_do_not() {
        let regs = register_space();
        let ram = ram_space();

        // RAX 0x00:8 and EAX 0x00:4 overlap; BL 0x20:1 and BH 0x21:1 abut but are each 1 byte at
        // distinct addresses -- Java coalesces only on *overlap*, so they stay apart.
        let rax = vn(&regs, 0x00, 8);
        let eax = vn(&regs, 0x00, 4);
        let bl = vn(&regs, 0x20, 1);
        let bh = vn(&regs, 0x21, 1);
        let mem = vn(&ram, 0x4000, 4);

        let dfm = Arc::new(MockDfm::default());
        let block = JitBlock::new();
        register_block(&dfm, block, &[eax.clone(), rax.clone(), bl.clone(), bh.clone()]);

        let cfm = Arc::new(JitControlFlowModel::new(vec![block], []));
        let model = JitVarScopeModel::new(cfm, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>);

        let coalesced: Vec<Varnode> = model.coalesced_varnodes().cloned().collect();
        assert_eq!(coalesced, vec![rax.clone(), bl.clone(), bh.clone()]);

        // EAX resolves to the whole RAX; BL and BH each resolve to themselves.
        assert_eq!(model.get_coalesced(&eax), rax);
        assert_eq!(model.get_coalesced(&rax), rax);
        assert_eq!(model.get_coalesced(&bl), bl);
        assert_eq!(model.get_coalesced(&bh), bh);
        // Memory varnodes pass straight through, uncoalesced (`getCoalesced`'s `isAddress` early
        // return) -- note `mem` never enters the coalesced map above.
        assert_eq!(model.get_coalesced(&mem), mem);
    }

    // Java: two varnodes that each overlap a third get merged into one span covering all of them.
    #[test]
    fn coalescing_merges_a_bridged_pair_into_one_span() {
        let regs = register_space();
        let low = vn(&regs, 0x00, 4); // 0x00-0x03
        let high = vn(&regs, 0x06, 4); // 0x06-0x09
        let bridge = vn(&regs, 0x02, 6); // 0x02-0x07, overlaps both

        let dfm = Arc::new(MockDfm::default());
        let block = JitBlock::new();
        register_block(&dfm, block, &[low, high, bridge]);

        let cfm = Arc::new(JitControlFlowModel::new(vec![block], []));
        let model = JitVarScopeModel::new(cfm, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>);

        // 0x00 through 0x09 inclusive: one 10-byte varnode.
        let coalesced: Vec<Varnode> = model.coalesced_varnodes().cloned().collect();
        assert_eq!(coalesced, vec![vn(&regs, 0x00, 10)]);
    }

    // The worked example from `JitVarScopeModel`'s class javadoc: an if-else diamond where the
    // error path (block 8) must not birth the "serious work" registers, RSP stays alive across the
    // whole body despite blocks 4-7 and 8 never touching it, and RIP appears only in the exit
    // block.
    //
    // Expected (from the javadoc's table):
    //   1-3   RDI, RSP, $U00:1
    //   4-7   EAX, RBX, RCX, RDI, RDX, RSI, RSP, $U10:8
    //   8     EAX, RSP
    //   9-12  RIP, RSP
    #[test]
    fn diamond_control_flow_matches_the_javadoc_liveness_table() {
        let regs = register_space();
        let uniq = AddressSpace::new("unique", 64, 1, AddressSpaceType::Unique, 2);

        let rsp = vn(&regs, 0x00, 8);
        let rdi = vn(&regs, 0x08, 8);
        let eax = vn(&regs, 0x10, 4);
        let rbx = vn(&regs, 0x18, 8);
        let rcx = vn(&regs, 0x20, 8);
        let rdx = vn(&regs, 0x28, 8);
        let rsi = vn(&regs, 0x30, 8);
        let rip = vn(&regs, 0x38, 8);
        let u00 = vn(&uniq, 0x00, 1);
        let u10 = vn(&uniq, 0x10, 8);

        let head = JitBlock::new(); // 1-3
        let work = JitBlock::new(); // 4-7
        let err = JitBlock::new(); // 8
        let exit = JitBlock::new(); // 9-12

        let dfm = Arc::new(MockDfm::default());
        // 1: RSP = INT_SUB RSP, 0x20   2: $U00:1 = INT_EQUAL RDI, 0   3: CBRANCH <err>, $U00:1
        register_block(&dfm, head, &[rsp.clone(), rdi.clone(), u00.clone()]);
        // 5: $U10:8 = INT_ADD RDI, 0xc   6: EAX = LOAD   plus the "serious work" on RBX/RCX/RDX/RSI
        register_block(
            &dfm,
            work,
            &[rdi.clone(), u10.clone(), eax.clone(), rbx.clone(), rcx.clone(), rdx.clone(), rsi.clone()],
        );
        // 8: EAX = COPY 0xffffffff
        register_block(&dfm, err, &[eax.clone()]);
        // 9: RSP = INT_ADD RSP, 0x20   10: RIP = LOAD RSP   11: RSP = INT_ADD RSP, 8   12: RETURN
        register_block(&dfm, exit, &[rsp.clone(), rip.clone()]);

        let cfm = Arc::new(JitControlFlowModel::new(
            vec![head, work, err, exit],
            [
                BlockFlow { from: Some(head), to: err },
                BlockFlow { from: Some(head), to: work },
                BlockFlow { from: Some(err), to: exit },
                BlockFlow { from: Some(work), to: exit },
            ],
        ));
        let model = JitVarScopeModel::new(cfm, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>);

        let live = |block| -> Vec<Varnode> { model.get_live_vars(block).to_vec() };

        // Live sets come back in address order: RSP(0x00), RDI(0x08), EAX(0x10), RBX(0x18),
        // RCX(0x20), RDX(0x28), RSI(0x30), RIP(0x38), then the unique space (a higher space id).
        assert_eq!(live(head), vec![rsp.clone(), rdi.clone(), u00.clone()]);
        assert_eq!(
            live(work),
            vec![
                rsp.clone(),
                rdi.clone(),
                eax.clone(),
                rbx.clone(),
                rcx.clone(),
                rdx.clone(),
                rsi.clone(),
                u10.clone(),
            ]
        );
        assert_eq!(live(err), vec![rsp.clone(), eax.clone()]);
        assert_eq!(live(exit), vec![rsp.clone(), rip.clone()]);

        // The point of the analysis: the error path never births the "serious work" registers...
        for reg in [&rbx, &rcx, &rdx, &rsi] {
            assert!(!live(err).contains(reg), "{reg} must not be live on the error path");
        }
        // ...and RSP is not retired and reborn in the middle, despite blocks 4-7 and 8 never
        // touching it.
        assert!(live(work).contains(&rsp));
        assert!(live(err).contains(&rsp));
        // RIP is written only in the exit block, so it is alive nowhere else.
        for block in [head, work, err] {
            assert!(!live(block).contains(&rip));
        }
    }

    // Java: all blocks in a loop end up with the same variables in scope, since the upward and
    // downward pushes each traverse the whole cycle.
    #[test]
    fn every_block_in_a_loop_sees_the_same_live_set() {
        let regs = register_space();
        let a_vn = vn(&regs, 0x00, 8);
        let b_vn = vn(&regs, 0x08, 8);

        let a = JitBlock::new();
        let b = JitBlock::new();

        let dfm = Arc::new(MockDfm::default());
        register_block(&dfm, a, &[a_vn.clone()]);
        register_block(&dfm, b, &[b_vn.clone()]);

        let cfm = Arc::new(JitControlFlowModel::new(
            vec![a, b],
            [BlockFlow { from: Some(a), to: b }, BlockFlow { from: Some(b), to: a }],
        ));
        let model = JitVarScopeModel::new(cfm, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>);

        let both = vec![a_vn, b_vn];
        assert_eq!(model.get_live_vars(a), both.as_slice());
        assert_eq!(model.get_live_vars(b), both.as_slice());
    }

    // Java: a straight-line chain births a variable at its first access and retires it after its
    // last -- a varnode touched only by the first block is not alive in the last, and vice versa.
    #[test]
    fn straight_line_flow_retires_a_variable_after_its_last_access() {
        let regs = register_space();
        let early = vn(&regs, 0x00, 8);
        let late = vn(&regs, 0x08, 8);

        let first = JitBlock::new();
        let middle = JitBlock::new();
        let last = JitBlock::new();

        let dfm = Arc::new(MockDfm::default());
        register_block(&dfm, first, &[early.clone()]);
        register_block(&dfm, middle, &[]);
        register_block(&dfm, last, &[late.clone()]);

        let cfm = Arc::new(JitControlFlowModel::new(
            vec![first, middle, last],
            [
                BlockFlow { from: Some(first), to: middle },
                BlockFlow { from: Some(middle), to: last },
            ],
        ));
        let model = JitVarScopeModel::new(cfm, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>);

        assert_eq!(model.get_live_vars(first), [early].as_slice());
        // Nothing is alive in the middle: `early`'s last access is upstream, `late`'s first is
        // downstream, so the upward and downward views do not intersect there.
        assert_eq!(model.get_live_vars(middle), [].as_slice());
        assert_eq!(model.get_live_vars(last), [late].as_slice());
    }
}
