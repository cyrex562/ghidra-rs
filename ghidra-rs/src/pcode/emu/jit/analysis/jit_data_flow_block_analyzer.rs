//! Per-block data flow analysis.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitDataFlowBlockAnalyzer`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic;
use crate::pcode::emu::jit::op::{JitDefOp, JitPhiOp};
use crate::pcode::emu::jit::var::{JitVal, JitVarnodeVar};
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::seam_stubs::{
    BlockFlow, JitAnalysisContext, JitBlock, JitDataFlowExecutor, JitDataFlowModel,
    JitDataFlowState, JitDataFlowUseropLibrary,
};
use crate::program::model::lang::register::Register;
use crate::program::model::pcode::Varnode;

/// An encapsulation of the per-block data flow analysis done by `JitDataFlowModel`.
///
/// One of these is created for each basic block in the passage. This does both the intra-block
/// analysis and encapsulates parts of the inter-block analysis. The class also contains and
/// provides access to some of the analytic results.
///
/// See `JitDataFlowModel::get_or_create_analyzer` (a stub on
/// [`JitDataFlowModel`](crate::pcode::seam_stubs::JitDataFlowModel), since the real
/// `JitDataFlowModel.java` is not ported).
pub struct JitDataFlowBlockAnalyzer {
    context: JitAnalysisContext,
    dfm: Arc<dyn JitDataFlowModel>,
    block: JitBlock,

    arithmetic: JitDataFlowArithmetic,
    library: JitDataFlowUseropLibrary,

    state: JitDataFlowState,
    is_entry: bool,
}

impl JitDataFlowBlockAnalyzer {
    /// Port of the package-private constructor
    /// `JitDataFlowBlockAnalyzer(JitAnalysisContext, JitDataFlowModel, JitBlock)`.
    pub fn new(context: JitAnalysisContext, dfm: Arc<dyn JitDataFlowModel>, block: JitBlock) -> Self {
        let arithmetic = dfm.get_arithmetic();
        let library = dfm.get_library();
        let state = JitDataFlowState::new(&context, Arc::clone(&dfm), block);
        let is_entry = context.is_block_entry(block);
        Self { context, dfm, block, arithmetic, library, state, is_entry }
    }

    /// Perform the intra-block analysis for this block.
    ///
    /// This just runs the block p-code through the analytic interpreter. See
    /// `JitDataFlowModel`'s section on intra-block analysis.
    pub fn do_intrablock(&self) {
        let exec = JitDataFlowExecutor::new(&self.context, Arc::clone(&self.dfm), &self.state);
        exec.execute(self.block, &self.library);
    }

    /// The initial entry into the recursive phi option seeking algorithm.
    ///
    /// See `JitDataFlowModel`'s section on inter-block analysis. This will modify the given phi
    /// op in place, adding to it each found option. Keep in mind a varnode may be partially
    /// defined, e.g., when reading `RAX`, perhaps only `EAX` has been defined. In such cases, we
    /// must catenate in the same manner we would when reading the varnode during intra-block
    /// analysis. The portions missing a definition will generate corresponding phi nodes, which
    /// are treated recursively.
    pub fn fill_phi_from_deps(&self, phi: &JitPhiOp) {
        let mut visited = HashSet::new();
        self.fill_phi_from_deps_inner(phi, &mut visited);
    }

    /// Fill options in for the given phi op.
    ///
    /// If our block is an entry, add that as a possible option. Additionally, consider each
    /// upstream block (dependency) as an option, recursively. Recursion will naturally terminate
    /// if there are no inward flows.
    fn fill_phi_from_deps_inner(&self, phi: &JitPhiOp, visited: &mut HashSet<JitBlock>) {
        if self.is_entry {
            phi.add_input_option();
        }
        for flow in self.dfm.flows_to(self.block) {
            let Some(from) = flow.from
            else {
                continue;
            };
            let analyzer_from = self.dfm.get_or_create_analyzer(from);
            analyzer_from.fill_phi_from_block(phi, flow, visited);
        }
    }

    /// Consider the given flow as an option for the given phi op, and fill it.
    ///
    /// If we've already visited the given block, we return immediately, without further
    /// recursion. Otherwise, we examine the varnode output state of this block for suitable
    /// definitions. If needed, we fill any gaps (possibly the entire varnode sought) with new phi
    /// nodes and recurse.
    fn fill_phi_from_block(&self, phi: &JitPhiOp, flow: BlockFlow, visited: &mut HashSet<JitBlock>) {
        if !visited.insert(self.block) {
            // NOTE: We do not need to remove the block before we return. If we didn't find it by
            // this path, we certainly are not going to find it from here by another path.
            return;
        }

        let phi_vn = phi.out().varnode();
        let mut defs = self.state.get_definitions(&phi_vn);
        if defs.len() != 1 {
            defs = self.state.generate_phis(defs, Some(&|p| self.dfm.phi_queue_add(p)));
            let cat_opt = self.arithmetic.catenate(&phi_vn, defs);
            phi.add_option(flow, cat_opt);
            // New phi nodes will be picked up in the next round of filling. Since parts are
            // smaller than the whole, the size of such nodes should shrink until a singular
            // definition is found.
            return;
        }

        let val = defs.into_iter().next().unwrap();
        if let Some(missing) = val.as_missing_var() {
            // Require the chain to have a node in this block.
            let missing_vn = missing.varnode();
            let phi2 = missing.generate_phi(&self.dfm, self.block);
            self.dfm.phi_queue_add(Arc::clone(&phi2));
            let out: Arc<dyn JitVal> = phi2.out();
            self.state.set_var(&missing_vn, Arc::clone(&out));
            phi.add_option(flow, out);
            // Will get filled on subsequent round.
            return;
        }

        phi.add_option(flow, val);
    }

    /// Get a complete catalog of all varnodes read, including overlapping, subregs, etc.
    pub fn get_varnodes_read(&self) -> Vec<Varnode> {
        self.state.get_varnodes_read()
    }

    /// Get a complete catalog of all varnodes written, including overlapping, subregs, etc.
    pub fn get_varnodes_written(&self) -> Vec<Varnode> {
        self.state.get_varnodes_written()
    }

    /// Get an ordered list of all values involved in the latest definition of the given varnode.
    ///
    /// Port of the `getOutput(Varnode)` overload -- Rust has no method overloading, so this and
    /// [`Self::get_output_register`] give Java's two `getOutput` methods distinct names.
    ///
    /// See `JitDataFlowState::get_definitions`.
    pub fn get_output_varnode(&self, varnode: &Varnode) -> Vec<Arc<dyn JitVal>> {
        self.state.get_definitions(varnode)
    }

    /// Get an ordered list of all values involved in the latest definition of the given register.
    ///
    /// Port of the `getOutput(Register)` overload. See [`Self::get_output_varnode`].
    pub fn get_output_register(&self, register: &Register) -> Vec<Arc<dyn JitVal>> {
        let varnode = Varnode::new(register.address().clone(), register.num_bytes());
        self.state.get_definitions(&varnode)
    }

    /// Get the latest definition of the given varnode, synthesizing ops if required.
    ///
    /// NOTE: May produce phi nodes that need additional inter-block analysis.
    pub fn get_var(&self, vn: &Varnode) -> Arc<dyn JitVal> {
        self.state.get_var(vn, Reason::ExecuteRead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::jit_var::JitVar;
    use crate::pcode::seam_stubs::{JitConstVal, JitLocalOutVar, JitOutVar};
use crate::pcode::emu::jit::op::JitOp;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    /// A trivial, never-called `JitDataFlowModel`, used only so [`JitDataFlowArithmetic::new`]
    /// has *some* `Arc<dyn JitDataFlowModel>` to hold onto in tests where the arithmetic itself
    /// is never exercised.
    struct NoopDfm;
    impl JitDataFlowModel for NoopDfm {
        fn generate_out_var(&self, _out: &Varnode) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
        fn notify_op(&self, _op: Arc<dyn JitOp>) {
            unimplemented!()
        }
    }

    /// A minimal stand-in for the unported `JitDataFlowModel`, sufficient to drive
    /// `JitDataFlowBlockAnalyzer`'s own logic (as opposed to the arithmetic's, which
    /// [`jit_data_flow_arithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic)
    /// already tests against its own `RecordingModel`).
    #[derive(Default)]
    struct MockDfm {
        next_id: AtomicI32,
        notified: Mutex<Vec<Arc<dyn JitOp>>>,
        flows: Mutex<HashMap<JitBlock, Vec<BlockFlow>>>,
        analyzers: Mutex<HashMap<JitBlock, Arc<JitDataFlowBlockAnalyzer>>>,
        phi_queue: Mutex<Vec<Arc<JitPhiOp>>>,
    }

    impl JitDataFlowModel for MockDfm {
        fn generate_out_var(&self, out: &Varnode) -> Arc<dyn JitOutVar> {
            Arc::new(JitLocalOutVar::new(self.next_id.fetch_add(1, Ordering::Relaxed), out.clone()))
        }

        fn notify_op(&self, op: Arc<dyn JitOp>) {
            op.link();
            self.notified.lock().unwrap().push(op);
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
                self.analyzers
                    .lock()
                    .unwrap()
                    .get(&block)
                    .expect("test: analyzer must be pre-registered"),
            )
        }

        fn flows_to(&self, block: JitBlock) -> Vec<BlockFlow> {
            self.flows.lock().unwrap().get(&block).cloned().unwrap_or_default()
        }

        fn phi_queue_add(&self, phi: Arc<JitPhiOp>) {
            self.phi_queue.lock().unwrap().push(phi);
        }
    }

    // Java: `getVar` on a register/unique varnode with no prior definition synthesizes a phi node
    // (via `MiniDFState.generatePhis`'s missing-var substitution) and returns its output, rather
    // than the raw `JitMissingVar` -- since `JitMissingVar`s must never enter the use-def graph.
    #[test]
    fn get_var_with_no_definition_synthesizes_a_phi_output() {
        let dfm = Arc::new(MockDfm::default());
        let block = JitBlock::new();
        let context = JitAnalysisContext::new(Endian::Little);
        let analyzer =
            JitDataFlowBlockAnalyzer::new(context, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>, block);

        // Register/unique space, not memory: `getVar` routes memory-space varnodes straight to
        // `dfm.generateDirectMemoryVar` (see `get_var_on_constant_space_returns_the_encoded_constant`'s
        // sibling for the constant-space branch), never through the def-state/phi machinery this
        // test exercises.
        let space = AddressSpace::new("register", 64, 1, AddressSpaceType::Register, 0);
        let vn = varnode(&space, 0x1000, 4);

        let val = analyzer.get_var(&vn);

        // The returned value is the phi's output, not a `JitMissingVar` -- and it was recorded
        // into the block's def state (a subsequent read returns the same node).
        assert!(val.as_missing_var().is_none());
        let again = analyzer.get_var(&vn);
        assert_eq!(Arc::as_ptr(&again) as *const (), Arc::as_ptr(&val) as *const ());
    }

    // Java: `getVar` on a constant-space varnode returns a `JitConstVal` built directly from the
    // varnode's offset (the constant's actual value) and size -- no def-state lookup at all.
    #[test]
    fn get_var_on_constant_space_returns_the_encoded_constant() {
        let dfm = Arc::new(MockDfm::default());
        let context = JitAnalysisContext::new(Endian::Little);
        let analyzer = JitDataFlowBlockAnalyzer::new(
            context,
            Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>,
            JitBlock::new(),
        );

        let const_space = AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0);
        let vn = varnode(&const_space, 42, 4);

        let val = analyzer.get_var(&vn);

        assert_eq!(val.as_const_val().unwrap().value(), 42);
        assert!(analyzer.get_varnodes_read().is_empty());
    }

    // Java: `getVarnodesWritten`/`getOutput(Varnode)` reflect writes made to the block's state
    // (here via `state.setVar`, as `fillPhiFromBlock` does internally).
    #[test]
    fn writes_are_reflected_in_varnodes_written_and_output() {
        let dfm = Arc::new(MockDfm::default());
        let context = JitAnalysisContext::new(Endian::Little);
        let block = JitBlock::new();
        let analyzer =
            JitDataFlowBlockAnalyzer::new(context, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>, block);

        let space = space();
        let vn = varnode(&space, 0x2000, 4);
        let val: Arc<dyn JitVal> = Arc::new(JitConstVal::new(4, 7));
        analyzer.state.set_var(&vn, Arc::clone(&val));

        assert_eq!(analyzer.get_varnodes_written(), vec![vn.clone()]);
        let out = analyzer.get_output_varnode(&vn);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_const_val().unwrap().value(), 7);
    }

    // Java: `isEntry` (computed in the constructor from `context.getOpEntry(block.first()) !=
    // null`) drives `fillPhiFromDeps`'s `phi.addInputOption()` call.
    #[test]
    fn entry_block_adds_input_option_when_filling_phi_from_deps() {
        let dfm = Arc::new(MockDfm::default());
        let block = JitBlock::new();
        let context = JitAnalysisContext::with_entry_blocks(Endian::Little, [block].into());
        let analyzer =
            JitDataFlowBlockAnalyzer::new(context, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>, block);

        let space = space();
        let vn = varnode(&space, 0x3000, 4);
        let out: Arc<dyn JitOutVar> = Arc::new(JitLocalOutVar::new(0, vn));
        let phi = JitPhiOp::new(block, out);

        analyzer.fill_phi_from_deps(&phi);

        assert!(phi.has_input_option());
        assert_eq!(phi.inputs().len(), 1);
    }

    // Java: `fillPhiFromDeps` walks `block.flowsTo()`, asks the predecessor's analyzer to
    // consider that flow via `fillPhiFromBlock`, which -- finding exactly one (non-missing)
    // definition in the predecessor's state -- adds it as the phi's option for that flow.
    #[test]
    fn fill_phi_from_deps_pulls_a_defined_value_from_a_predecessor_block() {
        let dfm = Arc::new(MockDfm::default());
        let context = JitAnalysisContext::new(Endian::Little);
        let space = space();
        let vn = varnode(&space, 0x4000, 4);

        let block_a = JitBlock::new();
        let block_b = JitBlock::new();

        let analyzer_b = Arc::new(JitDataFlowBlockAnalyzer::new(
            context.clone(),
            Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>,
            block_b,
        ));
        let b_val: Arc<dyn JitVal> = Arc::new(JitConstVal::new(4, 99));
        analyzer_b.state.set_var(&vn, Arc::clone(&b_val));
        dfm.analyzers.lock().unwrap().insert(block_b, Arc::clone(&analyzer_b));

        let flow = BlockFlow { from: Some(block_b), to: block_a };
        dfm.flows.lock().unwrap().insert(block_a, vec![flow]);

        let analyzer_a =
            JitDataFlowBlockAnalyzer::new(context, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>, block_a);
        let out: Arc<dyn JitOutVar> = Arc::new(JitLocalOutVar::new(0, vn));
        let phi = JitPhiOp::new(block_a, out);

        analyzer_a.fill_phi_from_deps(&phi);

        let inputs = phi.inputs();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].as_const_val().unwrap().value(), 99);
    }
}
