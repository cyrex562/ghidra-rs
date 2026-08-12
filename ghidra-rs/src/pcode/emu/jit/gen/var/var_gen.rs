//! The bytecode generator for a specific use-def variable (operand) access.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.VarGen`.
//!
//! For a table of value types, their use-def types, their generator types, and relevant read/write
//! opcodes, see [`JitVal`](crate::pcode::emu::jit::var::JitVal). This trait is an extension of the
//! `ValGen` interface that allows *writing*. The only non-`JitVar` `JitVal` is `JitConstVal`; as
//! such, most of the variable-access logic lives here.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`MpAccessGen`](crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen).
//! - Java's `VarGen<V> extends ValGen<V>` and inherits `ValGen`'s six abstract members. `ValGen`
//!   itself is not ported yet (it sits on the same cycle), so this trait restates those six
//!   members directly, exactly as the placeholder it replaces did. When `ValGen` lands, they move
//!   to it and this trait keeps only its own three `gen_write_from_*` members. `ValGen.subpiece`
//!   is still omitted: no ported implementor calls or overrides it, and its return type is
//!   `ValGen` itself.
//! - Java's static `lookup(V)` is **not** ported. It switches on the runtime class of `v` and
//!   returns the singleton generator for it, via an unchecked cast to `VarGen<V>` that only
//!   erasure makes possible: the five targets (`WholeDirectMemoryVarGen.GEN`,
//!   `WholeInputVarGen.GEN`, `MissingVarGen.GEN`, `WholeMemoryOutVarGen.GEN`,
//!   `WholeLocalOutVarGen.GEN`) each implement `VarGen` at a *different*, concrete `V`, so no
//!   monomorphic Rust signature `fn lookup<V: JitVar>(v: &V) -> impl VarGen<V>` can produce them.
//!   All five are also unported. The crate's established shape for such a Java static -- an erased
//!   `Any*` enum plus a free `lookup`, as in
//!   [`access_gen`](crate::pcode::emu::jit::gen::access::access_gen) -- is what this should become
//!   once those five generators exist and `JitVal` grows the downcasts needed to tell their
//!   variable types apart (today it only offers `as_varnode_var`/`as_out_var`/`as_missing_var`,
//!   which cannot distinguish e.g. a direct-memory var from an input var).
//! - Java's `Set<Varnode>` (a `LinkedHashSet`, i.e. insertion-ordered and de-duplicated) becomes a
//!   `Vec<Varnode>` kept de-duplicated by the constructors here, matching
//!   [`JitVarScopeModel::get_live_vars`], which already returns Java's live-var `LinkedHashSet` as
//!   an ordered slice. [`Varnode`] implements `Eq` but not `Hash`, so a real `HashSet` is not
//!   available anyway.
//! - `gen_read_val_direct_to_stack` and [`gen_write_val_direct_from_stack`] must erase `JT` (via
//!   [`SimpleJitType::erase_simple`]) to perform the `AccessGen` lookup, then
//!   [`Emitter::recast`] the concrete accessor's result back to the caller's stack shape. Java
//!   instead recovers `JT` from the lookup with an unchecked cast its sealed `SimpleJitType`
//!   hierarchy justifies. Only [`IntJitType`](crate::pcode::emu::jit::analysis::jit_type::IntJitType)
//!   and [`LongJitType`](crate::pcode::emu::jit::analysis::jit_type::LongJitType) currently have
//!   real `SimpleAccessGen` implementations; the `Float`/`Double` arms are unimplemented until
//!   `FloatAccessGen`/`DoubleAccessGen` grow one.
//! - Java's `genWriteValDirectFromStack` is overloaded on `Varnode` vs `JitVarnodeVar`; Rust has no
//!   overloading, so the latter is [`gen_write_val_direct_from_stack_of_var`].

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::analysis::jit_var_scope_model::JitVarScopeModel;
use crate::pcode::emu::jit::gen::access::access_gen::{lookup_simple, AnySimpleAccessGen};
use crate::pcode::emu::jit::gen::access::simple_access_gen::SimpleAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::var::{JitVar, JitVarnodeVar};
use crate::pcode::seam_stubs::{Ext, JitBlock, JitCodeGenerator, Opnd, OpndEm, Scope};
use crate::program::model::pcode::Varnode;

/// Mirrors `GenConsts.BLOCK_SIZE` (`SemisparseByteArray.BLOCK_SIZE`).
const BLOCK_SIZE: i64 = 0x1000;

/// The bytecode generator for a specific use-def variable (operand) access.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.VarGen<V>`. See the [module docs](self).
pub trait VarGen<V: JitVar>: Send + Sync {
    /// Emit bytecode to initialize the class in support of accessing this variable.
    ///
    /// Port of the inherited `ValGen.genValInit`.
    fn gen_val_init<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<N>;

    /// Read a value onto the JVM stack as the given p-code type.
    ///
    /// Port of the inherited `ValGen.genReadToStack`.
    fn gen_read_to_stack<JT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: JT,
        ext: Ext,
    ) -> Emitter<Ent<N, JT::B>>
    where
        JT: SimpleJitType,
        N: Next;

    /// Read a value into a multi-precision operand.
    ///
    /// Port of the inherited `ValGen.genReadToOpnd`.
    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N>;

    /// Read one leg of a multi-precision value onto the JVM stack.
    ///
    /// Port of the inherited `ValGen.genReadLegToStack`.
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>>;

    /// Read a multi-precision value into a fresh `int[]` on the JVM stack.
    ///
    /// Port of the inherited `ValGen.genReadToArray`.
    #[allow(clippy::too_many_arguments)]
    fn gen_read_to_array<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>>;

    /// Read a value onto the JVM stack as a p-code bool (JVM `int`).
    ///
    /// Port of the inherited `ValGen.genReadToBool`.
    fn gen_read_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<Ent<N, TInt>>;

    /// Write a value from a stack operand into the given variable.
    ///
    /// Port of `VarGen.genWriteFromStack`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack, having the value on top.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `v`: the variable to write.
    /// - `type_`: the p-code type of the stack operand.
    /// - `ext`: the kind of extension to apply when adjusting from varnode size to JVM size.
    /// - `scope`: a scope for temporaries.
    fn gen_write_from_stack<JT, N1>(
        &self,
        em: Emitter<Ent<N1, JT::B>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: JT,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: SimpleJitType,
        N1: Next;

    /// Write a value from a local (multi-precision) operand into the given variable.
    ///
    /// Port of `VarGen.genWriteFromOpnd`.
    fn gen_write_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N>;

    /// Write a value from an array operand into the given variable.
    ///
    /// Port of `VarGen.genWriteFromArray`.
    fn gen_write_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>;
}

/// Emit bytecode necessary to support access to the given varnode.
///
/// Port of `VarGen.genVarnodeInit`.
///
/// This applies to all varnode types: `memory`, `unique`, and `register`, but not `const`. For
/// memory varnodes, the byte arrays backing their pages must be pre-fetched so they can be
/// accessed at the translation site. For unique and register varnodes, those arrays are needed to
/// birth and retire them at [`BlockTransition`]s. The read/write generators would request these
/// fields anyway; requesting them here first is what makes them appear in the classfile in address
/// order, since the code generator iterates the variables in address order.
pub fn gen_varnode_init<N: Next>(
    em: Emitter<N>,
    gen: &dyn JitCodeGenerator,
    vn: &Varnode,
) -> Emitter<N> {
    let start = vn.get_offset();
    let end_incl = start + vn.get_size() as i64 - 1;
    let start_block = start.div_euclid(BLOCK_SIZE) * BLOCK_SIZE;
    let end_block_incl = end_incl.div_euclid(BLOCK_SIZE) * BLOCK_SIZE;
    let space = vn.get_address().space();
    let mut block = start_block;
    // Use != instead of < to allow wrap-around, as Java does.
    while block != end_block_incl + BLOCK_SIZE {
        gen.request_field_for_arr_direct(space, block);
        block += BLOCK_SIZE;
    }
    em
}

/// Emit bytecode that loads the given varnode, with the given p-code type, from the
/// `JitBytesPcodeExecutorState` onto the stack.
///
/// Port of `VarGen.genReadValDirectToStack`. Used for direct memory accesses and for
/// register/unique scope transitions. See the [module docs](self) on the erase-then-recast
/// deviation this requires.
pub fn gen_read_val_direct_to_stack<JT: SimpleJitType, N: Next>(
    em: Emitter<N>,
    local_this: &Local<TRef>,
    gen: &dyn JitCodeGenerator,
    type_: JT,
    vn: &Varnode,
) -> Emitter<Ent<N, JT::B>> {
    let endian = gen.get_analysis_context().get_endian();
    match lookup_simple(endian, &type_.erase_simple()) {
        AnySimpleAccessGen::Int(g) => g.gen_read_to_stack(em, local_this, gen, vn).recast(),
        AnySimpleAccessGen::Long(g) => g.gen_read_to_stack(em, local_this, gen, vn).recast(),
        AnySimpleAccessGen::Float(_) => {
            unimplemented!("FloatAccessGen does not implement SimpleAccessGen yet")
        }
        AnySimpleAccessGen::Double(_) => {
            unimplemented!("DoubleAccessGen does not implement SimpleAccessGen yet")
        }
    }
}

/// Emit bytecode that writes the given varnode, with the given p-code type, into the
/// `JitBytesPcodeExecutorState` from a stack operand.
///
/// Port of `VarGen.genWriteValDirectFromStack(Emitter, Local, JitCodeGenerator, JT, Varnode)`.
/// Used for direct memory accesses and for register/unique scope transitions. Since the value is
/// written directly into the state, which is just raw bytes, the "assigned" type is ignored in
/// favor of `type_`.
pub fn gen_write_val_direct_from_stack<JT: SimpleJitType, N1: Next>(
    em: Emitter<Ent<N1, JT::B>>,
    local_this: &Local<TRef>,
    gen: &dyn JitCodeGenerator,
    type_: JT,
    vn: &Varnode,
) -> Emitter<N1> {
    let endian = gen.get_analysis_context().get_endian();
    match lookup_simple(endian, &type_.erase_simple()) {
        AnySimpleAccessGen::Int(g) => g.gen_write_from_stack(em.recast(), local_this, gen, vn),
        AnySimpleAccessGen::Long(g) => g.gen_write_from_stack(em.recast(), local_this, gen, vn),
        AnySimpleAccessGen::Float(_) => {
            unimplemented!("FloatAccessGen does not implement SimpleAccessGen yet")
        }
        AnySimpleAccessGen::Double(_) => {
            unimplemented!("DoubleAccessGen does not implement SimpleAccessGen yet")
        }
    }
}

/// Emit bytecode that writes the given use-def variable into the `JitBytesPcodeExecutorState` from
/// a stack operand.
///
/// Port of `VarGen.genWriteValDirectFromStack(Emitter, Local, JitCodeGenerator, JT,
/// JitVarnodeVar)`, the overload taking the use-def node rather than its varnode.
pub fn gen_write_val_direct_from_stack_of_var<JT: SimpleJitType, N1: Next>(
    em: Emitter<Ent<N1, JT::B>>,
    local_this: &Local<TRef>,
    gen: &dyn JitCodeGenerator,
    type_: JT,
    v: &dyn JitVarnodeVar,
) -> Emitter<N1> {
    gen_write_val_direct_from_stack(em, local_this, gen, type_, &v.varnode())
}

/// For block transitions: emit bytecode that births (loads) variables from the
/// `JitBytesPcodeExecutorState` into their allocated JVM locals.
///
/// Port of `VarGen.genBirth`.
pub fn gen_birth<N: Next>(
    mut em: Emitter<N>,
    local_this: &Local<TRef>,
    gen: &dyn JitCodeGenerator,
    to_birth: &[Varnode],
) -> Emitter<N> {
    for vn in to_birth {
        for local in gen.get_allocation_model().locals_for_vn(vn) {
            em = local.gen_birth_code(em, local_this, gen);
        }
    }
    em
}

/// For block transitions: emit bytecode that retires (writes) variables into the
/// `JitBytesPcodeExecutorState` from their allocated JVM locals.
///
/// Port of `VarGen.genRetire`.
pub fn gen_retire<N: Next>(
    mut em: Emitter<N>,
    local_this: &Local<TRef>,
    gen: &dyn JitCodeGenerator,
    to_retire: &[Varnode],
) -> Emitter<N> {
    for vn in to_retire {
        for local in gen.get_allocation_model().locals_for_vn(vn) {
            em = local.gen_retire_code(em, local_this, gen);
        }
    }
    em
}

/// A means to emit bytecode on transitions between blocks.
///
/// Port of `VarGen.BlockTransition`. The Java record is mutable in practice -- it is common to
/// create a blank one with [`BlockTransition::new`] and then populate `to_retire`/`to_birth` --
/// which is why both are public and [`add_retire`](Self::add_retire)/[`add_birth`](Self::add_birth)
/// exist to preserve the de-duplication Java's `LinkedHashSet` gave for free.
pub struct BlockTransition<'a> {
    /// A handle to the local holding the `this` reference.
    pub local_this: Local<TRef>,
    /// The code generator.
    pub gen: &'a dyn JitCodeGenerator,
    /// The varnodes to retire on the transition, in insertion order and without duplicates.
    pub to_retire: Vec<Varnode>,
    /// The varnodes to birth on the transition, in insertion order and without duplicates.
    pub to_birth: Vec<Varnode>,
}

impl<'a> BlockTransition<'a> {
    /// Construct a "nop" or blank transition.
    ///
    /// Port of the compact `BlockTransition(Local, JitCodeGenerator)` constructor.
    pub fn new(local_this: Local<TRef>, gen: &'a dyn JitCodeGenerator) -> Self {
        Self { local_this, gen, to_retire: Vec::new(), to_birth: Vec::new() }
    }

    /// Add a varnode to retire, ignoring one already present.
    ///
    /// Stands in for `toRetire.add(vn)` on Java's `LinkedHashSet`.
    pub fn add_retire(&mut self, vn: Varnode) {
        if !self.to_retire.contains(&vn) {
            self.to_retire.push(vn);
        }
    }

    /// Add a varnode to birth, ignoring one already present.
    ///
    /// Stands in for `toBirth.add(vn)` on Java's `LinkedHashSet`.
    pub fn add_birth(&mut self, vn: Varnode) {
        if !self.to_birth.contains(&vn) {
            self.to_birth.push(vn);
        }
    }

    /// Check if a transition is actually needed.
    ///
    /// Port of `BlockTransition.needed`. When one is not needed, some smaller control-flow
    /// constructs (e.g., in `CBranchOpGen`) can be averted.
    pub fn needed(&self) -> bool {
        !self.to_retire.is_empty() || !self.to_birth.is_empty()
    }

    /// Emit bytecode for the transition.
    ///
    /// Port of `BlockTransition.genFwd`.
    pub fn gen_fwd<N: Next>(&self, em: Emitter<N>) -> Emitter<N> {
        let em = gen_retire(em, &self.local_this, self.gen, &self.to_retire);
        gen_birth(em, &self.local_this, self.gen, &self.to_birth)
    }

    /// Emit bytecode for the reverse transition.
    ///
    /// Port of `BlockTransition.genInv`. Sometimes "transitions" are used around hazards, notably
    /// `CallOtherOpGen`; this is used *after* the hazard to restore the live variables in scope,
    /// where [`gen_fwd`](Self::gen_fwd) is used before it. Variables that were retired are
    /// re-birthed here. There should not have been any variables birthed going into the hazard.
    pub fn gen_inv<N: Next>(&self, em: Emitter<N>) -> Emitter<N> {
        let em = gen_retire(em, &self.local_this, self.gen, &self.to_birth);
        gen_birth(em, &self.local_this, self.gen, &self.to_retire)
    }
}

/// Compute the retired and birthed varnodes for a transition between the given blocks.
///
/// Port of `VarGen.computeBlockTransition`. Either block may be `None` to indicate entering or
/// leaving the passage; additionally, `to` should be `None` when generating transitions around a
/// hazard.
pub fn compute_block_transition<'a>(
    local_this: Local<TRef>,
    gen: &'a dyn JitCodeGenerator,
    from: Option<JitBlock>,
    to: Option<JitBlock>,
) -> BlockTransition<'a> {
    let scope_model: &JitVarScopeModel = &gen.get_variable_scope_model();
    let live_from: Vec<Varnode> =
        from.map_or_else(Vec::new, |block| scope_model.get_live_vars(block).to_vec());
    let live_to: Vec<Varnode> =
        to.map_or_else(Vec::new, |block| scope_model.get_live_vars(block).to_vec());
    let mut result = BlockTransition::new(local_this, gen);

    result.to_retire = live_from.iter().filter(|vn| !live_to.contains(vn)).cloned().collect();
    result.to_birth = live_to.iter().filter(|vn| !live_from.contains(vn)).cloned().collect();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic;
    use crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::op::JitPhiOp;
    use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
    use crate::pcode::seam_stubs::{
        FieldForArrDirect, JitAllocationModel, JitAnalysisContext, JitControlFlowModel,
        JitDataFlowModel, JitDataFlowUseropLibrary, JitLocalOutVar, JitOp, JitOutVar,
        MethodVisitor,
    };
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 64, 1, AddressSpaceType::Register, 0)
    }

    fn vn(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    /// An allocation model handing back one [`JvmLocal`] per varnode it is asked about, so
    /// [`gen_birth`]/[`gen_retire`] have something to iterate.
    struct MockAllocationModel {
        locals: HashMap<i64, Vec<JvmLocal>>,
    }

    impl JitAllocationModel for MockAllocationModel {
        fn locals_for_vn(&self, vn: &Varnode) -> Vec<JvmLocal> {
            self.locals.get(&vn.get_offset()).cloned().unwrap_or_default()
        }
    }

    /// The scope model is rebuilt on each [`JitCodeGenerator::get_variable_scope_model`] call from
    /// the raw `(block, accessed varnodes)` pairs stored here, rather than held as an
    /// `Arc<JitVarScopeModel>` field: `JitCodeGenerator` requires `Send + Sync`, and
    /// [`JitVarScopeModel`] is neither, because the [`JitControlFlowModel`] stub it holds carries
    /// an `Arc<dyn Language>`. Block identity is what the model keys on, and [`JitBlock`] is
    /// `Copy`, so a rebuilt model answers `get_live_vars` for the same blocks.
    struct MockCodeGenerator {
        endian: Endian,
        requested: Mutex<Vec<i64>>,
        locals: HashMap<i64, Vec<JvmLocal>>,
        blocks: Vec<(JitBlock, Vec<Varnode>)>,
    }

    impl MockCodeGenerator {
        fn new(endian: Endian) -> Self {
            Self {
                endian,
                requested: Mutex::new(Vec::new()),
                locals: HashMap::new(),
                blocks: Vec::new(),
            }
        }
    }

    impl JitCodeGenerator for MockCodeGenerator {
        fn request_field_for_arr_direct(
            &self,
            _space: &AddressSpace,
            offset: i64,
        ) -> FieldForArrDirect {
            self.requested.lock().unwrap().push(offset);
            FieldForArrDirect { offset }
        }

        fn get_analysis_context(&self) -> JitAnalysisContext {
            JitAnalysisContext::new(self.endian)
        }

        fn get_allocation_model(&self) -> Box<dyn JitAllocationModel> {
            Box::new(MockAllocationModel { locals: self.locals.clone() })
        }

        fn get_variable_scope_model(&self) -> Arc<JitVarScopeModel> {
            let dfm = Arc::new(MockDfm::default());
            for (block, accessed) in &self.blocks {
                register_block(&dfm, *block, accessed);
            }
            let cfm = Arc::new(JitControlFlowModel::new(
                self.blocks.iter().map(|(block, _)| *block).collect(),
                [],
            ));
            Arc::new(JitVarScopeModel::new(cfm, dfm as Arc<dyn JitDataFlowModel>))
        }
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
    /// as accessed -- everything [`JitVarScopeModel`] asks of a `JitDataFlowModel`. Mirrors the
    /// mock in that module's own tests.
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

    #[test]
    fn gen_varnode_init_requests_every_block_the_varnode_spans() {
        // Java: genVarnodeInit walks startBlock..=endBlockIncl by BLOCK_SIZE. Offset 0x2FFE with
        // size 4 spans blocks 0x2000 and 0x3000.
        let space = register_space();
        let code_gen = MockCodeGenerator::new(Endian::Big);
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        gen_varnode_init(em, &code_gen, &vn(&space, 0x2FFE, 4));

        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x2000, 0x3000]);
    }

    #[test]
    fn gen_read_val_direct_to_stack_dispatches_to_the_endian_specific_accessor() {
        // Java: genReadValDirectToStack delegates to AccessGen.lookupSimple(endian, type)
        // .genReadToStack, which requests the block backing the varnode.
        let space = register_space();
        let code_gen = MockCodeGenerator::new(Endian::Big);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = gen_read_val_direct_to_stack(
            em,
            &local_this,
            &code_gen,
            IntJitType::I4,
            &vn(&space, 0x1000, 4),
        );
        let _: Vec<_> = result.local_variables();

        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_write_val_direct_from_stack_pops_the_value_and_requests_the_block() {
        // Java: genWriteValDirectFromStack takes ..., value and leaves ... -- i.e. it pops the
        // operand -- delegating to the same endian/type-specific accessor.
        let space = register_space();
        let code_gen = MockCodeGenerator::new(Endian::Little);
        let local_this = make_local_this();
        let em: Emitter<Ent<Bot, TInt>> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Bot> = gen_write_val_direct_from_stack(
            em,
            &local_this,
            &code_gen,
            IntJitType::I4,
            &vn(&space, 0x5000, 4),
        );
        let _: Vec<_> = result.local_variables();

        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x5000]);
    }

    #[test]
    fn gen_birth_and_retire_emit_one_access_per_allocated_local() {
        // Java: genBirth/genRetire iterate gen.getAllocationModel().localsForVn(vn) and emit each
        // local's birth/retire code, which reads/writes that local's varnode in the state.
        let space = register_space();
        let target = vn(&space, 0x3000, 4);
        let mut locals = HashMap::new();
        locals.insert(
            target.get_offset(),
            vec![
                JvmLocal::of(IntJitType::I4.erase_simple(), vn(&space, 0x3000, 4)),
                JvmLocal::of(IntJitType::I4.erase_simple(), vn(&space, 0x4000, 4)),
            ],
        );
        let mut code_gen = MockCodeGenerator::new(Endian::Big);
        code_gen.locals = locals;
        let local_this = make_local_this();

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Bot> = gen_birth(em, &local_this, &code_gen, &[target.clone()]);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x3000, 0x4000]);

        code_gen.requested.lock().unwrap().clear();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Bot> = gen_retire(em, &local_this, &code_gen, &[target]);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x3000, 0x4000]);
    }

    #[test]
    fn a_blank_transition_is_not_needed_but_a_populated_one_is() {
        // Java: needed() == !toRetire.isEmpty() || !toBirth().isEmpty().
        let space = register_space();
        let code_gen = MockCodeGenerator::new(Endian::Big);

        let mut transition = BlockTransition::new(make_local_this(), &code_gen);
        assert!(!transition.needed());

        transition.add_birth(vn(&space, 0x10, 4));
        assert!(transition.needed());

        // Java's LinkedHashSet ignores a duplicate add.
        transition.add_birth(vn(&space, 0x10, 4));
        assert_eq!(transition.to_birth.len(), 1);
    }

    #[test]
    fn compute_block_transition_retires_what_leaves_scope_and_births_what_enters() {
        // Java: toRetire = liveFrom - liveTo; toBirth = liveTo - liveFrom. Here block `a` accesses
        // r0 and r1, block `b` accesses r1 and r2, and each block's live set is exactly what it
        // accesses (no flows between them), so a -> b retires r0 and births r2, leaving r1 alone.
        let space = register_space();
        let r0 = vn(&space, 0x00, 4);
        let r1 = vn(&space, 0x10, 4);
        let r2 = vn(&space, 0x20, 4);

        let block_a = JitBlock::new();
        let block_b = JitBlock::new();

        let mut code_gen = MockCodeGenerator::new(Endian::Little);
        code_gen.blocks = vec![
            (block_a, vec![r0.clone(), r1.clone()]),
            (block_b, vec![r1.clone(), r2.clone()]),
        ];

        let transition =
            compute_block_transition(make_local_this(), &code_gen, Some(block_a), Some(block_b));

        assert_eq!(transition.to_retire, vec![r0.clone()]);
        assert_eq!(transition.to_birth, vec![r2.clone()]);
        assert!(transition.needed());

        // Leaving the passage (`to` is None) retires everything live in `from`, births nothing.
        let leaving = compute_block_transition(make_local_this(), &code_gen, Some(block_a), None);
        assert_eq!(leaving.to_retire, vec![r0, r1.clone()]);
        assert!(leaving.to_birth.is_empty());

        // Entering the passage (`from` is None) births everything live in `to`.
        let entering =
            compute_block_transition(make_local_this(), &code_gen, None, Some(block_b));
        assert!(entering.to_retire.is_empty());
        assert_eq!(entering.to_birth, vec![r1, r2]);
    }

    #[test]
    fn gen_inv_reverses_gen_fwd() {
        // Java: genFwd retires toRetire then births toBirth; genInv retires toBirth then births
        // toRetire. With one local per varnode, that is visible as the reversed order of the
        // state accesses each emits.
        let space = register_space();
        let retired = vn(&space, 0x1000, 4);
        let birthed = vn(&space, 0x2000, 4);
        let mut locals = HashMap::new();
        locals.insert(
            retired.get_offset(),
            vec![JvmLocal::of(IntJitType::I4.erase_simple(), retired.clone())],
        );
        locals.insert(
            birthed.get_offset(),
            vec![JvmLocal::of(IntJitType::I4.erase_simple(), birthed.clone())],
        );
        let mut code_gen = MockCodeGenerator::new(Endian::Big);
        code_gen.locals = locals;

        let mut transition = BlockTransition::new(make_local_this(), &code_gen);
        transition.add_retire(retired);
        transition.add_birth(birthed);

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Bot> = transition.gen_fwd(em);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000, 0x2000]);

        code_gen.requested.lock().unwrap().clear();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Bot> = transition.gen_inv(em);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x2000, 0x1000]);
    }
}
