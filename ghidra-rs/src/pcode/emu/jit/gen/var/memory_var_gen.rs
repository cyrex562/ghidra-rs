//! The generator for memory variables.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.MemoryVarGen`.
//!
//! These variables affect the `JitBytesPcodeExecutorState` state immediately, i.e., they are not
//! birthed or retired as local JVM variables. The generator delegates to the appropriate
//! [`AccessGen`](crate::pcode::emu::jit::gen::access::access_gen::AccessGen) for this variable's
//! varnode and assigned type.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`MpAccessGen`](crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen).
//! - `genValInit` and `genReadToStack` delegate to [`gen_varnode_init`] and
//!   [`gen_read_val_direct_to_stack`], the statics of
//!   [`VarGen`](crate::pcode::emu::jit::gen::var::var_gen) this file used to carry privately while
//!   that type was an unported forward reference. See that module's docs for the erase-then-recast
//!   deviation `gen_read_val_direct_to_stack` requires.
//! - `genReadLegToStack`'s real JVM-opcode emission (`Op::ldc__i`, `Op::ishl`, `Op::ishr`) is not
//!   yet ported, for the reason given in the
//!   [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen) module docs (`Op.java`
//!   has no real port despite its stale `DONE` marker). This port keeps the real control flow --
//!   whether the leg lies entirely past the varnode, and if so whether it is zero- or
//!   sign-extended -- but stubs the opcode sequence itself via [`Emitter::recast`].

use crate::pcode::emu::jit::analysis::jit_type::{
    IntJitType, LeggedJitType, MpIntJitType, SimpleJitType,
};
use crate::pcode::emu::jit::gen::access::access_gen::{gen_read_to_bool, lookup_mp};
use crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::var::JitVarnodeVar;
use crate::pcode::emu::jit::analysis::JitDataFlowArithmetic;
use crate::pcode::emu::jit::gen::var::var_gen::{
    gen_read_val_direct_to_stack, gen_varnode_init, VarGen,
};
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, OpndEm, Scope};
use crate::program::model::lang::Endian;
use crate::program::model::pcode::Varnode;

/// The number of bytes in a JVM `int`, i.e., Java's `Integer.BYTES`.
const INT_BYTES: i32 = 4;

/// The generator for memory variables.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.MemoryVarGen<V>`. See the [module docs](self).
pub trait MemoryVarGen<V: JitVarnodeVar>: VarGen<V> {
    /// Get the varnode actually accessed for the given p-code variable.
    ///
    /// This is made to be overridden for the implementation of subpiece access.
    ///
    /// Port of `MemoryVarGen.getVarnode`.
    fn get_varnode(&self, gen: &dyn JitCodeGenerator, v: &V) -> Varnode {
        let _ = gen;
        v.varnode()
    }

    /// Port of `MemoryVarGen.genValInit`.
    fn gen_val_init<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<N> {
        let _ = local_this;
        gen_varnode_init(em, gen, &self.get_varnode(gen, v))
    }

    /// Port of `MemoryVarGen.genReadToStack`.
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
        N: Next,
    {
        let _ = ext;
        let vn = self.get_varnode(gen, v);
        gen_read_val_direct_to_stack(em, local_this, gen, type_, &vn)
    }

    /// Port of `MemoryVarGen.genReadToOpnd`.
    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N> {
        let vn = self.get_varnode(gen, v);
        lookup_mp(gen.get_analysis_context().get_endian())
            .gen_read_to_opnd(em, local_this, gen, &vn, type_, ext, scope)
    }

    /// Port of `MemoryVarGen.genReadLegToStack`.
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>> {
        let vn = self.get_varnode(gen, v);
        if vn.get_size() <= leg * INT_BYTES {
            return match ext {
                Ext::Zero => em.recast(),
                Ext::Sign => {
                    let endian = gen.get_analysis_context().get_endian();
                    let msb_vn = match endian {
                        Endian::Big => Varnode::new(vn.get_address().clone(), 1),
                        Endian::Little => Varnode::new(
                            vn.get_address()
                                .add(vn.get_size() as i64 - 1)
                                .expect("address overflow"),
                            1,
                        ),
                    };
                    let em =
                        gen_read_val_direct_to_stack(em, local_this, gen, IntJitType::I1, &msb_vn);
                    em.recast()
                }
            };
        }
        let endian = gen.get_analysis_context().get_endian();
        let sub_vn = JitDataFlowArithmetic::sub_piece_vn(endian, &vn, leg * INT_BYTES, INT_BYTES);
        let leg_type = type_.leg_types_le_typed()[leg as usize];
        gen_read_val_direct_to_stack(em, local_this, gen, leg_type, &sub_vn)
    }

    /// Port of `MemoryVarGen.genReadToArray`.
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
    ) -> Emitter<Ent<N, TRef>> {
        let vn = self.get_varnode(gen, v);
        lookup_mp(gen.get_analysis_context().get_endian())
            .gen_read_to_array(em, local_this, gen, &vn, type_, ext, scope, slack)
    }

    /// Port of `MemoryVarGen.genReadToBool`.
    fn gen_read_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<Ent<N, TInt>> {
        let vn = self.get_varnode(gen, v);
        gen_read_to_bool(em, local_this, gen, &vn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::var::{JitVal, JitVar, JitVarnodeVar};
    use crate::pcode::seam_stubs::{FieldForArrDirect, JitAnalysisContext, MethodVisitor};
use crate::pcode::emu::jit::op::JitOp;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::{Arc, Mutex};

    struct MockCodeGenerator {
        endian: Endian,
        requested: Mutex<Vec<i64>>,
    }

    impl MockCodeGenerator {
        fn new(endian: Endian) -> Self {
            Self { endian, requested: Mutex::new(Vec::new()) }
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
    }

    struct TestVarnodeVar {
        varnode: Varnode,
    }

    impl JitVal for TestVarnodeVar {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitVar for TestVarnodeVar {
        fn id(&self) -> i32 {
            1
        }

        fn space(&self) -> Arc<AddressSpace> {
            Arc::clone(self.varnode.get_address().space())
        }
    }

    impl JitVarnodeVar for TestVarnodeVar {
        fn varnode(&self) -> Varnode {
            self.varnode.clone()
        }
    }

    /// A minimal implementor exercising `MemoryVarGen`'s default methods without any real
    /// bytecode-generation logic of its own -- just as `TestSimpleAccessGen`/`TestMpAccessGen` do
    /// for their traits elsewhere in this crate.
    struct TestMemoryVarGen;

    impl VarGen<TestVarnodeVar> for TestMemoryVarGen {
        fn gen_val_init<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
        ) -> Emitter<N> {
            MemoryVarGen::gen_val_init(self, em, local_this, gen, v)
        }

        fn gen_read_to_stack<JT, N>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
            type_: JT,
            ext: Ext,
        ) -> Emitter<Ent<N, JT::B>>
        where
            JT: SimpleJitType,
            N: Next,
        {
            MemoryVarGen::gen_read_to_stack(self, em, local_this, gen, v, type_, ext)
        }

        fn gen_read_to_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N> {
            MemoryVarGen::gen_read_to_opnd(self, em, local_this, gen, v, type_, ext, scope)
        }

        fn gen_read_leg_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
            type_: MpIntJitType,
            leg: i32,
            ext: Ext,
        ) -> Emitter<Ent<N, TInt>> {
            MemoryVarGen::gen_read_leg_to_stack(self, em, local_this, gen, v, type_, leg, ext)
        }

        fn gen_read_to_array<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
            slack: i32,
        ) -> Emitter<Ent<N, TRef>> {
            MemoryVarGen::gen_read_to_array(self, em, local_this, gen, v, type_, ext, scope, slack)
        }

        fn gen_read_to_bool<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
        ) -> Emitter<Ent<N, TInt>> {
            MemoryVarGen::gen_read_to_bool(self, em, local_this, gen, v)
        }

        // Java: MemoryVarGen does not override VarGen's abstract genWriteFromStack /
        // genWriteFromOpnd / genWriteFromArray -- only DirectMemoryVarGen (and other concrete
        // var-gens, not yet ported) provide real bodies. This test double for MemoryVarGen alone
        // has no real behavior to exercise here.
        fn gen_write_from_stack<JT, N1>(
            &self,
            _em: Emitter<Ent<N1, JT::B>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVarnodeVar,
            _type_: JT,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            JT: SimpleJitType,
            N1: Next,
        {
            unimplemented!("TestMemoryVarGen does not exercise genWriteFromStack")
        }

        fn gen_write_from_opnd<N: Next>(
            &self,
            _em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVarnodeVar,
            _opnd: &dyn crate::pcode::seam_stubs::Opnd<MpIntJitType>,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N> {
            unimplemented!("TestMemoryVarGen does not exercise genWriteFromOpnd")
        }

        fn gen_write_from_array<N1: Next>(
            &self,
            _em: Emitter<Ent<N1, TRef>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVarnodeVar,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1> {
            unimplemented!("TestMemoryVarGen does not exercise genWriteFromArray")
        }
    }

    impl MemoryVarGen<TestVarnodeVar> for TestMemoryVarGen {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    #[test]
    fn get_varnode_defaults_to_the_variable_s_varnode() {
        // Java: MemoryVarGen.getVarnode(gen, v) == v.varnode().
        let vn = make_varnode(0x1000, 4);
        let v = TestVarnodeVar { varnode: vn.clone() };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Big);
        assert_eq!(gen_impl.get_varnode(&code_gen, &v).get_offset(), vn.get_offset());
    }

    #[test]
    fn gen_val_init_requests_every_block_the_varnode_spans() {
        // Java: genVarnodeInit walks startBlock..=endBlockIncl by BLOCK_SIZE.
        // offset 0x2FFE, size 4 -> spans blocks 0x2000 and 0x3000.
        let vn = make_varnode(0x2FFE, 4);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Big);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        MemoryVarGen::gen_val_init(&gen_impl, em, &local_this, &code_gen, &v);

        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x2000, 0x3000]);
    }

    #[test]
    fn gen_val_init_requests_a_single_block_when_the_varnode_fits() {
        let vn = make_varnode(0x1000, 4);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Little);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        MemoryVarGen::gen_val_init(&gen_impl, em, &local_this, &code_gen, &v);

        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_read_to_stack_dispatches_through_the_endian_specific_int_accessor() {
        let vn = make_varnode(0x1000, 4);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Big);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = MemoryVarGen::gen_read_to_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            IntJitType::I4,
            Ext::Zero,
        );
        let _: Vec<_> = result.local_variables();
        // The int accessor requests the single block backing the varnode.
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_read_leg_to_stack_beyond_the_varnode_with_zero_ext_requests_no_fields() {
        // Java: vn.getSize() <= leg * Integer.BYTES with ZERO ext just pushes a constant; no
        // field is requested at all.
        let vn = make_varnode(0x1000, 4);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Little);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = MemoryVarGen::gen_read_leg_to_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            2,
            Ext::Zero,
        );
        let _: Vec<_> = result.local_variables();
        assert!(code_gen.requested.lock().unwrap().is_empty());
    }

    #[test]
    fn gen_read_leg_to_stack_beyond_the_varnode_with_sign_ext_reads_the_msb() {
        // Java: SIGN ext reads a 1-byte varnode at the MSB (LITTLE: address + size - 1) to derive
        // the sign, which requires requesting that byte's block.
        let vn = make_varnode(0x1000, 4);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Little);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = MemoryVarGen::gen_read_leg_to_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            2,
            Ext::Sign,
        );
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_read_leg_to_stack_within_the_varnode_reads_the_subpiece() {
        // Java: leg 0 of a 9-byte MpIntJitType reads the least-significant 4 bytes -- offset 0,
        // size 4 -- which for a varnode based at 0x1000 is still within block 0x1000.
        let vn = make_varnode(0x1000, 9);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Little);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = MemoryVarGen::gen_read_leg_to_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            0,
            Ext::Zero,
        );
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_read_to_bool_delegates_to_access_gen() {
        // Java: genReadToBool delegates to AccessGen.genReadToBool, which requests the varnode's
        // block(s) directly.
        let vn = make_varnode(0x1000, 4);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Big);
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> =
            MemoryVarGen::gen_read_to_bool(&gen_impl, em, &local_this, &code_gen, &v);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_read_to_opnd_and_array_use_the_stub_mp_accessor() {
        let vn = make_varnode(0x1000, 9);
        let v = TestVarnodeVar { varnode: vn };
        let gen_impl = TestMemoryVarGen;
        let code_gen = MockCodeGenerator::new(Endian::Little);
        let local_this = make_local_this();

        struct MockScope;
        impl Scope for MockScope {}

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let opnd_result = MemoryVarGen::gen_read_to_opnd(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            Ext::Zero,
            &MockScope,
        );
        let _: Vec<_> = opnd_result.em.local_variables();

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let array_result: Emitter<Ent<Bot, TRef>> = MemoryVarGen::gen_read_to_array(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            Ext::Zero,
            &MockScope,
            0,
        );
        let _: Vec<_> = array_result.local_variables();
    }
}
