//! An access generator that exports part of its implementation for reuse by an
//! `MpIntAccessGen`.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.ExportsLegAccessGen`.
//!
//! This really just avoids the re-creation of [`Varnode`] objects for each leg of a large
//! varnode. The leg methods instead take the `(space, offset, size)` triple as well as the
//! offset of the block containing its start.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`SimpleAccessGen`](crate::pcode::emu::jit::gen::access::simple_access_gen::SimpleAccessGen).
//! - Java expresses `genReadToStack`/`genWriteFromStack` as *default* methods on an interface
//!   that extends `SimpleAccessGen`, computed from the new abstract `genReadLegToStack`/
//!   `genWriteLegFromStack` methods. Rust has no equivalent of "default methods that satisfy a
//!   supertrait's abstract methods", so instead [`ExportsLegAccessGen`] requires only
//!   `AccessGen<IntJitType>`, and a blanket `impl<G: ExportsLegAccessGen> SimpleAccessGen<TInt,
//!   IntJitType> for G` supplies `gen_read_to_stack`/`gen_write_from_stack` in terms of the leg
//!   methods -- giving every implementor of [`ExportsLegAccessGen`] a [`SimpleAccessGen`] for
//!   free, exactly as in Java.
//! - `BLOCK_SIZE` mirrors `GenConsts.BLOCK_SIZE` (in turn `SemisparseByteArray.BLOCK_SIZE`,
//!   `0x1000`). `GenConsts` itself is a large namespace-interface of ASM type/method descriptors
//!   unrelated to this type's logic, so only the one constant this type needs is ported here.
//! - `MpIntAccessGen`, mentioned only in the Java class doc (not in any signature), is not
//!   referenced by this port.

use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
use crate::pcode::emu::jit::gen::access::simple_access_gen::SimpleAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::seam_stubs::{AccessGen, JitCodeGenerator};
use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::Varnode;

/// Mirrors `GenConsts.BLOCK_SIZE` (`SemisparseByteArray.BLOCK_SIZE`).
const BLOCK_SIZE: i64 = 0x1000;

/// A generator that exports part of its implementation for use in an `MpIntAccessGen`.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.ExportsLegAccessGen`.
pub trait ExportsLegAccessGen: AccessGen<IntJitType> {
    /// Emit code to read one JVM int, either a whole variable or one leg of a multi-precision
    /// int variable.
    ///
    /// Port of `ExportsLegAccessGen.genReadLegToStack`.
    ///
    /// Legs that span blocks are handled as in
    /// [`gen_read_to_stack`](SimpleAccessGen::gen_read_to_stack).
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `space`: the address space of the varnode.
    /// - `block`: the block offset containing the varnode (or leg).
    /// - `off`: the offset of the varnode (or leg).
    /// - `size`: the size of the varnode in bytes (or leg).
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., having pushed the value.
    #[allow(clippy::too_many_arguments)]
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        space: &AddressSpace,
        block: i64,
        off: i32,
        size: i32,
    ) -> Emitter<Ent<N, TInt>>;

    /// Emit code to write one JVM int, either a whole variable or one leg of a multi-precision
    /// int variable.
    ///
    /// Port of `ExportsLegAccessGen.genWriteLegFromStack`.
    ///
    /// Legs that span blocks are handled as in
    /// [`gen_write_from_stack`](SimpleAccessGen::gen_write_from_stack).
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack, having the value on top.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `space`: the address space of the varnode.
    /// - `block`: the block offset containing the varnode (or leg).
    /// - `off`: the offset of the varnode (or leg).
    /// - `size`: the size of the varnode in bytes (or leg).
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., having popped the value.
    #[allow(clippy::too_many_arguments)]
    fn gen_write_leg_from_stack<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TInt>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        space: &AddressSpace,
        block: i64,
        off: i32,
        size: i32,
    ) -> Emitter<N1>;
}

impl<G: ExportsLegAccessGen> SimpleAccessGen<TInt, IntJitType> for G {
    /// Port of `ExportsLegAccessGen.genReadToStack`.
    fn gen_read_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
    ) -> Emitter<Ent<N, TInt>> {
        let space = vn.get_address().space();
        let offset = vn.get_offset();
        let block = offset.div_euclid(BLOCK_SIZE) * BLOCK_SIZE;
        let off = (offset - block) as i32;
        let size = vn.get_size();
        self.gen_read_leg_to_stack(em, local_this, gen, space, block, off, size)
    }

    /// Port of `ExportsLegAccessGen.genWriteFromStack`.
    fn gen_write_from_stack<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TInt>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
    ) -> Emitter<N1> {
        let space = vn.get_address().space();
        let offset = vn.get_offset();
        let block = offset.div_euclid(BLOCK_SIZE) * BLOCK_SIZE;
        let off = (offset - block) as i32;
        let size = vn.get_size();
        self.gen_write_leg_from_stack(em, local_this, gen, space, block, off, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Mutex;

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    /// A minimal implementor recording the `(block, off, size)` triple it was asked to access,
    /// so tests can check `genReadToStack`/`genWriteFromStack`'s block-boundary math against the
    /// Java behavior without any real bytecode-generation logic.
    struct TestExportsLegAccessGen {
        last_leg: Mutex<Option<(i64, i32, i32)>>,
    }

    impl AccessGen<IntJitType> for TestExportsLegAccessGen {}

    impl ExportsLegAccessGen for TestExportsLegAccessGen {
        fn gen_read_leg_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _space: &AddressSpace,
            block: i64,
            off: i32,
            size: i32,
        ) -> Emitter<Ent<N, TInt>> {
            *self.last_leg.lock().unwrap() = Some((block, off, size));
            em.recast()
        }

        fn gen_write_leg_from_stack<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TInt>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _space: &AddressSpace,
            block: i64,
            off: i32,
            size: i32,
        ) -> Emitter<N1> {
            *self.last_leg.lock().unwrap() = Some((block, off, size));
            em.recast()
        }
    }

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    #[test]
    fn gen_read_to_stack_splits_offset_into_block_and_off_like_java() {
        // Java: block = offset / BLOCK_SIZE * BLOCK_SIZE; off = (int) (offset - block).
        // offset 0x1004, size 4 -> block 0x1000, off 4.
        let gen_impl = TestExportsLegAccessGen { last_leg: Mutex::new(None) };
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode(0x1004, 4);

        let result: Emitter<Ent<Bot, TInt>> =
            gen_impl.gen_read_to_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
        assert_eq!(gen_impl.last_leg.lock().unwrap().unwrap(), (0x1000, 4, 4));
    }

    #[test]
    fn gen_write_from_stack_splits_offset_into_block_and_off_like_java() {
        let gen_impl = TestExportsLegAccessGen { last_leg: Mutex::new(None) };
        let em: Emitter<Ent<Bot, TInt>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode(0x2FFE, 4);

        // offset 0x2FFE, size 4 -> block 0x2000, off 0xFFE (spans into the next block).
        let result: Emitter<Bot> =
            gen_impl.gen_write_from_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
        assert_eq!(gen_impl.last_leg.lock().unwrap().unwrap(), (0x2000, 0xFFE, 4));
    }
}
