//! The generator for reading and writing plain (non-multi-precision) integers.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.IntAccessGen`.
//!
//! # Differences from Java
//!
//! - Java's enum constant bodies (`BE { ... }`, `LE { ... }`) become `match self` arms in each
//!   trait method, since this is a closed Java `enum` -- a trait would reopen a set the Java
//!   source deliberately closed.
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every generic method,
//!   is dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`ExportsLegAccessGen`](crate::pcode::emu::jit::gen::access::exports_leg_access_gen::ExportsLegAccessGen).
//! - The real JVM-opcode emission (`Op::ldc__i`, `Op::invokestatic`, `Op::ior`, etc., from
//!   `ghidra.pcode.emu.jit.gen.util.Op`) and its `Inv`-chain helpers
//!   (`ghidra.pcode.emu.jit.gen.util.Methods.Inv`) are not yet ported: `Op.java` is marked `DONE`
//!   in `PORT_MANIFEST.tsv`, but no port of its opcode namespace exists anywhere in this crate
//!   (that marker is stale bookkeeping, not evidence of a port). `GenConsts` (the ASM
//!   type/method-descriptor namespace) is likewise unported. This port therefore keeps the real,
//!   testable business logic -- byte-order-dependent method-name selection
//!   ([`MethodAccessGen::choose_read_name`]/[`MethodAccessGen::choose_write_name`]) and the
//!   block-boundary field-splitting control flow in [`ExportsLegAccessGen`] -- and stubs the
//!   opcode sequence itself via [`FieldForArrDirect::gen_load`], a placeholder in
//!   [`seam_stubs`](crate::pcode::seam_stubs) that performs no real bytecode emission.
//! - `FieldForArrDirect` (`ghidra.pcode.emu.jit.gen.FieldForArrDirect`, a record) and
//!   `JitCodeGenerator::request_field_for_arr_direct` are minimal placeholders added to
//!   [`seam_stubs`](crate::pcode::seam_stubs); see `STUBS.tsv`. Java's `requestFieldForArrDirect`
//!   takes an `Address`; the stub takes the `(space, offset)` pair an `Address` wraps instead,
//!   since building an `Address` requires an owning `Arc<AddressSpace>` this type's callers (bound
//!   by [`ExportsLegAccessGen`]'s already-ported signature) do not have.
//! - `BLOCK_SIZE` mirrors `GenConsts.BLOCK_SIZE`, as in
//!   [`ExportsLegAccessGen`](crate::pcode::emu::jit::gen::access::exports_leg_access_gen).

use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
use crate::pcode::emu::jit::gen::access::exports_leg_access_gen::ExportsLegAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::seam_stubs::{AccessGen, JitCodeGenerator, MethodAccessGen};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::Endian;

/// Mirrors `GenConsts.BLOCK_SIZE` (`SemisparseByteArray.BLOCK_SIZE`).
const BLOCK_SIZE: i64 = 0x1000;

/// The generator for reading and writing plain (non-multi-precision) integers.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.IntAccessGen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntAccessGen {
    /// The big-endian instance.
    ///
    /// Port of the `IntAccessGen.BE` constant.
    Be,
    /// The little-endian instance.
    ///
    /// Port of the `IntAccessGen.LE` constant.
    Le,
}

impl IntAccessGen {
    /// Get the `int` access generator for the given byte order.
    ///
    /// Port of `IntAccessGen.forEndian`.
    pub fn for_endian(endian: Endian) -> Self {
        match endian {
            Endian::Big => IntAccessGen::Be,
            Endian::Little => IntAccessGen::Le,
        }
    }
}

impl MethodAccessGen for IntAccessGen {
    /// Port of `IntAccessGen.BE.chooseReadName`/`IntAccessGen.LE.chooseReadName`.
    fn choose_read_name(&self, size: i32) -> String {
        let name = match self {
            IntAccessGen::Be => match size {
                1 => "readInt1",
                2 => "readIntBE2",
                3 => "readIntBE3",
                4 => "readIntBE4",
                _ => panic!("AssertionError: unsupported int read size {size}"),
            },
            IntAccessGen::Le => match size {
                1 => "readInt1",
                2 => "readIntLE2",
                3 => "readIntLE3",
                4 => "readIntLE4",
                _ => panic!("AssertionError: unsupported int read size {size}"),
            },
        };
        name.to_string()
    }

    /// Port of `IntAccessGen.BE.chooseWriteName`/`IntAccessGen.LE.chooseWriteName`.
    fn choose_write_name(&self, size: i32) -> String {
        let name = match self {
            IntAccessGen::Be => match size {
                1 => "writeInt1",
                2 => "writeIntBE2",
                3 => "writeIntBE3",
                4 => "writeIntBE4",
                _ => panic!("AssertionError: unsupported int write size {size}"),
            },
            IntAccessGen::Le => match size {
                1 => "writeInt1",
                2 => "writeIntLE2",
                3 => "writeIntLE3",
                4 => "writeIntLE4",
                _ => panic!("AssertionError: unsupported int write size {size}"),
            },
        };
        name.to_string()
    }
}

impl AccessGen<IntJitType> for IntAccessGen {}

impl ExportsLegAccessGen for IntAccessGen {
    /// Port of `IntAccessGen.BE.genReadLegToStack`/`IntAccessGen.LE.genReadLegToStack`.
    ///
    /// Preserves the Java control flow -- request the field(s) backing the block(s) the leg spans,
    /// and choose the read method name(s) by size -- but the opcode emission itself
    /// (`Op::invokestatic`, `Op::ior`, ...) is stubbed; see the module docs.
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        space: &AddressSpace,
        block: i64,
        off: i32,
        size: i32,
    ) -> Emitter<Ent<N, TInt>> {
        let blk_field = gen.request_field_for_arr_direct(space, block);
        if off + size <= BLOCK_SIZE as i32 {
            let _name = self.choose_read_name(size);
            let em = blk_field.gen_load(em, local_this, gen);
            return em.recast();
        }
        let nxt_field = gen.request_field_for_arr_direct(space, block + BLOCK_SIZE);
        match self {
            IntAccessGen::Be => {
                let _name_hi = self.choose_read_name(BLOCK_SIZE as i32 - off);
                let _name_lo = self.choose_read_name(off + size - BLOCK_SIZE as i32);
                let em = blk_field.gen_load(em, local_this, gen);
                let em = nxt_field.gen_load(em, local_this, gen);
                em.recast()
            }
            IntAccessGen::Le => {
                let _name_lo = self.choose_read_name(off + size - BLOCK_SIZE as i32);
                let _name_hi = self.choose_read_name(BLOCK_SIZE as i32 - off);
                let em = nxt_field.gen_load(em, local_this, gen);
                let em = blk_field.gen_load(em, local_this, gen);
                em.recast()
            }
        }
    }

    /// Port of `IntAccessGen.BE.genWriteLegFromStack`/`IntAccessGen.LE.genWriteLegFromStack`.
    ///
    /// Preserves the Java control flow -- request the field(s) backing the block(s) the leg spans,
    /// and choose the write method name(s) by size -- but the opcode emission itself
    /// (`Op::invokestatic`, `Op::dup`, `Op::ishl`/`Op::iushr`, ...) is stubbed; see the module
    /// docs.
    fn gen_write_leg_from_stack<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TInt>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        space: &AddressSpace,
        block: i64,
        off: i32,
        size: i32,
    ) -> Emitter<N1> {
        let blk_field = gen.request_field_for_arr_direct(space, block);
        if off + size <= BLOCK_SIZE as i32 {
            let _name = self.choose_write_name(size);
            let em = blk_field.gen_load(em, local_this, gen);
            return em.recast();
        }
        let nxt_field = gen.request_field_for_arr_direct(space, block + BLOCK_SIZE);
        match self {
            IntAccessGen::Be => {
                let _name_hi = self.choose_write_name(BLOCK_SIZE as i32 - off);
                let _name_lo = self.choose_write_name(off + size - BLOCK_SIZE as i32);
                let em = blk_field.gen_load(em, local_this, gen);
                let em = nxt_field.gen_load(em, local_this, gen);
                em.recast()
            }
            IntAccessGen::Le => {
                let _name_lo = self.choose_write_name(off + size - BLOCK_SIZE as i32);
                let _name_hi = self.choose_write_name(BLOCK_SIZE as i32 - off);
                let em = nxt_field.gen_load(em, local_this, gen);
                let em = blk_field.gen_load(em, local_this, gen);
                em.recast()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::MethodVisitor;

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {
        fn request_field_for_arr_direct(
            &self,
            _space: &AddressSpace,
            offset: i64,
        ) -> crate::pcode::seam_stubs::FieldForArrDirect {
            crate::pcode::seam_stubs::FieldForArrDirect { offset }
        }
    }

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_space() -> std::sync::Arc<AddressSpace> {
        use crate::program::model::address::AddressSpaceType;
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn for_endian_matches_java_switch() {
        // Java: forEndian(BIG) -> BE; forEndian(LITTLE) -> LE.
        assert_eq!(IntAccessGen::for_endian(Endian::Big), IntAccessGen::Be);
        assert_eq!(IntAccessGen::for_endian(Endian::Little), IntAccessGen::Le);
    }

    #[test]
    fn choose_read_name_be_matches_java_switch() {
        assert_eq!(IntAccessGen::Be.choose_read_name(1), "readInt1");
        assert_eq!(IntAccessGen::Be.choose_read_name(2), "readIntBE2");
        assert_eq!(IntAccessGen::Be.choose_read_name(3), "readIntBE3");
        assert_eq!(IntAccessGen::Be.choose_read_name(4), "readIntBE4");
    }

    #[test]
    fn choose_read_name_le_matches_java_switch() {
        assert_eq!(IntAccessGen::Le.choose_read_name(1), "readInt1");
        assert_eq!(IntAccessGen::Le.choose_read_name(2), "readIntLE2");
        assert_eq!(IntAccessGen::Le.choose_read_name(3), "readIntLE3");
        assert_eq!(IntAccessGen::Le.choose_read_name(4), "readIntLE4");
    }

    #[test]
    fn choose_write_name_be_matches_java_switch() {
        assert_eq!(IntAccessGen::Be.choose_write_name(1), "writeInt1");
        assert_eq!(IntAccessGen::Be.choose_write_name(2), "writeIntBE2");
        assert_eq!(IntAccessGen::Be.choose_write_name(3), "writeIntBE3");
        assert_eq!(IntAccessGen::Be.choose_write_name(4), "writeIntBE4");
    }

    #[test]
    fn choose_write_name_le_matches_java_switch() {
        assert_eq!(IntAccessGen::Le.choose_write_name(1), "writeInt1");
        assert_eq!(IntAccessGen::Le.choose_write_name(2), "writeIntLE2");
        assert_eq!(IntAccessGen::Le.choose_write_name(3), "writeIntLE3");
        assert_eq!(IntAccessGen::Le.choose_write_name(4), "writeIntLE4");
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn choose_read_name_panics_on_unsupported_size_like_java_default_case() {
        IntAccessGen::Be.choose_read_name(5);
    }

    #[test]
    fn gen_read_leg_to_stack_within_one_block_pushes_int() {
        // Java: off + size <= BLOCK_SIZE takes the single-field branch.
        let gen_impl = IntAccessGen::Be;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let space = make_space();

        let result: Emitter<Ent<Bot, TInt>> =
            gen_impl.gen_read_leg_to_stack(em, &local_this, &code_gen, &space, 0x1000, 4, 4);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_read_leg_to_stack_spanning_blocks_requests_both_fields() {
        // Java: off + size > BLOCK_SIZE takes the two-field branch, splitting across the block
        // boundary.
        let gen_impl = IntAccessGen::Le;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let space = make_space();

        let result: Emitter<Ent<Bot, TInt>> = gen_impl.gen_read_leg_to_stack(
            em,
            &local_this,
            &code_gen,
            &space,
            0x2000,
            0xFFE,
            4,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_leg_from_stack_within_one_block_pops_int() {
        let gen_impl = IntAccessGen::Be;
        let em: Emitter<Ent<Bot, TInt>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let space = make_space();

        let result: Emitter<Bot> =
            gen_impl.gen_write_leg_from_stack(em, &local_this, &code_gen, &space, 0x1000, 4, 4);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_leg_from_stack_spanning_blocks_requests_both_fields() {
        let gen_impl = IntAccessGen::Le;
        let em: Emitter<Ent<Bot, TInt>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let space = make_space();

        let result: Emitter<Bot> = gen_impl.gen_write_leg_from_stack(
            em,
            &local_this,
            &code_gen,
            &space,
            0x2000,
            0xFFE,
            4,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn int_access_gen_extends_method_access_gen_and_access_gen() {
        let gen_impl = IntAccessGen::Be;
        let _as_method_access_gen: &dyn MethodAccessGen = &gen_impl;
        let _as_access_gen: &dyn AccessGen<IntJitType> = &gen_impl;
    }
}
