//! The generator for reading and writing plain (non-multi-precision) longs.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.LongAccessGen`.
//!
//! # Differences from Java
//!
//! - Java's enum constant bodies (`BE { ... }`, `LE { ... }`) become `match self` arms in each
//!   trait method, since this is a closed Java `enum` -- a trait would reopen a set the Java
//!   source deliberately closed.
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every generic method,
//!   is dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen::IntAccessGen).
//! - Unlike `IntAccessGen`, Java's `LongAccessGen` implements `SimpleAccessGen<TLong,
//!   LongJitType>` directly (not `ExportsLegAccessGen`), so this port implements
//!   [`SimpleAccessGen`] directly too, taking the whole `Varnode` and deriving `block`/`off`/
//!   `size` itself, as the Java `genReadToStack`/`genWriteFromStack` bodies do.
//! - The real JVM-opcode emission (`Op::ldc__i`, `Op::invokestatic`, `Op::lor`, etc., from
//!   `ghidra.pcode.emu.jit.gen.util.Op`) and its `Inv`-chain helpers
//!   (`ghidra.pcode.emu.jit.gen.util.Methods.Inv`) are not yet ported -- see the module docs on
//!   [`IntAccessGen`] for why. This port therefore keeps the real, testable business logic --
//!   byte-order-dependent method-name selection
//!   ([`MethodAccessGen::choose_read_name`]/[`MethodAccessGen::choose_write_name`]) and the
//!   block-boundary field-splitting control flow -- and stubs the opcode sequence itself via
//!   `FieldForArrDirect::gen_load`, a placeholder in
//!   [`seam_stubs`](crate::pcode::seam_stubs) that performs no real bytecode emission.
//! - `BLOCK_SIZE` mirrors `GenConsts.BLOCK_SIZE`, as in [`IntAccessGen`].

use crate::pcode::emu::jit::analysis::jit_type::LongJitType;
use crate::pcode::emu::jit::gen::access::method_access_gen::MethodAccessGen;
use crate::pcode::emu::jit::gen::access::simple_access_gen::SimpleAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TLong, TRef};
use crate::pcode::seam_stubs::{AccessGen, JitCodeGenerator};
use crate::program::model::lang::Endian;
use crate::program::model::pcode::Varnode;

/// Mirrors `GenConsts.BLOCK_SIZE` (`SemisparseByteArray.BLOCK_SIZE`).
const BLOCK_SIZE: i64 = 0x1000;

/// Bytes writer for longs in big- or little-endian order.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.LongAccessGen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongAccessGen {
    /// The big-endian instance.
    ///
    /// Port of the `LongAccessGen.BE` constant.
    Be,
    /// The little-endian instance.
    ///
    /// Port of the `LongAccessGen.LE` constant.
    Le,
}

impl LongAccessGen {
    /// Get the `long` access generator for the given byte order.
    ///
    /// Port of `LongAccessGen.forEndian`.
    pub fn for_endian(endian: Endian) -> Self {
        match endian {
            Endian::Big => LongAccessGen::Be,
            Endian::Little => LongAccessGen::Le,
        }
    }
}

impl MethodAccessGen for LongAccessGen {
    /// Port of `LongAccessGen.BE.chooseReadName`/`LongAccessGen.LE.chooseReadName`.
    fn choose_read_name(&self, size: i32) -> String {
        let name = match self {
            LongAccessGen::Be => match size {
                1 => "readLong1",
                2 => "readLongBE2",
                3 => "readLongBE3",
                4 => "readLongBE4",
                5 => "readLongBE5",
                6 => "readLongBE6",
                7 => "readLongBE7",
                8 => "readLongBE8",
                _ => panic!("AssertionError: unsupported long read size {size}"),
            },
            LongAccessGen::Le => match size {
                1 => "readLong1",
                2 => "readLongLE2",
                3 => "readLongLE3",
                4 => "readLongLE4",
                5 => "readLongLE5",
                6 => "readLongLE6",
                7 => "readLongLE7",
                8 => "readLongLE8",
                _ => panic!("AssertionError: unsupported long read size {size}"),
            },
        };
        name.to_string()
    }

    /// Port of `LongAccessGen.BE.chooseWriteName`/`LongAccessGen.LE.chooseWriteName`.
    fn choose_write_name(&self, size: i32) -> String {
        let name = match self {
            LongAccessGen::Be => match size {
                1 => "writeLong1",
                2 => "writeLongBE2",
                3 => "writeLongBE3",
                4 => "writeLongBE4",
                5 => "writeLongBE5",
                6 => "writeLongBE6",
                7 => "writeLongBE7",
                8 => "writeLongBE8",
                _ => panic!("AssertionError: unsupported long write size {size}"),
            },
            LongAccessGen::Le => match size {
                1 => "writeLong1",
                2 => "writeLongLE2",
                3 => "writeLongLE3",
                4 => "writeLongLE4",
                5 => "writeLongLE5",
                6 => "writeLongLE6",
                7 => "writeLongLE7",
                8 => "writeLongLE8",
                _ => panic!("AssertionError: unsupported long write size {size}"),
            },
        };
        name.to_string()
    }
}

impl AccessGen<LongJitType> for LongAccessGen {}

impl SimpleAccessGen<TLong, LongJitType> for LongAccessGen {
    /// Port of `LongAccessGen.BE.genReadToStack`/`LongAccessGen.LE.genReadToStack`.
    ///
    /// Preserves the Java control flow -- request the field(s) backing the block(s) the varnode
    /// spans, and choose the read method name(s) by size -- but the opcode emission itself
    /// (`Op::invokestatic`, `Op::lshl`, `Op::lor`, ...) is stubbed; see the module docs.
    fn gen_read_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
    ) -> Emitter<Ent<N, TLong>> {
        let offset = vn.get_offset();
        let block = offset / BLOCK_SIZE * BLOCK_SIZE;
        let off = (offset - block) as i32;
        let size = vn.get_size();
        let space = vn.get_address().space();
        let blk_field = gen.request_field_for_arr_direct(space, block);
        if off + size <= BLOCK_SIZE as i32 {
            let _name = self.choose_read_name(size);
            let em = blk_field.gen_load(em, local_this, gen);
            return em.recast();
        }
        let nxt_field = gen.request_field_for_arr_direct(space, block + BLOCK_SIZE);
        match self {
            LongAccessGen::Be => {
                let _name_hi = self.choose_read_name(BLOCK_SIZE as i32 - off);
                let _name_lo = self.choose_read_name(off + size - BLOCK_SIZE as i32);
                let em = blk_field.gen_load(em, local_this, gen);
                let em = nxt_field.gen_load(em, local_this, gen);
                em.recast()
            }
            LongAccessGen::Le => {
                let _name_lo = self.choose_read_name(off + size - BLOCK_SIZE as i32);
                let _name_hi = self.choose_read_name(BLOCK_SIZE as i32 - off);
                let em = nxt_field.gen_load(em, local_this, gen);
                let em = blk_field.gen_load(em, local_this, gen);
                em.recast()
            }
        }
    }

    /// Port of `LongAccessGen.BE.genWriteFromStack`/`LongAccessGen.LE.genWriteFromStack`.
    ///
    /// Preserves the Java control flow -- request the field(s) backing the block(s) the varnode
    /// spans, and choose the write method name(s) by size -- but the opcode emission itself
    /// (`Op::invokestatic`, `Op::dup2__2`, `Op::lushr`, ...) is stubbed; see the module docs.
    fn gen_write_from_stack<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TLong>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
    ) -> Emitter<N1> {
        let offset = vn.get_offset();
        let block = offset / BLOCK_SIZE * BLOCK_SIZE;
        let off = (offset - block) as i32;
        let size = vn.get_size();
        let space = vn.get_address().space();
        let blk_field = gen.request_field_for_arr_direct(space, block);
        if off + size <= BLOCK_SIZE as i32 {
            let _name = self.choose_write_name(size);
            let em = blk_field.gen_load(em, local_this, gen);
            return em.recast();
        }
        let nxt_field = gen.request_field_for_arr_direct(space, block + BLOCK_SIZE);
        match self {
            LongAccessGen::Be => {
                let _name_hi = self.choose_write_name(BLOCK_SIZE as i32 - off);
                let _name_lo = self.choose_write_name(off + size - BLOCK_SIZE as i32);
                let em = blk_field.gen_load(em, local_this, gen);
                let em = nxt_field.gen_load(em, local_this, gen);
                em.recast()
            }
            LongAccessGen::Le => {
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
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

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

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    #[test]
    fn for_endian_matches_java_switch() {
        // Java: forEndian(BIG) -> BE; forEndian(LITTLE) -> LE.
        assert_eq!(LongAccessGen::for_endian(Endian::Big), LongAccessGen::Be);
        assert_eq!(LongAccessGen::for_endian(Endian::Little), LongAccessGen::Le);
    }

    #[test]
    fn choose_read_name_be_matches_java_switch() {
        assert_eq!(LongAccessGen::Be.choose_read_name(1), "readLong1");
        assert_eq!(LongAccessGen::Be.choose_read_name(2), "readLongBE2");
        assert_eq!(LongAccessGen::Be.choose_read_name(3), "readLongBE3");
        assert_eq!(LongAccessGen::Be.choose_read_name(4), "readLongBE4");
        assert_eq!(LongAccessGen::Be.choose_read_name(5), "readLongBE5");
        assert_eq!(LongAccessGen::Be.choose_read_name(6), "readLongBE6");
        assert_eq!(LongAccessGen::Be.choose_read_name(7), "readLongBE7");
        assert_eq!(LongAccessGen::Be.choose_read_name(8), "readLongBE8");
    }

    #[test]
    fn choose_read_name_le_matches_java_switch() {
        assert_eq!(LongAccessGen::Le.choose_read_name(1), "readLong1");
        assert_eq!(LongAccessGen::Le.choose_read_name(2), "readLongLE2");
        assert_eq!(LongAccessGen::Le.choose_read_name(3), "readLongLE3");
        assert_eq!(LongAccessGen::Le.choose_read_name(4), "readLongLE4");
        assert_eq!(LongAccessGen::Le.choose_read_name(5), "readLongLE5");
        assert_eq!(LongAccessGen::Le.choose_read_name(6), "readLongLE6");
        assert_eq!(LongAccessGen::Le.choose_read_name(7), "readLongLE7");
        assert_eq!(LongAccessGen::Le.choose_read_name(8), "readLongLE8");
    }

    #[test]
    fn choose_write_name_be_matches_java_switch() {
        assert_eq!(LongAccessGen::Be.choose_write_name(1), "writeLong1");
        assert_eq!(LongAccessGen::Be.choose_write_name(2), "writeLongBE2");
        assert_eq!(LongAccessGen::Be.choose_write_name(8), "writeLongBE8");
    }

    #[test]
    fn choose_write_name_le_matches_java_switch() {
        assert_eq!(LongAccessGen::Le.choose_write_name(1), "writeLong1");
        assert_eq!(LongAccessGen::Le.choose_write_name(2), "writeLongLE2");
        assert_eq!(LongAccessGen::Le.choose_write_name(8), "writeLongLE8");
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn choose_read_name_panics_on_unsupported_size_like_java_default_case() {
        LongAccessGen::Be.choose_read_name(9);
    }

    #[test]
    fn gen_read_to_stack_within_one_block_pushes_long() {
        // Java: off + size <= BLOCK_SIZE takes the single-field branch.
        let gen_impl = LongAccessGen::Be;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode(0x1000, 8);

        let result: Emitter<Ent<Bot, TLong>> =
            gen_impl.gen_read_to_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_read_to_stack_spanning_blocks_requests_both_fields() {
        // Java: off + size > BLOCK_SIZE takes the two-field branch, splitting across the block
        // boundary.
        let gen_impl = LongAccessGen::Le;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode(0x2FFE, 8);

        let result: Emitter<Ent<Bot, TLong>> =
            gen_impl.gen_read_to_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_from_stack_within_one_block_pops_long() {
        let gen_impl = LongAccessGen::Be;
        let em: Emitter<Ent<Bot, TLong>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode(0x1000, 8);

        let result: Emitter<Bot> =
            gen_impl.gen_write_from_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_from_stack_spanning_blocks_requests_both_fields() {
        let gen_impl = LongAccessGen::Le;
        let em: Emitter<Ent<Bot, TLong>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode(0x2FFE, 8);

        let result: Emitter<Bot> =
            gen_impl.gen_write_from_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn long_access_gen_extends_method_access_gen_and_access_gen() {
        let gen_impl = LongAccessGen::Be;
        let _as_method_access_gen: &dyn MethodAccessGen = &gen_impl;
        let _as_access_gen: &dyn AccessGen<LongJitType> = &gen_impl;
    }
}
