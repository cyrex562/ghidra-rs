//! An allocated JVM local.
//!
//! Port of `ghidra.pcode.emu.jit.alloc.JvmLocal`.
//!
//! # Differences from Java
//!
//! Java's record is `JvmLocal<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>(Local<T>
//! local, JT type, Varnode vn, SimpleOpnd<T, JT> opnd)`. Two of its four fields are not carried
//! here:
//!
//! - `opnd`, built by the unported static factory `SimpleOpnd.of(JT, Local<T>)`, which dispatches
//!   on the p-code type to one of `IntLocalOpnd`/`LongLocalOpnd`/`FloatLocalOpnd`/
//!   `DoubleLocalOpnd`/`IntReadOnlyLocalOpnd`. [`SimpleOpnd`](crate::pcode::emu::jit::gen::opnd::simple_opnd::SimpleOpnd)
//!   itself is ported, but none of those five implementors are, so there is no way to construct a
//!   real value of it yet.
//! - `local`, which only matters paired with the `opnd` built from it; carrying it alone would add
//!   a `T` type parameter with nothing to do.
//!
//! Consequently `type` and `vn` -- the two members [`gen_birth_code`](JvmLocal::gen_birth_code),
//! [`gen_retire_code`](JvmLocal::gen_retire_code), and
//! [`max_prim_addr`](JvmLocal::max_prim_addr) actually read -- are what remain, with `type` erased
//! over Java's `<T, JT>` pair to [`AnySimpleJitType`], per the existential convention documented
//! in [`jit_type`](crate::pcode::emu::jit::analysis::jit_type).
//!
//! For the same reason, `JvmLocal.name()` (`local.name()`) and `JvmLocal.castOf` (an
//! unchecked-cast workaround for recovering `<TT, TJT>` after a switch over sealed `JT`
//! subtypes, meaningless once `T`/`JT` are erased to a single runtime tag) are not ported.
//!
//! `genLoadToStack` and `genStoreFromStack` are also not ported: both center on
//! `Opnd.convert`, and `Opnd` (`ghidra.pcode.emu.jit.gen.opnd.Opnd`, the static conversion
//! helper -- distinct from `SimpleOpnd`) is not ported at all yet, not even far enough to stub a
//! usable `convert`.
//!
//! `genBirthCode`/`genRetireCode` keep Java's real control flow -- read the varnode from the
//! state into the local, and write the local back into the state, respectively -- via
//! [`gen_read_val_direct_to_stack`]/[`gen_write_val_direct_from_stack`]. The operand half of each
//! (`opnd.writeDirect`/`opnd.read`, which is what makes the local itself change) is stubbed via
//! [`Emitter::recast`] until a concrete `SimpleOpnd` implementor exists to hold as `opnd`.

use crate::pcode::emu::jit::analysis::jit_type::{AnySimpleJitType, JitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::emu::jit::gen::var::var_gen::{
    gen_read_val_direct_to_stack, gen_write_val_direct_from_stack,
};
use crate::pcode::seam_stubs::JitCodeGenerator;
use crate::program::model::address::Address;
use crate::program::model::pcode::Varnode;

/// An allocated JVM local.
///
/// Port of `ghidra.pcode.emu.jit.alloc.JvmLocal<T, JT>`. See the [module docs](self) for which
/// members this carries and why.
#[derive(Debug, Clone)]
pub struct JvmLocal {
    /// The p-code type of this local, erased over Java's `<T, JT>` pair.
    pub type_: AnySimpleJitType,
    /// The varnode whose value this local holds.
    pub vn: Varnode,
}

impl JvmLocal {
    /// Create a [`JvmLocal`] for the given type and varnode.
    ///
    /// Port of `JvmLocal.of(Local, JT, Varnode)`, minus the `Local`/`SimpleOpnd` members this
    /// port does not carry (see the [module docs](self)).
    pub fn of(type_: AnySimpleJitType, vn: Varnode) -> Self {
        Self { type_, vn }
    }

    /// Emit bytecode to bring this varnode into scope, copying its value from the state into the
    /// local variable.
    ///
    /// Port of `JvmLocal.genBirthCode`. See the [module docs](self) on what is stubbed.
    pub fn gen_birth_code<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
    ) -> Emitter<N> {
        match self.type_ {
            AnySimpleJitType::Int(t) => {
                gen_read_val_direct_to_stack(em, local_this, gen, t, &self.vn).recast()
            }
            AnySimpleJitType::Long(t) => {
                gen_read_val_direct_to_stack(em, local_this, gen, t, &self.vn).recast()
            }
            AnySimpleJitType::Float(_) | AnySimpleJitType::Double(_) => {
                unimplemented!("JvmLocal::gen_birth_code: no SimpleAccessGen for float types yet")
            }
        }
    }

    /// Emit bytecode to take this varnode out of scope, copying its value from the local variable
    /// into the state.
    ///
    /// Port of `JvmLocal.genRetireCode`. See the [module docs](self) on what is stubbed.
    pub fn gen_retire_code<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
    ) -> Emitter<N> {
        match self.type_ {
            AnySimpleJitType::Int(t) => {
                gen_write_val_direct_from_stack(em.recast(), local_this, gen, t, &self.vn)
            }
            AnySimpleJitType::Long(t) => {
                gen_write_val_direct_from_stack(em.recast(), local_this, gen, t, &self.vn)
            }
            AnySimpleJitType::Float(_) | AnySimpleJitType::Double(_) => {
                unimplemented!("JvmLocal::gen_retire_code: no SimpleAccessGen for float types yet")
            }
        }
    }

    /// The maximum address that would be occupied by the full primitive type.
    ///
    /// Port of `JvmLocal.maxPrimAddr()`.
    pub fn max_prim_addr(&self) -> Address {
        self.vn
            .get_address()
            .add(self.type_.ext_simple().size() as i64 - 1)
            .expect("JvmLocal::max_prim_addr: address overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, SimpleJitType};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn vn(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Varnode::new(Address::new(space, offset), size)
    }

    #[test]
    fn of_carries_the_type_and_varnode() {
        // Java: `new JvmLocal<>(local, type, vn, opnd)` fields `type()`/`vn()`.
        let local = JvmLocal::of(IntJitType::I4.erase_simple(), vn(0x1000, 4));
        assert_eq!(local.type_, AnySimpleJitType::Int(IntJitType::I4));
        assert_eq!(local.vn.get_offset(), 0x1000);
        assert_eq!(local.vn.get_size(), 4);
    }

    #[test]
    fn max_prim_addr_is_the_last_byte_of_the_full_primitive() {
        // Java: `vn.getAddress().add(type.ext().size() - 1)`. I4 extends to itself (size 4), so
        // a varnode at 0x1000 occupies [0x1000, 0x1003].
        let local = JvmLocal::of(IntJitType::I4.erase_simple(), vn(0x1000, 4));
        assert_eq!(local.max_prim_addr().offset(), 0x1003);
    }

    #[test]
    fn max_prim_addr_uses_the_extended_type_not_the_varnode_size() {
        // A 1-byte varnode typed I1 still extends to a 4-byte int slot for genBirthCode/
        // genRetireCode purposes, so maxPrimAddr must reflect the extended size, not vn.getSize().
        let local = JvmLocal::of(IntJitType::I1.erase_simple(), vn(0x2000, 1));
        let ext_size = IntJitType::I1.ext_simple().size() as i64;
        assert_eq!(local.max_prim_addr().offset(), 0x2000 + ext_size - 1);
    }
}
