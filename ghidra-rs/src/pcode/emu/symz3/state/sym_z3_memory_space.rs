//! Port of `ghidra.pcode.emu.symz3.state.SymZ3MemorySpace`.
//!
//! The storage space for memory in a [`SymZ3PcodeExecutorStatePiece`]: a [`SymZ3MemoryMap`]
//! addressed by (possibly symbolic) offsets.
//!
//! # Deviations from Java
//!
//! * **Callbacks.** As for
//!   [`SymZ3RegisterSpace`](crate::pcode::emu::symz3::state::sym_z3_register_space::SymZ3RegisterSpace),
//!   the owning [`SymZ3PcodeExecutorStatePiece`] reports `dataWritten`/`readUninitialized`
//!   around its calls into this space, which cannot refer back to the piece that owns it. The
//!   check Java makes before reporting `readUninitialized` is [`SymZ3MemorySpace::has_value_for`].
//! * **`Context`.** Held, as for the other spaces; see
//!   [`SymZ3UniqueSpace`](crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace).
//! * **Reads mutate.** Java's `SymZ3MemoryMap.load` records a witness behind [`SymZ3Space::get`]'s
//!   non-mutating signature, so the map is kept behind a [`Mutex`].
//!
//! [`SymZ3PcodeExecutorStatePiece`]: crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece

use std::sync::{Arc, Mutex, MutexGuard};

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::emu::symz3::state::sym_z3_space::SymZ3Space;
use crate::pcode::emu::symz3::sym_z3_memory_map::SymZ3MemoryMap;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;

/// The storage space for memory.
///
/// Port of `ghidra.pcode.emu.symz3.state.SymZ3MemorySpace`. See the module docs.
pub struct SymZ3MemorySpace {
    space: Arc<AddressSpace>,
    mmap: Mutex<SymZ3MemoryMap>,
    ctx: Arc<dyn Z3Context>,
}

impl SymZ3MemorySpace {
    /// Construct the storage for the given memory space of the given language.
    ///
    /// Port of `SymZ3MemorySpace(Language, AddressSpace, AbstractSymZ3OffsetPcodeExecutorStatePiece)`;
    /// the piece is not held (see the module docs), and `ctx` stands for Java's per-use contexts.
    pub fn new(language: Arc<dyn Language>, space: Arc<AddressSpace>, ctx: Arc<dyn Z3Context>) -> Self {
        let mmap = SymZ3MemoryMap::new(Box::new(language));
        Self { space, mmap: Mutex::new(mmap), ctx }
    }

    /// The address space this stores.
    pub fn space(&self) -> &Arc<AddressSpace> {
        &self.space
    }

    fn mmap(&self) -> MutexGuard<'_, SymZ3MemoryMap> {
        self.mmap.lock().expect("memory map lock poisoned")
    }

    /// Whether memory at `offset` has a value, i.e., whether Java's `get` would *not* report
    /// `readUninitialized` for it: `mmap.hasValueFor(offset, size)`, including that method's
    /// disregard of `size` (see [`SymZ3MemoryMap::has_value_for`]).
    pub fn has_value_for(&self, offset: &SymValueZ3, size: i32) -> bool {
        self.mmap().has_value_for(offset, size)
    }
}

impl SymZ3Space for SymZ3MemorySpace {
    /// Port of the overridden `get(SymValueZ3, int, Reason, PcodeStateCallbacks)`: a load that
    /// records its witness. The owning piece reports `readUninitialized`; see the module docs.
    fn get<CB: PcodeStateCallbacks>(&self, offset: &SymValueZ3, size: i32, _reason: Reason, cb: &CB) -> SymValueZ3 {
        self.mmap().load(&*self.ctx, offset, size, true, cb)
    }

    /// Port of the overridden `set(SymValueZ3, int, SymValueZ3, PcodeStateCallbacks)`. The owning
    /// piece reports `dataWritten`; see the module docs.
    fn set<CB: PcodeStateCallbacks>(&mut self, offset: &SymValueZ3, size: i32, val: &SymValueZ3, _cb: &CB) {
        let ctx = Arc::clone(&self.ctx);
        self.mmap().store(&*ctx, offset, size, val);
    }

    /// Port of the overridden `getNextEntry(long)`.
    fn get_next_entry(&self, offset: i64) -> Option<(i64, SymValueZ3)> {
        self.mmap().get_next_entry(&*self.ctx, offset)
    }

    /// Port of the overridden `printableSummary()`.
    fn printable_summary(&self) -> String {
        let z3p = Z3InfixPrinter::new(Arc::clone(&self.ctx));
        self.mmap().printable_summary(&*self.ctx, &z3p)
    }

    /// Port of the overridden `streamValuations(Context, Z3InfixPrinter)`.
    fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        self.mmap().stream_valuations(ctx, z3p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::testing::EvalCtx;
    use crate::pcode::exec::pcode_state_callbacks::NONE;

    fn space() -> SymZ3MemorySpace {
        let language = decode_tests::language();
        let ram = Language::get_default_space(language.as_ref());
        SymZ3MemorySpace::new(language as Arc<dyn Language>, ram, Arc::new(EvalCtx))
    }

    fn bv(v: i64, bits: u32) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(&EvalCtx, &*EvalCtx.mk_bv(v, bits))
    }

    #[test]
    fn a_store_reads_back_and_counts_as_initialized() {
        let mut s = space();
        assert!(!s.has_value_for(&bv(0x1000, 32), 2));
        s.set(&bv(0x1000, 32), 2, &bv(0x1234, 16), &NONE);
        assert!(s.has_value_for(&bv(0x1000, 32), 2));
        // The fixture language is big-endian: the bytes are stored most significant first, and
        // reassembled the same way.
        assert_eq!(s.get(&bv(0x1000, 32), 2, Reason::Inspect, &NONE).to_long(&EvalCtx), Some(0x1234));
        assert_eq!(s.get(&bv(0x1001, 32), 1, Reason::Inspect, &NONE).to_long(&EvalCtx), Some(0x34));
    }

    #[test]
    fn an_unstored_byte_loads_as_a_named_symbol() {
        let s = space();
        let loaded = s.get(&bv(0x2000, 32), 1, Reason::Inspect, &NONE);
        let text = loaded.get_bit_vec_expr(&EvalCtx).unwrap().as_expr().to_smt_string();
        assert!(text.starts_with("load_32_8("), "{text}");
    }
}
