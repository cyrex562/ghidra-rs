//! Port of `ghidra.pcode.emu.symz3.SymZ3MemoryMap`.
//!
//! A class that can store `SymValueZ3`s in memory.
//!
//! **NOTE: DELIBERATELY NO KNOWLEDGE OF SPACES, Languages, or "get" and "set".**
//!
//! The core idea is that quite often the code being summarized will load from memory arbitrary
//! values. Those values should exist as a unit: e.g., if the user loads 64 unknown bits from an
//! address `0xdeadbeef`, the name of those bits should be `MEM[0xdeadbeef]:64`, instead of, for
//! example, a concat of each unknown byte. However, the 64-bit value might later be sliced and
//! diced: if a 64-bit symbolic value `RBX` is stored into `MEM[0xdeadbeef]` and then later an
//! interior byte is loaded, that should be detected. Of course, loading `MEM[RCX]` when `RCX`
//! isn't known keeps the value symbolic.
//!
//! In terms of storage, there were two options: (1) always store byte-sized values (so a 64-bit
//! store creates 8 entries), or (2) store arbitrary sizes (fewer entries, but tricky when writes
//! partially overlap prior writes). Java went with option (1) -- the "byte model" -- and this port
//! follows suit; see the `USE_BYTE_MODEL` discussion below.
//!
//! # Deviations from Java
//!
//! * Java's `static final boolean USE_BYTE_MODEL = true` is a compile-time constant. Every branch
//!   in `load`/`store` guarded by `!USE_BYTE_MODEL` is therefore genuinely unreachable dead code
//!   in the original -- not merely unused, but structurally impossible to hit at runtime. This
//!   port implements only the reachable byte-model branches; the dead `!USE_BYTE_MODEL` branches
//!   (a second, size-keyed storage scheme built on a Z3 uninterpreted function
//!   `FuncDecl<BitVecSort> buildLoad(...)`) are not modeled, matching this crate's established
//!   treatment of other unreachable Java branches (e.g.
//!   [`PcodeContext`](crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext)'s
//!   `op == null` branch).
//! * The reachable byte-model branch of `load` *does* use a genuine Z3 uninterpreted function
//!   (`buildLoad(ctx, addressSize, 8)` applied via `ctx.mkApp`) whenever a requested byte has
//!   never been stored. The [`crate::feature::seam_stubs::Z3Context`] seam this crate uses has no
//!   function-declaration/application primitives (only expression constructors) -- the same gap
//!   [`SymZ3RegisterMap`](crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap)
//!   sidesteps by materializing unknown registers as named symbolic constants via `mk_bv_const`.
//!   This port makes the identical substitution: [`build_load`] returns just the deterministic
//!   function *name* Java's `FuncDecl` would have been created with, and [`SymZ3MemoryMap::load`]
//!   combines it with the specific unstored byte address's own rendering to synthesize a
//!   uniquely-named symbolic bit-vector constant -- preserving the same "syntactically identical
//!   term for identical inputs, distinct term for distinct inputs" property the real uninterpreted
//!   function application would have.
//! * Every Z3-dependent method here takes the context explicitly as `&dyn Z3Context`, rather than
//!   Java's own `try (Context ctx = new Context())`, matching
//!   [`SymZ3RegisterMap`](crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap) (the
//!   most direct sibling in this same package, itself not a
//!   [`SymZ3Space`](crate::pcode::emu::symz3::state::sym_z3_space::SymZ3Space) trait implementor
//!   and so free to add the parameter everywhere, unlike, e.g.,
//!   [`SymZ3UniqueSpace`](crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace)).
//! * `.simplify()` calls on rendered Z3 expressions (in `printableSummary`/`valuationForMemval`/
//!   `valuationForWitness`/`load`/`store`'s `byteAddress.simplify()`) are not modeled: there is no
//!   real Z3 engine behind the seam to simplify anything with, and no `simplify` method on the
//!   `BitVecExpr` seam trait. The raw (unsimplified) expression is rendered/used instead, matching
//!   the same substitution `SymZ3RegisterMap` already makes for the same reason.
//! * `getNextEntry(long)` rebuilds its `byOffset` cache using `new TreeMap<>(Long::compareUnsigned)`
//!   -- an *unsigned* `Long` comparator, unlike, e.g.,
//!   [`SymZ3RegisterMap::get_next_entry`](crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap::get_next_entry)'s
//!   plain (signed) `TreeMap<>`. Rust's `BTreeMap` has no custom-comparator support, so this port
//!   keys the cache by `u64` instead of `i64` (a bit-preserving cast both ways), whose `Ord` is
//!   exactly unsigned comparison -- reproducing `Long.compareUnsigned`'s ordering exactly.
//! * `load`/`store` accept a `PcodeStateCallbacks cb` parameter that neither method's body ever
//!   actually calls a method on -- a genuine, preserved quirk of the Java source (shared, in fact,
//!   with [`SymZ3UniqueSpace`](crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace)'s
//!   own `set`/`get` overrides). The parameter is kept, unused, for signature parity.
//! * `valuationForMemval`'s/`printableSummary`'s defensive `if (vv == null)` branch (`vv` being a
//!   `Map.get` result that Java's own `store()` never actually stores as `null`) has no Rust
//!   equivalent to model: [`SymZ3MemoryMap::memvals`] is `HashMap<String, SymValueZ3>`, whose
//!   values can never be absent-but-present the way a Java `Map` entry mapped to `null` can. The
//!   inner `if (v == null)` check -- `vv.getBitVecExpr(ctx)` returning `null`, genuinely reachable
//!   for a bool-only `SymValueZ3` -- *is* modeled.
//! * `printableSummary()` and `valuationForMemval`/`valuationForWitness`/`streamValuations`
//!   implement near-identical "render one memory cell" logic *twice*, with slightly different
//!   message text (`"MEM ... is null"` vs `"MEM ..."`) and, for witness deduplication, two
//!   different collection types (a local `ArrayList<BitVecExpr>` with linear-scan `.contains()` in
//!   `printableSummary`, vs. a `HashSet<BitVecExpr>` in `streamValuations`/`valuationForWitness`).
//!   This is preserved faithfully as genuine, if redundant, duplication rather than deduplicated
//!   in this port -- both methods are ported with their own separate logic and their own
//!   dedup-collection shape. Java's `Set<BitVecExpr>`/`List<BitVecExpr>` (relying on Z3's AST-node
//!   structural `equals`/`hashCode`) becomes a `HashSet<String>`/`Vec<String>` here, keyed by each
//!   witness address's own serialized `bit_vec_expr_string` -- the same "identity via serialized
//!   form" already used throughout this file to key [`SymZ3MemoryMap::memvals`] itself.
//! * `hasValueFor(SymValueZ3, int)` is preserved *exactly* as Java wrote it, including what
//!   appears to be a real, acknowledged bug -- its `size` parameter is accepted but never
//!   actually consulted: see [`SymZ3MemoryMap::has_value_for`]'s own docs.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::feature::seam_stubs::{BitVecExpr, Z3Context};
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::emu::symz3::lib::z3_memory_witness::{Z3MemoryWitness, WitnessType};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::lang::language::Language;

/// Java: the static `buildLoad(Context, int, int)`. See the module docs for why this returns just
/// the deterministic function *name* a real `FuncDecl` would have been created with, rather than a
/// genuine function declaration.
pub fn build_load(address_size: i32, data_size: i32) -> String {
    format!("load_{address_size}_{data_size}")
}

/// A class that can store `SymValueZ3`s in memory.
///
/// Port of `ghidra.pcode.emu.symz3.SymZ3MemoryMap`. See the module docs for this port's
/// deviations, in particular around the compile-time-dead `USE_BYTE_MODEL` branches and the
/// `Z3Context` seam's lack of uninterpreted-function support.
pub struct SymZ3MemoryMap {
    /// `// TODO ... encapsulate traversal of memvals so it can become private` (preserved from
    /// Java). Keyed by each stored byte's own serialized bit-vector-expression address (the same
    /// `"V:..."` shape [`SymValueZ3::bit_vec_expr_string`] itself carries).
    pub memvals: HashMap<String, SymValueZ3>,
    by_offset: Option<BTreeMap<u64, SymValueZ3>>,
    witnesses: Vec<Z3MemoryWitness>,
    language: Box<dyn Language>,
}

impl SymZ3MemoryMap {
    /// Port of `SymZ3MemoryMap(Language)`.
    pub fn new(language: Box<dyn Language>) -> Self {
        Self { memvals: HashMap::new(), by_offset: None, witnesses: Vec::new(), language }
    }

    /// Port of the protected `valuationForMemval(Context, Z3InfixPrinter, Entry<String,
    /// SymValueZ3>)`. Takes the entry's key/value as separate parameters rather than a tuple,
    /// standing in for Java's `Map.Entry`.
    pub fn valuation_for_memval(
        &self,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
        address: &str,
        vv: &SymValueZ3,
    ) -> (String, String) {
        let address_expr = SymValueZ3::deserialize_bit_vec_expr(ctx, address)
            .expect("Java: unchecked deserializeBitVecExpr(ctx, address) on a memvals key");
        match vv.get_bit_vec_expr(ctx) {
            None => (
                format!("MEM {}", z3p.infix_with_brackets(address_expr.as_expr())),
                format!("null (?) {vv}"),
            ),
            Some(v) => {
                // Java: `v = (BitVecExpr) v.simplify();` -- not modeled; see module docs.
                let bit_size = v.sort_size();
                (
                    format!("MEM {}:{}", z3p.infix_with_brackets(address_expr.as_expr()), bit_size),
                    z3p.infix_unsigned(v.as_expr()),
                )
            }
        }
    }

    /// Port of the protected `valuationForWitness(Context, Z3InfixPrinter, Set<BitVecExpr>,
    /// Z3MemoryWitness)`. `reported` is keyed by each witness address's own serialized
    /// bit-vector-expression string; see the module docs.
    pub fn valuation_for_witness(
        &mut self,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
        reported: &mut HashSet<String>,
        w: &Z3MemoryWitness,
    ) -> Option<(String, String)> {
        let address_expr = w
            .address
            .get_bit_vec_expr(ctx)
            .expect("Java: unchecked getBitVecExpr(ctx) on a witness address");
        let key = w.address.bit_vec_expr_string.clone().unwrap_or_default();
        if !reported.insert(key) {
            return None;
        }

        let cb = crate::pcode::exec::pcode_state_callbacks::NONE;
        let vv = self.load(ctx, &w.address, w.bytes_moved, false, &cb);
        match vv.get_bit_vec_expr(ctx) {
            None => Some((
                format!("MEM {}", z3p.infix_with_brackets(address_expr.as_expr())),
                "null (?)".to_string(),
            )),
            Some(v) => {
                // Java: `v = (BitVecExpr) vexpr.simplify();` -- not modeled; see module docs.
                let bit_size = v.sort_size();
                Some((
                    format!("MEM {}:{}", z3p.infix_with_brackets(address_expr.as_expr()), bit_size),
                    z3p.infix_unsigned(v.as_expr()),
                ))
            }
        }
    }

    /// Port of `printableSummary()`. Takes `ctx`/`z3p` explicitly; see the module docs. Note this
    /// duplicates (with slightly different message text) rather than reuses
    /// [`Self::valuation_for_memval`]/[`Self::valuation_for_witness`], matching Java; see the
    /// module docs.
    pub fn printable_summary(&mut self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> String {
        let mut result = String::new();

        let memvals: Vec<(String, SymValueZ3)> =
            self.memvals.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (address, vv) in &memvals {
            let address_expr = SymValueZ3::deserialize_bit_vec_expr(ctx, address)
                .expect("Java: unchecked deserializeBitVecExpr(ctx, address) on a memvals key");
            match vv.get_bit_vec_expr(ctx) {
                None => {
                    result.push_str(&format!(
                        "MEM {} is null (?){vv}\n",
                        z3p.infix_with_brackets(address_expr.as_expr())
                    ));
                }
                Some(v) => {
                    // Java: `v = (BitVecExpr) v.simplify();` -- not modeled; see module docs.
                    let bit_size = v.sort_size();
                    result.push_str(&format!(
                        "MEM {}:{} = {}\n",
                        z3p.infix_with_brackets(address_expr.as_expr()),
                        bit_size,
                        z3p.infix_unsigned(v.as_expr())
                    ));
                }
            }
        }

        // Java: `ArrayList<BitVecExpr> reported` here (linear-scan `.contains()`), distinct from
        // `streamValuations`'s `HashSet<BitVecExpr>`; see the module docs.
        let mut reported: Vec<String> = Vec::new();
        let witnesses = self.witnesses.clone();
        for w in &witnesses {
            let address_expr = w
                .address
                .get_bit_vec_expr(ctx)
                .expect("Java: unchecked getBitVecExpr(ctx) on a witness address");
            let key = w.address.bit_vec_expr_string.clone().unwrap_or_default();
            if reported.contains(&key) {
                continue;
            }
            reported.push(key);

            let cb = crate::pcode::exec::pcode_state_callbacks::NONE;
            let value = self.load(ctx, &w.address, w.bytes_moved, false, &cb);
            match value.get_bit_vec_expr(ctx) {
                None => {
                    result.push_str(&format!(
                        "MEM {} is null (?)\n",
                        z3p.infix_with_brackets(address_expr.as_expr())
                    ));
                }
                Some(v) => {
                    // Java: `BitVecExpr v = (BitVecExpr) vexpr.simplify();` -- not modeled.
                    let bit_size = v.sort_size();
                    result.push_str(&format!(
                        "MEM {}:{} = {}\n",
                        z3p.infix_with_brackets(address_expr.as_expr()),
                        bit_size,
                        z3p.infix_unsigned(v.as_expr())
                    ));
                }
            }
        }

        result
    }

    /// Port of `streamValuations(Context, Z3InfixPrinter)`. Returns a `Vec` rather than a lazy
    /// stream; see
    /// [`SymZ3Space::stream_valuations`](crate::pcode::emu::symz3::state::sym_z3_space::SymZ3Space::stream_valuations)'s
    /// docs for why this crate makes the same substitution elsewhere.
    pub fn stream_valuations(&mut self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        let mut result: Vec<(String, String)> = self
            .memvals
            .iter()
            .map(|(address, vv)| self.valuation_for_memval(ctx, z3p, address, vv))
            .collect();

        let mut reported = HashSet::new();
        let witnesses = self.witnesses.clone();
        for w in &witnesses {
            if let Some(pair) = self.valuation_for_witness(ctx, z3p, &mut reported, w) {
                result.push(pair);
            }
        }
        result
    }

    /// Port of `load(SymValueZ3, int, boolean, PcodeStateCallbacks)`. `cb` is unused; see the
    /// module docs.
    ///
    /// # Panics
    ///
    /// If `size <= 0`: Java's `new SymValueZ3(ctx, result)` with `result == null` (no pieces ever
    /// assembled) would throw a `NullPointerException` deep inside `serialize`; this port panics
    /// explicitly instead, at the same "there is nothing to build a value from" point. No real
    /// caller in this codebase invokes `load` with a non-positive size.
    pub fn load<CB: PcodeStateCallbacks>(
        &mut self,
        ctx: &dyn Z3Context,
        offset: &SymValueZ3,
        size: i32,
        add_witness: bool,
        _cb: &CB,
    ) -> SymValueZ3 {
        if add_witness {
            self.witnesses.push(Z3MemoryWitness::new(offset.clone(), size, WitnessType::Load));
        }

        let address =
            offset.get_bit_vec_expr(ctx).expect("Java: unchecked getBitVecExpr(ctx) on the load offset");
        let address_size = address.sort_size();

        let one = ctx.mk_bv(1, address_size);
        let mut result_pieces: Vec<Box<dyn BitVecExpr>> = Vec::new();
        let mut byte_address = address;
        for byte_offset in 0..size {
            if byte_offset > 0 {
                byte_address = ctx.mk_bvadd(&*byte_address, &*one);
            }
            // Java: `byteAddress = (BitVecExpr) byteAddress.simplify();` -- not modeled.
            let byte_address_as_string = SymValueZ3::serialize_bit_vec(ctx, &*byte_address);

            if let Some(stored) = self.memvals.get(&byte_address_as_string) {
                let piece = stored
                    .get_bit_vec_expr(ctx)
                    .expect("Java: unchecked getBitVecExpr(ctx) on a stored memvals entry");
                result_pieces.push(piece);
            } else {
                // Java builds and applies a genuine Z3 uninterpreted function here; see
                // `build_load`'s and this module's docs for why this port synthesizes a
                // deterministically-named symbolic constant instead.
                let name =
                    format!("{}({})", build_load(address_size as i32, 8), byte_address.as_expr().to_smt_string());
                result_pieces.push(ctx.mk_bv_const(&name, 8));
            }
        }

        if !self.language.is_big_endian() {
            result_pieces.reverse();
        }

        let mut pieces = result_pieces.into_iter();
        let mut result: Box<dyn BitVecExpr> = pieces
            .next()
            .expect("Java: `new SymValueZ3(ctx, result)` with result == null throws NPE when size <= 0");
        for piece in pieces {
            result = ctx.mk_concat(&*result, &*piece);
        }

        SymValueZ3::from_bit_vec(ctx, &*result)
    }

    /// Port of `store(SymValueZ3, int, SymValueZ3)`.
    pub fn store(&mut self, ctx: &dyn Z3Context, offset: &SymValueZ3, size: i32, val: &SymValueZ3) {
        self.witnesses.push(Z3MemoryWitness::new(offset.clone(), size, WitnessType::Store));

        let bval =
            val.get_bit_vec_expr(ctx).expect("Java: unchecked getBitVecExpr(ctx) on the stored value");
        let address =
            offset.get_bit_vec_expr(ctx).expect("Java: unchecked getBitVecExpr(ctx) on the store offset");
        // Java: `assert bval.getSortSize() == size * 8;` -- a Java `assert` statement, compiled
        // out of production builds by default; modeled via `debug_assert_eq!` for the same reason
        // established elsewhere in this crate (e.g.
        // `ConditionContext`(crate::feature::lisa::pcode::contexts::condition_context::ConditionContext)).
        debug_assert_eq!(
            bval.sort_size(),
            (size * 8) as u32,
            "Java: `assert bval.getSortSize() == size * 8;`"
        );

        let one = ctx.mk_bv(1, address.sort_size());
        let mut byte_address = address;
        for byte_offset in 0..size {
            if byte_offset > 0 {
                byte_address = ctx.mk_bvadd(&*byte_address, &*one);
            }
            // Java: `byteAddress = (BitVecExpr) byteAddress.simplify();` -- not modeled.
            let byte_address_as_string = SymValueZ3::serialize_bit_vec(ctx, &*byte_address);

            let bit_size = size * 8;
            let (high, low) = if self.language.is_big_endian() {
                (bit_size - byte_offset * 8 - 1, bit_size - (byte_offset + 1) * 8)
            } else {
                (byte_offset * 8 + 7, byte_offset * 8)
            };
            let val_portion = ctx.mk_extract(high as u32, low as u32, &*bval);
            self.memvals.insert(byte_address_as_string, SymValueZ3::from_bit_vec(ctx, &*val_portion));
            self.by_offset = None;
        }
    }

    /// Port of `hasValueFor(SymValueZ3, int)`.
    ///
    /// **Preserved Java quirk/bug**: unlike [`Self::load`], this does *not* iterate the per-byte
    /// sub-addresses `offset` combined with `size` would actually touch -- it only checks whether
    /// `offset`'s own *unmodified* serialized bit-vector string happens to already be a key in
    /// [`Self::memvals`]. Because [`Self::store`]'s very first iteration (`byte_offset == 0`)
    /// always writes exactly that same unmodified address as its key, `has_value_for(offset,
    /// size)` reports `true` after *any* [`Self::store`] call at that `offset` -- but the `size`
    /// argument passed here is never actually consulted (it is a dead parameter, kept only for
    /// signature parity), so it cannot distinguish "one byte is present at `offset`" from "`size`
    /// contiguous bytes are present starting at `offset`". Asking `has_value_for(offset, 1_000)`
    /// right after storing a single byte at `offset` still reports `true`, even though nowhere
    /// near 1,000 bytes exist there. Java's own source acknowledges this is unfinished: `// TODO
    /// need to think about the size`.
    pub fn has_value_for(&self, offset: &SymValueZ3, _size: i32) -> bool {
        match offset.bit_vec_expr_string.as_deref() {
            Some(key) => self.memvals.contains_key(key),
            None => false,
        }
    }

    /// Port of `getNextEntry(long)`. Takes `ctx` explicitly; see the module docs. Keys the cache
    /// by `u64` rather than `i64` to reproduce Java's `Long.compareUnsigned` ordering; see the
    /// module docs.
    pub fn get_next_entry(&mut self, ctx: &dyn Z3Context, offset: i64) -> Option<(i64, SymValueZ3)> {
        if self.by_offset.is_none() {
            let mut map = BTreeMap::new();
            for (key, val) in self.memvals.iter() {
                if let Some(bv_off) = SymValueZ3::deserialize_bit_vec_expr(ctx, key) {
                    if BitVecExpr::is_numeral(&*bv_off) {
                        if let Some(long_val) = bv_off.to_long() {
                            map.insert(long_val as u64, val.clone());
                        }
                    }
                }
            }
            self.by_offset = Some(map);
        }
        self.by_offset
            .as_ref()
            .unwrap()
            .range((offset as u64)..)
            .next()
            .map(|(k, v)| (*k as i64, v.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{BoolExpr, Expr};
    use crate::pcode::exec::pcode_state_callbacks::NONE;
    use std::any::Any;

    /// An all-ones mask covering the low `width` bits, used by [`MockCtx`]'s constant-folding
    /// `mk_extract`/`mk_concat` to mimic Z3's real (eager, no-`.simplify()`-needed) numeral
    /// constant folding.
    fn mask_for_width(width: u32) -> u64 {
        if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        }
    }

    /// A bit-vector expression carrying its SMT-LIB2 text, size, and (optionally) a numeral
    /// value, mirroring this module family's other `Bv` test doubles (see, e.g.,
    /// `sym_z3_register_map`'s and `sym_z3_unique_space`'s own tests).
    #[derive(Clone)]
    struct Bv {
        smt: String,
        size: u32,
        numeral: Option<i64>,
    }

    impl Expr for Bv {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl BitVecExpr for Bv {
        fn as_expr(&self) -> &dyn Expr {
            self
        }
        fn sort_size(&self) -> u32 {
            self.size
        }
        fn is_numeral(&self) -> bool {
            self.numeral.is_some()
        }
        fn to_big_integer(&self) -> Option<i128> {
            self.numeral.map(|v| v as i128)
        }
        fn to_long(&self) -> Option<i64> {
            self.numeral
        }
    }

    #[derive(Clone)]
    struct Bl {
        smt: String,
        arg: Option<Bv>,
    }

    impl Expr for Bl {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl BoolExpr for Bl {
        fn as_expr(&self) -> &dyn Expr {
            self
        }
        fn bit_vec_arg(&self, index: usize) -> Option<Box<dyn BitVecExpr>> {
            match (index, &self.arg) {
                (0, Some(bv)) => Some(Box::new(bv.clone())),
                _ => None,
            }
        }
    }

    /// A `Z3Context` test double that builds/parses SMT-LIB2-ish text instead of calling a real
    /// solver, following the same convention as this module family's other `MockCtx`es. Encodes a
    /// numeral marker so `deserialize`d round-trips preserve `is_numeral`/`to_long`.
    struct MockCtx;

    impl MockCtx {
        fn bv(&self, smt: String, size: u32, numeral: Option<i64>) -> Box<dyn BitVecExpr> {
            Box::new(Bv { smt, size, numeral })
        }
    }

    impl Z3Context for MockCtx {
        fn smt_lib_for_bit_vec(&self, b: &dyn BitVecExpr) -> String {
            let numeral_part = b.to_long().map(|v| v.to_string()).unwrap_or_default();
            format!("bv;{};{};{}", b.sort_size(), numeral_part, b.as_expr().to_smt_string())
        }
        fn smt_lib_for_bool(&self, _b: &dyn BoolExpr) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
            let mut parts = smt.splitn(4, ';');
            match parts.next()? {
                "bv" => {
                    let size: u32 = parts.next()?.parse().ok()?;
                    let numeral_str = parts.next()?;
                    let numeral = if numeral_str.is_empty() { None } else { numeral_str.parse::<i64>().ok() };
                    let term = parts.next()?.to_string();
                    let bv = Bv { smt: term.clone(), size, numeral };
                    Some(Box::new(Bl { smt: format!("(= {0} {0})", term), arg: Some(bv) }))
                }
                _ => None,
            }
        }
        fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn BitVecExpr> {
            self.bv(format!("#x{:x}", value), size_bits, Some(value))
        }
        fn mk_bv_const(&self, name: &str, size_bits: u32) -> Box<dyn BitVecExpr> {
            self.bv(name.to_string(), size_bits, None)
        }
        fn mk_true(&self) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_false(&self) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_eq(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_ite_bv(&self, _p: &dyn BoolExpr, _t: &dyn BitVecExpr, _f: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_ite_bool(&self, _p: &dyn BoolExpr, _t: &dyn BoolExpr, _f: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvslt(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvsle(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvult(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvule(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bv_add_no_overflow(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr, _s: bool) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bv_sub_no_overflow(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvadd(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let numeral = match (l.to_long(), r.to_long()) {
                (Some(a), Some(b)) => Some(a.wrapping_add(b)),
                _ => None,
            };
            self.bv(
                format!("(bvadd {} {})", l.as_expr().to_smt_string(), r.as_expr().to_smt_string()),
                l.sort_size(),
                numeral,
            )
        }
        fn mk_bvsub(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvxor(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvand(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvor(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvmul(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvudiv(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvsdiv(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvshl(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvlshr(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvashr(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_concat(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let result_size = l.sort_size() + r.sort_size();
            // Real Z3 eagerly constant-folds `concat` of two numerals into a single canonically
            // rendered numeral (it does not need an explicit `.simplify()` for this -- unlike the
            // deeper symbolic simplifications `SymZ3MemoryMap`'s own `.simplify()` calls are for,
            // which this seam genuinely does not model; see the module docs). This mock mirrors
            // that constant folding so a concrete multi-byte store/load round trip is byte-for-
            // byte identical, the same way it would be against a real Z3 `Context`.
            if let (Some(lv), Some(rv)) = (l.to_long(), r.to_long()) {
                let l_mask = mask_for_width(l.sort_size());
                let r_mask = mask_for_width(r.sort_size());
                let combined = (((lv as u64) & l_mask) << r.sort_size()) | ((rv as u64) & r_mask);
                return self.bv(format!("#x{:x}", combined), result_size, Some(combined as i64));
            }
            self.bv(
                format!("(concat {} {})", l.as_expr().to_smt_string(), r.as_expr().to_smt_string()),
                result_size,
                None,
            )
        }
        fn mk_zero_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("((_ zero_extend {}) {})", bits, b.as_expr().to_smt_string()),
                b.sort_size() + bits,
                None,
            )
        }
        fn mk_sign_ext(&self, _bits: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_extract(&self, high: u32, low: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let width = high - low + 1;
            // Real Z3 eagerly constant-folds `extract` of a numeral into a single canonically
            // rendered numeral; see `mk_concat`'s own comment for why this mock mirrors that.
            if let Some(v) = b.to_long() {
                let extracted = ((v as u64) >> low) & mask_for_width(width);
                return self.bv(format!("#x{:x}", extracted), width, Some(extracted as i64));
            }
            self.bv(
                format!("((_ extract {} {}) {})", high, low, b.as_expr().to_smt_string()),
                width,
                None,
            )
        }
        fn mk_not(&self, _u: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_xor(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_and(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_or(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A [`Language`] test double reporting only a configurable endianness; every other method is
    /// unreachable from `SymZ3MemoryMap` and panics if called, mirroring the `NullLanguage`
    /// pattern already used elsewhere in this crate's tests (e.g.
    /// `pcode::exec::pcode_program::testing::NullLanguage`).
    struct TestLanguage {
        big_endian: bool,
    }

    macro_rules! unimplemented_language_methods {
        () => {
            fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_language_description(
                &self,
            ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_parallel_instruction_helper(
                &self,
            ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
            {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_version(&self) -> i32 {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_minor_version(&self) -> i32 {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_default_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_default_data_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_instruction_alignment(&self) -> i32 {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn supports_pcode(&self) -> bool {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn parse(
                &self,
                _buf: &dyn crate::program::model::mem::MemBuffer,
                _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
                _in_delay_slot: bool,
            ) -> Result<
                Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
                crate::program::model::lang::language::ParseError,
            > {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_number_of_user_defined_op_names(&self) -> i32 {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_registers_at(
                &self,
                _address: &crate::program::model::address::Address,
            ) -> Vec<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_register_in_space(
                &self,
                _addrspc: &std::sync::Arc<crate::program::model::address::AddressSpace>,
                _offset: i64,
                _size: i32,
            ) -> Option<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_register_names(&self) -> Vec<String> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_register_by_name(
                &self,
                _name: &str,
            ) -> Option<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_register_at(
                &self,
                _addr: &crate::program::model::address::Address,
                _size: i32,
            ) -> Option<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_context_base_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_default_memory_blocks(
                &self,
            ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_segmented_space(&self) -> String {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn apply_context_settings(
                &self,
                _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
            ) {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_compatible_compiler_spec_descriptions(
                &self,
            ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
            {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_compiler_spec_by_id(
                &self,
                _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
            ) -> Result<
                Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
                crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
            > {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn has_property(&self, _key: &str) -> bool {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_property(&self, _key: &str) -> Option<String> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_property_keys(&self) -> std::collections::HashSet<String> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn has_manual(&self) -> bool {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
                unimplemented!("TestLanguage is not meant to be called")
            }
            fn get_maximum_instruction_length(&self) -> Option<i32> {
                unimplemented!("TestLanguage is not meant to be called")
            }
        };
    }

    impl Language for TestLanguage {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        unimplemented_language_methods!();
    }

    fn little_endian_map() -> SymZ3MemoryMap {
        SymZ3MemoryMap::new(Box::new(TestLanguage { big_endian: false }))
    }

    fn big_endian_map() -> SymZ3MemoryMap {
        SymZ3MemoryMap::new(Box::new(TestLanguage { big_endian: true }))
    }

    fn numeral_offset(ctx: &MockCtx, value: i64, size: u32) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(ctx, &*ctx.bv(format!("#x{:x}", value), size, Some(value)))
    }

    fn symbolic_value(ctx: &MockCtx, name: &str, size: u32) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(ctx, &*ctx.mk_bv_const(name, size))
    }

    #[test]
    fn store_then_load_round_trips_a_single_byte_little_endian() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x100, 32);
        let val = numeral_offset(&ctx, 0xAB, 8);

        map.store(&ctx, &offset, 1, &val);
        let got = map.load(&ctx, &offset, 1, false, &NONE);

        assert_eq!(got, val);
    }

    #[test]
    fn store_then_load_round_trips_multiple_bytes_little_endian() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x200, 32);
        // A concrete 32-bit value: `MockCtx`'s `mk_extract`/`mk_concat` constant-fold numerals
        // (mirroring what a real Z3 `Context` does even without an explicit `.simplify()` call --
        // see `MockCtx::mk_concat`'s own comment), so the reassembled value round-trips to a
        // canonically-rendered numeral byte-for-byte identical to the original.
        let val = numeral_offset(&ctx, 0xdeadbeefu32 as i64, 32);

        map.store(&ctx, &offset, 4, &val);
        let got = map.load(&ctx, &offset, 4, false, &NONE);

        assert_eq!(got, val);
    }

    #[test]
    fn store_then_load_of_a_symbolic_value_reassembles_it_from_its_stored_byte_pieces() {
        // Unlike a concrete value, a symbolic 32-bit value has no numeral to constant-fold, so
        // (matching what real Z3 would also do here, since `load` never calls `.simplify()` on
        // its reassembled result -- see the module docs) the round trip does *not* produce a
        // value textually equal to the original atom `RBX`; it produces a nested
        // concat-of-extracts expression that only real Z3 could confirm is semantically
        // equivalent. This test instead checks the structural properties this port's mechanism
        // actually guarantees: every stored byte contributes (each naming `RBX`), and the
        // reassembled width matches.
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x200, 32);
        let val = symbolic_value(&ctx, "RBX", 32);

        map.store(&ctx, &offset, 4, &val);
        let got = map.load(&ctx, &offset, 4, false, &NONE);

        let got_expr = got.get_bit_vec_expr(&ctx).expect("load always produces a bit-vector value");
        assert_eq!(got_expr.sort_size(), 32);
        assert_eq!(got_expr.as_expr().to_smt_string().matches("RBX").count(), 4);
    }

    #[test]
    fn load_of_a_never_stored_address_synthesizes_a_deterministic_symbolic_byte() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0xdeadbeefu32 as i64, 32);

        let first = map.load(&ctx, &offset, 1, false, &NONE);
        let second = map.load(&ctx, &offset, 1, false, &NONE);

        // Loading the same never-written address twice must yield the same symbolic value both
        // times (the "consistent unknown" property the real uninterpreted function would give).
        assert_eq!(first, second);
    }

    #[test]
    fn load_of_distinct_never_stored_addresses_synthesizes_distinct_symbolic_bytes() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let a = numeral_offset(&ctx, 0x10, 32);
        let b = numeral_offset(&ctx, 0x20, 32);

        let va = map.load(&ctx, &a, 1, false, &NONE);
        let vb = map.load(&ctx, &b, 1, false, &NONE);

        assert_ne!(va, vb);
    }

    #[test]
    fn endianness_affects_byte_order_on_store_and_load() {
        let ctx = MockCtx;
        let value = numeral_offset(&ctx, 0x1122, 16);

        let mut le = little_endian_map();
        let le_offset = numeral_offset(&ctx, 0x10, 32);
        le.store(&ctx, &le_offset, 2, &value);

        let mut be = big_endian_map();
        let be_offset = numeral_offset(&ctx, 0x10, 32);
        be.store(&ctx, &be_offset, 2, &value);

        // Both round-trip correctly through their own `load`...
        assert_eq!(le.load(&ctx, &le_offset, 2, false, &NONE), value);
        assert_eq!(be.load(&ctx, &be_offset, 2, false, &NONE), value);

        // ...but the low-order byte lands at a different address for each endianness: for LE the
        // low byte (0x22) is at the base address; for BE the high byte (0x11) is.
        let low_byte_key_le = SymValueZ3::serialize_bit_vec(&ctx, &*ctx.bv("#x10".to_string(), 32, Some(0x10)));
        let stored_at_base_le = le.memvals.get(&low_byte_key_le).unwrap();
        assert_eq!(stored_at_base_le.get_bit_vec_expr(&ctx).unwrap().to_long(), Some(0x22));

        let low_byte_key_be = SymValueZ3::serialize_bit_vec(&ctx, &*ctx.bv("#x10".to_string(), 32, Some(0x10)));
        let stored_at_base_be = be.memvals.get(&low_byte_key_be).unwrap();
        assert_eq!(stored_at_base_be.get_bit_vec_expr(&ctx).unwrap().to_long(), Some(0x11));
    }

    #[test]
    fn has_value_for_reports_presence_once_stored_at_that_exact_offset() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x300, 32);
        let one_byte = numeral_offset(&ctx, 0x42, 8);

        assert!(!map.has_value_for(&offset, 1));
        map.store(&ctx, &offset, 1, &one_byte);
        assert!(map.has_value_for(&offset, 1));
    }

    #[test]
    fn has_value_for_ignores_the_size_parameter_entirely() {
        // See `has_value_for`'s own docs: the preserved Java quirk/bug. `store`'s very first
        // iteration always writes a `memvals` entry keyed by exactly `offset`'s own unmodified
        // address, no matter how large `size` is -- and `has_value_for` only ever checks that one
        // key, never actually consulting the `size` it was asked about. So claiming a wildly
        // larger `size` than was ever stored still reports `true`.
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x400, 32);
        let one_byte = numeral_offset(&ctx, 0x42, 8);

        map.store(&ctx, &offset, 1, &one_byte);

        assert!(map.has_value_for(&offset, 1));
        assert!(map.has_value_for(&offset, 1_000));
    }

    #[test]
    fn has_value_for_only_checks_the_exact_offset_passed_in() {
        // An offset that was never itself used as a `store` base address (nor happens to be one
        // of the per-byte addresses a larger `store` wrote to) has no entry, even if it sits
        // conceptually "within" a region that was stored under a different base offset.
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x500, 32);
        let val = numeral_offset(&ctx, 0xdead, 16);

        map.store(&ctx, &offset, 2, &val);

        let unrelated = numeral_offset(&ctx, 0x999, 32);
        assert!(!map.has_value_for(&unrelated, 1));
    }

    #[test]
    fn has_value_for_an_offset_with_no_bit_vec_expr_is_false() {
        // `SymValueZ3::default()` carries neither a bit-vector nor boolean expression, so
        // `bit_vec_expr_string` is `None` -- exercising `has_value_for`'s `None => false` arm
        // (Java: `memvals.containsKey(null)`, which is legal and always `false` there too).
        let map = little_endian_map();
        let offset = SymValueZ3::default();
        assert!(!map.has_value_for(&offset, 1));
    }

    #[test]
    fn get_next_entry_orders_addresses_unsigned() {
        let ctx = MockCtx;
        let mut map = little_endian_map();

        // A "negative" (as i64) but large-unsigned address, and a small positive one.
        let small = numeral_offset(&ctx, 0x10, 64);
        let large = numeral_offset(&ctx, -1i64, 64); // 0xFFFF...FFFF unsigned
        map.store(&ctx, &small, 1, &numeral_offset(&ctx, 1, 8));
        map.store(&ctx, &large, 1, &numeral_offset(&ctx, 2, 8));

        // Unsigned ordering: 0x10 sorts before 0xFFFF...FFFF (-1 as i64).
        let (offset, _) = map.get_next_entry(&ctx, 0).expect("an entry exists at or after 0");
        assert_eq!(offset, 0x10);

        let (offset2, _) = map.get_next_entry(&ctx, 0x11).expect("an entry exists at or after 0x11");
        assert_eq!(offset2, -1);
    }

    #[test]
    fn stream_valuations_covers_both_memvals_and_deduplicated_witnesses() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let printer = Z3InfixPrinter::new(std::sync::Arc::new(MockCtx));

        let offset = numeral_offset(&ctx, 0x500, 32);
        map.store(&ctx, &offset, 1, &numeral_offset(&ctx, 7, 8));
        // Load the same address twice with witnessing on; the witness should be deduplicated.
        let _ = map.load(&ctx, &offset, 1, true, &NONE);
        let _ = map.load(&ctx, &offset, 1, true, &NONE);

        let valuations = map.stream_valuations(&ctx, &printer);
        // One entry from `memvals` (the stored byte) plus exactly one entry from the
        // deduplicated witness (not two).
        assert_eq!(valuations.len(), 2);
    }

    #[test]
    fn printable_summary_reports_stored_and_witnessed_addresses() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let printer = Z3InfixPrinter::new(std::sync::Arc::new(MockCtx));

        let offset = numeral_offset(&ctx, 0x600, 32);
        map.store(&ctx, &offset, 1, &numeral_offset(&ctx, 9, 8));
        let _ = map.load(&ctx, &offset, 1, true, &NONE);

        let summary = map.printable_summary(&ctx, &printer);
        assert!(summary.contains("MEM"));
        assert!(!summary.is_empty());
    }

    #[test]
    fn build_load_matches_javas_funcdecl_naming_scheme() {
        assert_eq!(build_load(64, 8), "load_64_8");
        assert_eq!(build_load(32, 16), "load_32_16");
    }

    #[test]
    #[should_panic(expected = "assert bval.getSortSize() == size * 8")]
    fn store_debug_asserts_the_values_size_matches_the_declared_size() {
        let ctx = MockCtx;
        let mut map = little_endian_map();
        let offset = numeral_offset(&ctx, 0x700, 32);
        // `val` is 8 bits wide, but `size` claims 2 bytes (16 bits) -- Java's `assert` fires.
        let val = numeral_offset(&ctx, 1, 8);
        map.store(&ctx, &offset, 2, &val);
    }
}
