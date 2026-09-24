//! Port of `ghidra.pcode.emu.symz3.SymZ3RegisterMap`.
//!
//! A class that can store `SymValueZ3` values in registers.
//!
//! **NOTE:** DELIBERATELY NO KNOWLEDGE OF SPACES, Languages, or "get" and "set".
//!
//! # Deviations from Java
//!
//! * Java's methods that touch Z3 open their own `try (Context ctx = new Context())`. This crate
//!   has no Z3 binding yet, so, following the convention already established by
//!   [`SymValueZ3`](crate::feature::symz3::model::sym_value_z3::SymValueZ3) and
//!   [`Z3InfixPrinter`](crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter), every
//!   Z3-dependent method here takes the context explicitly instead
//!   ([`crate::feature::seam_stubs::Z3Context`]).
//! * Java's `public Map<Register, SymValueZ3> regvals` is keyed directly by `Register` (which
//!   overrides `equals`/`hashCode`). This crate's [`RegisterRef`] is `Rc<RefCell<Register>>`, and
//!   the standard library deliberately does not implement `Hash`/`Eq` for `RefCell<T>` (a
//!   borrowed, mutated value could silently change its hash out from under a map). [`RegKey`]
//!   wraps a `RegisterRef` and reads through the borrow to delegate to `Register`'s own
//!   `Hash`/`Eq`, standing in for Java's direct use of `Register` as a map key. The field stays
//!   `pub`, preserving Java's own `// TODO: make this be private and provide appropriate methods`
//!   comment -- a genuine, acknowledged loose end in the original, not something this port tidies
//!   up.
//! * `valuationFor`/`printableRegister` call `.simplify()` on the rendered Z3 expression before
//!   printing it. There is no real Z3 engine behind the [`crate::feature::seam_stubs::Z3Context`]
//!   seam to simplify anything with, and no `simplify` method exists on the `Expr`/`BitVecExpr`/
//!   `BoolExpr` seam traits, so this step is not modeled: the raw (unsimplified) expression is
//!   rendered instead. A future real Z3 binding would restore the call.
//! * `printableSummary()` takes no parameters in Java (it opens its own `Context` and builds its
//!   own `Z3InfixPrinter`); this port takes both explicitly, for the same reason as the first
//!   bullet.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::program::model::lang::register::{Register, RegisterRef};

/// Wraps a [`RegisterRef`] so it can key [`SymZ3RegisterMap::regvals`]. See the module docs for
/// why a direct `HashMap<RegisterRef, _>` does not work.
#[derive(Clone)]
pub struct RegKey(pub RegisterRef);

impl RegKey {
    /// The wrapped register.
    pub fn register(&self) -> &RegisterRef {
        &self.0
    }
}

impl PartialEq for RegKey {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for RegKey {}

impl std::hash::Hash for RegKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// A class that can store `SymValueZ3` values in registers.
///
/// Port of `ghidra.pcode.emu.symz3.SymZ3RegisterMap`. See the module docs for the deviations this
/// port makes to work without a real Z3 binding and around `RefCell`'s lack of `Hash`.
pub struct SymZ3RegisterMap {
    /// In the map, all registers are base registers. Java: `public Map<Register, SymValueZ3>
    /// regvals`, left `pub` (and left keyed roughly as Java left it) per the module docs.
    ///
    /// TODO: make this be private and provide appropriate methods (preserved from Java).
    pub regvals: HashMap<RegKey, SymValueZ3>,
    by_offset: Option<BTreeMap<i64, SymValueZ3>>,
    register_names_read: HashSet<String>,
    register_names_updated: HashSet<String>,
    known_registers: HashMap<String, RegisterRef>,
}

impl SymZ3RegisterMap {
    /// Construct an empty register map.
    pub fn new() -> Self {
        Self {
            regvals: HashMap::new(),
            by_offset: None,
            register_names_read: HashSet::new(),
            register_names_updated: HashSet::new(),
            known_registers: HashMap::new(),
        }
    }

    /// Port of `getRegisterNamesRead()`.
    pub fn get_register_names_read(&self) -> Vec<String> {
        let mut result: Vec<String> = self.register_names_read.iter().cloned().collect();
        result.sort();
        result
    }

    /// Port of `getRegisterNamesUpdated()`.
    pub fn get_register_names_updated(&self) -> Vec<String> {
        let mut result: Vec<String> = self.register_names_updated.iter().cloned().collect();
        result.sort();
        result
    }

    /// Port of `getRegisterNamesReadOrUpdated()`.
    pub fn get_register_names_read_or_updated(&self) -> Vec<String> {
        let mut both: HashSet<String> = self.register_names_read.clone();
        both.extend(self.register_names_updated.iter().cloned());
        let mut result: Vec<String> = both.into_iter().collect();
        result.sort();
        result
    }

    /// Port of `getRegisterNames()`.
    ///
    /// Java: "make this recursive later and get children???" (preserved as-is: this lists only
    /// the base registers actually stored in [`Self::regvals`]).
    pub fn get_register_names(&self) -> Vec<String> {
        self.regvals.keys().map(|k| k.0.name().to_string()).collect()
    }

    /// Port of `updateRegister(Register, SymValueZ3)`.
    pub fn update_register(&mut self, ctx: &dyn Z3Context, r: &RegisterRef, update: &SymValueZ3) {
        let name = r.name().to_string();
        self.register_names_updated.insert(name.clone());
        self.update_register_helper(ctx, r, update);
        self.known_registers.entry(name).or_insert_with(|| r.clone());
    }

    /// Port of the private `updateRegisterHelper(Context, Register, SymValueZ3)`.
    fn update_register_helper(&mut self, ctx: &dyn Z3Context, r: &RegisterRef, update: &SymValueZ3) {
        if r.is_base_register() {
            self.regvals.insert(RegKey(r.clone()), update.clone());
            self.by_offset = None;
            return;
        }
        // So, we want to update the base, but also need to keep portions of it.
        // 3 cases, the base might contribute at left, right, or both.
        let bv = update
            .get_bit_vec_expr(ctx)
            .expect("Java: unchecked getBitVecExpr(ctx) on the update value");
        let base = r.get_base_register();
        let base_val = self.get_register_helper(ctx, &base);
        let lsb_in_base = r.least_significant_bit_in_base_register();
        let r_bit_length = r.bit_length();
        let base_bit_length = base.bit_length();

        let mut result = if r_bit_length + lsb_in_base < base_bit_length {
            let high = (base_bit_length - 1) as u32;
            let low = (r_bit_length + lsb_in_base) as u32;
            let base_bv = base_val
                .get_bit_vec_expr(ctx)
                .expect("Java: unchecked getBitVecExpr(ctx) on the base value");
            let left = ctx.mk_extract(high, low, &*base_bv);
            ctx.mk_concat(&*left, &*bv)
        }
        else {
            bv
        };

        // Consider whether some portion of base remains on the right.
        if result.sort_size() < base_bit_length as u32 {
            let high = base_bit_length as u32 - result.sort_size() - 1;
            let low = 0;
            let base_bv = base_val
                .get_bit_vec_expr(ctx)
                .expect("Java: unchecked getBitVecExpr(ctx) on the base value");
            let right = ctx.mk_extract(high, low, &*base_bv);
            result = ctx.mk_concat(&*result, &*right);
        }

        self.regvals.insert(RegKey(base.clone()), SymValueZ3::from_bit_vec(ctx, &*result));
        self.by_offset = None;
    }

    /// Port of `getRegister(Register)`.
    pub fn get_register(&mut self, ctx: &dyn Z3Context, r: &RegisterRef) -> SymValueZ3 {
        let name = r.name().to_string();
        self.register_names_read.insert(name.clone());
        self.known_registers.entry(name).or_insert_with(|| r.clone());
        self.get_register_helper(ctx, r)
    }

    /// Port of `hasValueForRegister(Register)`.
    ///
    /// Normally a call to `get` will create a symbolic, but we might want the ability to check if
    /// there is a value.
    pub fn has_value_for_register(&self, r: &RegisterRef) -> bool {
        if r.is_base_register() {
            return self.regvals.contains_key(&RegKey(r.clone()));
        }
        let base = r.get_base_register();
        self.has_value_for_register(&base)
    }

    /// Port of the private `getRegisterHelper(Context, Register)`.
    fn get_register_helper(&mut self, ctx: &dyn Z3Context, r: &RegisterRef) -> SymValueZ3 {
        if r.is_base_register() {
            if let Some(v) = self.regvals.get(&RegKey(r.clone())) {
                return v.clone();
            }

            let is_flags = r.group() == Some("FLAGS");
            let name = r.name().to_string();
            let bit_length = r.bit_length();

            if is_flags {
                // We treat flags as special, because we create a single symbolic bit.
                let e = ctx.mk_bv_const(&name, 1);
                let zeros = ctx.mk_bv(0, (bit_length - 1) as u32);
                let di = SymValueZ3::from_bit_vec(ctx, &*ctx.mk_concat(&*zeros, &*e));
                self.update_register_helper(ctx, r, &di);
                return di;
            }

            let e = ctx.mk_bv_const(&name, bit_length as u32);
            let di = SymValueZ3::from_bit_vec(ctx, &*e);
            self.update_register_helper(ctx, r, &di);
            return di;
        }

        let lsb_in_base = r.least_significant_bit_in_base_register();
        let bit_length = r.bit_length();
        let base = r.get_base_register();
        let base_val = self.get_register_helper(ctx, &base);

        let base_bv = base_val
            .get_bit_vec_expr(ctx)
            .expect("Java: unchecked getBitVecExpr(ctx) on the base value");
        let b = ctx.mk_extract((lsb_in_base + bit_length - 1) as u32, lsb_in_base as u32, &*base_bv);
        SymValueZ3::from_bit_vec(ctx, &*b)
    }

    /// Port of `printableRegister(Context, Register)`.
    pub fn printable_register(
        &mut self,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
        r: &RegisterRef,
    ) -> String {
        let (key, value) = self.valuation_for(ctx, z3p, r);
        format!("{} = {}", key, value)
    }

    /// Port of `valuationFor(Context, Z3InfixPrinter, Register)`.
    pub fn valuation_for(
        &mut self,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
        r: &RegisterRef,
    ) -> (String, String) {
        let size_string = format!(":{}", r.num_bytes() * 8);
        let rv = self.get_register_helper(ctx, r);

        let key = format!("{}{}", r, size_string);

        if r.num_bytes() == 1 && rv.has_bool_expr() {
            let e = rv.get_bool_expr(ctx).expect("hasBoolExpr() implies getBoolExpr succeeds");
            // Java: `e = (BoolExpr) e.simplify();` -- not modeled; see the module docs.
            return (key, z3p.infix_top_level(e.as_expr()));
        }
        let v = rv.get_bit_vec_expr(ctx).expect("a bit-vector-only value must have a bit-vector expr");
        // Java: `v = (BitVecExpr) v.simplify();` -- not modeled; see the module docs.
        (key, z3p.infix_top_level(v.as_expr()))
    }

    /// Port of `printableSummary()`. Takes `ctx`/`z3p` explicitly; see the module docs.
    pub fn printable_summary(&mut self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> String {
        let mut result = String::new();
        result.push_str("----------------------------------------------------\n");
        result.push_str("Registers that were read: \n");
        result.push_str(&z3p.fetch_list_of_strings_helper(&self.get_register_names_read()));

        result.push_str("Registers that were updated: \n");
        result.push_str(&z3p.fetch_list_of_strings_helper(&self.get_register_names_updated()));

        result.push_str("Registers that were read or updated: \n");
        result.push_str(&z3p.fetch_list_of_strings_helper(&self.get_register_names_read_or_updated()));

        result.push_str("Current Valuations (in terms of valuations at start)\n");

        for name in self.get_register_names_read_or_updated() {
            let r = self
                .known_registers
                .get(&name)
                .cloned()
                .expect("a tracked register name is always recorded in known_registers");
            result.push_str(&self.printable_register(ctx, z3p, &r));
            result.push('\n');
        }
        result
    }

    /// Port of `streamValuations(Context, Z3InfixPrinter)`. Returns a `Vec` rather than a lazy
    /// stream; see [`SymZ3Space`](crate::pcode::emu::symz3::state::SymZ3Space)'s docs for why this
    /// crate makes the same substitution elsewhere.
    pub fn stream_valuations(&mut self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        let names = self.get_register_names_read_or_updated();
        let mut result = Vec::with_capacity(names.len());
        for name in names {
            let r = self
                .known_registers
                .get(&name)
                .cloned()
                .expect("a tracked register name is always recorded in known_registers");
            result.push(self.valuation_for(ctx, z3p, &r));
        }
        result
    }

    /// Port of `getNextEntry(long)`.
    pub fn get_next_entry(&mut self, offset: i64) -> Option<(i64, SymValueZ3)> {
        if self.by_offset.is_none() {
            let mut map = BTreeMap::new();
            for (key, val) in self.regvals.iter() {
                map.insert(key.0.address().offset(), val.clone());
            }
            self.by_offset = Some(map);
        }
        self.by_offset.as_ref().unwrap().range(offset..).next().map(|(k, v)| (*k, v.clone()))
    }
}

impl Default for SymZ3RegisterMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Expr};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc as StdArc;

    /// A minimal bit-vector expression that carries its SMT-LIB2 text and width, mirroring the
    /// `Bv` test double already established in `sym_value_z3`'s own tests.
    #[derive(Clone)]
    struct Bv {
        smt: String,
        size: u32,
    }

    impl Expr for Bv {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
        }
        fn as_any(&self) -> &dyn std::any::Any {
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
            false
        }
        fn to_big_integer(&self) -> Option<i128> {
            None
        }
        fn to_long(&self) -> Option<i64> {
            None
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
        fn as_any(&self) -> &dyn std::any::Any {
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
    /// solver, following the same convention as `sym_value_z3`'s and `z3_infix_printer`'s own
    /// `MockCtx`es. Only the operations `SymZ3RegisterMap` actually exercises (`mk_bv_const`,
    /// `mk_bv`, `mk_concat`, `mk_extract`, round-trip serialization) are implemented for real;
    /// everything else panics.
    struct MockCtx;

    impl MockCtx {
        fn bv(&self, smt: String, size: u32) -> Box<dyn BitVecExpr> {
            Box::new(Bv { smt, size })
        }
    }

    impl Z3Context for MockCtx {
        fn smt_lib_for_bit_vec(&self, b: &dyn BitVecExpr) -> String {
            format!("bv;{};{}", b.sort_size(), b.to_smt_string())
        }
        fn smt_lib_for_bool(&self, _b: &dyn BoolExpr) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
            let mut parts = smt.splitn(3, ';');
            match parts.next()? {
                "bv" => {
                    let size = parts.next()?.parse().ok()?;
                    let term = parts.next()?.to_string();
                    let bv = Bv { smt: term.clone(), size };
                    Some(Box::new(Bl { smt: format!("(= {0} {0})", term), arg: Some(bv) }))
                }
                _ => None,
            }
        }
        fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn BitVecExpr> {
            self.bv(format!("#x{:x}:{}", value, size_bits), size_bits)
        }
        fn mk_bv_const(&self, name: &str, size_bits: u32) -> Box<dyn BitVecExpr> {
            self.bv(name.to_string(), size_bits)
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
        fn mk_bvadd(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
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
            self.bv(
                format!("(concat {} {})", l.as_expr().to_smt_string(), r.as_expr().to_smt_string()),
                l.sort_size() + r.sort_size(),
            )
        }
        fn mk_zero_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(format!("((_ zero_extend {}) {})", bits, b.as_expr().to_smt_string()), b.sort_size() + bits)
        }
        fn mk_sign_ext(&self, _bits: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_extract(&self, high: u32, low: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("((_ extract {} {}) {})", high, low, b.as_expr().to_smt_string()),
                high - low + 1,
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

    fn register_space() -> StdArc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1)
    }

    /// Builds a 32-bit `EAX` base register with an `AX`(16)/`AL`(8, lsb 0)/`AH`(8, lsb 8) child
    /// hierarchy, little-endian -- mirroring `register.rs`'s own test fixtures.
    fn eax_family() -> (RegisterRef, RegisterRef, RegisterRef, RegisterRef) {
        let space = register_space();
        let eax = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let ax = Register::with_bit_range("AX", "", space.address(0x0), 2, 0, 16, false, Register::TYPE_NONE);
        let al = Register::with_bit_range("AL", "", space.address(0x0), 1, 0, 8, false, Register::TYPE_NONE);
        let ah = Register::with_bit_range("AH", "", space.address(0x1), 1, 0, 8, false, Register::TYPE_NONE);

        let [eax, ax, al, ah]: [Register; 4] =
            crate::program::model::lang::register::test_support::linked(&[&eax, &ax, &al, &ah], &[(1, &[2, 3]), (0, &[1])]).try_into().unwrap();

        (eax, ax, al, ah)
    }

    fn flags_register() -> RegisterRef {
        let space = register_space();
        let flags = Register::new("EFLAGS", "", space.address(0x10), 4, false, Register::TYPE_NONE);
        crate::program::model::lang::register::test_support::edited(&flags, |store, id| store.set_group(id, "FLAGS"))
    }

    fn bv_text(v: &SymValueZ3, ctx: &dyn Z3Context) -> String {
        v.get_bit_vec_expr(ctx).unwrap().to_smt_string()
    }

    #[test]
    fn get_register_on_an_untouched_base_register_materializes_a_named_symbolic() {
        let ctx = MockCtx;
        let (eax, ..) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        let value = map.get_register(&ctx, &eax);

        assert_eq!(bv_text(&value, &ctx), "EAX");
        assert!(map.has_value_for_register(&eax));
        assert_eq!(map.get_register_names_read(), vec!["EAX".to_string()]);
        assert!(map.get_register_names_updated().is_empty());
    }

    #[test]
    fn get_register_is_idempotent_once_materialized() {
        let ctx = MockCtx;
        let (eax, ..) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        let first = map.get_register(&ctx, &eax);
        let second = map.get_register(&ctx, &eax);

        assert_eq!(first, second);
    }

    #[test]
    fn get_register_on_a_sub_register_extracts_from_the_freshly_materialized_base() {
        let ctx = MockCtx;
        let (_, ax, al, ah) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        let al_val = map.get_register(&ctx, &al);
        assert_eq!(bv_text(&al_val, &ctx), "((_ extract 7 0) EAX)");

        let ah_val = map.get_register(&ctx, &ah);
        assert_eq!(bv_text(&ah_val, &ctx), "((_ extract 15 8) EAX)");

        let ax_val = map.get_register(&ctx, &ax);
        assert_eq!(bv_text(&ax_val, &ctx), "((_ extract 15 0) EAX)");
    }

    #[test]
    fn get_register_on_a_flags_style_register_wraps_a_single_symbolic_bit() {
        let ctx = MockCtx;
        let flags = flags_register();
        let mut map = SymZ3RegisterMap::new();

        let value = map.get_register(&ctx, &flags);

        assert_eq!(bv_text(&value, &ctx), "(concat #x0:31 EFLAGS)");
    }

    #[test]
    fn update_register_on_a_base_register_replaces_it_outright() {
        let ctx = MockCtx;
        let (eax, ..) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        let replacement = SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv_const("newval", 32));
        map.update_register(&ctx, &eax, &replacement);

        let got = map.get_register(&ctx, &eax);
        assert_eq!(got, replacement);
        assert_eq!(map.get_register_names_updated(), vec!["EAX".to_string()]);
    }

    #[test]
    fn update_register_on_al_splices_into_the_base_leaving_the_rest_untouched() {
        let ctx = MockCtx;
        let (eax, _, al, _) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        // Materialize EAX first so the "left" portion of the splice is a concrete symbol, not a
        // second freshly-materialized name.
        let _ = map.get_register(&ctx, &eax);

        let update = SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv_const("lo", 8));
        map.update_register(&ctx, &al, &update);

        let new_eax = map.get_register(&ctx, &eax);
        // AL occupies bits [7:0]; nothing remains "on the right" (lsb 0), but bits [31:8] of the
        // original EAX remain on the left.
        assert_eq!(bv_text(&new_eax, &ctx), "(concat ((_ extract 31 8) EAX) lo)");
    }

    #[test]
    fn register_names_read_updated_and_union_are_sorted_and_deduplicated() {
        let ctx = MockCtx;
        let (eax, ax, al, ah) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        let _ = map.get_register(&ctx, &ah);
        let _ = map.get_register(&ctx, &al);
        map.update_register(&ctx, &ax, &SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv_const("v", 16)));
        let _ = map.get_register(&ctx, &eax);

        assert_eq!(map.get_register_names_read(), vec!["AH".to_string(), "AL".to_string(), "EAX".to_string()]);
        assert_eq!(map.get_register_names_updated(), vec!["AX".to_string()]);
        assert_eq!(
            map.get_register_names_read_or_updated(),
            vec!["AH".to_string(), "AL".to_string(), "AX".to_string(), "EAX".to_string()]
        );
    }

    #[test]
    fn has_value_for_register_checks_the_base_registers_presence() {
        let ctx = MockCtx;
        let (eax, ax, al, _) = eax_family();
        let mut map = SymZ3RegisterMap::new();

        assert!(!map.has_value_for_register(&al));
        let _ = map.get_register(&ctx, &al);
        // Reading AL materializes EAX (the base), so AX and AL now report a value too.
        assert!(map.has_value_for_register(&al));
        assert!(map.has_value_for_register(&ax));
        assert!(map.has_value_for_register(&eax));
    }

    #[test]
    fn get_register_names_lists_only_stored_base_registers() {
        let ctx = MockCtx;
        let (_, _, al, _) = eax_family();
        let mut map = SymZ3RegisterMap::new();
        assert!(map.get_register_names().is_empty());

        let _ = map.get_register(&ctx, &al);
        // Only EAX (the base) is ever stored in `regvals`.
        assert_eq!(map.get_register_names(), vec!["EAX".to_string()]);
    }

    #[test]
    fn get_next_entry_returns_the_ceiling_entry_by_register_address_offset() {
        let ctx = MockCtx;
        let (eax, ..) = eax_family();
        let flags = flags_register();
        let mut map = SymZ3RegisterMap::new();

        let _ = map.get_register(&ctx, &eax); // address offset 0x0
        let _ = map.get_register(&ctx, &flags); // address offset 0x10

        let (offset, _) = map.get_next_entry(0x1).expect("an entry at or after 0x1 exists");
        assert_eq!(offset, 0x10);

        assert!(map.get_next_entry(0x11).is_none());
        assert_eq!(map.get_next_entry(0x0).unwrap().0, 0x0);
    }

    #[test]
    fn printable_register_formats_key_equals_value() {
        let ctx = MockCtx;
        let (eax, ..) = eax_family();
        let mut map = SymZ3RegisterMap::new();
        let printer = Z3InfixPrinter::new(StdArc::new(MockCtx));

        let rendered = map.printable_register(&ctx, &printer, &eax);
        assert_eq!(rendered, "EAX:32 = EAX");
    }

    #[test]
    fn printable_summary_lists_read_updated_and_valuations() {
        let ctx = MockCtx;
        let (eax, ..) = eax_family();
        let mut map = SymZ3RegisterMap::new();
        let printer = Z3InfixPrinter::new(StdArc::new(MockCtx));

        let _ = map.get_register(&ctx, &eax);
        let summary = map.printable_summary(&ctx, &printer);

        assert!(summary.contains("Registers that were read"));
        assert!(summary.contains("EAX"));
        assert!(summary.contains("EAX:32 = EAX"));
    }

    #[test]
    fn stream_valuations_covers_every_read_or_updated_register() {
        let ctx = MockCtx;
        let (eax, ax, al, ah) = eax_family();
        let mut map = SymZ3RegisterMap::new();
        let printer = Z3InfixPrinter::new(StdArc::new(MockCtx));

        let _ = map.get_register(&ctx, &al);
        let _ = map.get_register(&ctx, &ah);
        let _ = map.get_register(&ctx, &ax);
        let _ = map.get_register(&ctx, &eax);

        let valuations = map.stream_valuations(&ctx, &printer);
        let names: Vec<&str> = valuations.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["AH:8", "AL:8", "AX:16", "EAX:32"]);
    }
}
