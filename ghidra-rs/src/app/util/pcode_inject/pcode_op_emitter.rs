//! Port of `ghidra.app.util.pcodeInject.PcodeOpEmitter`.
//!
//! Java's `PcodeOpEmitter` is a small helper used by hand-written `InjectPayload`s (see e.g.
//! this module's own [`InjectPayloadJava`](super::InjectPayloadJava)) to build up a list of
//! [`PcodeOp`]s imperatively, by name (`"SP"`, `"cpool"`, ...) rather than by directly
//! constructing [`Varnode`]s. It depends on `ghidra.app.plugin.processors.sleigh.SleighLanguage`
//! for register lookups, the constant/default/unique address spaces, and looking up
//! `CALLOTHER` userop indices by name.
//!
//! That `SleighLanguage` class is a much larger, still-unported type -- and a *different* one
//! from this crate's existing [`crate::program::model::lang::sleigh::SleighLanguage`], which is a
//! lower-level `.sla`-decoding representation with no register table, address-space-by-name
//! lookup, or global symbol table of the kind used here. Rather than block this port on porting
//! that whole class, or grafting an unrelated register table onto the wrong struct, this module
//! defines [`PcodeOpEmitterLanguage`]: a trait capturing exactly the slice of `SleighLanguage`
//! this class actually calls. This mirrors the same dependency-cutting technique already used by
//! [`InjectPayloadSleigh`](crate::program::model::lang::inject_payload_sleigh::InjectPayloadSleigh)
//! (see that module's own doc comment for the same rationale).
//!
//! Note: [`crate::app::seam_stubs`] separately declares its own small `PcodeOpEmitter` *trait* --
//! a placeholder standing in for this very class, used only by
//! [`array_methods`](super::array_methods) (the port of `ArrayMethods`, a different class not in
//! this port's scope) pending this real port landing. That seam trait and this module's
//! [`PcodeOpEmitter`] struct are unrelated Rust items that happen to share a name in different
//! modules; reconciling `array_methods`'s seam usage with this real, now-ported class is left as
//! follow-up work, out of scope here.

use std::collections::HashMap;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};

/// Declared, but never referenced anywhere, by the real Java class either (`static final String
/// RAM = "ram";`) -- kept, unused, for parity.
#[allow(dead_code)]
pub const RAM: &str = "ram";

/// The address and bit-length of a named register, exactly the slice of Java's `Register` that
/// [`PcodeOpEmitter`] ever reads (`getAddress()`/`getBitLength()`).
#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub address: Address,
    pub bit_length: i32,
}

/// The slice of `ghidra.app.plugin.processors.sleigh.SleighLanguage` that [`PcodeOpEmitter`]
/// needs. See the module docs for why this is a locally-defined trait rather than the crate's
/// existing (differently-scoped) `SleighLanguage` struct.
pub trait PcodeOpEmitterLanguage {
    /// Mirrors `language.getAddressFactory().getConstantSpace()`.
    fn get_constant_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `language.getDefaultSpace()`.
    fn get_default_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `language.getAddressFactory().getUniqueSpace()`.
    fn get_unique_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `language.getAddressFactory().getAddressSpace(String)`, used only by
    /// [`PcodeOpEmitter::emit_write_to_memory`]. Java returns `null` for an unrecognized name,
    /// which then NPEs on the very next line (`spc.getSpaceID()`); this port instead leaves that
    /// failure mode up to the implementor (e.g. panicking), since there is no `null` `Arc` to
    /// return here.
    fn get_address_space(&self, name: &str) -> Arc<AddressSpace>;

    /// Mirrors `language.getRegister(String)`, which returns `null` (here: `None`) if no such
    /// register exists.
    fn get_register(&self, name: &str) -> Option<RegisterInfo>;

    /// Mirrors `language.getSymbolTable().findGlobalSymbol(name)` immediately followed by an
    /// `instanceof UseropSymbol` check and (on success) `.getIndex()`. Folded into one lookup
    /// since this port has no separately-ported `Symbol`/`UseropSymbol` hierarchy to mirror that
    /// sequence step by step; returns `None` exactly when Java's `instanceof` check would have
    /// failed (including "no such global symbol at all").
    fn find_userop_index(&self, name: &str) -> Option<i32>;
}

/// An approximation of Java's `Long.decode(String)`: accepts an optional leading sign, then
/// `0x`/`0X`-prefixed or `#`-prefixed hexadecimal, `0`-prefixed octal, or plain decimal digits.
///
/// Panics on malformed input, mirroring `NumberFormatException`. This does not reproduce every
/// edge case of `Long.decode` (e.g. `Long.MIN_VALUE`'s exact overflow boundary), but covers the
/// realistic set of numeric-literal strings a hand-written `InjectPayload` actually passes to
/// [`PcodeOpEmitter::constant_or_register`]/[`PcodeOpEmitter::emit_write_to_memory`].
fn long_decode(s: &str) -> i64 {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (digits, radix) = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (hex, 16)
    } else if let Some(hex) = rest.strip_prefix('#') {
        (hex, 16)
    } else if rest.len() > 1 && rest.starts_with('0') {
        (&rest[1..], 8)
    } else {
        (rest, 10)
    };
    let value = i64::from_str_radix(digits, radix)
        .unwrap_or_else(|_| panic!("For input string: \"{s}\""));
    if neg {
        -value
    } else {
        value
    }
}

/// Builds up a list of [`PcodeOp`]s by name, for use by hand-written `InjectPayload`s.
///
/// Port of `ghidra.app.util.pcodeInject.PcodeOpEmitter`. `'lang` is the borrow of the
/// [`PcodeOpEmitterLanguage`] this emitter was constructed from -- Java simply holds a reference
/// to the (long-lived, shared) `SleighLanguage` object; this is the direct Rust equivalent.
pub struct PcodeOpEmitter<'lang> {
    name_to_reg: HashMap<String, Varnode>,
    op_list: Vec<PcodeOp>,
    language: &'lang dyn PcodeOpEmitterLanguage,
    def_space: Arc<AddressSpace>,
    const_space: Arc<AddressSpace>,
    unique_space: Arc<AddressSpace>,
    sp_varnode: Varnode,
    def_space_id: Varnode,
    unique_base: i64,
    op_address: Address,
    seqnum: i32,
}

// `language` is a `&dyn PcodeOpEmitterLanguage` trait object with no `Debug` supertrait, so
// `#[derive(Debug)]` isn't available on `PcodeOpEmitter` itself; this manual impl covers all the
// other, Debug-able fields and stands in a fixed placeholder for `language` (only ever needed by
// test assertions, which don't inspect it).
impl<'lang> std::fmt::Debug for PcodeOpEmitter<'lang> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcodeOpEmitter")
            .field("name_to_reg", &self.name_to_reg)
            .field("op_list", &self.op_list)
            .field("language", &"<dyn PcodeOpEmitterLanguage>")
            .field("def_space", &self.def_space)
            .field("const_space", &self.const_space)
            .field("unique_space", &self.unique_space)
            .field("sp_varnode", &self.sp_varnode)
            .field("def_space_id", &self.def_space_id)
            .field("unique_base", &self.unique_base)
            .field("op_address", &self.op_address)
            .field("seqnum", &self.seqnum)
            .finish()
    }
}

impl<'lang> PcodeOpEmitter<'lang> {
    /// Constructs a new emitter for p-code at `op_addr`, whose synthesized temporaries start at
    /// `uniq_base` within the unique space.
    ///
    /// Mirrors `PcodeOpEmitter(SleighLanguage, Address, long)`.
    ///
    /// # Panics
    ///
    /// Panics if `language` has no `"SP"` register (mirrors Java's `IllegalArgumentException`
    /// from the constructor's own `findRegister("SP")` call).
    pub fn new(language: &'lang dyn PcodeOpEmitterLanguage, op_addr: Address, uniq_base: i64) -> Self {
        let mut name_to_reg = HashMap::new();
        let const_space = language.get_constant_space();
        let def_space = language.get_default_space();
        let unique_space = language.get_unique_space();

        let sp_reg = language
            .get_register("SP")
            .unwrap_or_else(|| panic!("Register must already exist: SP"));
        let sp_varnode = Varnode::new(sp_reg.address, sp_reg.bit_length / 8);
        name_to_reg.insert("SP".to_string(), sp_varnode.clone());

        let def_space_id = Varnode::new(const_space.address(def_space.space_id() as i64), 4);

        Self {
            name_to_reg,
            op_list: Vec::new(),
            language,
            def_space,
            const_space,
            unique_space,
            sp_varnode,
            def_space_id,
            unique_base: uniq_base,
            op_address: op_addr,
            seqnum: 0,
        }
    }

    fn push_op(&mut self, opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) {
        let seqnum = self.seqnum;
        self.seqnum += 1;
        self.op_list.push(PcodeOp::with_address(self.op_address.clone(), seqnum, opcode, inputs, output));
    }

    /// Mirrors the private `findTempName(Address)`.
    fn find_temp_name(&self, addr: &Address) -> Option<String> {
        if addr.space() != &self.unique_space {
            return None;
        }
        self.name_to_reg
            .iter()
            .find(|(_, vn)| vn.get_address() == addr)
            .map(|(name, _)| name.clone())
    }

    /// Mirrors the private `findRegister(String)`.
    ///
    /// # Panics
    ///
    /// Panics if no such register exists (mirrors Java's `IllegalArgumentException`).
    fn find_register(&mut self, name: &str) -> Varnode {
        if let Some(vn) = self.name_to_reg.get(name) {
            return vn.clone();
        }
        let reg = self
            .language
            .get_register(name)
            .unwrap_or_else(|| panic!("Register must already exist: {name}"));
        let vn = Varnode::new(reg.address, reg.bit_length / 8);
        self.name_to_reg.insert(name.to_string(), vn.clone());
        vn
    }

    /// Mirrors the private `findVarnode(String, int)`.
    ///
    /// # Panics
    ///
    /// Panics if `name` already names a varnode of a different size (mirrors Java's
    /// `IllegalArgumentException`).
    fn find_varnode(&mut self, name: &str, size: i32) -> Varnode {
        if let Some(vn) = self.name_to_reg.get(name) {
            if vn.get_size() != size {
                panic!("Cannot find varnode: {name}");
            }
            return vn.clone();
        }
        if let Some(reg) = self.language.get_register(name) {
            if reg.bit_length == size * 8 {
                let vn = Varnode::new(reg.address, reg.bit_length / 8);
                self.name_to_reg.insert(name.to_string(), vn.clone());
                return vn;
            }
        }
        let vn = Varnode::new(self.unique_space.address(self.unique_base), size);
        self.unique_base += 16;
        self.name_to_reg.insert(name.to_string(), vn.clone());
        vn
    }

    /// Mirrors the private `constantOrRegister(String)`.
    ///
    /// # Deviations
    ///
    /// Java's `name.charAt(0) <= '9'` is not an `isDigit` check: it also matches every ASCII
    /// character below `'9'` (0x39) that isn't a digit -- e.g. `'-'`, `'!'`, `'#'`, space, and so
    /// on -- routing any such name into [`long_decode`] instead of a register lookup. Faithfully
    /// preserved (see the dedicated test) rather than "fixed" into a real digit check.
    ///
    /// # Panics
    ///
    /// Panics on an empty `name` (Java: `charAt(0)` throws `StringIndexOutOfBoundsException`),
    /// on malformed numeric input (see [`long_decode`]), or if `name` doesn't name an existing
    /// register (see [`Self::find_register`]).
    fn constant_or_register(&mut self, name: &str) -> Varnode {
        let first = name
            .chars()
            .next()
            .expect("empty varnode/register name (Java: charAt(0) throws StringIndexOutOfBoundsException)");
        if first <= '9' {
            let val = long_decode(name);
            self.get_constant(val, 8)
        } else {
            self.find_register(name)
        }
    }

    /// Mirrors the private `getConstant(long, int)`.
    fn get_constant(&self, val: i64, size: i32) -> Varnode {
        Varnode::new(self.const_space.address(val), size)
    }

    /// Mirrors the private `findOpCode(String)`.
    fn find_opcode(name: &str) -> OpCode {
        if name == "cpool" {
            OpCode::CpoolRef
        } else {
            OpCode::Copy
        }
    }

    /// Shared "is this a userop, or an ordinary opcode" branch used by both
    /// [`Self::emit_assign_varnode_from_pcode_op_call`] and
    /// [`Self::emit_assign_register_from_pcode_op_call`].
    fn build_call_inputs(&mut self, pcodeop: &str, userop_index: Option<i32>, args: &[&str]) -> (OpCode, Vec<Varnode>) {
        match userop_index {
            Some(index) => {
                let mut inputs = Vec::with_capacity(args.len() + 1);
                inputs.push(self.get_constant(index as i64, 4));
                for &a in args {
                    inputs.push(self.constant_or_register(a));
                }
                (OpCode::CallOther, inputs)
            }
            None => {
                let mut inputs = Vec::with_capacity(args.len());
                for &a in args {
                    inputs.push(self.constant_or_register(a));
                }
                (Self::find_opcode(pcodeop), inputs)
            }
        }
    }

    /// Returns the p-code ops emitted so far.
    ///
    /// Mirrors `getPcodeOps()`.
    pub fn get_pcode_ops(&self) -> Vec<PcodeOp> {
        self.op_list.clone()
    }

    /// Declares `name` as a temporary/register of the given size, without emitting any p-code.
    ///
    /// Mirrors `defineTemp(String, int)`.
    ///
    /// # Panics
    ///
    /// Panics if `name` already refers to a non-unique varnode (e.g. a real register) or one of
    /// a different size (mirrors Java's `IllegalArgumentException`).
    pub fn define_temp(&mut self, name: &str, size: i32) {
        let vn = self.find_varnode(name, size);
        if !vn.is_unique() || vn.get_size() != size {
            panic!("Name is already assigned: {name}");
        }
    }

    /// Emits p-code to push a value of computational category 1 onto the stack.
    ///
    /// Mirrors `emitPushCat1Value(String)`.
    pub fn emit_push_cat1_value(&mut self, value_name: &str) {
        let sp_size = self.sp_varnode.get_size();
        let sub_inputs = vec![self.sp_varnode.clone(), self.get_constant(4, sp_size)];
        self.push_op(OpCode::IntSub, sub_inputs, Some(self.sp_varnode.clone()));

        let value_vn = self.find_register(value_name);
        let store_inputs = vec![self.def_space_id.clone(), self.sp_varnode.clone(), value_vn];
        self.push_op(OpCode::Store, store_inputs, None);
    }

    /// Emits p-code to push a value of computational category 2 onto the stack.
    ///
    /// Mirrors `emitPushCat2Value(String)`.
    pub fn emit_push_cat2_value(&mut self, value_name: &str) {
        let sp_size = self.sp_varnode.get_size();
        let sub_inputs = vec![self.sp_varnode.clone(), self.get_constant(8, sp_size)];
        self.push_op(OpCode::IntSub, sub_inputs, Some(self.sp_varnode.clone()));

        let value_vn = self.find_register(value_name);
        let store_inputs = vec![self.def_space_id.clone(), self.sp_varnode.clone(), value_vn];
        self.push_op(OpCode::Store, store_inputs, None);
    }

    /// Emits p-code to pop a value of computational category 2 from the stack.
    ///
    /// Mirrors `emitPopCat2Value(String)`.
    pub fn emit_pop_cat2_value(&mut self, dest_name: &str) {
        let out = self.find_varnode(dest_name, 8);
        let load_inputs = vec![self.def_space_id.clone(), self.sp_varnode.clone()];
        self.push_op(OpCode::Load, load_inputs, Some(out));

        let sp_size = self.sp_varnode.get_size();
        let add_inputs = vec![self.sp_varnode.clone(), self.get_constant(8, sp_size)];
        self.push_op(OpCode::IntAdd, add_inputs, Some(self.sp_varnode.clone()));
    }

    /// Emits p-code to pop a value of computational category 1 from the stack.
    ///
    /// Mirrors `emitPopCat1Value(String)`.
    pub fn emit_pop_cat1_value(&mut self, dest_name: &str) {
        let out = self.find_varnode(dest_name, 4);
        let load_inputs = vec![self.def_space_id.clone(), self.sp_varnode.clone()];
        self.push_op(OpCode::Load, load_inputs, Some(out));

        let sp_size = self.sp_varnode.get_size();
        let add_inputs = vec![self.sp_varnode.clone(), self.get_constant(4, sp_size)];
        self.push_op(OpCode::IntAdd, add_inputs, Some(self.sp_varnode.clone()));
    }

    /// Emits p-code to assign the result of a black-box pcodeop call (`args.len()` arguments) to
    /// a varnode.
    ///
    /// Mirrors `emitAssignVarnodeFromPcodeOpCall(String, int, String, String...)`.
    pub fn emit_assign_varnode_from_pcode_op_call(
        &mut self,
        varnode_name: &str,
        size: i32,
        pcodeop: &str,
        args: &[&str],
    ) {
        let userop_index = self.language.find_userop_index(pcodeop);
        let out = self.find_varnode(varnode_name, size);
        let (opcode, inputs) = self.build_call_inputs(pcodeop, userop_index, args);
        self.push_op(opcode, inputs, Some(out));
    }

    /// Emits p-code to call a void black-box pcodeop.
    ///
    /// Mirrors `emitVoidPcodeOpCall(String, String...)`.
    ///
    /// # Deviations / preserved quirks
    ///
    /// Unlike [`Self::emit_assign_varnode_from_pcode_op_call`]/
    /// [`Self::emit_assign_register_from_pcode_op_call`], Java's real method has **no**
    /// `instanceof UseropSymbol` check here: it unconditionally casts whatever
    /// `findGlobalSymbol` returned to `UseropSymbol` and calls `.getIndex()`, throwing
    /// `ClassCastException`/`NullPointerException` if `pcodeop` doesn't actually name a userop.
    /// This port panics the same way for the same reason -- faithfully preserved, not
    /// "generously" falling back to [`Self::find_opcode`] like its two siblings do.
    ///
    /// # Panics
    ///
    /// Panics if `pcodeop` doesn't name a userop symbol. See above.
    pub fn emit_void_pcode_op_call(&mut self, pcodeop: &str, args: &[&str]) {
        let index = self.language.find_userop_index(pcodeop).unwrap_or_else(|| {
            panic!(
                "emitVoidPcodeOpCall requires a userop pcodeop (Java: unchecked cast/NPE here): {pcodeop}"
            )
        });
        let mut inputs = Vec::with_capacity(args.len() + 1);
        inputs.push(self.get_constant(index as i64, 4));
        for &a in args {
            inputs.push(self.constant_or_register(a));
        }
        self.push_op(OpCode::CallOther, inputs, None);
    }

    /// Appends the p-code to assign an integer constant to a register.
    ///
    /// Mirrors `emitAssignConstantToRegister(String, int)`.
    pub fn emit_assign_constant_to_register(&mut self, register: &str, constant: i32) {
        let out = self.find_register(register);
        let inputs = vec![self.get_constant(constant as i64, out.get_size())];
        self.push_op(OpCode::Copy, inputs, Some(out));
    }

    /// Appends the p-code to assign a register to the result of a pcodeop call with `args`.
    ///
    /// Mirrors `emitAssignRegisterFromPcodeOpCall(String, String, String...)`.
    pub fn emit_assign_register_from_pcode_op_call(&mut self, register: &str, pcodeop: &str, args: &[&str]) {
        let userop_index = self.language.find_userop_index(pcodeop);
        let out = self.find_register(register);
        let (opcode, inputs) = self.build_call_inputs(pcodeop, userop_index, args);
        self.push_op(opcode, inputs, Some(out));
    }

    /// Appends the p-code to write a value at an offset of a named memory space.
    ///
    /// Mirrors `emitWriteToMemory(String, int, String, String)`. See [`Self::constant_or_register`]
    /// for the "is this numeric" quirk this shares.
    ///
    /// # Panics
    ///
    /// Panics on an empty `offset`, on an `offset` starting with a digit-like character but
    /// missing its `":size"` suffix, or on malformed numeric text (mirroring Java's
    /// `ArrayIndexOutOfBoundsException`/`NumberFormatException`).
    pub fn emit_write_to_memory(&mut self, space: &str, size: i32, offset: &str, value: &str) {
        let spc = self.language.get_address_space(space);
        let mut inputs = Vec::with_capacity(3);
        inputs.push(self.get_constant(spc.space_id() as i64, 4));

        let first = offset
            .chars()
            .next()
            .expect("empty offset (Java: charAt(0) throws StringIndexOutOfBoundsException)");
        if first <= '9' {
            let mut piece = offset.split(':');
            let val_str = piece.next().unwrap();
            let sz_str = piece.next().unwrap_or_else(|| {
                panic!("emitWriteToMemory offset missing \":size\" suffix: {offset}")
            });
            let sz: i32 = sz_str
                .parse()
                .unwrap_or_else(|_| panic!("For input string: \"{sz_str}\""));
            let val = long_decode(val_str);
            inputs.push(self.get_constant(val, sz));
        } else {
            inputs.push(self.find_register(offset));
        }
        inputs.push(self.find_varnode(value, size));
        self.push_op(OpCode::Store, inputs, None);
    }

    /// Appends the p-code to emit an indirect call through `target`.
    ///
    /// Mirrors `emitIndirectCall(String)`.
    pub fn emit_indirect_call(&mut self, target: &str) {
        let input = self.find_register(target);
        self.push_op(OpCode::CallInd, vec![input], None);
    }

    /// Appends the p-code to sign-extend `src` into `dest`.
    ///
    /// Mirrors `emitSignExtension(String, int, String)`.
    pub fn emit_sign_extension(&mut self, dest: &str, size: i32, src: &str) {
        let out = self.find_varnode(dest, size);
        let input = self.find_register(src);
        self.push_op(OpCode::IntSext, vec![input], Some(out));
    }

    /// Appends the p-code to zero-extend `src` into `dest`.
    ///
    /// Mirrors `emitZeroExtension(String, int, String)`.
    pub fn emit_zero_extension(&mut self, dest: &str, size: i32, src: &str) {
        let out = self.find_varnode(dest, size);
        let input = self.find_register(src);
        self.push_op(OpCode::IntZext, vec![input], Some(out));
    }

    /// Appends the p-code to truncate `src` into `dest`.
    ///
    /// Mirrors `emitTruncate(String, int, String)`.
    pub fn emit_truncate(&mut self, dest: &str, size: i32, src: &str) {
        let out = self.find_varnode(dest, size);
        let inputs = vec![self.find_register(src), self.get_constant(0, 4)];
        self.push_op(OpCode::Subpiece, inputs, Some(out));
    }

    /// Appends the p-code to assign `lhs` from a dereference of `rhs`.
    ///
    /// Mirrors `emitAssignVarnodeFromDereference(String, int, String)`.
    pub fn emit_assign_varnode_from_dereference(&mut self, lhs: &str, size: i32, rhs: &str) {
        let out = self.find_varnode(lhs, size);
        let input = self.find_register(rhs);
        let inputs = vec![self.def_space_id.clone(), input];
        self.push_op(OpCode::Load, inputs, Some(out));
    }

    /// Mirrors the private `compareVarnode(Varnode, Varnode, PcodeOpEmitter)`.
    fn compare_varnode(&self, vn1: Option<&Varnode>, vn2: Option<&Varnode>, op2: &PcodeOpEmitter) -> bool {
        let (vn1, vn2) = match (vn1, vn2) {
            (None, None) => return true,
            (None, Some(_)) | (Some(_), None) => return false,
            (Some(a), Some(b)) => (a, b),
        };
        if vn1.get_size() != vn2.get_size() {
            return false;
        }
        if vn1.get_address().space() != vn2.get_address().space() {
            return false;
        }
        if vn1.get_offset() == vn2.get_offset() {
            return true;
        }
        let Some(name1) = self.find_temp_name(vn1.get_address()) else {
            return false;
        };
        let Some(name2) = op2.find_temp_name(vn2.get_address()) else {
            return false;
        };
        name1 == name2
    }
}

impl<'a> PartialEq for PcodeOpEmitter<'a> {
    /// Mirrors `equals(Object)`. Java's version unconditionally downcasts `obj` to
    /// `PcodeOpEmitter` (`ClassCastException` if it isn't one); comparing two `&Self` values
    /// makes that downcast a non-issue here -- it's simply not representable.
    fn eq(&self, op2: &Self) -> bool {
        if self.op_list.len() != op2.op_list.len() {
            return false;
        }
        for i in 0..self.op_list.len() {
            let aop = &self.op_list[i];
            let bop = &op2.op_list[i];
            if aop.get_opcode() != bop.get_opcode() {
                return false;
            }
            if aop.get_num_inputs() != bop.get_num_inputs() {
                return false;
            }
            if !self.compare_varnode(aop.get_output(), bop.get_output(), op2) {
                return false;
            }
            for j in 0..aop.get_num_inputs() {
                if !self.compare_varnode(aop.get_input(j), bop.get_input(j), op2) {
                    return false;
                }
            }
        }
        true
    }
}

impl<'a> Eq for PcodeOpEmitter<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    /// A minimal [`PcodeOpEmitterLanguage`] backing a handful of named registers, one userop
    /// (`"myop"` at index 5), and the four address spaces `PcodeOpEmitter` always needs.
    struct MockLanguage {
        registers: HashMap<&'static str, (i64, i32)>, // name -> (offset, bit_length)
        register_space: Arc<AddressSpace>,
        const_space: Arc<AddressSpace>,
        default_space: Arc<AddressSpace>,
        unique_space: Arc<AddressSpace>,
        ram_space: Arc<AddressSpace>,
        userops: HashMap<&'static str, i32>,
    }

    impl MockLanguage {
        fn new() -> Self {
            let mut registers = HashMap::new();
            registers.insert("SP", (0i64, 32));
            registers.insert("A", (4i64, 32));
            registers.insert("B", (8i64, 32));
            registers.insert("W", (12i64, 64)); // 8-byte-wide register, for cat2 tests

            let mut userops = HashMap::new();
            userops.insert("myop", 5);

            MockLanguage {
                registers,
                register_space: AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0),
                const_space: AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0),
                default_space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
                unique_space: AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 0),
                ram_space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
                userops,
            }
        }
    }

    impl PcodeOpEmitterLanguage for MockLanguage {
        fn get_constant_space(&self) -> Arc<AddressSpace> {
            self.const_space.clone()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.default_space.clone()
        }
        fn get_unique_space(&self) -> Arc<AddressSpace> {
            self.unique_space.clone()
        }
        fn get_address_space(&self, name: &str) -> Arc<AddressSpace> {
            match name {
                "ram" => self.ram_space.clone(),
                "register" => self.register_space.clone(),
                other => panic!("unknown address space: {other}"),
            }
        }
        fn get_register(&self, name: &str) -> Option<RegisterInfo> {
            let &(offset, bit_length) = self.registers.get(name)?;
            Some(RegisterInfo { address: self.register_space.address(offset), bit_length })
        }
        fn find_userop_index(&self, name: &str) -> Option<i32> {
            self.userops.get(name).copied()
        }
    }

    fn op_addr(lang: &MockLanguage) -> Address {
        lang.default_space.address(0x1000)
    }

    #[test]
    fn constructor_binds_sp_and_default_space_id() {
        let lang = MockLanguage::new();
        let emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        assert_eq!(emitter.get_pcode_ops().len(), 0);
    }

    #[test]
    #[should_panic(expected = "Register must already exist: SP")]
    fn constructor_panics_without_an_sp_register() {
        let mut lang = MockLanguage::new();
        lang.registers.remove("SP");
        let addr = op_addr(&lang);
        let _emitter = PcodeOpEmitter::new(&lang, addr, 0);
    }

    #[test]
    fn emit_push_and_pop_cat1_round_trips_through_the_stack() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_push_cat1_value("A");
        emitter.emit_pop_cat1_value("B");
        let ops = emitter.get_pcode_ops();
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].get_opcode(), OpCode::IntSub);
        assert_eq!(ops[1].get_opcode(), OpCode::Store);
        assert_eq!(ops[2].get_opcode(), OpCode::Load);
        assert_eq!(ops[3].get_opcode(), OpCode::IntAdd);
        // The STORE's value operand is register "A"'s varnode.
        assert_eq!(ops[1].get_input(2).unwrap().get_size(), 4);
    }

    #[test]
    fn emit_push_and_pop_cat2_uses_eight_byte_stack_adjustment() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_push_cat2_value("W");
        let ops = emitter.get_pcode_ops();
        // INT_SUB's second input is the constant "8".
        assert_eq!(ops[0].get_input(1).unwrap().get_offset(), 8);
    }

    #[test]
    fn emit_assign_varnode_from_pcode_op_call_uses_callother_for_a_userop() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.define_temp("result", 4);
        emitter.emit_assign_varnode_from_pcode_op_call("result", 4, "myop", &["A", "5"]);
        let ops = emitter.get_pcode_ops();
        let op = ops.last().unwrap();
        assert_eq!(op.get_opcode(), OpCode::CallOther);
        // in[0] is the userop index constant (5).
        assert_eq!(op.get_input(0).unwrap().get_offset(), 5);
    }

    #[test]
    fn emit_assign_varnode_from_pcode_op_call_falls_back_to_find_opcode_for_non_userops() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.define_temp("result", 4);
        emitter.emit_assign_varnode_from_pcode_op_call("result", 4, "cpool", &["A"]);
        let ops = emitter.get_pcode_ops();
        assert_eq!(ops.last().unwrap().get_opcode(), OpCode::CpoolRef);
    }

    #[test]
    fn emit_assign_varnode_from_pcode_op_call_uses_copy_for_an_unknown_non_cpool_name() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.define_temp("result", 4);
        emitter.emit_assign_varnode_from_pcode_op_call("result", 4, "notauserop", &["A"]);
        assert_eq!(emitter.get_pcode_ops().last().unwrap().get_opcode(), OpCode::Copy);
    }

    /// Faithful reproduction of the Java quirk documented on
    /// [`PcodeOpEmitter::emit_void_pcode_op_call`]: unlike its two siblings, it never falls back
    /// to [`PcodeOpEmitter::find_opcode`] -- it panics if `pcodeop` isn't a userop.
    #[test]
    #[should_panic(expected = "emitVoidPcodeOpCall requires a userop pcodeop")]
    fn emit_void_pcode_op_call_panics_for_a_non_userop() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_void_pcode_op_call("cpool", &["A"]);
    }

    #[test]
    fn emit_void_pcode_op_call_emits_callother_for_a_userop() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_void_pcode_op_call("myop", &["A", "B"]);
        let op = emitter.get_pcode_ops().into_iter().next().unwrap();
        assert_eq!(op.get_opcode(), OpCode::CallOther);
        assert!(op.get_output().is_none());
        assert_eq!(op.get_num_inputs(), 3); // index + 2 args
    }

    #[test]
    fn emit_assign_constant_to_register() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_assign_constant_to_register("A", 42);
        let op = emitter.get_pcode_ops().into_iter().next().unwrap();
        assert_eq!(op.get_opcode(), OpCode::Copy);
        assert_eq!(op.get_input(0).unwrap().get_offset(), 42);
    }

    #[test]
    fn emit_write_to_memory_with_a_register_offset() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_write_to_memory("ram", 4, "A", "B");
        let op = emitter.get_pcode_ops().into_iter().next().unwrap();
        assert_eq!(op.get_opcode(), OpCode::Store);
        // in[1] is register A's varnode (its offset within the *register* space is 4).
        assert_eq!(op.get_input(1).unwrap().get_offset(), 4);
    }

    #[test]
    fn emit_write_to_memory_with_a_numeric_colon_sized_offset() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_write_to_memory("ram", 4, "16:4", "A");
        let op = emitter.get_pcode_ops().into_iter().next().unwrap();
        assert_eq!(op.get_input(1).unwrap().get_offset(), 16);
        assert_eq!(op.get_input(1).unwrap().get_size(), 4);
    }

    #[test]
    fn emit_indirect_call() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_indirect_call("A");
        assert_eq!(emitter.get_pcode_ops()[0].get_opcode(), OpCode::CallInd);
    }

    #[test]
    fn emit_sign_and_zero_extension_and_truncate() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_sign_extension("sx", 8, "A");
        emitter.emit_zero_extension("zx", 8, "B");
        emitter.emit_truncate("tr", 4, "W");
        let ops = emitter.get_pcode_ops();
        assert_eq!(ops[0].get_opcode(), OpCode::IntSext);
        assert_eq!(ops[1].get_opcode(), OpCode::IntZext);
        assert_eq!(ops[2].get_opcode(), OpCode::Subpiece);
        assert_eq!(ops[2].get_input(1).unwrap().get_offset(), 0);
    }

    #[test]
    fn emit_assign_varnode_from_dereference() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_assign_varnode_from_dereference("deref", 4, "A");
        let op = emitter.get_pcode_ops().into_iter().next().unwrap();
        assert_eq!(op.get_opcode(), OpCode::Load);
    }

    #[test]
    fn define_temp_on_a_fresh_name_succeeds() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.define_temp("t1", 4); // does not panic
    }

    #[test]
    #[should_panic(expected = "Name is already assigned: A")]
    fn define_temp_on_an_existing_register_panics() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.find_register_for_test("A"); // registers "A" as a non-unique varnode first
        emitter.define_temp("A", 4);
    }

    // Small test-only accessor so the test above can force "A" into `name_to_reg` the same way
    // any real emit_* call would, without depending on emit_* method ordering.
    impl<'lang> PcodeOpEmitter<'lang> {
        fn find_register_for_test(&mut self, name: &str) -> Varnode {
            self.find_register(name)
        }
    }

    /// Faithful reproduction of the Java quirk documented on
    /// [`PcodeOpEmitter::constant_or_register`]: any name whose first character's code point is
    /// `<= '9'` -- not just actual digits -- is routed to [`long_decode`], including a leading
    /// `'-'` (intentional, for negative literals) but also, e.g., a leading `'!'`.
    #[test]
    fn constant_or_register_treats_a_leading_minus_as_numeric() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        // "-5" as an arg to a CALLOTHER: constant_or_register("-5") must decode to -5, not
        // attempt (and fail) a register lookup for a register literally named "-5".
        emitter.emit_void_pcode_op_call("myop", &["-5"]);
        let op = emitter.get_pcode_ops().into_iter().next().unwrap();
        assert_eq!(op.get_input(1).unwrap().get_offset(), -5);
    }

    #[test]
    fn get_pcode_ops_returns_an_independent_snapshot() {
        let lang = MockLanguage::new();
        let mut emitter = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        emitter.emit_indirect_call("A");
        let snapshot = emitter.get_pcode_ops();
        emitter.emit_indirect_call("B");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(emitter.get_pcode_ops().len(), 2);
    }

    // ---- equals / compare_varnode ----

    #[test]
    fn equal_emitters_with_identical_ops_compare_equal() {
        let lang = MockLanguage::new();
        let mut a = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        let mut b = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        a.emit_assign_constant_to_register("A", 7);
        b.emit_assign_constant_to_register("A", 7);
        assert_eq!(a, b);
    }

    #[test]
    fn emitters_with_different_opcodes_are_not_equal() {
        let lang = MockLanguage::new();
        let mut a = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        let mut b = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        a.emit_assign_constant_to_register("A", 7);
        b.emit_indirect_call("A");
        assert_ne!(a, b);
    }

    #[test]
    fn emitters_with_different_op_counts_are_not_equal() {
        let lang = MockLanguage::new();
        let mut a = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        let b = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        a.emit_indirect_call("A");
        assert_ne!(a, b);
    }

    #[test]
    fn equal_emitters_with_corresponding_temp_names_compare_equal_despite_different_offsets() {
        // Two independently-constructed emitters each allocate their first unique temp at their
        // own `unique_base`; `compare_varnode`'s temp-name fallback means they still compare
        // equal as long as the *sequence* of temp allocations lines up, exactly mirroring Java's
        // `findTempName`-based structural comparison.
        let lang = MockLanguage::new();
        let mut a = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x100);
        let mut b = PcodeOpEmitter::new(&lang, op_addr(&lang), 0x200); // different unique_base
        a.emit_assign_varnode_from_dereference("tempA", 4, "A");
        b.emit_assign_varnode_from_dereference("tempA", 4, "A");
        assert_eq!(a, b);
    }
}
