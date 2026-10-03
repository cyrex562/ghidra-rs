//! Port of `ghidra.util.state.VarnodeOperation`.
//!
//! Represents a synthetic "virtual" varnode standing in for the result of an unresolved p-code
//! operation -- e.g. built by `SymbolicPropogator` when a value can't be reduced to a concrete
//! constant, but the operation and its (possibly still-symbolic) inputs are worth remembering.
//!
//! ## Composition, not inheritance
//!
//! Java's `VarnodeOperation extends Varnode`, overriding every "kind" predicate (`isAddress`,
//! `isAddrTied`, `isConstant`, `isFree`, `isInput`, `isPersistent`, `isRegister`, `isUnaffected`,
//! `isUnique`) to `false`, overriding `trim()` to a no-op, and overriding `equals`/`hashCode`/
//! `toString`/`toString(Language)`. Following this crate's composition-over-inheritance
//! convention (see [`VarnodeAST`](crate::program::model::pcode::VarnodeAST), which composes the
//! same base for the same reason), this struct composes a `base: Varnode` field for the
//! inherited-and-unoverridden accessors (`getAddress`/`getSize`/`getOffset`/`getSpace`/
//! `encodeRaw`/...) and defines its own methods for everything Java overrides.
//!
//! ## `inputValues`: a recursive `Varnode`-or-`VarnodeOperation` tree, and `null` slots
//!
//! Java's `Varnode[] inputValues` is polymorphic: each element is either a plain `Varnode` or
//! (recursively) another `VarnodeOperation`, built up by callers like `SymbolicPropogator` to
//! represent compound expressions (e.g. `(a + b) * c`). Java arrays can also hold `null` --
//! `toString()` explicitly checks `inputValues[i] == null` -- something a real call site can
//! produce (an operand that could not be resolved at all). This is modeled here as
//! `Vec<Option<VarnodeOperand>>`, where [`VarnodeOperand`] is a two-variant enum standing in for
//! the `Varnode`/`VarnodeOperation` polymorphism Rust has no direct analog for without a trait
//! object (and a trait object would not support the recursive, structurally-compared `equals`
//! Java relies on as cleanly as a concrete enum does).
//!
//! ## Quirk: `equals()` has no null-check, unlike `toString()`
//!
//! `VarnodeOperation.equals` loops `inputValues[i].equals(other.inputValues[i])` with **no**
//! `null` guard, unlike `toString()`'s explicit `if (inputValues[i] == null)` check just above it
//! in the same file. A `null` element of `inputValues` therefore throws a
//! `NullPointerException` from `equals()` (while working fine in `toString()`). This is a real,
//! reachable bug in the upstream class, faithfully reproduced here as a panic from
//! [`PartialEq::eq`] when either side has a `None` input at the same index -- see
//! `equals_panics_on_null_input_quirk` below.
//!
//! ## Quirk: `equals()` never compares the output varnode
//!
//! `VarnodeOperation.equals` compares only `pcodeOp.getOpcode()` and every `inputValues[i]` --
//! never the varnode's own address/size (derived from the defining op's output). Two
//! `VarnodeOperation`s with the same opcode and inputs but different output varnodes (e.g.
//! different sizes) are therefore `equals()` even though they are, in every other sense,
//! different varnodes. Faithfully preserved; see `equals_ignores_output_varnode_quirk` below.

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::Language;
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};
use std::cell::Cell;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Either a plain [`Varnode`] or a nested [`VarnodeOperation`]. Stands in for the
/// `Varnode`/`VarnodeOperation` polymorphism Java's `inputValues` array elements exhibit. See the
/// module docs.
#[derive(Debug, Clone)]
pub enum VarnodeOperand {
    Plain(Varnode),
    Operation(Box<VarnodeOperation>),
}

impl VarnodeOperand {
    /// True if this operand is (recursively) a [`VarnodeOperation`], mirroring Java's
    /// `instanceof VarnodeOperation` checks in `toString`/`toString(Language)`.
    pub fn is_operation(&self) -> bool {
        matches!(self, VarnodeOperand::Operation(_))
    }
}

impl PartialEq for VarnodeOperand {
    /// Mirrors the polymorphic dispatch of Java's `Varnode.equals`/`VarnodeOperation.equals`: a
    /// plain `Varnode` and a `VarnodeOperation` are never equal (`VarnodeOperation.equals`
    /// begins with `if (!(o instanceof VarnodeOperation)) return false;`, and this crate's base
    /// `Varnode::eq` is address/size-structural, which a synthetic operation's derived
    /// address/size essentially never coincidentally matches either).
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VarnodeOperand::Plain(a), VarnodeOperand::Plain(b)) => a == b,
            (VarnodeOperand::Operation(a), VarnodeOperand::Operation(b)) => a == b,
            _ => false,
        }
    }
}

/// A synthetic varnode representing the result of an unresolved p-code operation. Port of
/// `ghidra.util.state.VarnodeOperation`. See the module docs for the composition strategy and
/// preserved Java quirks.
#[derive(Debug, Clone)]
pub struct VarnodeOperation {
    /// Address/size state, derived from the defining `pcodeOp`'s output. Port of the implicit
    /// superclass state (`Varnode`'s own `address`/`size` fields).
    base: Varnode,
    /// The p-code operation this varnode represents the (unresolved) result of. Port of the
    /// private `pcodeOp` field.
    pcode_op: PcodeOp,
    /// The (possibly symbolic, possibly `null`) input values to `pcode_op`. Port of the private
    /// `inputValues` field. See the module docs for the `Option<VarnodeOperand>` typing.
    input_values: Vec<Option<VarnodeOperand>>,
    /// Port of the private `simplified` field. `Cell` for interior mutability, matching this
    /// crate's established pattern for Java's small mutable boolean fields accessed through
    /// otherwise-`&self` accessor methods (e.g. `VarnodeAST`'s `b_input`/`b_free`/...).
    simplified: Cell<bool>,
}

impl VarnodeOperation {
    /// Port of `VarnodeOperation(PcodeOp, Varnode[])`.
    pub fn new(pcode_op: PcodeOp, input_values: Vec<Option<VarnodeOperand>>) -> Self {
        let size = Self::op_output_size(&pcode_op);
        let base = Varnode::new(pcode_op.get_seqnum().get_target().clone(), size);
        VarnodeOperation { base, pcode_op, input_values, simplified: Cell::new(false) }
    }

    /// Port of the private static `VarnodeOperation.getSize(PcodeOp)`.
    fn op_output_size(op: &PcodeOp) -> i32 {
        match op.get_output() {
            Some(v) => v.get_size(),
            None => 0,
        }
    }

    /// Port of `VarnodeOperation.isSimplified()`.
    pub fn is_simplified(&self) -> bool {
        self.simplified.get()
    }

    /// Port of `VarnodeOperation.setSimplified(boolean)`.
    pub fn set_simplified(&self, simplified: bool) {
        self.simplified.set(simplified);
    }

    /// Port of `VarnodeOperation.getPCodeOp()`.
    pub fn get_pcode_op(&self) -> &PcodeOp {
        &self.pcode_op
    }

    /// Port of `VarnodeOperation.getInputValues()`.
    pub fn get_input_values(&self) -> &[Option<VarnodeOperand>] {
        &self.input_values
    }

    // ---- Inherited from `Varnode`, unoverridden by Java's `VarnodeOperation`. ----

    /// Port of the inherited `Varnode.getAddress()`.
    pub fn get_address(&self) -> &Address {
        self.base.get_address()
    }

    /// Port of the inherited `Varnode.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.base.get_size()
    }

    /// Port of the inherited `Varnode.getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.base.get_offset()
    }

    /// Port of the inherited `Varnode.getSpace()` (returns the space id, matching real Java's
    /// `int getSpace()`).
    pub fn get_space_id(&self) -> i32 {
        self.base.get_space_id()
    }

    // ---- Overridden by Java's `VarnodeOperation`: every "kind" predicate is forced `false`. ----

    /// Port of `VarnodeOperation.isAddress()`.
    pub fn is_address(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isAddrTied()`.
    pub fn is_addr_tied(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isConstant()`.
    pub fn is_constant(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isFree()`.
    pub fn is_free(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isInput()`.
    pub fn is_input(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isPersistent()`.
    pub fn is_persistent(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isRegister()`.
    pub fn is_register(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isUnaffected()`.
    pub fn is_unaffected(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.isUnique()`.
    pub fn is_unique(&self) -> bool {
        false
    }

    /// Port of `VarnodeOperation.trim()`: a no-op override (base `Varnode.trim()` masks constant
    /// varnodes to size, but this varnode is never `isConstant()`).
    pub fn trim(&mut self) {}

    // ---- toString variants. ----

    /// Port of the private `VarnodeOperation.getIndirectString(Language)`.
    fn get_indirect_string(&self, language: Option<&dyn Language>) -> String {
        let output = self
            .pcode_op
            .get_output()
            .expect("VarnodeOperation::get_indirect_string: INDIRECT op has no output (Java's equivalent would NullPointerException dereferencing a null getOutput() too)");
        let mnemonic = self.pcode_op.get_mnemonic();
        let target = self.pcode_op.get_seqnum().get_target();
        match language {
            None => format!("{mnemonic}[{output}, @{target}]"),
            Some(lang) => format!("{mnemonic}[{}, @{target}]", output.to_string_with_language(lang)),
        }
    }

    /// Port of `VarnodeOperation.toString()`.
    pub fn to_string_plain(&self) -> String {
        if self.pcode_op.get_opcode() == OpCode::Indirect {
            return self.get_indirect_string(None);
        }
        let mut s = format!("{} ", self.pcode_op.get_mnemonic());
        for (i, input) in self.input_values.iter().enumerate() {
            match input {
                None => s.push_str("null"),
                Some(VarnodeOperand::Operation(op)) => {
                    s.push('{');
                    s.push_str(&op.to_string_plain());
                    s.push('}');
                }
                Some(VarnodeOperand::Plain(v)) => s.push_str(&v.to_string()),
            }
            if i < self.input_values.len() - 1 {
                s.push_str(", ");
            }
        }
        s
    }

    /// Port of `VarnodeOperation.toString(Language)`.
    pub fn to_string_with_language(&self, language: &dyn Language) -> String {
        if self.pcode_op.get_opcode() == OpCode::Indirect {
            return self.get_indirect_string(Some(language));
        }
        let mut s = format!("{} ", self.pcode_op.get_mnemonic());
        for (i, input) in self.input_values.iter().enumerate() {
            if i == 0 && matches!(self.pcode_op.get_opcode(), OpCode::Load | OpCode::Store) {
                if let Some(VarnodeOperand::Plain(v0)) = input {
                    let space: Option<Arc<AddressSpace>> =
                        language.get_address_factory().get_address_space_by_id(v0.get_offset() as i32);
                    if let Some(space) = space {
                        s.push('[');
                        s.push_str(space.name());
                        s.push_str("], ");
                        continue;
                    }
                }
            }
            match input {
                None => s.push_str("null"),
                Some(VarnodeOperand::Operation(op)) => {
                    s.push('{');
                    s.push_str(&op.to_string_with_language(language));
                    s.push('}');
                }
                Some(VarnodeOperand::Plain(v)) => s.push_str(&v.to_string_with_language(language)),
            }
            if i < self.input_values.len() - 1 {
                s.push_str(", ");
            }
        }
        s
    }
}

impl std::fmt::Display for VarnodeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_plain())
    }
}

impl PartialEq for VarnodeOperation {
    /// Port of `VarnodeOperation.equals(Object)`. See the module docs for the two preserved
    /// quirks: no `null`-input guard (panics, mirroring a Java `NullPointerException`), and the
    /// output varnode is never compared.
    fn eq(&self, other: &Self) -> bool {
        if std::ptr::eq(self, other) {
            return true;
        }
        if self.pcode_op.get_opcode() != other.pcode_op.get_opcode() {
            return false;
        }
        for i in 0..self.input_values.len() {
            let a = self.input_values[i]
                .as_ref()
                .expect("VarnodeOperation::eq: null input element (Java's equivalent would NullPointerException calling .equals() on it too)");
            let b = &other.input_values[i];
            match b {
                None => panic!(
                    "VarnodeOperation::eq: comparing against a null input element (Java's equivalent would NullPointerException too)"
                ),
                Some(b) => {
                    if a != b {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl Eq for VarnodeOperation {}

impl Hash for VarnodeOperation {
    /// Port of `VarnodeOperation.hashCode()`: just `pcodeOp.getSeqnum().hashCode()`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pcode_op.get_seqnum().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn plain(offset: i64, size: i32) -> Varnode {
        Varnode::new(addr(offset), size)
    }

    fn op_at(offset: i64, opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        PcodeOp::new(opcode, SequenceNumber::new(addr(offset), 0), inputs, output)
    }

    fn simple_add(offset: i64) -> VarnodeOperation {
        let output = plain(offset, 4);
        let op = op_at(offset, OpCode::IntAdd, vec![plain(0x10, 4), plain(0x20, 4)], Some(output));
        VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(plain(0x10, 4))),
                Some(VarnodeOperand::Plain(plain(0x20, 4))),
            ],
        )
    }

    #[test]
    fn new_derives_address_and_size_from_pcode_op_output() {
        let v = simple_add(0x1000);
        assert_eq!(v.get_address(), &addr(0x1000));
        assert_eq!(v.get_size(), 4);
    }

    #[test]
    fn new_with_no_output_has_size_zero() {
        let op = op_at(0x2000, OpCode::Branch, vec![], None);
        let v = VarnodeOperation::new(op, vec![]);
        assert_eq!(v.get_size(), 0);
    }

    #[test]
    fn all_kind_predicates_are_false() {
        let v = simple_add(0x1000);
        assert!(!v.is_address());
        assert!(!v.is_addr_tied());
        assert!(!v.is_constant());
        assert!(!v.is_free());
        assert!(!v.is_input());
        assert!(!v.is_persistent());
        assert!(!v.is_register());
        assert!(!v.is_unaffected());
        assert!(!v.is_unique());
    }

    /// Even a varnode whose output lives in the constant space is never `is_constant()` --
    /// unlike the base `Varnode`, `VarnodeOperation` hard-codes every predicate to `false`.
    #[test]
    fn is_constant_overridden_even_for_constant_space_output() {
        let output = Varnode::new(Address::new(const_space(), 5), 4);
        let op = op_at(0x1000, OpCode::Copy, vec![plain(0x10, 4)], Some(output));
        let v = VarnodeOperation::new(op, vec![Some(VarnodeOperand::Plain(plain(0x10, 4)))]);
        assert!(!v.is_constant());
    }

    #[test]
    fn trim_is_a_no_op() {
        let mut v = simple_add(0x1000);
        let before = v.get_address().clone();
        v.trim();
        assert_eq!(v.get_address(), &before, "trim() must not alter address/size");
    }

    #[test]
    fn simplified_flag_round_trips() {
        let v = simple_add(0x1000);
        assert!(!v.is_simplified());
        v.set_simplified(true);
        assert!(v.is_simplified());
    }

    #[test]
    fn to_string_plain_joins_inputs_with_mnemonic() {
        let v = simple_add(0x1000);
        let s = v.to_string_plain();
        assert!(s.starts_with(&format!("{} ", OpCode::IntAdd.mnemonic())));
        assert!(s.contains(", "));
    }

    #[test]
    fn to_string_plain_handles_null_input_and_nested_operation() {
        let inner = simple_add(0x1000);
        let op = op_at(
            0x2000,
            OpCode::IntMult,
            vec![plain(0x30, 4)],
            Some(plain(0x2000, 4)),
        );
        let v = VarnodeOperation::new(
            op,
            vec![None, Some(VarnodeOperand::Operation(Box::new(inner)))],
        );
        let s = v.to_string_plain();
        assert!(s.contains("null"), "null input must render as the literal string \"null\"");
        assert!(s.contains('{') && s.contains('}'), "nested VarnodeOperation must render braced");
    }

    #[test]
    fn to_string_plain_indirect_op_uses_indirect_format() {
        let output = plain(0x3000, 4);
        let op = op_at(0x3000, OpCode::Indirect, vec![plain(0x10, 4), plain(0x20, 4)], Some(output.clone()));
        let v = VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(plain(0x10, 4))),
                Some(VarnodeOperand::Plain(plain(0x20, 4))),
            ],
        );
        let s = v.to_string_plain();
        assert!(s.starts_with(&format!("{}[", OpCode::Indirect.mnemonic())));
        assert!(s.contains(&output.to_string()));
    }

    #[test]
    #[should_panic(expected = "INDIRECT op has no output")]
    fn to_string_plain_indirect_op_with_no_output_panics_like_java_npe() {
        let op = op_at(0x3000, OpCode::Indirect, vec![plain(0x10, 4)], None);
        let v = VarnodeOperation::new(op, vec![Some(VarnodeOperand::Plain(plain(0x10, 4)))]);
        v.to_string_plain();
    }

    #[test]
    fn equals_true_for_same_opcode_and_equal_inputs_regardless_of_output() {
        // Faithful reproduction of a real Java quirk: `equals()` never compares the derived
        // output varnode (address/size), only `pcodeOp.getOpcode()` and `inputValues`. Two
        // operations built from ops with different outputs (different defining addresses here)
        // still compare equal.
        let op_a = op_at(0x1000, OpCode::IntAdd, vec![], Some(plain(0x1000, 4)));
        let op_b = op_at(0x9999, OpCode::IntAdd, vec![], Some(plain(0x9999, 8)));
        let a = VarnodeOperation::new(
            op_a,
            vec![
                Some(VarnodeOperand::Plain(plain(0x10, 4))),
                Some(VarnodeOperand::Plain(plain(0x20, 4))),
            ],
        );
        let b = VarnodeOperation::new(
            op_b,
            vec![
                Some(VarnodeOperand::Plain(plain(0x10, 4))),
                Some(VarnodeOperand::Plain(plain(0x20, 4))),
            ],
        );

        assert_ne!(a.get_address(), b.get_address(), "sanity: outputs really do differ");
        assert_eq!(a, b, "equals() quirk: output varnode is never compared");
    }

    #[test]
    fn equals_false_for_different_opcode() {
        let op_a = op_at(0x1000, OpCode::IntAdd, vec![], Some(plain(0x1000, 4)));
        let op_b = op_at(0x1000, OpCode::IntSub, vec![], Some(plain(0x1000, 4)));
        let a = VarnodeOperation::new(op_a, vec![Some(VarnodeOperand::Plain(plain(0x10, 4)))]);
        let b = VarnodeOperation::new(op_b, vec![Some(VarnodeOperand::Plain(plain(0x10, 4)))]);
        assert_ne!(a, b);
    }

    #[test]
    fn equals_false_for_different_inputs() {
        let op_a = op_at(0x1000, OpCode::IntAdd, vec![], Some(plain(0x1000, 4)));
        let op_b = op_at(0x1000, OpCode::IntAdd, vec![], Some(plain(0x1000, 4)));
        let a = VarnodeOperation::new(op_a, vec![Some(VarnodeOperand::Plain(plain(0x10, 4)))]);
        let b = VarnodeOperation::new(op_b, vec![Some(VarnodeOperand::Plain(plain(0x11, 4)))]);
        assert_ne!(a, b);
    }

    /// Faithful reproduction of a real Java bug: `equals()` has no `null`-guard on
    /// `inputValues[i]` (unlike `toString()`, which does), so a `null`/`None` input element
    /// crashes `equals()` with what would be a `NullPointerException` in Java.
    #[test]
    #[should_panic(expected = "null input element")]
    fn equals_panics_on_null_input_quirk() {
        let op_a = op_at(0x1000, OpCode::IntAdd, vec![], Some(plain(0x1000, 4)));
        let op_b = op_at(0x1000, OpCode::IntAdd, vec![], Some(plain(0x1000, 4)));
        let a = VarnodeOperation::new(op_a, vec![None]);
        let b = VarnodeOperation::new(op_b, vec![None]);
        let _ = a == b;
    }

    #[test]
    fn hash_matches_pcode_op_seqnum_hash() {
        use std::collections::hash_map::DefaultHasher;

        let v = simple_add(0x1000);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v.hash(&mut h1);
        v.get_pcode_op().get_seqnum().hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn get_pcode_op_and_input_values_accessors() {
        let v = simple_add(0x1000);
        assert_eq!(v.get_pcode_op().get_opcode(), OpCode::IntAdd);
        assert_eq!(v.get_input_values().len(), 2);
    }

    #[test]
    fn varnode_operand_plain_vs_operation_never_equal() {
        let plain_operand = VarnodeOperand::Plain(plain(0x10, 4));
        let op_operand = VarnodeOperand::Operation(Box::new(simple_add(0x10)));
        assert_ne!(plain_operand, op_operand);
        assert!(!plain_operand.is_operation());
        assert!(op_operand.is_operation());
    }
}
