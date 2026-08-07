//! Port of `ghidra.program.model.pcode.DynamicHash`.
//!
//! A hash utility to uniquely identify a temporary Varnode in data-flow. Most Varnodes can be
//! identified within the data-flow graph by their storage address and the address of the
//! `PcodeOp` that defines them. For temporary registers this does not work, because the storage
//! address is ephemeral; `DynamicHash` instead robustly identifies such Varnodes by hashing
//! details of the local data-flow.
//!
//! The Java class is a concrete algorithm class (not an interface), but it was selected as a
//! dependency-cycle cut-point, so its observable instance contract (`getHash()`/`getAddress()`)
//! is promoted to a trait here, following the precedent of other cut-point ports in this module
//! (e.g. [`HighConstant`](crate::program::model::pcode::high_constant::HighConstant)).
//!
//! Most of the class's real work, though, is a multi-level data-flow graph walk (the
//! `Varnode`/`PcodeOp`/`PcodeOp,int` constructors, `calcHash`, `uniqueHash`, `buildVnUp`,
//! `buildVnDown`, `buildOpUp`, `buildOpDown`) plus `PcodeSyntaxTree`-driven static lookups
//! (`findVarnode`, `findOp`, `gatherOpsAtAddress`, `gatherFirstLevelVars`). All of that needs
//! `PcodeSyntaxTree` (not ported here, not even as a placeholder -- the same treatment
//! [`HighParamID`](crate::program::model::pcode::high_param_id::HighParamID) gives it) and
//! graph-linked `VarnodeAST`/`PcodeOpAST` navigation (`getDef`, `getLoneDescend`,
//! `getDescendants`, `getSlot`) that this crate's plain, graph-unlinked
//! [`Varnode`](crate::program::model::pcode::Varnode)/[`PcodeOp`](crate::program::model::pcode::PcodeOp)
//! cannot provide. Since `DynamicHash` was selected purely as a cut-point (nothing currently
//! ported calls into its graph-walk API), that machinery is left unported here rather than
//! growing new placeholder graph-navigation traits speculatively.
//!
//! What *is* fully self-contained and ported faithfully:
//! - [`canonical_opcode`], standing in for the public `transtable` field (the lookup used to
//!   collapse related opcodes -- e.g. `INT_SLESSEQUAL` hashes the same as `INT_SLESS` -- onto one
//!   canonical value, or `None` to mean "skip this op").
//! - The seven hash-bitfield accessors/mutators (`getSlotFromHash`, `getMethodFromHash`,
//!   `getOpCodeFromHash`, `getPositionFromHash`, `getTotalFromHash`, `getIsNotAttached`,
//!   `clearTotalPosition`) and `getComparable`, which only operate on an already-computed `i64`
//!   hash value and have no type dependencies at all.
//! - [`calc_level0_hash`], standing in for the `DynamicHash(PcodeOp op, int inputIndex)`
//!   constructor (a "level 0" hash of one input Varnode to a possibly-unlinked `PcodeOp`,
//!   explicitly documented in Java as not needing the op to be linked into a `PcodeSyntaxTree`)
//!   plus `getHash()`/`getAddress()`. This needs no graph navigation at all: the constructor
//!   builds one synthetic edge back to `op` and hashes that directly.
//! - [`calc_constant_hash`], standing in for the public static `calcConstantHash(Instruction,
//!   long)`, which only calls the `(PcodeOp, int)` constructor above -- so it ports over
//!   directly using the already-ported [`Instruction`] trait.

use crate::generic::hash::SimpleCRC32;
use crate::program::model::address::Address;
use crate::program::model::listing::Instruction;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// Maps an opcode to the canonical opcode used for hashing purposes, collapsing related
/// operators onto one value (e.g. `INT_NOTEQUAL` hashes the same as `INT_EQUAL`). `None` means
/// the operator should be skipped entirely when building a hash. Stands in for the public
/// `DynamicHash.transtable` lookup table.
pub fn canonical_opcode(opcode: OpCode) -> Option<OpCode> {
    use OpCode::*;
    match opcode {
        Unimplemented => None,
        Copy => Some(Copy),
        Load => Some(Load),
        Store => Some(Store),
        Branch => Some(Branch),
        CBranch => Some(CBranch),
        BranchInd => Some(BranchInd),
        Call => Some(Call),
        CallInd => Some(CallInd),
        CallOther => Some(CallOther),
        Return => Some(Return),
        IntEqual | IntNotEqual => Some(IntEqual),
        IntSless | IntSlessEqual => Some(IntSless),
        IntLess | IntLessEqual => Some(IntLess),
        IntZext => Some(IntZext),
        IntSext => Some(IntSext),
        IntAdd | IntSub | PtrAdd | PtrSub => Some(IntAdd),
        IntCarry => Some(IntCarry),
        IntScarry => Some(IntScarry),
        IntSborrow => Some(IntSborrow),
        Int2Comp => Some(Int2Comp),
        IntNegate => Some(IntNegate),
        IntXor => Some(IntXor),
        IntAnd => Some(IntAnd),
        IntOr => Some(IntOr),
        IntLeft | IntMult => Some(IntMult),
        IntRight => Some(IntRight),
        IntSright => Some(IntSright),
        IntDiv => Some(IntDiv),
        IntSdiv => Some(IntSdiv),
        IntRem => Some(IntRem),
        IntSrem => Some(IntSrem),
        BoolNegate => Some(BoolNegate),
        BoolXor => Some(BoolXor),
        BoolAnd => Some(BoolAnd),
        BoolOr => Some(BoolOr),
        FloatEqual | FloatNotEqual => Some(FloatEqual),
        FloatLess | FloatLessEqual => Some(FloatLess),
        FloatNan => Some(FloatNan),
        FloatAdd | FloatSub => Some(FloatAdd),
        FloatDiv => Some(FloatDiv),
        FloatMult => Some(FloatMult),
        FloatNeg => Some(FloatNeg),
        FloatAbs => Some(FloatAbs),
        FloatSqrt => Some(FloatSqrt),
        FloatInt2Float => Some(FloatInt2Float),
        FloatFloat2Float => Some(FloatFloat2Float),
        FloatTrunc => Some(FloatTrunc),
        FloatCeil => Some(FloatCeil),
        FloatFloor => Some(FloatFloor),
        FloatRound => Some(FloatRound),
        MultiEqual => Some(MultiEqual),
        Indirect => Some(Indirect),
        Piece => Some(Piece),
        Subpiece => Some(Subpiece),
        Cast => None,
        SegmentOp => Some(SegmentOp),
        CpoolRef => Some(CpoolRef),
        New => Some(New),
        Insert => Some(Insert),
        Zpull => Some(Zpull),
        Popcount => Some(Popcount),
        Lzcount => Some(Lzcount),
        Spull => Some(Spull),
    }
}

/// Extract the slot field (-1 for output, >=0 for a specific input) from an encoded hash. Port
/// of `DynamicHash.getSlotFromHash(long)`.
pub fn get_slot_from_hash(h: i64) -> i32 {
    let res = ((h >> 32) & 0x1f) as i32;
    if res == 31 {
        -1
    } else {
        res
    }
}

/// Extract the hash method (0-6) from an encoded hash. Port of
/// `DynamicHash.getMethodFromHash(long)`.
pub fn get_method_from_hash(h: i64) -> i32 {
    ((h >> 44) & 0xf) as i32
}

/// Extract the canonical opcode field from an encoded hash. Port of
/// `DynamicHash.getOpCodeFromHash(long)`.
pub fn get_op_code_from_hash(h: i64) -> i32 {
    ((h >> 37) & 0x7f) as i32
}

/// Extract the duplicate-hash position field from an encoded hash. Port of
/// `DynamicHash.getPositionFromHash(long)`.
pub fn get_position_from_hash(h: i64) -> i32 {
    ((h >> 49) & 7) as i32
}

/// Extract the duplicate-hash total-count field from an encoded hash. Port of
/// `DynamicHash.getTotalFromHash(long)`.
pub fn get_total_from_hash(h: i64) -> i32 {
    (((h >> 52) & 7) as i32) + 1
}

/// True if the varnode/op the hash was built from was not directly attached to the p-code op
/// recorded in the hash (only reachable by skipping over "skip" ops). Port of
/// `DynamicHash.getIsNotAttached(long)`.
pub fn get_is_not_attached(h: i64) -> bool {
    ((h >> 48) & 1) != 0
}

/// Clear the duplicate-hash position/total fields from an encoded hash, leaving the
/// method/opcode/slot/neighborhood-hash fields untouched. Port of
/// `DynamicHash.clearTotalPosition(long)`.
pub fn clear_total_position(h: i64) -> i64 {
    let mut val: i64 = 0x3f;
    val <<= 49;
    val = !val;
    h & val
}

/// Truncate an encoded hash to its low 32 bits for a coarse, collision-tolerant comparison. Port
/// of `DynamicHash.getComparable(long)`.
pub fn get_comparable(h: i64) -> i32 {
    h as i32
}

/// Test that `extendval` is equal to `val1`, where `extendval` may be a sign- or zero-extension
/// of `val1`. Port of the private `DynamicHash.matchWithPossibleExtension(long, int, long)`,
/// needed by [`calc_constant_hash`].
fn match_with_possible_extension(val1: i64, size: i32, extendval: i64) -> bool {
    if extendval >= 0 {
        return val1 == extendval;
    }
    // Possible sign extension.
    let mask = ((-1i64 as u64) >> ((8 - size) * 8) as u32) as i64;
    let maskcomp = (!mask) >> 1; // Add bit that we are extending from.
    if (extendval & maskcomp) != maskcomp {
        // Sign-extension is not consistent.
        return false;
    }
    val1 == (mask & extendval)
}

/// Compute a "level 0" hash identifying `op`'s input Varnode at `input_index`, along with the
/// address of `op` itself. `op` need not be linked into any larger data-flow graph. Returns
/// `None` if `input_index` is out of range. Port of the `DynamicHash(PcodeOp op, int
/// inputIndex)` constructor plus `getHash()`/`getAddress()`.
pub fn calc_level0_hash(op: &PcodeOp, input_index: usize) -> Option<(i64, Address)> {
    let root = op.inputs.get(input_index)?;

    // Calculate the 32-bit neighborhood hash (`pieceTogetherHash`'s `reg`).
    let mut reg: u32 = 0x3ba0fe06;
    reg = SimpleCRC32::hash_one_byte(reg, root.get_size() as u32);
    if root.is_constant() {
        let mut val = root.get_offset();
        for _ in 0..root.get_size() {
            reg = SimpleCRC32::hash_one_byte(reg, val as u32);
            val = ((val as u64) >> 8) as i64; // unsigned shift, mirroring Java's `>>>=`
        }
    }

    // The single synthetic `ToOpEdge(op, input_index)` contribution (`ToOpEdge.hash`).
    reg = SimpleCRC32::hash_one_byte(reg, input_index as u32);
    let canon = canonical_opcode(op.opcode);
    let canon_value = canon.map(|c| c as u32).unwrap_or(0);
    reg = SimpleCRC32::hash_one_byte(reg, canon_value);
    let target = &op.seqnum.pc;
    let mut val = target.offset();
    let sz = target.space().size();
    let mut i = 0;
    while i < sz {
        reg = SimpleCRC32::hash_one_byte(reg, val as u32);
        val >>= 8; // signed shift, mirroring Java's `>>=`
        i += 8;
    }

    // Build the final 64-bit hash (`pieceTogetherHash`'s tail). `root` is always directly
    // attached to `op` here (it *is* `op.getInput(input_index)`), and there is no larger method
    // being cycled through, so `attachedop` is always true and `method` is always 0.
    let mut hash: i64 = 0; // attachedop == true
    hash <<= 4;
    hash |= 0; // method
    hash <<= 7;
    hash |= canon_value as i64;
    hash <<= 5;
    hash |= (input_index as i64) & 0x1f;
    hash <<= 32;
    hash |= (reg as i64) & 0xffff_ffff;

    Some((hash, target.clone()))
}

/// Given a constant value accessed as an operand by a particular instruction, calculate a
/// (level 0) hash for (any) corresponding constant Varnode. Port of the public static
/// `DynamicHash.calcConstantHash(Instruction, long)`.
pub fn calc_constant_hash(instr: &dyn Instruction, value: i64) -> Vec<i64> {
    let mut result = Vec::new();
    for op in instr.get_pcode_with_overrides(true) {
        for (i, input) in op.inputs.iter().enumerate() {
            if input.is_constant()
                && match_with_possible_extension(input.get_offset(), input.get_size(), value)
            {
                if let Some((hash, _addr)) = calc_level0_hash(&op, i) {
                    if hash != 0 {
                        result.push(hash);
                    }
                }
            }
        }
    }
    result
}

/// A hash utility to uniquely identify a temporary Varnode in data-flow. Port of the instance
/// contract of `ghidra.program.model.pcode.DynamicHash`; see the module docs for what of the
/// full Java class is and is not ported here.
pub trait DynamicHash {
    /// The computed hash. Port of `DynamicHash.getHash()`.
    fn get_hash(&self) -> i64;

    /// The address of the p-code op most closely associated with the hashed variable. Port of
    /// `DynamicHash.getAddress()`.
    fn get_address(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::{ContextChangeException, OperandValue};
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::{PcodeOp, SequenceNumber, Varnode};
    use crate::program::model::symbol::{ExternalReference, Reference, ReferenceIterator, RefType, SourceType, Symbol};
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{FlowOverride, InstructionContext, MemBuffer, RegisterValue};
use crate::program::model::listing::CommentType;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
    }

    fn ram_addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    fn const_varnode(space: &Arc<AddressSpace>, value: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), value), size)
    }

    #[test]
    fn canonical_opcode_collapses_related_operators() {
        assert_eq!(canonical_opcode(OpCode::IntNotEqual), Some(OpCode::IntEqual));
        assert_eq!(canonical_opcode(OpCode::IntSlessEqual), Some(OpCode::IntSless));
        assert_eq!(canonical_opcode(OpCode::IntLessEqual), Some(OpCode::IntLess));
        assert_eq!(canonical_opcode(OpCode::IntSub), Some(OpCode::IntAdd));
        assert_eq!(canonical_opcode(OpCode::PtrAdd), Some(OpCode::IntAdd));
        assert_eq!(canonical_opcode(OpCode::PtrSub), Some(OpCode::IntAdd));
        assert_eq!(canonical_opcode(OpCode::IntLeft), Some(OpCode::IntMult));
        assert_eq!(canonical_opcode(OpCode::FloatSub), Some(OpCode::FloatAdd));
    }

    #[test]
    fn canonical_opcode_skips_cast_and_unimplemented() {
        assert_eq!(canonical_opcode(OpCode::Cast), None);
        assert_eq!(canonical_opcode(OpCode::Unimplemented), None);
    }

    #[test]
    fn hash_bitfield_accessors_round_trip() {
        // Craft a hash by hand matching `pieceTogetherHash`'s packing, then confirm every
        // accessor recovers the field it was given.
        let attachedop_bit: i64 = 1; // "not attached"
        let method: i64 = 3;
        let opcode: i64 = 0x2a;
        let slot: i64 = 5;
        let reg: i64 = 0x1234_5678;

        let mut hash = attachedop_bit;
        hash <<= 4;
        hash |= method;
        hash <<= 7;
        hash |= opcode;
        hash <<= 5;
        hash |= slot;
        hash <<= 32;
        hash |= reg;

        assert_eq!(get_slot_from_hash(hash), slot as i32);
        assert_eq!(get_method_from_hash(hash), method as i32);
        assert_eq!(get_op_code_from_hash(hash), opcode as i32);
        assert!(get_is_not_attached(hash));
        assert_eq!(get_comparable(hash), reg as i32);
    }

    #[test]
    fn get_slot_from_hash_maps_max_field_value_to_output_slot() {
        // Field value 31 (0x1f) is the sentinel for "no input slot" (the op's output).
        let hash: i64 = 0x1f << 32;
        assert_eq!(get_slot_from_hash(hash), -1);
    }

    #[test]
    fn position_and_total_round_trip_and_clear() {
        let position: i64 = 4;
        let total_field: i64 = 2; // encodes total = 3

        let mut hash: i64 = 0xdead_beef; // arbitrary lower bits
        hash |= position << 49;
        hash |= total_field << 52;

        assert_eq!(get_position_from_hash(hash), 4);
        assert_eq!(get_total_from_hash(hash), 3);

        let cleared = clear_total_position(hash);
        assert_eq!(get_position_from_hash(cleared), 0);
        assert_eq!(get_total_from_hash(cleared), 1);
        // The untouched lower bits must survive the clear.
        assert_eq!(cleared & 0xdead_beef, 0xdead_beef & clear_total_position(0xdead_beef));
    }

    #[test]
    fn calc_level0_hash_encodes_slot_opcode_and_is_attached() {
        let ram = ram_space();
        let konst = const_space();
        let pc = ram_addr(&ram, 0x400100);
        let seqnum = SequenceNumber::new(pc.clone(), 0);

        let const_input = const_varnode(&konst, 7, 4);
        let other_input = Varnode::new(ram_addr(&ram, 0x2000), 4);
        let op = PcodeOp::new(
            OpCode::IntAdd,
            seqnum,
            vec![const_input, other_input],
            Some(Varnode::new(ram_addr(&ram, 0x3000), 4)),
        );

        let (hash, addr) = calc_level0_hash(&op, 0).expect("input index 0 is in range");

        assert_eq!(addr, pc);
        assert_ne!(hash, 0);
        assert_eq!(get_slot_from_hash(hash), 0);
        assert_eq!(get_op_code_from_hash(hash), OpCode::IntAdd as i32);
        assert_eq!(get_method_from_hash(hash), 0);
        assert!(!get_is_not_attached(hash), "root is always directly attached to op here");

        // Hashing input index 1 must record that slot and produce a different hash.
        let (hash1, _) = calc_level0_hash(&op, 1).expect("input index 1 is in range");
        assert_eq!(get_slot_from_hash(hash1), 1);
        assert_ne!(hash, hash1);
    }

    #[test]
    fn calc_level0_hash_out_of_range_input_returns_none() {
        let ram = ram_space();
        let pc = ram_addr(&ram, 0x400100);
        let seqnum = SequenceNumber::new(pc, 0);
        let op = PcodeOp::new(OpCode::Return, seqnum, vec![], None);

        assert!(calc_level0_hash(&op, 0).is_none());
    }

    #[test]
    fn canonical_opcode_collapse_is_visible_in_the_encoded_hash() {
        // INT_SUB and INT_ADD must hash identically (same canonical opcode field), matching the
        // "SUB hashes same as ADD" comment on the Java `transtable`.
        let ram = ram_space();
        let konst = const_space();
        let pc = ram_addr(&ram, 0x400100);

        let build = |opcode: OpCode| {
            let seqnum = SequenceNumber::new(pc.clone(), 0);
            PcodeOp::new(
                opcode,
                seqnum,
                vec![const_varnode(&konst, 9, 4)],
                Some(Varnode::new(ram_addr(&ram, 0x3000), 4)),
            )
        };

        let (add_hash, _) = calc_level0_hash(&build(OpCode::IntAdd), 0).unwrap();
        let (sub_hash, _) = calc_level0_hash(&build(OpCode::IntSub), 0).unwrap();
        assert_eq!(add_hash, sub_hash);
    }

    struct MockInstruction {
        pcode: Vec<PcodeOp>,
    }

    impl MemBuffer for MockInstruction {
        fn get_address(&self) -> Address {
            ram_addr(&ram_space(), 0x1000)
        }
    }
    impl PropertySet for MockInstruction {}

    impl ProcessorContextView for MockInstruction {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockInstruction {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(&mut self, _value: Box<dyn RegisterValue>) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "0x1000".to_string()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            ram_addr(&ram_space(), 0x1000)
        }
        fn get_max_address(&self) -> Address {
            ram_addr(&ram_space(), 0x1000)
        }
        fn get_mnemonic_string(&self) -> String {
            "MOCK".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            4
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            for b in buffer.iter_mut() {
                *b = 0x90;
            }
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr == &ram_addr(&ram_space(), 0x1000)
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            (0x1000i64).cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SourceType, _ref_type: RefType) {}
        fn set_register_reference(&mut self, _op_index: i32, _reg: &Register, _source_type: SourceType, _ref_type: RefType) {}
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    impl InstructionContext for MockInstruction {}

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }
        fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> {
            vec![]
        }
        fn get_input_objects(&self) -> Vec<OperandValue> {
            vec![]
        }
        fn get_result_objects(&self) -> Vec<OperandValue> {
            vec![]
        }
        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }
        fn get_default_operand_representation_list(&self, _operand_index: i32) -> Option<Vec<OperandValue>> {
            None
        }
        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }
        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }
        fn get_operand_ref_type(&self, _operand_index: i32) -> RefType {
            RefType::Invalid
        }
        fn get_default_fall_through_offset(&self) -> i32 {
            4
        }
        fn get_default_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_fall_from(&self) -> Option<Address> {
            None
        }
        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }
        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }
        fn get_flow_type(&self) -> RefType {
            RefType::Invalid
        }
        fn is_fallthrough(&self) -> bool {
            true
        }
        fn has_fallthrough(&self) -> bool {
            true
        }
        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::None
        }
        fn set_flow_override(&mut self, _override: FlowOverride) {}
        fn set_length_override(&mut self, _len: i32) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }
        fn is_length_overridden(&self) -> bool {
            false
        }
        fn get_parsed_length(&self) -> i32 {
            4
        }
        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
        }
        fn get_pcode(&self) -> Vec<PcodeOp> {
            self.pcode.clone()
        }
        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
            self.pcode.clone()
        }
        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> {
            vec![]
        }
        fn get_delay_slot_depth(&self) -> i32 {
            0
        }
        fn is_in_delay_slot(&self) -> bool {
            false
        }
        fn get_next(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn set_fall_through(&mut self, _addr: Option<Address>) {}
        fn clear_fall_through_override(&mut self) {}
        fn is_fall_through_overridden(&self) -> bool {
            false
        }
        fn get_instruction_context(&self) -> Arc<dyn InstructionContext> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn calc_constant_hash_finds_matching_constant_input() {
        let ram = ram_space();
        let konst = const_space();
        let pc = ram_addr(&ram, 0x400100);
        let seqnum = SequenceNumber::new(pc, 0);

        let matching = const_varnode(&konst, 42, 4);
        let non_matching = const_varnode(&konst, 99, 4);
        let op = PcodeOp::new(
            OpCode::IntAdd,
            seqnum,
            vec![matching.clone(), non_matching],
            Some(Varnode::new(ram_addr(&ram, 0x3000), 4)),
        );

        let instr = MockInstruction { pcode: vec![op.clone()] };
        let hashes = calc_constant_hash(&instr, 42);

        assert_eq!(hashes.len(), 1);
        let (expected_hash, _) = calc_level0_hash(&op, 0).unwrap();
        assert_eq!(hashes[0], expected_hash);
    }

    #[test]
    fn calc_constant_hash_matches_sign_extended_byte_constant() {
        // A one-byte constant of 0xFF represents -1 once sign-extended; searching for the
        // 64-bit value -1 must still find it, exercising `matchWithPossibleExtension`'s
        // sign-extension branch.
        let ram = ram_space();
        let konst = const_space();
        let pc = ram_addr(&ram, 0x400200);
        let seqnum = SequenceNumber::new(pc, 0);

        let byte_const = const_varnode(&konst, 0xFF, 1);
        let op = PcodeOp::new(
            OpCode::IntNegate,
            seqnum,
            vec![byte_const],
            Some(Varnode::new(ram_addr(&ram, 0x3000), 1)),
        );

        let instr = MockInstruction { pcode: vec![op] };
        let hashes = calc_constant_hash(&instr, -1);

        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn calc_constant_hash_no_match_returns_empty() {
        let ram = ram_space();
        let konst = const_space();
        let pc = ram_addr(&ram, 0x400100);
        let seqnum = SequenceNumber::new(pc, 0);

        let op = PcodeOp::new(
            OpCode::IntAdd,
            seqnum,
            vec![const_varnode(&konst, 5, 4)],
            Some(Varnode::new(ram_addr(&ram, 0x3000), 4)),
        );

        let instr = MockInstruction { pcode: vec![op] };
        assert!(calc_constant_hash(&instr, 999).is_empty());
    }

    struct StoredHash {
        hash: i64,
        address: Address,
    }

    impl DynamicHash for StoredHash {
        fn get_hash(&self) -> i64 {
            self.hash
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    #[test]
    fn dynamic_hash_trait_is_object_safe() {
        let ram = ram_space();
        let konst = const_space();
        let pc = ram_addr(&ram, 0x400100);
        let seqnum = SequenceNumber::new(pc.clone(), 0);
        let op = PcodeOp::new(
            OpCode::IntAdd,
            seqnum,
            vec![const_varnode(&konst, 3, 4)],
            Some(Varnode::new(ram_addr(&ram, 0x3000), 4)),
        );
        let (hash, address) = calc_level0_hash(&op, 0).unwrap();

        let boxed: Box<dyn DynamicHash> = Box::new(StoredHash { hash, address: address.clone() });
        assert_eq!(boxed.get_hash(), hash);
        assert_eq!(boxed.get_address(), address);
    }
}
