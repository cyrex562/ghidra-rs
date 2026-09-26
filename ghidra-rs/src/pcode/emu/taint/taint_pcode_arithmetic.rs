//! Port of `ghidra.pcode.emu.taint.TaintPcodeArithmetic`.
//!
//! The p-code arithmetic on the taint domain.
//!
//! The p-code arithmetic serves as the bridge between p-code and the domain of analysis.
//! Technically, the state itself also contributes minimally to that bridge.

use crate::feature::taint::model::{ShiftMode, TaintSet, TaintVec};
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// The p-code arithmetic on the taint domain.
///
/// Port of `ghidra.pcode.emu.taint.TaintPcodeArithmetic`. Java models this as a two-constant
/// `enum` (`BIG_ENDIAN`/`LITTLE_ENDIAN`) implementing `PcodeArithmetic<TaintVec>`; this port
/// keeps the same shape as a Rust enum implementing [`PcodeArithmetic<TaintVec>`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintPcodeArithmetic {
    /// The instance for big-endian languages.
    BigEndian,
    /// The instance for little-endian languages.
    LittleEndian,
}

impl TaintPcodeArithmetic {
    /// Get the taint arithmetic for the given endianness.
    ///
    /// This method is provided since clients of this class may expect it, as they would for any
    /// realization of [`PcodeArithmetic`].
    ///
    /// Java: `forEndian(boolean)`.
    pub fn for_endian(big_endian: bool) -> Self {
        if big_endian {
            TaintPcodeArithmetic::BigEndian
        } else {
            TaintPcodeArithmetic::LittleEndian
        }
    }

    /// Get the taint arithmetic for the given language.
    ///
    /// This method is provided since clients of this class may expect it, as they would for any
    /// realization of [`PcodeArithmetic`].
    ///
    /// Java: `forLanguage(Language)`.
    pub fn for_language(language: &dyn Language) -> Self {
        Self::for_endian(language.is_big_endian())
    }

    fn endian(self) -> Endian {
        match self {
            TaintPcodeArithmetic::BigEndian => Endian::Big,
            TaintPcodeArithmetic::LittleEndian => Endian::Little,
        }
    }
}

impl PcodeArithmetic<TaintVec> for TaintPcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "TaintVec"
    }

    fn get_endian(&self) -> Option<Endian> {
        Some(self.endian())
    }

    /// {@inheritDoc}
    ///
    /// We can't just naively return `in1`, because each unary op may mix the bytes of the
    /// operand a little differently. For `COPY`, we can, since no mixing happens at all. This is
    /// also the case of both `NEGATE` operations ("negate" is a bit of a misnomer, as they
    /// merely invert the bits.) For `INT_ZEXT`, we append empties to the correct end of the
    /// vector. Similarly, we replicate the most-significant element and append for `INT_SEXT`.
    /// For `INT_2COMP` (which negates an integer in 2's complement), we have to consider that the
    /// "add one" step may cause a cascade of carries. All others, we assume every byte could be
    /// tainted by any other byte in the vector, so we union and broadcast.
    ///
    /// Java overrides `unaryOp(PcodeOp, TaintVec)` (the full-op overload) purely to tag the
    /// result with the originating op afterward, delegating to `PcodeArithmetic.super.unaryOp`
    /// for the actual computation. Rust has no `super` call once a default trait method is
    /// overridden, so this duplicates that default's body (see
    /// [`PcodeArithmetic::unary_op_from_pcode_op`]) with the extra `.with_op(op)` step appended.
    fn unary_op_from_pcode_op(&self, op: &PcodeOp, in1: &TaintVec) -> TaintVec {
        let output = op.output.as_ref().expect("unary p-code op has no output");
        let result = self.unary_op(op.opcode, output.get_size(), op.inputs[0].get_size(), in1);
        result.with_op(op.clone())
    }

    fn unary_op(&self, opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &TaintVec) -> TaintVec {
        match opcode {
            OpCode::Copy | OpCode::BoolNegate | OpCode::IntNegate => in1.clone(),
            OpCode::IntZext => in1.extended(sizeout as usize, self.endian().is_big_endian(), false),
            OpCode::IntSext => in1.extended(sizeout as usize, self.endian().is_big_endian(), true),
            OpCode::Int2Comp => {
                let mut copy = in1.copy();
                copy.set_cascade(self.endian().is_big_endian());
                copy
            }
            _ => TaintVec::copies(in1.union(), sizeout as usize),
        }
    }

    /// {@inheritDoc}
    ///
    /// We override the form taking the full p-code op, so that we can treat certain idioms.
    /// Notably, on x86, `XOR RAX,RAX` is a common optimization of `MOV RAX,0`, since it takes
    /// fewer bytes to encode. Thus, we must examine the input variables, not their values, to
    /// detect this. Note that, while less common, `SUB RAX,RAX` would accomplish the same.
    /// Additionally, in p-code `INT_XOR` is identical to `BOOL_XOR`. When we detect these idioms,
    /// we want to clear any taints, since the value output is constant. This is achieved
    /// intuitively, by deferring to [`PcodeArithmetic::from_const_u64`], passing in 0 and the
    /// output size.
    ///
    /// As with [`Self::unary_op_from_pcode_op`], this duplicates the default's body (see
    /// [`PcodeArithmetic::binary_op_from_pcode_op`]) with the extra `.with_op(op)` step, since
    /// Rust has no `super` call to invoke from an override.
    fn binary_op_from_pcode_op(&self, op: &PcodeOp, in1: &TaintVec, in2: &TaintVec) -> TaintVec {
        let output = op.output.as_ref().expect("binary p-code op has no output");
        let result = self.binary_op(
            op.opcode,
            output.get_size(),
            op.inputs[0].get_size(),
            in1,
            op.inputs[1].get_size(),
            in2,
        );
        result.with_op(op.clone())
    }

    fn binary_op(
        &self,
        opcode: OpCode,
        sizeout: i32,
        _sizein1: i32,
        in1: &TaintVec,
        sizein2: i32,
        in2: &TaintVec,
    ) -> TaintVec {
        // TODO: Detect immediate operands and be more precise
        if matches!(opcode, OpCode::IntXor | OpCode::IntSub | OpCode::BoolXor) && in1 == in2 {
            // NB: with_op unneeded, as this essentially removes taint
            return self.from_const_u64(0, sizeout);
        }
        let big_endian = self.endian().is_big_endian();
        match opcode {
            OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::BoolXor
            | OpCode::IntAnd
            | OpCode::IntOr
            | OpCode::IntXor => in1.zip_union(in2),
            OpCode::IntAdd | OpCode::IntSub => {
                let mut temp = in1.zip_union(in2);
                temp.set_cascade(big_endian);
                temp
            }
            OpCode::IntSless
            | OpCode::IntSlessEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual
            | OpCode::FloatEqual
            | OpCode::FloatNotEqual => {
                let temp = in1.union().union(&in2.union());
                TaintVec::copies(temp, sizeout as usize)
            }
            OpCode::Piece => {
                let mut temp = in1.extended(sizeout as usize, big_endian, false);
                let shift_amount = if big_endian { -sizein2 } else { sizein2 };
                temp.set_shifted(shift_amount, ShiftMode::Unbounded);
                let set_start = if big_endian { (sizeout - sizein2) as usize } else { 0 };
                temp.set_range(set_start, in2);
                temp
            }
            _ => {
                let u = in1.union().union(&in2.union());
                TaintVec::copies(u, sizeout as usize)
            }
        }
    }

    /// {@inheritDoc}
    ///
    /// Here we handle indirect taint for indirect writes
    fn mod_before_store_from_pcode_op(
        &self,
        op: &PcodeOp,
        _space: &AddressSpace,
        in_offset: &TaintVec,
        in_value: &TaintVec,
    ) -> TaintVec {
        in_value.tag_indirect_write(in_offset).with_op(op.clone())
    }

    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &TaintVec,
        _sizein_value: i32,
        _in_value: &TaintVec,
    ) -> TaintVec {
        // Java's `modBeforeStore(int, AddressSpace, TaintVec, int, TaintVec)` always throws
        // `new RuntimeException("Not supported")`. Preserved faithfully as a panic rather than
        // "fixed" to do something more useful -- this really is unreachable from a normal p-code
        // executor, which only ever calls the full-op overload above.
        panic!("Not supported")
    }

    /// {@inheritDoc}
    ///
    /// Here we handle indirect taint for indirect reads
    fn mod_after_load_from_pcode_op(
        &self,
        op: &PcodeOp,
        _space: &AddressSpace,
        in_offset: &TaintVec,
        in_value: &TaintVec,
    ) -> TaintVec {
        in_value.tag_indirect_read(in_offset).with_op(op.clone())
    }

    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &TaintVec,
        _sizein_value: i32,
        _in_value: &TaintVec,
    ) -> TaintVec {
        // See `mod_before_store` above: mirrors the Java int-overload's unconditional
        // `RuntimeException("Not supported")`.
        panic!("Not supported")
    }

    /// {@inheritDoc}
    ///
    /// Constant values have no taint, so we just return a vector of empty taint sets
    fn from_const_bytes(&self, value: &[u8]) -> TaintVec {
        TaintVec::empties(value.len())
    }

    /// {@inheritDoc}
    ///
    /// Taint vectors have no values. We're expect the taint arithmetic to be used as an
    /// auxiliary to concrete bytes, so the paired arithmetic should always defer to its concrete
    /// element. Thus, an `AssertionError` might also be fitting here, but we'll stick to
    /// convention, since technically a user script could attempt to concretize taint.
    fn to_concrete(&self, _value: &TaintVec, purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
        Err(ConcretionError::new("Cannot make taint concrete", purpose))
    }

    /// {@inheritDoc}
    ///
    /// Taint vectors do have length, so return it here.
    fn size_of(&self, value: &TaintVec) -> i64 {
        value.length as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace as Space, AddressSpaceType};
    use crate::program::model::pcode::{SequenceNumber, Varnode};

    fn taint(name: &str) -> TaintSet {
        TaintSet::of([crate::feature::taint::model::TaintMark::new(
            name,
            std::iter::empty::<String>(),
        )])
    }

    fn ram() -> std::sync::Arc<Space> {
        Space::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn op(opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        let addr = Address::new(ram(), 0x1000);
        PcodeOp::new(opcode, SequenceNumber::new(addr, 0), inputs, output)
    }

    fn vn(size: i32) -> Varnode {
        Varnode::new(Address::new(ram(), 0x2000), size)
    }

    #[test]
    fn for_endian_and_for_language_select_the_right_instance() {
        assert_eq!(TaintPcodeArithmetic::for_endian(true), TaintPcodeArithmetic::BigEndian);
        assert_eq!(TaintPcodeArithmetic::for_endian(false), TaintPcodeArithmetic::LittleEndian);
    }

    #[test]
    fn get_endian_reports_the_variant() {
        assert_eq!(TaintPcodeArithmetic::BigEndian.get_endian(), Some(Endian::Big));
        assert_eq!(TaintPcodeArithmetic::LittleEndian.get_endian(), Some(Endian::Little));
    }

    #[test]
    fn unary_copy_and_negate_forms_return_input_unchanged() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        assert_eq!(a.unary_op(OpCode::Copy, 2, 2, &v), v);
        assert_eq!(a.unary_op(OpCode::BoolNegate, 2, 2, &v), v);
        assert_eq!(a.unary_op(OpCode::IntNegate, 2, 2, &v), v);
    }

    #[test]
    fn unary_zext_appends_empty_at_the_correct_end() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let extended = a.unary_op(OpCode::IntZext, 4, 2, &v);
        assert_eq!(extended.to_display(), "[a][b][][]");
    }

    #[test]
    fn unary_sext_replicates_the_most_significant_element() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let extended = a.unary_op(OpCode::IntSext, 4, 2, &v);
        assert_eq!(extended.to_display(), "[a][b][b][b]");
    }

    #[test]
    fn unary_2comp_cascades_via_set_cascade() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let mut expected = v.copy();
        expected.set_cascade(false);
        assert_eq!(a.unary_op(OpCode::Int2Comp, 2, 2, &v), expected);
    }

    #[test]
    fn unary_default_unions_and_broadcasts() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let result = a.unary_op(OpCode::FloatAbs, 3, 2, &v);
        assert_eq!(result.length, 3);
        for i in 0..3 {
            assert_eq!(result.get(i), &v.union());
        }
    }

    #[test]
    fn unary_op_from_pcode_op_tags_the_result_with_the_op() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let in1 = vn(2);
        let out = vn(2);
        let pop = op(OpCode::Copy, vec![in1], Some(out));
        let v = TaintVec::new(2);
        let result = a.unary_op_from_pcode_op(&pop, &v);
        assert!(result.get_originating_op().is_some());
    }

    #[test]
    fn binary_xor_of_equal_taint_vecs_is_constant_zero_taint() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let result = a.binary_op(OpCode::IntXor, 2, 2, &v, 2, &v);
        assert!(result.get(0).is_empty());
        assert!(result.get(1).is_empty());
    }

    #[test]
    fn binary_sub_of_equal_taint_vecs_is_constant_zero_taint() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let result = a.binary_op(OpCode::IntSub, 2, 2, &v, 2, &v);
        assert!(result.get(0).is_empty());
        assert!(result.get(1).is_empty());
    }

    #[test]
    fn binary_xor_of_different_taint_vecs_unions_per_element() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v1 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let v2 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("c"), taint("d")]);
        let result = a.binary_op(OpCode::IntXor, 2, 2, &v1, 2, &v2);
        assert_eq!(result.get(0), &taint("a").union(&taint("c")));
    }

    #[test]
    fn binary_bool_and_zip_unions() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v1 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a")]);
        let v2 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("b")]);
        let result = a.binary_op(OpCode::BoolAnd, 1, 1, &v1, 1, &v2);
        assert_eq!(result.get(0), &taint("a").union(&taint("b")));
    }

    #[test]
    fn binary_add_cascades_carries() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v1 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let v2 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("c"), taint("d")]);
        let mut expected = v1.zip_union(&v2);
        expected.set_cascade(false);
        let result = a.binary_op(OpCode::IntAdd, 2, 2, &v1, 2, &v2);
        assert_eq!(result, expected);
    }

    #[test]
    fn binary_compare_ops_union_everything_and_broadcast() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v1 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a"), taint("b")]);
        let v2 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("c")]);
        let result = a.binary_op(OpCode::IntSless, 1, 2, &v1, 1, &v2);
        assert_eq!(result.length, 1);
        assert_eq!(result.get(0), &v1.union().union(&v2.union()));
    }

    #[test]
    fn binary_piece_little_endian_loses_the_high_half_via_taint_vecs_own_documented_quirk() {
        // One would expect "[lo][hi]" here (in1="hi" kept at the high slot, in2="lo" written to
        // the low slot). What actually happens: `set_shifted(sizein2, Unbounded)` is called with
        // a *positive* `right` (`sizein2 = 1`), and `TaintVec::set_shifted`'s own docs (see
        // `taint_vec.rs`) record that as a real Java quirk: for `right >= 0` under
        // `ShiftMode::Unbounded`/`Remainder`, the shift loop's first iteration always computes a
        // negative `src` and breaks immediately, so the vector comes back **completely
        // unchanged** rather than shifted right. So `in1.extended(..)` (`["hi", ""]`) is left
        // untouched by the "shift" step, and the subsequent `set_range(0, in2)` then overwrites
        // index 0 ("hi") with "lo" -- leaving "hi" nowhere, and the still-untouched extension
        // slot at index 1 empty. This is a faithful cascade of `TaintVec`'s own documented
        // quirk into `TaintPcodeArithmetic`'s PIECE handling, not a new bug introduced here.
        let a = TaintPcodeArithmetic::LittleEndian;
        let hi = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("hi")]);
        let lo = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("lo")]);
        let result = a.binary_op(OpCode::Piece, 2, 1, &hi, 1, &lo);
        assert_eq!(result.to_display(), "[lo][]");
    }

    #[test]
    fn binary_default_unions_and_broadcasts() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v1 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("a")]);
        let v2 = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("b")]);
        let result = a.binary_op(OpCode::FloatAdd, 3, 1, &v1, 1, &v2);
        assert_eq!(result.length, 3);
        for i in 0..3 {
            assert_eq!(result.get(i), &taint("a").union(&taint("b")));
        }
    }

    #[test]
    fn binary_op_from_pcode_op_tags_the_result_with_the_op() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let pop = op(OpCode::IntAdd, vec![vn(2), vn(2)], Some(vn(2)));
        let v1 = TaintVec::new(2);
        let v2 = TaintVec::new(2);
        let result = a.binary_op_from_pcode_op(&pop, &v1, &v2);
        assert!(result.get_originating_op().is_some());
    }

    #[test]
    fn mod_before_store_tags_indirect_write_and_the_op() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let space = ram();
        let offset = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("off")]);
        let value = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("val")]);
        let pop = op(OpCode::Store, vec![], None);
        let result = a.mod_before_store_from_pcode_op(&pop, &space, &offset, &value);
        assert_eq!(result, value.tag_indirect_write(&offset));
        assert!(result.get_originating_op().is_some());
    }

    #[test]
    fn mod_after_load_tags_indirect_read_and_the_op() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let space = ram();
        let offset = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("off")]);
        let value = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("val")]);
        let pop = op(OpCode::Load, vec![], None);
        let result = a.mod_after_load_from_pcode_op(&pop, &space, &offset, &value);
        assert_eq!(result, value.tag_indirect_read(&offset));
        assert!(result.get_originating_op().is_some());
    }

    #[test]
    #[should_panic(expected = "Not supported")]
    fn mod_before_store_without_op_panics() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let space = ram();
        let v = TaintVec::new(1);
        a.mod_before_store(1, &space, &v, 1, &v);
    }

    #[test]
    #[should_panic(expected = "Not supported")]
    fn mod_after_load_without_op_panics() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let space = ram();
        let v = TaintVec::new(1);
        a.mod_after_load(1, &space, &v, 1, &v);
    }

    #[test]
    fn from_const_bytes_is_all_empty_taint() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = a.from_const_bytes(&[0, 0, 0, 0]);
        assert_eq!(v.length, 4);
        for i in 0..4 {
            assert!(v.get(i).is_empty());
        }
    }

    #[test]
    fn to_concrete_always_errors() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::new(1);
        let err = a.to_concrete(&v, Purpose::Inspect).unwrap_err();
        assert!(err.to_string().contains("Cannot make taint concrete"));
    }

    #[test]
    fn size_of_reports_the_vector_length() {
        let a = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::new(7);
        assert_eq!(a.size_of(&v), 7);
    }

    #[test]
    fn big_endian_piece_places_in2_at_the_computed_offset() {
        let a = TaintPcodeArithmetic::BigEndian;
        let hi = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("hi")]);
        let lo = TaintVec::of(op(OpCode::Copy, vec![], None), vec![taint("lo")]);
        let result = a.binary_op(OpCode::Piece, 2, 1, &hi, 1, &lo);
        assert_eq!(result.to_display(), "[hi][lo]");
    }
}
