//! Port of `ghidra.lisa.pcode.statements.PcodeTernaryOperator`.

use std::collections::HashSet;
use std::fmt;

use crate::feature::lisa::pcode::statements::pcode_binary_operator::common_numerical_type;
use crate::feature::lisa::pcode::types::pcode_type_system::{PcodeType, PcodeTypeSystem};
use crate::program::model::pcode::PcodeOp;

/// A p-code operator, usable as the ternary-operator tag for a LiSA `TernaryExpression` over
/// p-code.
///
/// Corresponds to `ghidra.lisa.pcode.statements.PcodeTernaryOperator` in the Java source, which
/// `implements it.unive.lisa.symbolic.value.operator.ternary.TernaryOperator`. That LiSA interface
/// (and the `Operator`/`Type`/`TypeSystem` types its `typeInference` signature uses) are an
/// external third-party dependency with no Rust port anywhere in this crate -- the same situation
/// [`PcodeBinaryOperator`](crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator)'s
/// docs describe -- so, following that established convention, this is a plain struct with the
/// operations the Java class's body actually performs, using this crate's own
/// [`PcodeType`]/[`PcodeTypeSystem`] in place of LiSA's own `Type`/`TypeSystem`/`NumericType`
/// interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PcodeTernaryOperator {
    op: PcodeOp,
}

impl PcodeTernaryOperator {
    /// Java: `PcodeTernaryOperator(PcodeOp op)`.
    pub fn new(op: PcodeOp) -> Self {
        Self { op }
    }

    /// Java: `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        &self.op
    }

    /// Java: `typeInference(TypeSystem, Set<Type>, Set<Type>, Set<Type>)`.
    ///
    /// Delegates to [`common_numerical_type`] (this crate's stand-in for LiSA's
    /// `NumericType.commonNumericalType`) over `left`/`right` and, if that comes back empty, falls
    /// back to the boolean type -- matching Java's `if (!set.isEmpty()) return set; return
    /// Collections.singleton(types.getBooleanType());`. Java's `middle` parameter is accepted (to
    /// mirror the Java signature) but, exactly as in Java, never consulted by the computation
    /// itself.
    pub fn type_inference(
        &self,
        types: &PcodeTypeSystem,
        left: &HashSet<PcodeType>,
        middle: &HashSet<PcodeType>,
        right: &HashSet<PcodeType>,
    ) -> HashSet<PcodeType> {
        let _ = middle;
        let set = common_numerical_type(left, right);
        if !set.is_empty() {
            return set;
        }
        let mut fallback = HashSet::new();
        fallback.insert(types.boolean_type());
        fallback
    }
}

impl fmt::Display for PcodeTernaryOperator {
    /// Java: `toString()`, `op.getMnemonic()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.op.get_mnemonic())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber};

    fn op(opcode: OpCode) -> PcodeOp {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(opcode, seq, vec![], None)
    }

    fn set(types: &[PcodeType]) -> HashSet<PcodeType> {
        types.iter().copied().collect()
    }

    #[test]
    fn get_op_returns_the_wrapped_op() {
        let o = op(OpCode::PtrAdd);
        let ternary = PcodeTernaryOperator::new(o.clone());
        assert_eq!(ternary.get_op(), &o);
    }

    #[test]
    fn display_matches_the_ops_mnemonic() {
        let ternary = PcodeTernaryOperator::new(op(OpCode::PtrAdd));
        assert_eq!(ternary.to_string(), op(OpCode::PtrAdd).get_mnemonic());
    }

    #[test]
    fn type_inference_picks_the_common_numeric_type_of_left_and_right() {
        let ternary = PcodeTernaryOperator::new(op(OpCode::PtrAdd));
        let types = PcodeTypeSystem;

        let both32 = ternary.type_inference(
            &types,
            &set(&[PcodeType::Int32]),
            &set(&[PcodeType::Bool]),
            &set(&[PcodeType::Int32]),
        );
        assert_eq!(both32, set(&[PcodeType::Int32]));

        let widened = ternary.type_inference(
            &types,
            &set(&[PcodeType::Int32]),
            &set(&[PcodeType::Bool]),
            &set(&[PcodeType::Int64]),
        );
        assert_eq!(widened, set(&[PcodeType::Int64]));
    }

    #[test]
    fn type_inference_ignores_the_middle_set_entirely() {
        let ternary = PcodeTernaryOperator::new(op(OpCode::PtrAdd));
        let types = PcodeTypeSystem;

        // Even if `middle` alone contains a numeric type not shared by `left`/`right`, it has no
        // effect on the result: only `left` and `right` feed `commonNumericalType`.
        let with_numeric_middle = ternary.type_inference(
            &types,
            &set(&[PcodeType::Bool]),
            &set(&[PcodeType::Int64]),
            &set(&[PcodeType::Bool]),
        );
        let with_empty_middle = ternary.type_inference(
            &types,
            &set(&[PcodeType::Bool]),
            &set(&[]),
            &set(&[PcodeType::Bool]),
        );
        assert_eq!(with_numeric_middle, with_empty_middle);
    }

    #[test]
    fn type_inference_falls_back_to_boolean_when_neither_side_has_a_common_numeric_type() {
        let ternary = PcodeTernaryOperator::new(op(OpCode::IntEqual));
        let types = PcodeTypeSystem;

        let result = ternary.type_inference(
            &types,
            &set(&[PcodeType::Bool]),
            &set(&[PcodeType::Bool]),
            &set(&[PcodeType::Bool]),
        );
        assert_eq!(result, set(&[types.boolean_type()]));
    }

    #[test]
    fn equal_ops_are_equal_and_hash_equal() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = PcodeTernaryOperator::new(op(OpCode::PtrAdd));
        let b = PcodeTernaryOperator::new(op(OpCode::PtrAdd));
        assert_eq!(a, b);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}
