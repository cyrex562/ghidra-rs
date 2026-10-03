//! Port of `ghidra.lisa.pcode.statements.PcodeBinaryOperator`.

use std::collections::HashSet;
use std::fmt;

use crate::feature::lisa::pcode::types::pcode_type_system::{PcodeType, PcodeTypeSystem};
use crate::program::model::pcode::PcodeOp;

/// A p-code operator, usable as the binary-operator tag for a LiSA `BinaryExpression` over p-code.
///
/// Corresponds to `ghidra.lisa.pcode.statements.PcodeBinaryOperator` in the Java source, which
/// `implements it.unive.lisa.symbolic.value.operator.binary.BinaryOperator`. That LiSA interface
/// (and the `Operator`/`Type`/`TypeSystem` types its `typeInference` signature uses) are an
/// external third-party dependency with no Rust port anywhere in this crate (the same situation
/// [`PcodeNonRelationalValueDomain`](crate::feature::lisa::pcode::analyses::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain)'s
/// docs describe), so, following that established convention, this is a plain struct with the
/// operations the Java class's body actually performs, using this crate's own
/// [`PcodeType`]/[`PcodeTypeSystem`] (the sibling port of LiSA's concrete `Type`/`TypeSystem`
/// singletons -- see [`crate::feature::lisa::pcode::types::pcode_type_system`]) in place of
/// LiSA's own `Type`/`TypeSystem`/`NumericType` interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PcodeBinaryOperator {
    op: PcodeOp,
}

impl PcodeBinaryOperator {
    /// Java: `PcodeBinaryOperator(PcodeOp op)`.
    pub fn new(op: PcodeOp) -> Self {
        Self { op }
    }

    /// Java: `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        &self.op
    }

    /// Java: `typeInference(TypeSystem, Set<Type>, Set<Type>)`.
    ///
    /// Delegates to [`common_numerical_type`] (this crate's stand-in for LiSA's
    /// `NumericType.commonNumericalType`) and, if that comes back empty, falls back to the boolean
    /// type -- matching Java's `if (!set.isEmpty()) return set; return
    /// Collections.singleton(types.getBooleanType());`.
    pub fn type_inference(
        &self,
        types: &PcodeTypeSystem,
        left: &HashSet<PcodeType>,
        right: &HashSet<PcodeType>,
    ) -> HashSet<PcodeType> {
        let set = common_numerical_type(left, right);
        if !set.is_empty() {
            return set;
        }
        let mut fallback = HashSet::new();
        fallback.insert(types.boolean_type());
        fallback
    }
}

impl fmt::Display for PcodeBinaryOperator {
    /// Java: `toString()`, `op.getMnemonic()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.op.get_mnemonic())
    }
}

/// Stand-in for LiSA's `NumericType.commonNumericalType(Set<Type>, Set<Type>)`, restricted to this
/// crate's [`PcodeType`] domain.
///
/// LiSA's real algorithm pairs every numeric type on the left with every numeric type on the right
/// and collects each pair's `NumericType.commonNumericalType(NumericType)` (generally the wider of
/// the two, promoting to floating-point if either operand is). This crate's [`PcodeType`] only has
/// two numeric variants ([`PcodeType::Int32`]/[`PcodeType::Int64`]; [`PcodeType::Bool`]/
/// [`PcodeType::Str`]/[`PcodeType::InMemory`] are not numeric), so the "wider of the two" rule
/// collapses to: [`PcodeType::Int64`] wins over [`PcodeType::Int32`], and a type paired with itself
/// stays itself.
pub fn common_numerical_type(left: &HashSet<PcodeType>, right: &HashSet<PcodeType>) -> HashSet<PcodeType> {
    let mut result = HashSet::new();
    for &l in left.iter().filter(|t| is_numeric(t)) {
        for &r in right.iter().filter(|t| is_numeric(t)) {
            result.insert(wider_numeric(l, r));
        }
    }
    result
}

fn is_numeric(t: &PcodeType) -> bool {
    matches!(t, PcodeType::Int32 | PcodeType::Int64)
}

fn wider_numeric(a: PcodeType, b: PcodeType) -> PcodeType {
    if a == PcodeType::Int64 || b == PcodeType::Int64 {
        PcodeType::Int64
    }
    else {
        PcodeType::Int32
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
        let o = op(OpCode::IntAdd);
        let bin = PcodeBinaryOperator::new(o.clone());
        assert_eq!(bin.get_op(), &o);
    }

    #[test]
    fn display_matches_the_ops_mnemonic() {
        let bin = PcodeBinaryOperator::new(op(OpCode::IntAdd));
        assert_eq!(bin.to_string(), op(OpCode::IntAdd).get_mnemonic());
    }

    #[test]
    fn type_inference_picks_the_common_numeric_type_when_both_sides_are_numeric() {
        let bin = PcodeBinaryOperator::new(op(OpCode::IntAdd));
        let types = PcodeTypeSystem;

        let both32 = bin.type_inference(&types, &set(&[PcodeType::Int32]), &set(&[PcodeType::Int32]));
        assert_eq!(both32, set(&[PcodeType::Int32]));

        let widened = bin.type_inference(&types, &set(&[PcodeType::Int32]), &set(&[PcodeType::Int64]));
        assert_eq!(widened, set(&[PcodeType::Int64]));
    }

    #[test]
    fn type_inference_falls_back_to_boolean_when_neither_side_has_a_common_numeric_type() {
        let bin = PcodeBinaryOperator::new(op(OpCode::IntEqual));
        let types = PcodeTypeSystem;

        let result = bin.type_inference(&types, &set(&[PcodeType::Bool]), &set(&[PcodeType::Bool]));
        assert_eq!(result, set(&[types.boolean_type()]));

        // One side numeric, the other not: still no common numeric type, so still boolean.
        let mixed = bin.type_inference(&types, &set(&[PcodeType::Int32]), &set(&[PcodeType::Str]));
        assert_eq!(mixed, set(&[types.boolean_type()]));
    }

    #[test]
    fn common_numerical_type_is_empty_when_neither_side_is_numeric() {
        assert!(common_numerical_type(&set(&[PcodeType::Bool]), &set(&[PcodeType::Str])).is_empty());
    }

    #[test]
    fn common_numerical_type_unions_over_multiple_candidates() {
        let left = set(&[PcodeType::Int32, PcodeType::Int64]);
        let right = set(&[PcodeType::Int32]);
        // (Int32,Int32) -> Int32; (Int64,Int32) -> Int64.
        assert_eq!(common_numerical_type(&left, &right), set(&[PcodeType::Int32, PcodeType::Int64]));
    }
}
