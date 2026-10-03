//! Port of `ghidra.lisa.pcode.statements.PcodeUnaryOperator`.

use std::collections::HashSet;
use std::fmt;

use crate::feature::lisa::pcode::types::pcode_type_system::{PcodeType, PcodeTypeSystem};
use crate::program::model::pcode::PcodeOp;

/// A p-code operator, usable as the unary-operator tag for a LiSA `UnaryExpression` over p-code.
///
/// Corresponds to `ghidra.lisa.pcode.statements.PcodeUnaryOperator` in the Java source, which
/// `implements it.unive.lisa.symbolic.value.operator.unary.UnaryOperator`. That LiSA interface
/// (and the `Operator`/`Type`/`TypeSystem` types its `typeInference` signature uses) are an
/// external third-party dependency with no Rust port anywhere in this crate -- the same situation
/// [`PcodeBinaryOperator`](crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator)'s
/// docs describe -- so, following that established convention, this is a plain struct with the
/// operations the Java class's body actually performs, using this crate's own
/// [`PcodeType`]/[`PcodeTypeSystem`] in place of LiSA's own `Type`/`TypeSystem` interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PcodeUnaryOperator {
    op: PcodeOp,
}

impl PcodeUnaryOperator {
    /// Java: `PcodeUnaryOperator(PcodeOp op)`.
    pub fn new(op: PcodeOp) -> Self {
        Self { op }
    }

    /// Java: `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        &self.op
    }

    /// Java: `typeInference(TypeSystem, Set<Type>)`, `return
    /// Collections.singleton(types.getBooleanType());` -- unconditionally the boolean type,
    /// regardless of `argument`'s contents.
    ///
    /// Java's `argument` parameter is accepted (to mirror the Java signature) but, exactly as in
    /// Java, never consulted by the computation itself.
    pub fn type_inference(
        &self,
        types: &PcodeTypeSystem,
        argument: &HashSet<PcodeType>,
    ) -> HashSet<PcodeType> {
        let _ = argument;
        let mut result = HashSet::new();
        result.insert(types.boolean_type());
        result
    }
}

impl fmt::Display for PcodeUnaryOperator {
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
        let o = op(OpCode::IntNegate);
        let unary = PcodeUnaryOperator::new(o.clone());
        assert_eq!(unary.get_op(), &o);
    }

    #[test]
    fn display_matches_the_ops_mnemonic() {
        let unary = PcodeUnaryOperator::new(op(OpCode::IntNegate));
        assert_eq!(unary.to_string(), op(OpCode::IntNegate).get_mnemonic());
    }

    #[test]
    fn type_inference_is_always_boolean_regardless_of_the_argument() {
        let unary = PcodeUnaryOperator::new(op(OpCode::IntNegate));
        let types = PcodeTypeSystem;

        assert_eq!(
            unary.type_inference(&types, &set(&[PcodeType::Int32])),
            set(&[types.boolean_type()])
        );
        assert_eq!(
            unary.type_inference(&types, &set(&[PcodeType::Bool])),
            set(&[types.boolean_type()])
        );
        assert_eq!(unary.type_inference(&types, &set(&[])), set(&[types.boolean_type()]));
    }

    #[test]
    fn equal_ops_are_equal_and_hash_equal() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = PcodeUnaryOperator::new(op(OpCode::IntNegate));
        let b = PcodeUnaryOperator::new(op(OpCode::IntNegate));
        assert_eq!(a, b);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn different_ops_are_not_equal() {
        let a = PcodeUnaryOperator::new(op(OpCode::IntNegate));
        let b = PcodeUnaryOperator::new(op(OpCode::BoolNegate));
        assert_ne!(a, b);
    }
}
