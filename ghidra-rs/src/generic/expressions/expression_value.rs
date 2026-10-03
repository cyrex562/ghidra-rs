use crate::generic::expressions::expression_element::ExpressionElement;
use crate::generic::expressions::expression_exception::ExpressionException;
use crate::generic::expressions::expression_operator::ExpressionOperator;

/// Operand types used by the [`ExpressionEvaluator`](super::expression_evaluator::ExpressionEvaluator)
/// must implement this trait.
///
/// Port of `generic.expressions.ExpressionValue`.
pub trait ExpressionValue: ExpressionElement {
    /// Applies a unary operator to this value, returning the new value after the operator is
    /// applied.
    ///
    /// # Errors
    /// Returns [`ExpressionException`] if the operator is not applicable for this value.
    ///
    /// Mirrors `applyUnaryOperator(ExpressionOperator)`.
    fn apply_unary_operator(
        &self,
        operator: &dyn ExpressionOperator,
    ) -> Result<Box<dyn ExpressionValue>, ExpressionException>;

    /// Applies a binary operator to this value, combining it with `value`, returning the new
    /// value after the operator is applied.
    ///
    /// # Errors
    /// Returns [`ExpressionException`] if the operator is not applicable for this value or the
    /// other value is not applicable for this operand and operator.
    ///
    /// Mirrors `applyBinaryOperator(ExpressionOperator, ExpressionValue)`.
    fn apply_binary_operator(
        &self,
        operator: &dyn ExpressionOperator,
        value: &dyn ExpressionValue,
    ) -> Result<Box<dyn ExpressionValue>, ExpressionException>;

    /// Returns this value as `&dyn Any`, so implementations of
    /// [`ExpressionValue::apply_binary_operator`] can downcast the `value` operand back to a
    /// concrete type before combining it with `self`.
    ///
    /// Not part of the Java interface: Java's `applyBinaryOperator` freely downcasts its
    /// `ExpressionValue value` parameter via an implicit `instanceof`/cast (every Java object
    /// carries runtime type information), something a Rust `&dyn ExpressionValue` cannot do
    /// without an explicit escape hatch. This mirrors the same convention already established by
    /// [`CodeLocation::as_any`](crate::feature::lisa::pcode::locations::CodeLocation::as_any) for
    /// an analogous need.
    fn as_any(&self) -> &dyn std::any::Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal integer-valued `ExpressionValue`, supporting just enough operators (`+`, `-`
    /// unary/binary) to prove the trait shape and its error path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct IntValue(i64);

    impl ExpressionElement for IntValue {}

    struct PlusOp;
    impl ExpressionOperator for PlusOp {
        fn symbol(&self) -> &str {
            "+"
        }
        fn is_unary(&self) -> bool {
            true
        }
        fn is_binary(&self) -> bool {
            true
        }
        fn precedence(&self) -> i32 {
            1
        }
    }

    struct MinusOp;
    impl ExpressionOperator for MinusOp {
        fn symbol(&self) -> &str {
            "-"
        }
        fn is_unary(&self) -> bool {
            true
        }
        fn is_binary(&self) -> bool {
            true
        }
        fn precedence(&self) -> i32 {
            1
        }
    }

    struct MulOp;
    impl ExpressionOperator for MulOp {
        fn symbol(&self) -> &str {
            "*"
        }
        fn is_unary(&self) -> bool {
            false
        }
        fn is_binary(&self) -> bool {
            true
        }
        fn precedence(&self) -> i32 {
            2
        }
    }

    impl ExpressionValue for IntValue {
        fn apply_unary_operator(
            &self,
            operator: &dyn ExpressionOperator,
        ) -> Result<Box<dyn ExpressionValue>, ExpressionException> {
            match operator.symbol() {
                "+" => Ok(Box::new(IntValue(self.0))),
                "-" => Ok(Box::new(IntValue(-self.0))),
                other => Err(ExpressionException::new(format!(
                    "unary operator {other} not applicable to IntValue"
                ))),
            }
        }

        fn apply_binary_operator(
            &self,
            operator: &dyn ExpressionOperator,
            value: &dyn ExpressionValue,
        ) -> Result<Box<dyn ExpressionValue>, ExpressionException> {
            let other = value
                .as_any()
                .downcast_ref::<IntValue>()
                .ok_or_else(|| ExpressionException::new("operand is not an IntValue"))?;
            match operator.symbol() {
                "+" => Ok(Box::new(IntValue(self.0 + other.0))),
                "-" => Ok(Box::new(IntValue(self.0 - other.0))),
                other_sym => Err(ExpressionException::new(format!(
                    "binary operator {other_sym} not applicable to IntValue"
                ))),
            }
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn as_int(v: &dyn ExpressionValue) -> i64 {
        v.as_any().downcast_ref::<IntValue>().expect("IntValue").0
    }

    #[test]
    fn apply_unary_operator_plus_is_identity() {
        let v = IntValue(5);
        let result = v.apply_unary_operator(&PlusOp).expect("applies");
        assert_eq!(as_int(result.as_ref()), 5);
    }

    #[test]
    fn apply_unary_operator_minus_negates() {
        let v = IntValue(5);
        let result = v.apply_unary_operator(&MinusOp).expect("applies");
        assert_eq!(as_int(result.as_ref()), -5);
    }

    #[test]
    fn apply_unary_operator_unsupported_operator_errors() {
        let v = IntValue(5);
        match v.apply_unary_operator(&MulOp) {
            Err(e) => assert!(e.to_string().contains("not applicable")),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn apply_binary_operator_adds_and_subtracts() {
        let a = IntValue(3);
        let b = IntValue(4);
        assert_eq!(as_int(a.apply_binary_operator(&PlusOp, &b).unwrap().as_ref()), 7);
        assert_eq!(as_int(a.apply_binary_operator(&MinusOp, &b).unwrap().as_ref()), -1);
    }

    #[test]
    fn apply_binary_operator_unsupported_operator_errors() {
        let a = IntValue(3);
        let b = IntValue(4);
        assert!(a.apply_binary_operator(&MulOp, &b).is_err());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let a: Box<dyn ExpressionValue> = Box::new(IntValue(10));
        let b: Box<dyn ExpressionValue> = Box::new(IntValue(2));
        let sum = a.apply_binary_operator(&PlusOp, b.as_ref()).unwrap();
        assert_eq!(as_int(sum.as_ref()), 12);
    }
}
