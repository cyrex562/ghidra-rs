use crate::generic::expressions::expression_element::ExpressionElement;
use crate::generic::expressions::expression_exception::ExpressionException;
use crate::generic::expressions::expression_operator::ExpressionOperator;
use crate::generic::expressions::expression_value::ExpressionValue;

/// Long operand values. See [`ExpressionValue`]. Defines supported operators and other operands
/// for expression values that are long values.
///
/// Port of `generic.expressions.LongExpressionValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongExpressionValue {
    value: i64,
}

impl LongExpressionValue {
    /// Constructs a new `LongExpressionValue` wrapping `value`.
    ///
    /// Mirrors `LongExpressionValue(long)`.
    pub fn new(value: i64) -> Self {
        Self { value }
    }

    /// Returns the wrapped `i64` value.
    ///
    /// Mirrors `getLongValue()`.
    pub fn get_long_value(&self) -> i64 {
        self.value
    }
}

impl std::fmt::Display for LongExpressionValue {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl ExpressionElement for LongExpressionValue {}

impl ExpressionValue for LongExpressionValue {
    /// Mirrors `applyUnaryOperator(ExpressionOperator)`.
    fn apply_unary_operator(
        &self,
        operator: &dyn ExpressionOperator,
    ) -> Result<Box<dyn ExpressionValue>, ExpressionException> {
        match operator.symbol() {
            "~" => Ok(Box::new(LongExpressionValue::new(!self.value))),
            "!" => Ok(Box::new(LongExpressionValue::new(if self.value == 0 { 1 } else { 0 }))),
            "-" if operator.is_unary() => Ok(Box::new(LongExpressionValue::new(-self.value))),
            "+" if operator.is_unary() => Ok(Box::new(*self)),
            other => Err(ExpressionException::new(format!(
                "Unary Operator {other} not supported by Long values!"
            ))),
        }
    }

    /// Mirrors `applyBinaryOperator(ExpressionOperator, ExpressionValue)`.
    fn apply_binary_operator(
        &self,
        operator: &dyn ExpressionOperator,
        value: &dyn ExpressionValue,
    ) -> Result<Box<dyn ExpressionValue>, ExpressionException> {
        let Some(long_operand) = value.as_any().downcast_ref::<LongExpressionValue>() else {
            // Quirk preserved from Java: the message reports `self.value`, not anything about
            // the actual incompatible `value` operand -- see the dedicated test below.
            return Err(ExpressionException::new(format!(
                "Unsupported operand type for Long: {}",
                self.value
            )));
        };
        let other_value = long_operand.value;

        match operator.symbol() {
            "&" => Ok(Box::new(LongExpressionValue::new(self.value & other_value))),
            "|" => Ok(Box::new(LongExpressionValue::new(self.value | other_value))),
            "^" => Ok(Box::new(LongExpressionValue::new(self.value ^ other_value))),
            "/" => Ok(Box::new(LongExpressionValue::new(self.value / other_value))),
            "==" => Ok(Box::new(LongExpressionValue::new(if self.value == other_value {
                1
            } else {
                0
            }))),
            ">" => Ok(Box::new(LongExpressionValue::new(if self.value > other_value {
                1
            } else {
                0
            }))),
            ">=" => Ok(Box::new(LongExpressionValue::new(if self.value >= other_value {
                1
            } else {
                0
            }))),
            "<<" => Ok(Box::new(LongExpressionValue::new(self.value << other_value))),
            "<" => Ok(Box::new(LongExpressionValue::new(if self.value < other_value {
                1
            } else {
                0
            }))),
            "<=" => Ok(Box::new(LongExpressionValue::new(if self.value <= other_value {
                1
            } else {
                0
            }))),
            "&&" => {
                let b1 = if self.value == 0 { 0 } else { 1 };
                let b2 = if other_value == 0 { 0 } else { 1 };
                Ok(Box::new(LongExpressionValue::new(b1 & b2)))
            }
            "||" => {
                let b1 = if self.value == 0 { 0 } else { 1 };
                let b2 = if other_value == 0 { 0 } else { 1 };
                Ok(Box::new(LongExpressionValue::new(b1 | b2)))
            }
            "-" => Ok(Box::new(LongExpressionValue::new(self.value - other_value))),
            "!=" => Ok(Box::new(LongExpressionValue::new(if self.value == other_value {
                0
            } else {
                1
            }))),
            "+" => Ok(Box::new(LongExpressionValue::new(self.value + other_value))),
            ">>" => Ok(Box::new(LongExpressionValue::new(self.value >> other_value))),
            "*" => Ok(Box::new(LongExpressionValue::new(self.value * other_value))),
            other => Err(ExpressionException::new(format!(
                "Binary Operator \"{other}\" not supported by Long values!"
            ))),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOp {
        symbol: &'static str,
        unary: bool,
        binary: bool,
    }

    impl ExpressionOperator for MockOp {
        fn symbol(&self) -> &str {
            self.symbol
        }
        fn is_unary(&self) -> bool {
            self.unary
        }
        fn is_binary(&self) -> bool {
            self.binary
        }
        fn precedence(&self) -> i32 {
            0
        }
    }

    const BITWISE_NOT: MockOp = MockOp { symbol: "~", unary: true, binary: false };
    const LOGICAL_NOT: MockOp = MockOp { symbol: "!", unary: true, binary: false };
    const UNARY_MINUS: MockOp = MockOp { symbol: "-", unary: true, binary: false };
    const UNARY_PLUS: MockOp = MockOp { symbol: "+", unary: true, binary: false };
    const ADD: MockOp = MockOp { symbol: "+", unary: false, binary: true };
    const SUBTRACT: MockOp = MockOp { symbol: "-", unary: false, binary: true };
    const MULTIPLY: MockOp = MockOp { symbol: "*", unary: false, binary: true };
    const DIVIDE: MockOp = MockOp { symbol: "/", unary: false, binary: true };
    const SHIFT_LEFT: MockOp = MockOp { symbol: "<<", unary: false, binary: true };
    const SHIFT_RIGHT: MockOp = MockOp { symbol: ">>", unary: false, binary: true };
    const EQUALS: MockOp = MockOp { symbol: "==", unary: false, binary: true };
    const NOT_EQUALS: MockOp = MockOp { symbol: "!=", unary: false, binary: true };
    const LESS_THAN: MockOp = MockOp { symbol: "<", unary: false, binary: true };
    const LESS_THAN_OR_EQUAL: MockOp = MockOp { symbol: "<=", unary: false, binary: true };
    const GREATER_THAN: MockOp = MockOp { symbol: ">", unary: false, binary: true };
    const GREATER_THAN_OR_EQUAL: MockOp = MockOp { symbol: ">=", unary: false, binary: true };
    const BITWISE_AND: MockOp = MockOp { symbol: "&", unary: false, binary: true };
    const BITWISE_OR: MockOp = MockOp { symbol: "|", unary: false, binary: true };
    const BITWISE_XOR: MockOp = MockOp { symbol: "^", unary: false, binary: true };
    const LOGICAL_AND: MockOp = MockOp { symbol: "&&", unary: false, binary: true };
    const LOGICAL_OR: MockOp = MockOp { symbol: "||", unary: false, binary: true };

    fn long_val(v: i64) -> i64 {
        let boxed: Box<dyn ExpressionValue> = Box::new(LongExpressionValue::new(v));
        boxed.as_any().downcast_ref::<LongExpressionValue>().unwrap().get_long_value()
    }

    fn apply_unary(v: i64, op: &dyn ExpressionOperator) -> i64 {
        let value = LongExpressionValue::new(v);
        let result = value.apply_unary_operator(op).expect("applies");
        result.as_any().downcast_ref::<LongExpressionValue>().unwrap().get_long_value()
    }

    fn apply_binary(a: i64, op: &dyn ExpressionOperator, b: i64) -> i64 {
        let left = LongExpressionValue::new(a);
        let right = LongExpressionValue::new(b);
        let result = left.apply_binary_operator(op, &right).expect("applies");
        result.as_any().downcast_ref::<LongExpressionValue>().unwrap().get_long_value()
    }

    #[test]
    fn new_and_get_long_value_round_trip() {
        assert_eq!(LongExpressionValue::new(42).get_long_value(), 42);
        assert_eq!(long_val(-7), -7);
    }

    #[test]
    fn to_string_renders_the_decimal_value() {
        assert_eq!(LongExpressionValue::new(123).to_string(), "123");
        assert_eq!(LongExpressionValue::new(-5).to_string(), "-5");
    }

    #[test]
    fn unary_bitwise_not() {
        assert_eq!(apply_unary(0, &BITWISE_NOT), !0i64);
        assert_eq!(apply_unary(5, &BITWISE_NOT), !5i64);
    }

    #[test]
    fn unary_logical_not_treats_nonzero_as_true() {
        assert_eq!(apply_unary(0, &LOGICAL_NOT), 1);
        assert_eq!(apply_unary(42, &LOGICAL_NOT), 0);
    }

    #[test]
    fn unary_minus_negates() {
        assert_eq!(apply_unary(5, &UNARY_MINUS), -5);
        assert_eq!(apply_unary(-5, &UNARY_MINUS), 5);
    }

    #[test]
    fn unary_plus_is_identity() {
        assert_eq!(apply_unary(5, &UNARY_PLUS), 5);
    }

    #[test]
    fn unsupported_unary_operator_errors() {
        let value = LongExpressionValue::new(1);
        match value.apply_unary_operator(&MULTIPLY) {
            Err(e) => assert!(e.to_string().contains("not supported by Long values")),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn binary_arithmetic_operators() {
        assert_eq!(apply_binary(3, &ADD, 4), 7);
        assert_eq!(apply_binary(3, &SUBTRACT, 4), -1);
        assert_eq!(apply_binary(3, &MULTIPLY, 4), 12);
        assert_eq!(apply_binary(12, &DIVIDE, 4), 3);
        assert_eq!(apply_binary(1, &SHIFT_LEFT, 3), 8);
        assert_eq!(apply_binary(8, &SHIFT_RIGHT, 3), 1);
    }

    #[test]
    fn binary_comparison_operators() {
        assert_eq!(apply_binary(3, &EQUALS, 3), 1);
        assert_eq!(apply_binary(3, &EQUALS, 4), 0);
        assert_eq!(apply_binary(3, &NOT_EQUALS, 4), 1);
        assert_eq!(apply_binary(3, &NOT_EQUALS, 3), 0);
        assert_eq!(apply_binary(3, &LESS_THAN, 4), 1);
        assert_eq!(apply_binary(3, &LESS_THAN_OR_EQUAL, 3), 1);
        assert_eq!(apply_binary(4, &GREATER_THAN, 3), 1);
        assert_eq!(apply_binary(3, &GREATER_THAN_OR_EQUAL, 3), 1);
    }

    #[test]
    fn binary_bitwise_operators() {
        assert_eq!(apply_binary(0b110, &BITWISE_AND, 0b011), 0b010);
        assert_eq!(apply_binary(0b110, &BITWISE_OR, 0b011), 0b111);
        assert_eq!(apply_binary(0b110, &BITWISE_XOR, 0b011), 0b101);
    }

    #[test]
    fn binary_logical_operators_normalize_to_zero_or_one() {
        assert_eq!(apply_binary(5, &LOGICAL_AND, 3), 1);
        assert_eq!(apply_binary(5, &LOGICAL_AND, 0), 0);
        assert_eq!(apply_binary(0, &LOGICAL_OR, 3), 1);
        assert_eq!(apply_binary(0, &LOGICAL_OR, 0), 0);
    }

    #[test]
    fn unsupported_binary_operator_errors() {
        let a = LongExpressionValue::new(1);
        let b = LongExpressionValue::new(2);
        match a.apply_binary_operator(&BITWISE_NOT, &b) {
            Err(e) => assert!(e.to_string().contains("not supported by Long values")),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn binary_operator_with_non_long_operand_errors_reporting_this_values_own_value() {
        // Real Java quirk: `applyBinaryOperator`'s error message is
        // `"Unsupported operand type for Long: " + value`, where unqualified `value` resolves to
        // *this* instance's own field, not the incompatible `operand` that was actually passed
        // in. So the message reports `self`'s value (99 below), never anything about the actual
        // bad operand -- reproduced here rather than "fixed" to describe the real operand.
        struct OtherValue;
        impl ExpressionElement for OtherValue {}
        impl ExpressionValue for OtherValue {
            fn apply_unary_operator(
                &self,
                _operator: &dyn ExpressionOperator,
            ) -> Result<Box<dyn ExpressionValue>, ExpressionException> {
                unimplemented!()
            }
            fn apply_binary_operator(
                &self,
                _operator: &dyn ExpressionOperator,
                _value: &dyn ExpressionValue,
            ) -> Result<Box<dyn ExpressionValue>, ExpressionException> {
                unimplemented!()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let a = LongExpressionValue::new(99);
        let other = OtherValue;
        match a.apply_binary_operator(&ADD, &other) {
            Err(e) => assert_eq!(e.to_string(), "Unsupported operand type for Long: 99"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let a: Box<dyn ExpressionValue> = Box::new(LongExpressionValue::new(10));
        let b: Box<dyn ExpressionValue> = Box::new(LongExpressionValue::new(2));
        let sum = a.apply_binary_operator(&ADD, b.as_ref()).unwrap();
        assert_eq!(
            sum.as_any().downcast_ref::<LongExpressionValue>().unwrap().get_long_value(),
            12
        );
    }
}
