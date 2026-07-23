use crate::generic::seam_stubs::{ExpressionException, ExpressionValueLike};

/// Numeric-expression evaluator.
///
/// Port of `generic.expressions.ExpressionEvaluator`. All values are interpreted as longs.
/// Implementations can operate in either decimal or hex mode: if in hex mode, all numbers are
/// assumed to be hexadecimal; in decimal mode, numbers are assumed to be decimal unless
/// prefixed with `0x`.
///
/// The Java class's only true polymorphic seam is the constructor-supplied symbol evaluator
/// (called on any token that isn't an operator, group token, or number); the tokenizing and
/// operator-precedence algorithm itself is a fixed, private implementation detail that depends
/// on `generic.expressions.ExpressionOperator`/`ExpressionElement`/`ExpressionGrouper`, none of
/// which are ported yet. Rather than fold an unported algorithm into default trait methods,
/// [`parse_relative`](Self::parse_relative) is left as a required method for each concrete
/// evaluator to implement; [`parse`](Self::parse) and [`parse_as_long`](Self::parse_as_long)
/// are provided in terms of it, mirroring `parse(String)` and `parseAsLong(String)`.
///
/// Selected as a dependency-cycle cut-point.
pub trait ExpressionEvaluator {
    /// Returns whether numeric tokens are assumed to be hexadecimal.
    fn assume_hex(&self) -> bool;

    /// Changes the hex/decimal mode. If `true`, all numbers are assumed to be hexadecimal.
    fn set_assume_hex(&mut self, assume_hex: bool);

    /// Called on any token that can't be evaluated as an operator, group token, or number.
    /// Mirrors `evaluateSymbol`, which delegates to the constructor-supplied symbol `Function`.
    /// The default mirrors the Java default of `s -> null` (no symbol evaluator supplied).
    fn evaluate_symbol(&self, _token: &str) -> Option<Box<dyn ExpressionValueLike>> {
        None
    }

    /// Parses `input`, optionally seeded with an `initial` value. Used for relative expressions,
    /// e.g. evaluating `"+ 4"` against a running total. Mirrors the protected
    /// `parse(String, ExpressionValue)` overload.
    fn parse_relative(
        &self,
        input: &str,
        initial: Option<Box<dyn ExpressionValueLike>>,
    ) -> Result<Box<dyn ExpressionValueLike>, ExpressionException>;

    /// Parses `input` into a single expression value. Mirrors the protected `parse(String)`.
    fn parse(&self, input: &str) -> Result<Box<dyn ExpressionValueLike>, ExpressionException> {
        self.parse_relative(input, None)
    }

    /// Parses `input`, expecting the result to be a long value. Mirrors `parseAsLong`.
    fn parse_as_long(&self, input: &str) -> Result<i64, ExpressionException> {
        let value = self.parse(input)?;
        value
            .as_long()
            .ok_or_else(|| ExpressionException::new("Expression did not evalute to a long!"))
    }
}

/// Evaluates `input` as a long value using `evaluator`. Returns `None` if the expression could
/// not be evaluated.
///
/// Mirrors the static convenience method `ExpressionEvaluator.evaluateToLong(String, boolean)`.
/// The Java original constructs a fresh evaluator internally for each call; since this port is a
/// trait rather than a concrete class, the caller supplies (and this function's hex mode applies
/// to) an existing evaluator instead.
pub fn evaluate_to_long(
    evaluator: &mut dyn ExpressionEvaluator,
    input: &str,
    assume_hex: bool,
) -> Option<i64> {
    evaluator.set_assume_hex(assume_hex);
    evaluator.parse_as_long(input).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct LongValue(i64);

    impl ExpressionValueLike for LongValue {
        fn as_long(&self) -> Option<i64> {
            Some(self.0)
        }
    }

    /// A minimal but real left-to-right `+`/`-` evaluator, with an overridable symbol table --
    /// enough to exercise `ExpressionEvaluator`'s trait-object safety and default methods
    /// without depending on the unported operator-precedence machinery.
    struct SimpleLongEvaluator {
        assume_hex: bool,
        symbols: HashMap<String, i64>,
    }

    impl SimpleLongEvaluator {
        fn new(assume_hex: bool) -> Self {
            Self { assume_hex, symbols: HashMap::new() }
        }

        fn with_symbol(mut self, name: &str, value: i64) -> Self {
            self.symbols.insert(name.to_string(), value);
            self
        }

        fn try_parse_number(&self, token: &str) -> Option<i64> {
            if let Some(hex) = token.strip_prefix("0x") {
                return i64::from_str_radix(hex, 16).ok();
            }
            if self.assume_hex {
                return i64::from_str_radix(token, 16).ok();
            }
            token.parse::<i64>().ok()
        }

        fn parse_operand(&self, token: &str) -> Result<i64, ExpressionException> {
            if let Some(value) = self.try_parse_number(token) {
                return Ok(value);
            }
            if let Some(value) = self.evaluate_symbol(token) {
                return value.as_long().ok_or_else(|| {
                    ExpressionException::new(format!("Symbol \"{token}\" is not a long value"))
                });
            }
            Err(ExpressionException::new(format!("Could not evaluate token \"{token}\"")))
        }
    }

    impl ExpressionEvaluator for SimpleLongEvaluator {
        fn assume_hex(&self) -> bool {
            self.assume_hex
        }

        fn set_assume_hex(&mut self, assume_hex: bool) {
            self.assume_hex = assume_hex;
        }

        fn evaluate_symbol(&self, token: &str) -> Option<Box<dyn ExpressionValueLike>> {
            self.symbols.get(token).map(|&v| Box::new(LongValue(v)) as Box<dyn ExpressionValueLike>)
        }

        fn parse_relative(
            &self,
            input: &str,
            initial: Option<Box<dyn ExpressionValueLike>>,
        ) -> Result<Box<dyn ExpressionValueLike>, ExpressionException> {
            let mut tokens = input.split_whitespace();

            let mut acc = match initial {
                Some(value) => value
                    .as_long()
                    .ok_or_else(|| ExpressionException::new("initial value is not a long"))?,
                None => {
                    let first = tokens
                        .next()
                        .ok_or_else(|| ExpressionException::new("Expression is empty. Nothing to parse!"))?;
                    self.parse_operand(first)?
                }
            };

            loop {
                let Some(op) = tokens.next() else { break };
                let operand_token = tokens
                    .next()
                    .ok_or_else(|| ExpressionException::new(format!("Missing operand after \"{op}\"")))?;
                let operand = self.parse_operand(operand_token)?;
                acc = match op {
                    "+" => acc + operand,
                    "-" => acc - operand,
                    other => {
                        return Err(ExpressionException::new(format!(
                            "Could not evaluate token \"{other}\""
                        )))
                    }
                };
            }

            Ok(Box::new(LongValue(acc)))
        }
    }

    #[test]
    fn parses_decimal_addition_and_subtraction() {
        let evaluator = SimpleLongEvaluator::new(false);
        assert_eq!(evaluator.parse_as_long("3 + 4 - 2").unwrap(), 5);
    }

    #[test]
    fn hex_mode_treats_bare_numbers_as_hex() {
        let mut evaluator = SimpleLongEvaluator::new(false);
        evaluator.set_assume_hex(true);
        assert!(evaluator.assume_hex());
        assert_eq!(evaluator.parse_as_long("10 + 1").unwrap(), 0x10 + 1);
    }

    #[test]
    fn explicit_hex_prefix_works_regardless_of_mode() {
        let evaluator = SimpleLongEvaluator::new(false);
        assert_eq!(evaluator.parse_as_long("0x2a").unwrap(), 42);
    }

    #[test]
    fn symbol_evaluator_resolves_unknown_tokens() {
        let evaluator = SimpleLongEvaluator::new(false).with_symbol("x", 100);
        assert_eq!(evaluator.parse_as_long("x + 1").unwrap(), 101);
    }

    #[test]
    fn unresolvable_symbol_is_an_error() {
        let evaluator = SimpleLongEvaluator::new(false);
        let err = evaluator.parse_as_long("y + 1").unwrap_err();
        assert_eq!(err, ExpressionException::new("Could not evaluate token \"y\""));
    }

    #[test]
    fn empty_expression_is_an_error() {
        let evaluator = SimpleLongEvaluator::new(false);
        assert!(evaluator.parse("").is_err());
    }

    #[test]
    fn parse_relative_seeds_from_initial_value() {
        let evaluator = SimpleLongEvaluator::new(false);
        let result = evaluator
            .parse_relative("+ 4", Some(Box::new(LongValue(10))))
            .unwrap();
        assert_eq!(result.as_long(), Some(14));
    }

    #[test]
    fn trait_object_and_free_function_work_together() {
        let mut boxed: Box<dyn ExpressionEvaluator> = Box::new(SimpleLongEvaluator::new(false));
        assert_eq!(evaluate_to_long(boxed.as_mut(), "5 - 2", false), Some(3));
        // Switching to hex mode via the free function actually changes the evaluator's state.
        assert_eq!(evaluate_to_long(boxed.as_mut(), "10", true), Some(16));
    }
}
