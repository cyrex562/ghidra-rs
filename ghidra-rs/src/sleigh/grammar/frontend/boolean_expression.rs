//! Hand-written lexer + recursive-descent evaluator for the preprocessor's
//! `@if` / `@elif` boolean expressions.
//!
//! Mirrors `BooleanExpression.g` (ANTLR-3), which defines the grammar:
//!
//! ```text
//! expression : expr EOF
//! expr       : expr_or
//! expr_or    : expr_xor (OP_OR  expr_xor)*        // '||'
//! expr_xor   : expr_and (OP_XOR expr_and)*        // '^^'
//! expr_and   : expr_not (OP_AND expr_not)*        // '&&'
//! expr_not   : OP_NOT expr_paren
//!            | expr_paren
//!            | expr_eq
//!            | KEY_DEFINED '(' IDENTIFIER ')'
//! expr_paren : '(' expr ')'
//! expr_eq    : expr_term (OP_EQ | OP_NEQ) expr_term
//! expr_term  : IDENTIFIER | QSTRING
//! ```
//!
//! The Java parser resolves values through `ExpressionEnvironment`, whose
//! `lookup` returns `null` for undefined macros. The already-ported
//! `crate::sleigh::grammar::ExpressionEnvironment` trait collapses `null` to
//! an empty string, which loses the defined-vs-undefined distinction needed by
//! `defined(X)` and by the "Macro: X is undefined" error. This module
//! therefore uses its own [`BooleanExpressionEnvironment`] trait with an
//! `Option`-returning `lookup`.

/// Environment used to resolve macros while evaluating a boolean expression.
pub trait BooleanExpressionEnvironment {
    /// Returns the value of `variable`, or `None` if it is not defined.
    fn lookup_variable(&self, variable: &str) -> Option<String>;

    /// Reports a non-fatal evaluation error (e.g. an undefined macro in an
    /// equality comparison). Mirrors `ExpressionEnvironment.reportError`.
    fn report_expression_error(&mut self, msg: &str);
}

/// Token set from `BooleanExpression.g`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BoolTok {
    Or,       // '||'
    Xor,      // '^^'
    And,      // '&&'
    Not,      // '!'
    Eq,       // '=='
    Neq,      // '!='
    LParen,   // '('
    RParen,   // ')'
    Defined,  // 'defined'
    Identifier(String),
    QString(String), // value without surrounding quotes
}

/// Tokenizes a boolean expression string.
///
/// `IDENTIFIER : (ALPHA | '_' | DIGIT)+` and `QSTRING` per the grammar;
/// whitespace is skipped (HIDDEN channel in ANTLR).
fn tokenize(input: &str) -> Result<Vec<BoolTok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' | '\n' => i += 1,
            '|' if chars.get(i + 1) == Some(&'|') => {
                toks.push(BoolTok::Or);
                i += 2;
            }
            '^' if chars.get(i + 1) == Some(&'^') => {
                toks.push(BoolTok::Xor);
                i += 2;
            }
            '&' if chars.get(i + 1) == Some(&'&') => {
                toks.push(BoolTok::And);
                i += 2;
            }
            '=' if chars.get(i + 1) == Some(&'=') => {
                toks.push(BoolTok::Eq);
                i += 2;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                toks.push(BoolTok::Neq);
                i += 2;
            }
            '!' => {
                toks.push(BoolTok::Not);
                i += 1;
            }
            '(' => {
                toks.push(BoolTok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(BoolTok::RParen);
                i += 1;
            }
            '"' => {
                // QSTRING: '"' (ESCAPE | ~('\\' | '"'))* '"'
                let mut s = String::new();
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return Err("unterminated string in boolean expression".into()),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\') => {
                            // Keep the escape sequence verbatim; the Java
                            // grammar does not decode escapes in expr_term
                            // either (it only strips the quotes).
                            s.push('\\');
                            i += 1;
                            if let Some(&next) = chars.get(i) {
                                s.push(next);
                                i += 1;
                            }
                        }
                        Some(&other) => {
                            s.push(other);
                            i += 1;
                        }
                    }
                }
                toks.push(BoolTok::QString(s));
            }
            c if c.is_ascii_alphanumeric() || c == '_' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word == "defined" {
                    toks.push(BoolTok::Defined);
                } else {
                    toks.push(BoolTok::Identifier(word));
                }
            }
            other => {
                return Err(format!(
                    "unexpected character '{other}' in boolean expression"
                ))
            }
        }
    }
    Ok(toks)
}

struct BoolParser<'e> {
    toks: Vec<BoolTok>,
    pos: usize,
    env: &'e mut dyn BooleanExpressionEnvironment,
}

impl<'e> BoolParser<'e> {
    fn peek(&self) -> Option<&BoolTok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<BoolTok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, tok: &BoolTok) -> Result<(), String> {
        match self.bump() {
            Some(ref t) if t == tok => Ok(()),
            other => Err(format!("expected {tok:?}, found {other:?}")),
        }
    }

    /// `expression : expr EOF`
    fn expression(&mut self) -> Result<bool, String> {
        let b = self.expr_or()?;
        if self.pos != self.toks.len() {
            return Err(format!(
                "trailing input in boolean expression at token {:?}",
                self.peek()
            ));
        }
        Ok(b)
    }

    fn expr_or(&mut self) -> Result<bool, String> {
        let mut b = self.expr_xor()?;
        while self.peek() == Some(&BoolTok::Or) {
            self.bump();
            let rhs = self.expr_xor()?;
            b = b || rhs;
        }
        Ok(b)
    }

    fn expr_xor(&mut self) -> Result<bool, String> {
        let mut b = self.expr_and()?;
        while self.peek() == Some(&BoolTok::Xor) {
            self.bump();
            let rhs = self.expr_and()?;
            b ^= rhs;
        }
        Ok(b)
    }

    fn expr_and(&mut self) -> Result<bool, String> {
        let mut b = self.expr_not()?;
        while self.peek() == Some(&BoolTok::And) {
            self.bump();
            let rhs = self.expr_not()?;
            b = b && rhs;
        }
        Ok(b)
    }

    /// `expr_not : '!' expr_paren | expr_paren | expr_eq | 'defined' '(' ID ')'`
    fn expr_not(&mut self) -> Result<bool, String> {
        match self.peek() {
            Some(BoolTok::Not) => {
                self.bump();
                Ok(!self.expr_paren()?)
            }
            Some(BoolTok::LParen) => self.expr_paren(),
            Some(BoolTok::Defined) => {
                self.bump();
                self.expect(&BoolTok::LParen)?;
                let id = match self.bump() {
                    Some(BoolTok::Identifier(id)) => id,
                    other => {
                        return Err(format!("expected identifier in defined(), found {other:?}"))
                    }
                };
                self.expect(&BoolTok::RParen)?;
                Ok(self.env.lookup_variable(&id).is_some())
            }
            _ => self.expr_eq(),
        }
    }

    fn expr_paren(&mut self) -> Result<bool, String> {
        self.expect(&BoolTok::LParen)?;
        let b = self.expr_or()?;
        self.expect(&BoolTok::RParen)?;
        Ok(b)
    }

    /// `expr_eq : expr_term ('==' | '!=') expr_term`
    fn expr_eq(&mut self) -> Result<bool, String> {
        let lhs = self.expr_term()?;
        let eq = match self.bump() {
            Some(BoolTok::Eq) => true,
            Some(BoolTok::Neq) => false,
            other => return Err(format!("expected == or != in boolean expression, found {other:?}")),
        };
        let rhs = self.expr_term()?;
        // Java ExpressionEnvironment.equals returns false when either side is
        // null (undefined macro); reportError has already been issued.
        let equal = match (lhs, rhs) {
            (Some(l), Some(r)) => l == r,
            _ => false,
        };
        Ok(if eq { equal } else { !equal })
    }

    /// `expr_term : IDENTIFIER | QSTRING`; identifiers resolve through the
    /// environment, reporting an error (and yielding `None`) when undefined.
    fn expr_term(&mut self) -> Result<Option<String>, String> {
        match self.bump() {
            Some(BoolTok::Identifier(id)) => {
                let value = self.env.lookup_variable(&id);
                if value.is_none() {
                    self.env
                        .report_expression_error(&format!("Macro: {id} is undefined"));
                }
                Ok(value)
            }
            Some(BoolTok::QString(s)) => Ok(Some(s)),
            other => Err(format!(
                "expected identifier or string in boolean expression, found {other:?}"
            )),
        }
    }
}

/// Evaluates an `@if`/`@elif` boolean expression.
///
/// Returns `Err` on syntax errors; undefined macros used in comparisons are
/// reported through the environment and compare unequal, mirroring the Java
/// behavior.
pub fn evaluate_boolean_expression(
    expression: &str,
    env: &mut dyn BooleanExpressionEnvironment,
) -> Result<bool, String> {
    let toks = tokenize(expression)?;
    let mut parser = BoolParser { toks, pos: 0, env };
    parser.expression()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct TestEnv {
        vars: HashMap<String, String>,
        errors: Vec<String>,
    }

    impl TestEnv {
        fn with(vars: &[(&str, &str)]) -> Self {
            Self {
                vars: vars
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                errors: Vec::new(),
            }
        }
    }

    impl BooleanExpressionEnvironment for TestEnv {
        fn lookup_variable(&self, variable: &str) -> Option<String> {
            self.vars.get(variable).cloned()
        }

        fn report_expression_error(&mut self, msg: &str) {
            self.errors.push(msg.to_string());
        }
    }

    fn eval(expr: &str, env: &mut TestEnv) -> bool {
        evaluate_boolean_expression(expr, env).unwrap()
    }

    #[test]
    fn defined_true_and_false() {
        let mut env = TestEnv::with(&[("FOO", "1")]);
        assert!(eval("defined(FOO)", &mut env));
        assert!(!eval("defined(BAR)", &mut env));
    }

    #[test]
    fn defined_with_empty_value_is_true() {
        let mut env = TestEnv::with(&[("FLAG", "")]);
        assert!(eval("defined(FLAG)", &mut env));
    }

    #[test]
    fn equality_against_string() {
        let mut env = TestEnv::with(&[("MODE", "fast")]);
        assert!(eval("MODE == \"fast\"", &mut env));
        assert!(!eval("MODE == \"slow\"", &mut env));
        assert!(eval("MODE != \"slow\"", &mut env));
    }

    #[test]
    fn equality_between_identifiers() {
        let mut env = TestEnv::with(&[("A", "x"), ("B", "x"), ("C", "y")]);
        assert!(eval("A == B", &mut env));
        assert!(!eval("A == C", &mut env));
    }

    #[test]
    fn undefined_macro_in_comparison_reports_error_and_is_unequal() {
        let mut env = TestEnv::with(&[]);
        assert!(!eval("NOPE == \"x\"", &mut env));
        assert_eq!(env.errors, vec!["Macro: NOPE is undefined"]);
        // != of an undefined macro is true (not-equal), mirroring Java.
        let mut env2 = TestEnv::with(&[]);
        assert!(eval("NOPE != \"x\"", &mut env2));
    }

    #[test]
    fn boolean_connectives() {
        let mut env = TestEnv::with(&[("A", "1")]);
        assert!(eval("defined(A) || defined(B)", &mut env));
        assert!(!eval("defined(A) && defined(B)", &mut env));
        assert!(eval("defined(A) ^^ defined(B)", &mut env));
        assert!(!eval("defined(A) ^^ defined(A)", &mut env));
    }

    #[test]
    fn not_applies_to_parenthesized_expression() {
        let mut env = TestEnv::with(&[("A", "1")]);
        assert!(!eval("!(defined(A))", &mut env));
        assert!(eval("!(defined(B))", &mut env));
    }

    #[test]
    fn parentheses_group() {
        let mut env = TestEnv::with(&[("A", "1")]);
        assert!(eval("(defined(A) || defined(B)) && defined(A)", &mut env));
    }

    #[test]
    fn precedence_and_binds_tighter_than_or() {
        // false || (true && true) == true
        let mut env = TestEnv::with(&[("A", "1")]);
        assert!(eval(
            "defined(B) || defined(A) && defined(A)",
            &mut env
        ));
    }

    #[test]
    fn syntax_error_is_err() {
        let mut env = TestEnv::with(&[]);
        assert!(evaluate_boolean_expression("&&", &mut env).is_err());
        assert!(evaluate_boolean_expression("defined(", &mut env).is_err());
        assert!(evaluate_boolean_expression("A ==", &mut env).is_err());
        assert!(evaluate_boolean_expression("defined(A) extra", &mut env).is_err());
    }
}
