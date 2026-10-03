//! Port of `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionException`.
//!
//! An exception thrown when dealing with [`DWARFExpression`]s or when they are evaluated by
//! [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator).
//! Carries the expression and the position within it that caused the problem back up the call
//! chain, exactly as the Java exception does.
//!
//! # Departures from the Java class
//!
//! Java models the expression-evaluation error hierarchy as four classes:
//! `DWARFExpressionException` (this file), and three subclasses --
//! `DWARFExpressionUnsupportedOpException`, its own subclass
//! `DWARFExpressionTerminalDerefException`, and `DWARFExpressionValueException` -- each of which
//! carries additional state ([`DWARFExpressionInstruction`] and/or a
//! [`Varnode`](crate::program::model::pcode::Varnode)) alongside the base class's fields. Rust has
//! no exception hierarchy, so all four collapse into this one error type, discriminated by
//! [`DWARFExpressionExceptionKind`]. The base class's own five constructors --
//! `DWARFExpressionException()`, `(String, DWARFExpression, int, Throwable)`, `(String,
//! Throwable)`, `(String)`, and `(Throwable)` -- are ported faithfully as
//! [`Self::empty`]/[`Self::with_expr_and_cause`]/[`Self::with_cause`]/[`Self::new`]/[`Self::from_cause`]
//! respectively, since Rust has no constructor overloading; the three subclasses' own
//! constructors are ported as [`Self::unsupported_op`]/[`Self::terminal_deref`]/[`Self::value`].

use std::fmt;

use crate::format::dwarf::expression::dwarf_expression::DWARFExpression;
use crate::format::seam_stubs::DWARFExpressionInstruction;

/// Which of the `DWARFExpressionException` subclasses an error is, along with the extra state
/// that subclass carries. See the [module documentation](self) for why the four Java classes
/// collapse into this one Rust type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DWARFExpressionExceptionKind {
    /// Plain `DWARFExpressionException`.
    Generic,
    /// `DWARFExpressionUnsupportedOpException`: the evaluator does not implement this
    /// instruction.
    UnsupportedOp(DWARFExpressionInstruction),
    /// `DWARFExpressionTerminalDerefException` (a subclass of the unsupported-op exception): the
    /// expression ended with a `DW_OP_deref` of the given location, which some callers can still
    /// make use of.
    TerminalDeref(DWARFExpressionInstruction, crate::program::model::pcode::Varnode),
    /// `DWARFExpressionValueException`: the value of the given varnode could not be fetched.
    Value(crate::program::model::pcode::Varnode),
}

/// A exception that is thrown when dealing with [`DWARFExpression`]s or when they are evaluated.
///
/// Use this type when you want to pass the expression and the location in the expression that
/// caused the problem back up the call chain.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionException` (and its three
/// subclasses -- see the [module documentation](self)).
#[derive(Debug)]
pub struct DWARFExpressionException {
    message: String,
    kind: DWARFExpressionExceptionKind,
    expr: Option<DWARFExpression>,
    instr_index: i32,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DWARFExpressionException {
    /// Mirrors the no-arg `DWARFExpressionException()` constructor.
    pub fn empty() -> Self {
        DWARFExpressionException {
            message: String::new(),
            kind: DWARFExpressionExceptionKind::Generic,
            expr: None,
            instr_index: -1,
            cause: None,
        }
    }

    /// Mirrors `DWARFExpressionException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        DWARFExpressionException {
            message: message.into(),
            kind: DWARFExpressionExceptionKind::Generic,
            expr: None,
            instr_index: -1,
            cause: None,
        }
    }

    /// Mirrors `DWARFExpressionException(String message, Throwable cause)`.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        DWARFExpressionException {
            message: message.into(),
            kind: DWARFExpressionExceptionKind::Generic,
            expr: None,
            instr_index: -1,
            cause: Some(Box::new(cause)),
        }
    }

    /// Mirrors `DWARFExpressionException(Throwable cause)`, which (via `Exception(Throwable)`)
    /// sets this exception's message to `cause.toString()`.
    pub fn from_cause(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        let message = cause.to_string();
        DWARFExpressionException {
            message,
            kind: DWARFExpressionExceptionKind::Generic,
            expr: None,
            instr_index: -1,
            cause: Some(Box::new(cause)),
        }
    }

    /// Mirrors `DWARFExpressionException(String message, DWARFExpression expr, int instrIndex,
    /// Throwable cause)`.
    pub fn with_expr_and_cause(
        message: impl Into<String>,
        expr: DWARFExpression,
        instr_index: i32,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        DWARFExpressionException {
            message: message.into(),
            kind: DWARFExpressionExceptionKind::Generic,
            expr: Some(expr),
            instr_index,
            cause: Some(Box::new(cause)),
        }
    }

    /// Mirrors `DWARFExpressionUnsupportedOpException(DWARFExpressionInstruction)`.
    pub fn unsupported_op(instr: DWARFExpressionInstruction) -> Self {
        DWARFExpressionException {
            message: format!("Unsupported instruction {instr}"),
            kind: DWARFExpressionExceptionKind::UnsupportedOp(instr),
            expr: None,
            instr_index: -1,
            cause: None,
        }
    }

    /// Mirrors `DWARFExpressionTerminalDerefException(DWARFExpressionInstruction, Varnode)`,
    /// whose superclass constructor builds the same "Unsupported instruction" message.
    pub fn terminal_deref(
        instr: DWARFExpressionInstruction,
        varnode: crate::program::model::pcode::Varnode,
    ) -> Self {
        DWARFExpressionException {
            message: format!("Unsupported instruction {instr}"),
            kind: DWARFExpressionExceptionKind::TerminalDeref(instr, varnode),
            expr: None,
            instr_index: -1,
            cause: None,
        }
    }

    /// Mirrors `DWARFExpressionValueException(Varnode)`.
    pub fn value(vn: crate::program::model::pcode::Varnode) -> Self {
        DWARFExpressionException {
            message: format!("Unable to access value of {vn}"),
            kind: DWARFExpressionExceptionKind::Value(vn),
            expr: None,
            instr_index: -1,
            cause: None,
        }
    }

    /// Which Java exception class this stands in for.
    pub fn kind(&self) -> &DWARFExpressionExceptionKind {
        &self.kind
    }

    /// Mirrors `DWARFExpressionException.getExpression()`.
    pub fn get_expression(&self) -> Option<&DWARFExpression> {
        self.expr.as_ref()
    }

    /// Mirrors `DWARFExpressionException.setExpression(DWARFExpression)`.
    pub fn set_expression(&mut self, expr: DWARFExpression) {
        self.expr = Some(expr);
    }

    /// Mirrors `DWARFExpressionException.getInstructionIndex()`.
    pub fn get_instruction_index(&self) -> i32 {
        self.instr_index
    }

    /// Mirrors `DWARFExpressionException.setInstructionIndex(int)`.
    pub fn set_instruction_index(&mut self, instr_index: i32) {
        self.instr_index = instr_index;
    }

    /// The `DWARFExpressionUnsupportedOpException`/`DWARFExpressionTerminalDerefException`
    /// `getInstruction()` accessor.
    pub fn get_instruction(&self) -> Option<&DWARFExpressionInstruction> {
        match &self.kind {
            DWARFExpressionExceptionKind::UnsupportedOp(instr)
            | DWARFExpressionExceptionKind::TerminalDeref(instr, _) => Some(instr),
            _ => None,
        }
    }

    /// The `DWARFExpressionTerminalDerefException`/`DWARFExpressionValueException`
    /// `getVarnode()` accessor.
    pub fn get_varnode(&self) -> Option<&crate::program::model::pcode::Varnode> {
        match &self.kind {
            DWARFExpressionExceptionKind::TerminalDeref(_, vn)
            | DWARFExpressionExceptionKind::Value(vn) => Some(vn),
            _ => None,
        }
    }
}

impl fmt::Display for DWARFExpressionException {
    /// Mirrors `DWARFExpressionException.getMessage()`, which appends the expression (if known).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(expr) = &self.expr {
            write!(f, "\n{}", expr.to_string_formatted(self.instr_index, false, false, None))?;
        }
        Ok(())
    }
}

impl std::error::Error for DWARFExpressionException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_message_and_no_source() {
        let e = DWARFExpressionException::empty();
        assert_eq!(e.to_string(), "");
        assert_eq!(e.get_instruction_index(), -1);
        assert!(e.get_expression().is_none());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn new_stores_message_with_no_cause() {
        let e = DWARFExpressionException::new("bad expression");
        assert_eq!(e.to_string(), "bad expression");
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn with_cause_stores_message_and_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let e = DWARFExpressionException::with_cause("read failed", cause);
        assert_eq!(e.to_string(), "read failed");
        let source = std::error::Error::source(&e).expect("cause should be present");
        assert_eq!(source.to_string(), "eof");
    }

    #[test]
    fn from_cause_derives_message_from_cause_to_string() {
        let cause = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let cause_message = cause.to_string();
        let e = DWARFExpressionException::from_cause(cause);
        assert_eq!(e.to_string(), cause_message);
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn get_expression_and_instruction_index_round_trip() {
        let mut e = DWARFExpressionException::new("oops");
        assert!(e.get_expression().is_none());

        let expr = DWARFExpression::of(Vec::new());
        e.set_expression(expr.clone());
        e.set_instruction_index(3);

        assert_eq!(e.get_expression(), Some(&expr));
        assert_eq!(e.get_instruction_index(), 3);
    }

    #[test]
    fn display_appends_formatted_expression_when_present() {
        use crate::format::dwarf::expression::dwarf_expression_opcode::DWARFExpressionOpCode;

        let instr = DWARFExpressionInstruction::new(DWARFExpressionOpCode::DW_OP_lit2, Vec::new(), 0);
        let expr = DWARFExpression::of(vec![instr]);

        let mut e = DWARFExpressionException::new("boom");
        e.set_expression(expr.clone());
        e.set_instruction_index(0);

        let expected = format!("boom\n{}", expr.to_string_formatted(0, false, false, None));
        assert_eq!(e.to_string(), expected);
    }

    #[test]
    fn with_expr_and_cause_sets_every_field() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "underlying");
        let expr = DWARFExpression::of(Vec::new());
        let e = DWARFExpressionException::with_expr_and_cause("wrapped", expr.clone(), 7, cause);

        assert_eq!(e.get_instruction_index(), 7);
        assert_eq!(e.get_expression(), Some(&expr));
        assert!(std::error::Error::source(&e).is_some());
        assert!(e.to_string().starts_with("wrapped"));
    }

    #[test]
    fn kind_defaults_to_generic_for_base_constructors() {
        let e = DWARFExpressionException::new("plain");
        assert_eq!(*e.kind(), DWARFExpressionExceptionKind::Generic);
        assert!(e.get_instruction().is_none());
        assert!(e.get_varnode().is_none());
    }

    /// Exercises [`DWARFExpressionException::value`], which stands in for
    /// `DWARFExpressionValueException(Varnode)`: message, `Value` discriminant, and
    /// `getVarnode()` accessor all mirror the Java subclass exactly.
    #[test]
    fn value_mirrors_dwarf_expression_value_exception() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::Varnode;

        let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let vn = Varnode::new(ram.address(0x4000), 4);

        let e = DWARFExpressionException::value(vn.clone());

        assert_eq!(*e.kind(), DWARFExpressionExceptionKind::Value(vn.clone()));
        assert_eq!(e.get_varnode(), Some(&vn));
        assert!(e.get_instruction().is_none());
        assert_eq!(e.to_string(), format!("Unable to access value of {vn}"));
    }
}
