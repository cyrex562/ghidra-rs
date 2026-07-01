/// An exception to indicate that the solution of an expression is not yet known.
///
/// Furthermore, it cannot be determined whether or not the expression is even solvable.
/// When this exception is thrown, a backfill record is placed on the encoded resolution
/// indicating that the resolver must attempt to solve the expression again, once the
/// encoding is otherwise complete. This is needed, most notably, when an encoding depends
/// on the address of the next instruction, because the length of the current instruction
/// is not known until resolution has finished.
///
/// Backfill becomes a possibility when an expression depends on a symbol that is not
/// (yet) defined. Thus, as a matter of good record keeping, the exception records the
/// name of the missing symbol.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.NeedsBackfillException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedsBackfillException {
    symbol: String,
    message: String,
}

impl NeedsBackfillException {
    /// Construct a backfill exception from the name of the missing symbol.
    pub fn new(symbol: impl Into<String>) -> Self {
        let symbol_str = symbol.into();
        let message = format!("The symbol '{}' is not yet available", symbol_str);
        Self {
            symbol: symbol_str,
            message,
        }
    }

    /// Retrieve the missing symbol name from the original solution attempt.
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for NeedsBackfillException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for NeedsBackfillException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_symbol() {
        let e = NeedsBackfillException::new("undefined_var");
        assert_eq!(e.symbol(), "undefined_var");
    }

    #[test]
    fn new_creates_proper_message() {
        let e = NeedsBackfillException::new("missing_symbol");
        assert_eq!(
            e.message(),
            "The symbol 'missing_symbol' is not yet available"
        );
    }

    #[test]
    fn display_matches_message() {
        let e = NeedsBackfillException::new("foo");
        assert_eq!(e.to_string(), "The symbol 'foo' is not yet available");
    }

    #[test]
    fn debug_contains_message() {
        let e = NeedsBackfillException::new("bar");
        assert!(format!("{:?}", e).contains("bar"));
    }

    #[test]
    fn implements_error_trait() {
        let e = NeedsBackfillException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = NeedsBackfillException::new("err");
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = NeedsBackfillException::new("sym");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_symbols() {
        let a = NeedsBackfillException::new("alpha");
        let b = NeedsBackfillException::new("beta");
        assert_ne!(a, b);
    }

    #[test]
    fn accepts_owned_string() {
        let sym = String::from("owned");
        let e = NeedsBackfillException::new(sym);
        assert_eq!(e.symbol(), "owned");
    }

    #[test]
    fn empty_symbol_is_valid() {
        let e = NeedsBackfillException::new("");
        assert_eq!(e.symbol(), "");
        assert_eq!(e.message(), "The symbol '' is not yet available");
    }

    #[test]
    fn symbol_with_special_chars() {
        let e = NeedsBackfillException::new("$special_sym@123");
        assert_eq!(e.symbol(), "$special_sym@123");
        assert_eq!(
            e.message(),
            "The symbol '$special_sym@123' is not yet available"
        );
    }
}
