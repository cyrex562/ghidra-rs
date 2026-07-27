//! Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken`.

use std::hash::{Hash, Hasher};

use crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken;

/// A token having a numeric value.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken`, a concrete class
/// extending [`AssemblyParseToken`] that adds a single `val: long` field on top of the inherited
/// `term`/`str`. That class was chosen as the cut-point for a dependency cycle running through
/// the grammar, terminal, and parse-tree types (the same cycle [`AssemblyParseToken`] itself was
/// cut for). Since [`AssemblyParseToken`] is already a trait rather than a concrete struct, this
/// is modeled as a subtrait: [`get_numeric_value`](Self::get_numeric_value) stands in for the
/// `val` field/`getNumericValue()` accessor, and the constructor's `AssemblyGrammar` parameter is
/// dropped for the same reason [`AssemblyParseToken`] drops it -- nothing declared in
/// `AssemblyParseNumericToken.java` itself exposes it.
///
/// `equals`/`hashCode`/`toString` are all overridden in the Java class to fold `val` into the
/// inherited `term`/`str` comparison, so they're re-modeled here (shadowing the supertrait's
/// defaults, mirroring how `AssemblyExtendedNonTerminal::get_name` shadows
/// `AssemblyNonTerminal::get_name`) as default trait methods built from
/// [`get_numeric_value`](Self::get_numeric_value) plus the inherited `get_string`/`get_sym`.
pub trait AssemblyParseNumericToken: AssemblyParseToken {
    /// Get the numeric value of the token.
    ///
    /// Mirrors `AssemblyParseNumericToken.getNumericValue()` (and the `val` field it returns).
    fn get_numeric_value(&self) -> i64;

    /// Mirrors `AssemblyParseNumericToken.toString()`, which overrides
    /// `AssemblyParseToken.toString()` to append the numeric value.
    fn display_string(&self) -> String {
        format!("'{}'=>{}", self.get_string(), self.get_numeric_value())
    }
}

impl PartialEq for dyn AssemblyParseNumericToken + '_ {
    /// Mirrors `AssemblyParseNumericToken.equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        self.get_string() == other.get_string()
            && self.get_sym().terminal_tag() == other.get_sym().terminal_tag()
            && self.get_numeric_value() == other.get_numeric_value()
    }
}

impl Eq for dyn AssemblyParseNumericToken + '_ {}

impl Hash for dyn AssemblyParseNumericToken + '_ {
    /// Mirrors `AssemblyParseNumericToken.hashCode()`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_sym().terminal_tag().hash(state);
        self.get_string().hash(state);
        self.get_numeric_value().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;
    use crate::app::seam_stubs::{AssemblyNumericSymbols, AssemblySymbol};

    #[derive(Debug)]
    struct MockTerminal(&'static str);

    impl std::fmt::Display for MockTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockTerminal {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    impl AssemblyTerminal for MockTerminal {
        fn r#match(
            &self,
            _buffer: &str,
            _pos: usize,
            _grammar: &dyn crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar,
            _symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn AssemblyParseToken>> {
            Vec::new()
        }

        fn get_suggestions(&self, _got: &str, _symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
            Vec::new()
        }
    }

    struct NumericToken {
        term: Arc<dyn AssemblyTerminal>,
        str: String,
        val: i64,
    }

    impl AssemblyParseToken for NumericToken {
        fn get_string(&self) -> &str {
            &self.str
        }

        fn get_sym(&self) -> Arc<dyn AssemblyTerminal> {
            self.term.clone()
        }
    }

    impl AssemblyParseNumericToken for NumericToken {
        fn get_numeric_value(&self) -> i64 {
            self.val
        }
    }

    fn make(term: &'static str, str: &str, val: i64) -> NumericToken {
        NumericToken {
            term: Arc::new(MockTerminal(term)),
            str: str.to_string(),
            val,
        }
    }

    #[test]
    fn display_string_includes_value() {
        let tok = make("imm", "42", 42);
        assert_eq!(AssemblyParseNumericToken::display_string(&tok), "'42'=>42");
    }

    #[test]
    fn get_numeric_value_returns_the_stored_value() {
        let tok = make("imm", "0x2a", 42);
        assert_eq!(tok.get_numeric_value(), 42);
    }

    #[test]
    fn equal_tokens_have_equal_string_terminal_and_value() {
        let a: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 42);
        let b: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 42);
        assert!(a == b);
    }

    #[test]
    fn same_string_different_value_is_not_equal() {
        let a: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 42);
        let b: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 43);
        assert!(a != b);
    }

    #[test]
    fn hash_matches_for_equal_tokens() {
        use std::collections::hash_map::DefaultHasher;

        fn hash_of(tok: &dyn AssemblyParseNumericToken) -> u64 {
            let mut hasher = DefaultHasher::new();
            tok.hash(&mut hasher);
            hasher.finish()
        }

        let a: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 42);
        let b: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 42);
        assert_eq!(hash_of(a), hash_of(b));
    }

    #[test]
    fn hash_differs_for_different_value() {
        use std::collections::hash_map::DefaultHasher;

        fn hash_of(tok: &dyn AssemblyParseNumericToken) -> u64 {
            let mut hasher = DefaultHasher::new();
            tok.hash(&mut hasher);
            hasher.finish()
        }

        let a: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 42);
        let b: &dyn AssemblyParseNumericToken = &make("imm", "0x2a", 43);
        assert_ne!(hash_of(a), hash_of(b));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let tok = make("imm", "0x2a", 42);
        let as_dyn: &dyn AssemblyParseNumericToken = &tok;
        assert_eq!(as_dyn.get_numeric_value(), 42);
        assert_eq!(as_dyn.get_string(), "0x2a");
    }
}
