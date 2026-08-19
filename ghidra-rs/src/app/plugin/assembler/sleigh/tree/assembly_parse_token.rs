//! Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken`.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;

/// A string token in an assembly parse tree.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken`, a concrete class
/// extending the unported abstract `AssemblyParseTreeNode`. That class was chosen as the
/// cut-point for a dependency cycle running through the grammar, terminal, and parse-tree types.
/// This trait models only the members `AssemblyParseToken.java` itself declares (its own public
/// methods and overrides of `AssemblyParseTreeNode`'s abstract methods) -- the inherited
/// `AssemblyParseTreeNode` surface (`getParent()`, `setParent()`, `getGrammar()`, the public
/// `print(PrintStream)` convenience overload) belongs to that still-unported superclass and is
/// left for its own port. The constructor's `AssemblyGrammar` parameter is likewise dropped, since
/// nothing declared in `AssemblyParseToken.java` itself exposes it.
///
/// [`AssemblyTerminal`] (the type of the matched terminal, `getSym()`'s return type) isn't ported
/// yet, so it is modeled as a minimal placeholder trait in [`crate::app::seam_stubs`], referenced
/// here via `Arc<dyn AssemblyTerminal>` rather than a concrete type. `equals`/`hashCode`/
/// `toString`/`print`/`generateString` are all pure functions of the two accessor methods
/// (`get_string`, `get_sym`), so they're modeled as default trait methods here rather than
/// members every implementer must redefine -- mirroring that `AssemblyParseToken.java`'s own
/// overrides are already fully determined by its two fields.
pub trait AssemblyParseToken {
    /// Get the portion of the input comprising the token.
    ///
    /// Mirrors `AssemblyParseToken.getString()`.
    fn get_string(&self) -> &str;

    /// Get the terminal that matched this token.
    ///
    /// Mirrors `AssemblyParseToken.getSym()` (an override of `AssemblyParseTreeNode.getSym()`,
    /// narrowed here from `AssemblySymbol` to `AssemblyTerminal`).
    fn get_sym(&self) -> Arc<dyn AssemblyTerminal>;

    /// For debugging: format this token with the given indent.
    ///
    /// Mirrors `AssemblyParseToken.print(PrintStream, String)`, returning the formatted line
    /// instead of writing to a stream.
    fn print_indented(&self, indent: &str) -> String {
        format!("{indent}{} := {}", self.get_sym(), self.display_string())
    }

    /// Mirrors `AssemblyParseToken.toString()`.
    fn display_string(&self) -> String {
        format!("'{}'", self.get_string())
    }

    /// Generate the string that this token parsed.
    ///
    /// Mirrors `AssemblyParseToken.generateString()`.
    fn generate_string(&self) -> String {
        self.get_string().to_string()
    }
}

impl PartialEq for dyn AssemblyParseToken + '_ {
    /// Mirrors `AssemblyParseToken.equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        self.get_string() == other.get_string()
            && self.get_sym().terminal_tag() == other.get_sym().terminal_tag()
    }
}

impl Eq for dyn AssemblyParseToken + '_ {}

impl Hash for dyn AssemblyParseToken + '_ {
    /// Mirrors `AssemblyParseToken.hashCode()`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_sym().terminal_tag().hash(state);
        self.get_string().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    struct Token {
        term: Arc<dyn AssemblyTerminal>,
        str: String,
    }

    impl AssemblyParseToken for Token {
        fn get_string(&self) -> &str {
            &self.str
        }

        fn get_sym(&self) -> Arc<dyn AssemblyTerminal> {
            self.term.clone()
        }
    }

    fn make(term: &'static str, str: &str) -> Token {
        Token {
            term: Arc::new(MockTerminal(term)),
            str: str.to_string(),
        }
    }

    #[test]
    fn display_string_quotes_the_value() {
        let tok = make("imm", "42");
        assert_eq!(tok.display_string(), "'42'");
    }

    #[test]
    fn generate_string_returns_the_raw_value() {
        let tok = make("imm", "42");
        assert_eq!(tok.generate_string(), "42");
    }

    #[test]
    fn print_indented_includes_terminal_and_value() {
        let tok = make("imm", "42");
        assert_eq!(tok.print_indented("  "), "  imm := '42'");
    }

    #[test]
    fn equal_tokens_have_equal_string_and_terminal() {
        let a: &dyn AssemblyParseToken = &make("imm", "42");
        let b: &dyn AssemblyParseToken = &make("imm", "42");
        assert!(a == b);
    }

    #[test]
    fn different_string_is_not_equal() {
        let a: &dyn AssemblyParseToken = &make("imm", "42");
        let b: &dyn AssemblyParseToken = &make("imm", "43");
        assert!(a != b);
    }

    #[test]
    fn different_terminal_is_not_equal() {
        let a: &dyn AssemblyParseToken = &make("imm", "42");
        let b: &dyn AssemblyParseToken = &make("reg", "42");
        assert!(a != b);
    }

    #[test]
    fn hash_matches_for_equal_tokens() {
        use std::collections::hash_map::DefaultHasher;

        fn hash_of(tok: &dyn AssemblyParseToken) -> u64 {
            let mut hasher = DefaultHasher::new();
            tok.hash(&mut hasher);
            hasher.finish()
        }

        let a: &dyn AssemblyParseToken = &make("imm", "42");
        let b: &dyn AssemblyParseToken = &make("imm", "42");
        assert_eq!(hash_of(a), hash_of(b));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let tok = make("imm", "42");
        let as_dyn: &dyn AssemblyParseToken = &tok;
        assert_eq!(as_dyn.get_string(), "42");
    }
}
