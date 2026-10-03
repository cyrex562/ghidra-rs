//! Mirrors `ghidra.app.plugin.assembler.sleigh.util.TableEntryKey`.

use std::sync::Arc;

use crate::app::seam_stubs::AssemblySymbol;

/// A key in a (sparse) LR(0) transition table or LALR(1) action/goto table.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.util.TableEntryKey`, chosen as the cut-point for
/// a dependency cycle running through the parser's transition/action-goto tables
/// (`AssemblyParseTransitionTable`, `AssemblyParseActionGotoTable`) and the symbol hierarchy
/// (`AssemblySymbol`). It is ported as a trait: implementors own the `(state, sym)` pair however
/// they like, and this trait exposes the class's public surface -- `getState`/`getSym`, ported
/// directly as [`state`](Self::state)/[`sym`](Self::sym), plus `compareTo`, ported as
/// [`compare_to`](Self::compare_to).
///
/// `compare_to` compares `state` numerically, then falls back to the LAZY, `toString()`-based
/// `AssemblySymbol.compareTo` for `sym` (reproduced here via [`AssemblySymbol`]'s `Display`
/// bound, the same convention used by
/// [`AbstractAssemblyProduction::compare_to`](crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction::compare_to)
/// and
/// [`AssemblyParseTransitionTable`](crate::app::plugin::assembler::sleigh::parse::AssemblyParseTransitionTable)).
/// Unlike `AbstractAssemblyProduction` (whose `equals`/`hashCode` mix LAZY value-equality with
/// IDENTITY-equality and so aren't ported), `TableEntryKey.equals`/`hashCode` compare `state` and
/// `sym` the same LAZY, value-based way `compareTo` does, so equality here is exactly
/// "`compare_to` returns `Equal`" -- ported as [`key_eq`](Self::key_eq), implemented in terms of
/// it. [`key_hash`](Self::key_hash) hashes the same `(state, sym.to_string())` pair so that equal
/// keys (per `key_eq`) always hash equal, satisfying the usual `Eq`/`Hash` contract even though
/// it does not reproduce Java's exact `hashCode()` bit pattern.
pub trait TableEntryKey {
    /// Get the state (row) of the key in the table.
    ///
    /// Mirrors `TableEntryKey.getState()`.
    fn state(&self) -> i32;

    /// Get the symbol (column) of the entry in the table.
    ///
    /// Mirrors `TableEntryKey.getSym()`.
    fn sym(&self) -> Arc<dyn AssemblySymbol>;

    /// Compare this key to another, first by state, then by symbol.
    ///
    /// Mirrors `TableEntryKey.compareTo(TableEntryKey)`.
    fn compare_to(&self, that: &dyn TableEntryKey) -> std::cmp::Ordering {
        let state_ord = self.state().cmp(&that.state());
        if state_ord != std::cmp::Ordering::Equal {
            return state_ord;
        }
        self.sym().to_string().cmp(&that.sym().to_string())
    }

    /// Mirrors `TableEntryKey.equals(Object)`.
    fn key_eq(&self, that: &dyn TableEntryKey) -> bool {
        self.compare_to(that) == std::cmp::Ordering::Equal
    }

    /// A hash of this key consistent with [`key_eq`](Self::key_eq).
    ///
    /// Stands in for `TableEntryKey.hashCode()` (`state * 31 + sym.hashCode()`); rather than
    /// reproduce that exact formula (which itself depends on the LAZY, unspecified
    /// `AssemblySymbol.hashCode()`), this hashes the same `(state, sym.to_string())` pair
    /// `key_eq` compares, guaranteeing equal keys hash equal.
    fn key_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.state().hash(&mut hasher);
        self.sym().to_string().hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockSymbol(&'static str);

    impl std::fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    struct MockKey {
        state: i32,
        sym: Arc<dyn AssemblySymbol>,
    }

    impl TableEntryKey for MockKey {
        fn state(&self) -> i32 {
            self.state
        }

        fn sym(&self) -> Arc<dyn AssemblySymbol> {
            self.sym.clone()
        }
    }

    fn key(state: i32, sym: &'static str) -> MockKey {
        MockKey { state, sym: Arc::new(MockSymbol(sym)) }
    }

    #[test]
    fn compare_to_orders_by_state_then_sym() {
        assert_eq!(key(0, "a").compare_to(&key(1, "a")), std::cmp::Ordering::Less);
        assert_eq!(key(1, "a").compare_to(&key(0, "a")), std::cmp::Ordering::Greater);
        assert_eq!(key(0, "a").compare_to(&key(0, "b")), std::cmp::Ordering::Less);
        assert_eq!(key(0, "b").compare_to(&key(0, "a")), std::cmp::Ordering::Greater);
        assert_eq!(key(0, "a").compare_to(&key(0, "a")), std::cmp::Ordering::Equal);
    }

    #[test]
    fn key_eq_matches_state_and_sym_value() {
        assert!(key(3, "insn").key_eq(&key(3, "insn")));
        assert!(!key(3, "insn").key_eq(&key(4, "insn")));
        assert!(!key(3, "insn").key_eq(&key(3, "reg")));
    }

    #[test]
    fn key_hash_is_consistent_with_key_eq() {
        let a = key(3, "insn");
        let b = key(3, "insn");
        assert!(a.key_eq(&b));
        assert_eq!(a.key_hash(), b.key_hash());
    }

    #[test]
    fn state_and_sym_round_trip() {
        let k = key(7, "x");
        assert_eq!(k.state(), 7);
        assert_eq!(k.sym().terminal_tag(), "x");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let k: Box<dyn TableEntryKey> = Box::new(key(2, "z"));
        assert_eq!(k.state(), 2);
        assert_eq!(k.sym().terminal_tag(), "z");
    }
}
