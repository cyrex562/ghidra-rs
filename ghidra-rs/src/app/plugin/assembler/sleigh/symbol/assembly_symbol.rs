//! Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol`.

use std::cmp::Ordering;
use std::fmt;

/// A symbol in a context-free grammar.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol`, an abstract class with no
/// `extends` clause implementing `Comparable<AssemblySymbol>`. Ported as a trait per this crate's
/// composition-over-inheritance convention: implementers provide [`name`](Self::name) (standing
/// in for the `protected final String name` field set by the Java constructor) and [`Display`]
/// (standing in for the abstract `toString()` every concrete subclass must define -- traditionally
/// non-terminals are rendered in `[brackets]` and terminals in lower-case, per the class's own
/// doc comment).
///
/// Symbols can be either terminals or non-terminals. Non-terminals must have a defining
/// production, i.e. it must appear as the left-hand side of some production in the grammar.
///
/// This is the same conceptual type as the placeholder
/// [`crate::app::seam_stubs::AssemblySymbol`] that several already-ported sibling classes in this
/// module (e.g. [`AssemblyTerminal`](super::AssemblyTerminal)) currently depend on as their
/// supertrait; that placeholder is left as-is here (migrating its ~15 call sites across the
/// grammar/tree/parse packages is out of scope for this port, matching the precedent set by
/// [`AssemblyExtendedNonTerminal`](super::AssemblyExtendedNonTerminal), which similarly left its
/// own still-unported supertrait, `AssemblyNonTerminal`, as a placeholder rather than graduating
/// it as a side effect).
pub trait AssemblySymbol: fmt::Display {
    /// The name of this symbol.
    ///
    /// Mirrors the `protected final String name` field, set once by the constructor
    /// (`AssemblySymbol(String name)`) and returned verbatim by `getName()`.
    fn name(&self) -> &str;

    /// Get the name of this symbol.
    ///
    /// Mirrors `AssemblySymbol.getName()`.
    fn get_name(&self) -> &str {
        self.name()
    }

    /// Check if this symbol consumes an operand index of its constructor.
    ///
    /// Mirrors `AssemblySymbol.takesOperandIndex()`, which unconditionally returns `true` in the
    /// base class (subclasses such as `AssemblyStringMapTerminal` override it to return `false`).
    fn takes_operand_index(&self) -> bool {
        true
    }

    /// Compare this symbol to another.
    ///
    /// Mirrors `AssemblySymbol.compareTo(AssemblySymbol)`, which is LAZY: it compares by
    /// `toString()` rather than by [`name`](Self::name). Reproduced faithfully here via the
    /// [`Display`] bound rather than [`name`](Self::name) -- see
    /// [`compare_to_ignores_name_lazily`](tests::compare_to_ignores_name_lazily) for a dedicated
    /// test proving two symbols with different names but identical `toString()` output compare
    /// equal.
    fn compare_to(&self, that: &dyn AssemblySymbol) -> Ordering {
        self.to_string().cmp(&that.to_string())
    }

    /// Test this symbol for equality with another.
    ///
    /// Mirrors `AssemblySymbol.equals(Object)`, which -- like [`compare_to`](Self::compare_to) --
    /// is LAZY: `this.toString().equals(that.toString())` rather than a `name` or identity
    /// comparison.
    fn symbol_eq(&self, that: &dyn AssemblySymbol) -> bool {
        self.to_string() == that.to_string()
    }

    /// Hash this symbol.
    ///
    /// Mirrors `AssemblySymbol.hashCode()`, which -- consistently with
    /// [`symbol_eq`](Self::symbol_eq) -- is LAZY: `toString().hashCode()` rather than hashing
    /// [`name`](Self::name).
    fn symbol_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.to_string().hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A terminal-ish symbol whose `name` and `Display` output can be set independently, so tests
    /// can exercise the LAZY `toString()`-based semantics distinctly from `name()`.
    struct PlainSymbol {
        name: &'static str,
        display: &'static str,
    }

    impl fmt::Display for PlainSymbol {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.display)
        }
    }

    impl AssemblySymbol for PlainSymbol {
        fn name(&self) -> &str {
            self.name
        }
    }

    #[test]
    fn get_name_returns_constructor_name() {
        let sym = PlainSymbol { name: "insn", display: "insn" };
        assert_eq!(sym.get_name(), "insn");
    }

    #[test]
    fn takes_operand_index_defaults_true() {
        let sym = PlainSymbol { name: "insn", display: "insn" };
        assert!(sym.takes_operand_index());
    }

    #[test]
    fn compare_to_orders_by_display_string() {
        let a = PlainSymbol { name: "a", display: "aaa" };
        let b = PlainSymbol { name: "z", display: "bbb" };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
    }

    /// Java bug/quirk: `AssemblySymbol.compareTo`/`equals`/`hashCode` are all defined purely in
    /// terms of `toString()`, deliberately ignoring the `name` field -- see
    /// `AssemblySymbol.java` lines 60-75 ("// LAZY" comments on all three overrides). Two symbols
    /// with different `name`s but identical `toString()` output are therefore indistinguishable
    /// by `compareTo`/`equals`/`hashCode`, even though `getName()` would tell them apart. This
    /// test pins down that faithfully-reproduced quirk rather than "fixing" it to compare by
    /// name.
    #[test]
    fn compare_to_ignores_name_lazily() {
        let a = PlainSymbol { name: "alpha", display: "[same]" };
        let b = PlainSymbol { name: "beta", display: "[same]" };
        assert_ne!(a.name(), b.name());
        assert_eq!(a.compare_to(&b), Ordering::Equal);
        assert!(a.symbol_eq(&b));
        assert_eq!(a.symbol_hash(), b.symbol_hash());
    }

    #[test]
    fn symbol_eq_is_false_for_different_display_strings() {
        let a = PlainSymbol { name: "same-name", display: "[a]" };
        let b = PlainSymbol { name: "same-name", display: "[b]" };
        assert!(!a.symbol_eq(&b));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let sym = PlainSymbol { name: "insn", display: "[insn]" };
        let as_dyn: &dyn AssemblySymbol = &sym;
        assert_eq!(as_dyn.get_name(), "insn");
        assert_eq!(format!("{as_dyn}"), "[insn]");
    }
}
