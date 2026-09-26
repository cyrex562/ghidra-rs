//! Port of `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal`.

use std::fmt;

use crate::app::plugin::assembler::sleigh::symbol::AssemblySymbol;

/// The type of non-terminal for an assembly grammar.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal`, a concrete class
/// (`AssemblyNonTerminal extends AssemblySymbol`) whose entire surface is a constructor and one
/// overridden method: `toString()`, rendering the symbol's name in `[brackets]`. Everything else
/// (`getName()`, `compareTo`, `equals`, `hashCode`, `takesOperandIndex`) is inherited unchanged
/// from [`AssemblySymbol`] (the real port at
/// [`crate::app::plugin::assembler::sleigh::symbol::assembly_symbol`]).
///
/// This is a distinct type from the crate's pre-existing
/// [`crate::app::seam_stubs::AssemblyNonTerminal`] placeholder, which several already-ported
/// sibling classes (e.g. `AssemblyExtendedNonTerminal`, `AbstractAssemblyProduction`,
/// `AbstractAssemblyGrammar`) depend on as a polymorphic supertrait across roughly a dozen call
/// sites in the grammar/tree/parse packages. That placeholder is left as-is here, matching the
/// precedent already set when [`AssemblySymbol`] itself was ported (its own doc comment notes the
/// same deliberate non-migration) -- rewiring those call sites to depend on this concrete struct
/// instead of the polymorphic stub is out of scope for this port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyNonTerminal {
    name: String,
}

impl AssemblyNonTerminal {
    /// Construct a non-terminal having the given name.
    ///
    /// Mirrors `AssemblyNonTerminal(String name)`, which is just `super(name)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl fmt::Display for AssemblyNonTerminal {
    /// Mirrors the overridden `toString()`: `"[" + name + "]"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.name)
    }
}

impl AssemblySymbol for AssemblyNonTerminal {
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn get_name_returns_constructor_name() {
        let nt = AssemblyNonTerminal::new("insn");
        assert_eq!(nt.get_name(), "insn");
    }

    #[test]
    fn to_string_wraps_name_in_brackets() {
        let nt = AssemblyNonTerminal::new("insn");
        assert_eq!(nt.to_string(), "[insn]");
    }

    #[test]
    fn takes_operand_index_defaults_true_via_assembly_symbol() {
        let nt = AssemblyNonTerminal::new("insn");
        assert!(nt.takes_operand_index());
    }

    #[test]
    fn compare_to_orders_by_bracketed_display_string() {
        let a = AssemblyNonTerminal::new("aaa");
        let b = AssemblyNonTerminal::new("bbb");
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
    }

    #[test]
    fn symbol_eq_and_hash_agree_for_equal_names() {
        let a = AssemblyNonTerminal::new("insn");
        let b = AssemblyNonTerminal::new("insn");
        assert!(a.symbol_eq(&b));
        assert_eq!(a.symbol_hash(), b.symbol_hash());
    }

    #[test]
    fn symbol_eq_is_false_for_different_names() {
        let a = AssemblyNonTerminal::new("insn");
        let b = AssemblyNonTerminal::new("other");
        assert!(!a.symbol_eq(&b));
    }

    #[test]
    fn struct_equality_is_by_name_field() {
        let a = AssemblyNonTerminal::new("insn");
        let b = AssemblyNonTerminal::new("insn");
        let c = AssemblyNonTerminal::new("other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let nt = AssemblyNonTerminal::new("insn");
        let as_dyn: &dyn AssemblySymbol = &nt;
        assert_eq!(as_dyn.get_name(), "insn");
        assert_eq!(format!("{as_dyn}"), "[insn]");
    }
}
