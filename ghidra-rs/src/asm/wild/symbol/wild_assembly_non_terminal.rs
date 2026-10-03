//! Port of `ghidra.asm.wild.symbol.WildAssemblyNonTerminal`.

use std::fmt;

use crate::app::plugin::assembler::sleigh::symbol::AssemblyNonTerminal as RealAssemblyNonTerminal;
use crate::app::plugin::assembler::sleigh::symbol::AssemblySymbol;
use crate::app::seam_stubs::AssemblyNonTerminal as SeamAssemblyNonTerminal;

/// The type of non-terminal used in wildcarded assembly grammars.
///
/// Port of `ghidra.asm.wild.symbol.WildAssemblyNonTerminal`, a concrete class extending the
/// concrete `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal` and overriding
/// `takesOperandIndex()` to return a constructor-supplied flag instead of the inherited
/// unconditional `true`.
///
/// Ported per this crate's composition-over-inheritance convention: rather than re-inheriting,
/// this struct composes the already-ported concrete
/// [`AssemblyNonTerminal`](RealAssemblyNonTerminal) (see that module's own doc comment -- it is a
/// plain struct, not a trait, since Java's class itself has no subclasses to speak of beyond this
/// one) as a `base` field, and stores the `takesOperandIndex` field alongside it.
///
/// This type additionally implements the crate's pre-existing
/// [`crate::app::seam_stubs::AssemblyNonTerminal`] placeholder trait (kept distinct from
/// [`RealAssemblyNonTerminal`] itself -- see that module's own doc comment on why the two are not
/// unified), so a [`WildAssemblyNonTerminal`] can still be used anywhere the wider grammar/tree/
/// parse packages expect that placeholder (e.g. as the `lhs` of a
/// [`WildAssemblyProduction`](crate::asm::wild::grammars::WildAssemblyProduction)).
pub struct WildAssemblyNonTerminal {
    base: RealAssemblyNonTerminal,
    takes_operand_index: bool,
}

impl WildAssemblyNonTerminal {
    /// Port of `WildAssemblyNonTerminal(String name, boolean takesOperandIndex)`.
    pub fn new(name: impl Into<String>, takes_operand_index: bool) -> Self {
        Self { base: RealAssemblyNonTerminal::new(name), takes_operand_index }
    }
}

impl fmt::Display for WildAssemblyNonTerminal {
    /// Mirrors the inherited `AssemblyNonTerminal.toString()`: `"[" + name + "]"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)
    }
}

impl AssemblySymbol for WildAssemblyNonTerminal {
    fn name(&self) -> &str {
        self.base.name()
    }

    /// Port of `WildAssemblyNonTerminal.takesOperandIndex()`, overriding the inherited
    /// unconditional `true` with the constructor-supplied flag.
    fn takes_operand_index(&self) -> bool {
        self.takes_operand_index
    }
}

impl SeamAssemblyNonTerminal for WildAssemblyNonTerminal {
    fn get_name(&self) -> String {
        AssemblySymbol::get_name(self).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_name_returns_constructor_name() {
        let nt = WildAssemblyNonTerminal::new("reg", true);
        assert_eq!(AssemblySymbol::get_name(&nt), "reg");
    }

    #[test]
    fn to_string_wraps_name_in_brackets() {
        let nt = WildAssemblyNonTerminal::new("reg", true);
        assert_eq!(nt.to_string(), "[reg]");
    }

    #[test]
    fn takes_operand_index_reflects_constructor_flag_true() {
        let nt = WildAssemblyNonTerminal::new("reg", true);
        assert!(nt.takes_operand_index());
    }

    #[test]
    fn takes_operand_index_reflects_constructor_flag_false() {
        // Unlike the base `AssemblyNonTerminal`, which unconditionally returns `true`, this
        // override actually returns `false` when constructed with `takesOperandIndex = false`.
        let nt = WildAssemblyNonTerminal::new("reg", false);
        assert!(!nt.takes_operand_index());
    }

    #[test]
    fn seam_stub_get_name_matches_real_assembly_symbol_get_name() {
        let nt = WildAssemblyNonTerminal::new("imm", false);
        assert_eq!(SeamAssemblyNonTerminal::get_name(&nt), "imm");
    }

    #[test]
    fn object_safety_via_dyn_reference_real_assembly_symbol() {
        let nt = WildAssemblyNonTerminal::new("reg", true);
        let as_dyn: &dyn AssemblySymbol = &nt;
        assert_eq!(as_dyn.get_name(), "reg");
        assert!(as_dyn.takes_operand_index());
        assert_eq!(format!("{as_dyn}"), "[reg]");
    }

    #[test]
    fn object_safety_via_dyn_reference_seam_stub() {
        let nt = WildAssemblyNonTerminal::new("reg", false);
        let as_dyn: &dyn SeamAssemblyNonTerminal = &nt;
        assert_eq!(as_dyn.get_name(), "reg");
        assert_eq!(format!("{as_dyn}"), "[reg]");
    }
}
