//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyExtendedProduction`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::{
    AbstractAssemblyProduction, AssemblyProduction,
};
use crate::app::plugin::assembler::sleigh::symbol::AssemblyExtendedNonTerminal;

/// Defines a production of an "extended" grammar.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyExtendedProduction`, a concrete
/// class extending `AbstractAssemblyProduction<AssemblyExtendedNonTerminal>`. Per this crate's
/// composition-over-inheritance convention, this becomes a trait extending
/// [`AbstractAssemblyProduction`] -- the same "cut-point" superclass [`AssemblyProduction`] already
/// extends (see that trait's own docs) -- replacing this crate's prior placeholder for this exact
/// class, `crate::app::seam_stubs::AssemblyExtendedProduction` (an empty marker trait with no
/// implementors anywhere in the crate; it is retired in favor of this real port, mirroring how
/// `RichHeaderRecord`'s placeholder was retired in `format/seam_stubs.rs` once that class was
/// ported for real).
///
/// `finalState`/`ancestor` are constructor-assigned fields, ported as the required accessors
/// [`final_state`](Self::final_state)/[`ancestor`](Self::ancestor).
///
/// `getLHS()` is a covariant override -- `return super.getLHS();` -- narrowing the inherited
/// `AbstractAssemblyProduction.getLHS()`'s Java-generic-parameterized return type from
/// `AssemblyExtendedProduction`'s own `NT = AssemblyExtendedNonTerminal` type argument. Rust
/// traits have no covariant return overriding, and
/// [`AbstractAssemblyProduction::lhs`](crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction::lhs)
/// is pinned to the crate's
/// [`AssemblyNonTerminal`](crate::app::seam_stubs::AssemblyNonTerminal) placeholder (that trait's
/// own docs explain why the `NT` parameter was dropped there), so this is ported as a distinct
/// required method, [`lhs_extended`](Self::lhs_extended), which an implementer supplies from the
/// very same value it also exposes (up-cast) through the inherited
/// [`lhs`](AbstractAssemblyProduction::lhs) -- the same "new method alongside the inherited one"
/// shape already used by [`AssemblyProduction::is_constructor`].
pub trait AssemblyExtendedProduction: AbstractAssemblyProduction {
    /// Get the end state of the final symbol of the RHS.
    ///
    /// Mirrors `AssemblyExtendedProduction.getFinalState()`.
    fn final_state(&self) -> i32;

    /// Get the original production from which this production was derived.
    ///
    /// Mirrors `AssemblyExtendedProduction.getAncestor()`.
    fn ancestor(&self) -> Arc<dyn AssemblyProduction>;

    /// Get the extended left-hand side.
    ///
    /// Mirrors `AssemblyExtendedProduction.getLHS()`. See this trait's own docs for why it is a
    /// distinct required method rather than an override of
    /// [`AbstractAssemblyProduction::lhs`].
    fn lhs_extended(&self) -> Arc<dyn AssemblyExtendedNonTerminal>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblySentential;
    use crate::app::seam_stubs::{AssemblyNonTerminal, AssemblySymbol};

    struct MockNonTerminal(&'static str);

    impl std::fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockExtendedNonTerminal {
        end: i32,
        wrapped: Arc<dyn AssemblyNonTerminal>,
        own_name: String,
    }

    impl std::fmt::Display for MockExtendedNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", AssemblyExtendedNonTerminal::get_name(self))
        }
    }

    impl AssemblyNonTerminal for MockExtendedNonTerminal {
        fn get_name(&self) -> String {
            AssemblyExtendedNonTerminal::get_name(self)
        }
    }

    impl AssemblyExtendedNonTerminal for MockExtendedNonTerminal {
        fn end(&self) -> i32 {
            self.end
        }
        fn wrapped(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.wrapped.clone()
        }
        fn own_name(&self) -> String {
            self.own_name.clone()
        }
    }

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

    #[derive(Default, Clone)]
    struct MockSentential {
        symbols: Vec<Arc<dyn AssemblySymbol>>,
    }

    impl AssemblySentential for MockSentential {
        fn add_symbol(&mut self, symbol: Arc<dyn AssemblySymbol>) -> bool {
            self.symbols.push(symbol);
            true
        }
        fn get_symbols(&self) -> Vec<Arc<dyn AssemblySymbol>> {
            self.symbols.clone()
        }
        fn finish(&mut self) {}
        fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential> {
            Box::new(MockSentential { symbols: self.symbols[from_index..to_index].to_vec() })
        }
        fn white_space_symbol(&self) -> Arc<dyn AssemblySymbol> {
            unimplemented!("not exercised by this test")
        }
        fn make_string_terminal(&self, _str: &str) -> Arc<dyn AssemblySymbol> {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockAncestorProduction {
        idx: i32,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl AbstractAssemblyProduction for MockAncestorProduction {
        fn index(&self) -> i32 {
            self.idx
        }
        fn set_index(&mut self, idx: i32) {
            self.idx = idx;
        }
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            self.rhs.clone()
        }
    }

    impl AssemblyProduction for MockAncestorProduction {}

    /// A concrete extended production, mirroring `AssemblyExtendedProduction`'s constructor-
    /// assigned fields (`lhs`, `rhs`, `finalState`, `ancestor`) plus the inherited `idx`.
    struct ExtendedProduction {
        idx: i32,
        lhs: Arc<dyn AssemblyExtendedNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
        final_state: i32,
        ancestor: Arc<dyn AssemblyProduction>,
    }

    impl AbstractAssemblyProduction for ExtendedProduction {
        fn index(&self) -> i32 {
            self.idx
        }
        fn set_index(&mut self, idx: i32) {
            self.idx = idx;
        }
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            self.rhs.clone()
        }
    }

    impl AssemblyExtendedProduction for ExtendedProduction {
        fn final_state(&self) -> i32 {
            self.final_state
        }
        fn ancestor(&self) -> Arc<dyn AssemblyProduction> {
            self.ancestor.clone()
        }
        fn lhs_extended(&self) -> Arc<dyn AssemblyExtendedNonTerminal> {
            self.lhs.clone()
        }
    }

    fn make() -> ExtendedProduction {
        let mut ancestor_rhs = MockSentential::default();
        ancestor_rhs.add_symbol(Arc::new(MockSymbol("insn")));
        let ancestor: Arc<dyn AssemblyProduction> = Arc::new(MockAncestorProduction {
            idx: 0,
            lhs: Arc::new(MockNonTerminal("insn")),
            rhs: Arc::new(ancestor_rhs),
        });

        let ext_lhs: Arc<dyn AssemblyExtendedNonTerminal> = Arc::new(MockExtendedNonTerminal {
            end: 7,
            wrapped: Arc::new(MockNonTerminal("insn")),
            own_name: "3[insn]7".to_string(),
        });

        let mut rhs = MockSentential::default();
        rhs.add_symbol(Arc::new(MockSymbol("insn")));

        ExtendedProduction { idx: -1, lhs: ext_lhs, rhs: Arc::new(rhs), final_state: 4, ancestor }
    }

    #[test]
    fn final_state_and_ancestor_accessors() {
        let prod = make();
        assert_eq!(prod.final_state(), 4);
        assert_eq!(prod.ancestor().get_name(), "insn");
    }

    #[test]
    fn lhs_extended_matches_the_narrowed_lhs() {
        let prod = make();
        assert_eq!(
            AssemblyExtendedNonTerminal::get_name(prod.lhs_extended().as_ref()),
            "3[insn]7"
        );
        // The inherited (widened) accessor reports the exact same underlying value.
        assert_eq!(AbstractAssemblyProduction::lhs(&prod).get_name(), "3[insn]7");
    }

    #[test]
    fn inherits_abstract_assembly_production_defaults() {
        let mut prod = make();
        prod.set_index(2);
        assert_eq!(prod.display_string(), "2. 3[insn]7 => insn");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let prod = make();
        let as_dyn: &dyn AssemblyExtendedProduction = &prod;
        assert_eq!(as_dyn.final_state(), 4);
        assert_eq!(as_dyn.ancestor().get_name(), "insn");
    }
}
