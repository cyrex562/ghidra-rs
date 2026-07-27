//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyExtendedGrammar`.

use std::sync::Arc;

use crate::app::seam_stubs::{
    AssemblyExtendedNonTerminal, AssemblyExtendedProduction, AssemblySentential,
};

/// Defines an "extended" grammar.
///
/// "Extended grammar" as in a grammar extended with state numbers from an LR0 parser. See
/// [LALR(1) Parsing](http://web.cs.dal.ca/~sjackson/lalr1.html) from Stephen Jackson of
/// Dalhousie University, Halifax, Nova Scotia, Canada.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyExtendedGrammar`, a concrete
/// class extending the unported
/// `AbstractAssemblyGrammar<AssemblyExtendedNonTerminal, AssemblyExtendedProduction>`. That class
/// was chosen (alongside [`AssemblyGrammar`](
/// crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar)) as a cut-point for a
/// dependency cycle running through the grammar, production, and symbol types. This trait models
/// only the member `AssemblyExtendedGrammar.java` itself declares -- its override of
/// `newProduction`, which unconditionally throws `UnsupportedOperationException("Please
/// construct extended productions yourself")` -- since the inherited `AbstractAssemblyGrammar`
/// surface (`addProduction`, `combine`, `verify()`, iteration, etc.) belongs to that still-unported
/// superclass and is left for its own port. [`AssemblyExtendedNonTerminal`] and
/// [`AssemblyExtendedProduction`], the core types this method references that aren't ported yet,
/// are modeled as minimal placeholder traits in [`crate::app::seam_stubs`];
/// [`AssemblySentential`] is likewise a placeholder there already, reused here.
pub trait AssemblyExtendedGrammar {
    /// Construct a new extended production given its LHS and RHS.
    ///
    /// Mirrors `AssemblyExtendedGrammar.newProduction(AssemblyExtendedNonTerminal,
    /// AssemblySentential<AssemblyExtendedNonTerminal>)`, which always throws
    /// `UnsupportedOperationException`: extended productions carry a final state and an
    /// ancestor production that this factory signature has no way to supply, so callers must
    /// construct `AssemblyExtendedProduction`s directly instead. The default implementation
    /// reproduces that always-panicking behavior; implementors need not override it, matching
    /// the fact that the Java class fully determines this member itself.
    fn new_production(
        &self,
        _lhs: Arc<dyn AssemblyExtendedNonTerminal>,
        _rhs: Arc<dyn AssemblySentential>,
    ) -> Arc<dyn AssemblyExtendedProduction> {
        panic!("Please construct extended productions yourself");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExtendedNonTerminal;
    impl crate::app::seam_stubs::AssemblyNonTerminal for MockExtendedNonTerminal {}
    impl AssemblyExtendedNonTerminal for MockExtendedNonTerminal {}

    struct MockSentential;
    impl AssemblySentential for MockSentential {}

    /// A grammar that relies entirely on the trait's default `new_production`, proving
    /// object-safety through a `dyn` reference and that the default matches the Java class's
    /// documented behavior of refusing to synthesize extended productions on its own.
    #[derive(Default)]
    struct TestExtendedGrammar;

    impl AssemblyExtendedGrammar for TestExtendedGrammar {}

    #[test]
    #[should_panic(expected = "Please construct extended productions yourself")]
    fn new_production_panics_via_dyn_reference() {
        let grammar = TestExtendedGrammar::default();
        let as_dyn: &dyn AssemblyExtendedGrammar = &grammar;
        let lhs: Arc<dyn AssemblyExtendedNonTerminal> = Arc::new(MockExtendedNonTerminal);
        let rhs: Arc<dyn AssemblySentential> = Arc::new(MockSentential);
        as_dyn.new_production(lhs, rhs);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let grammar = TestExtendedGrammar::default();
        let as_dyn: &dyn AssemblyExtendedGrammar = &grammar;
        // Just proves the trait object can be constructed and stored without invoking the
        // panicking default method.
        let _ = as_dyn as *const dyn AssemblyExtendedGrammar;
    }
}
