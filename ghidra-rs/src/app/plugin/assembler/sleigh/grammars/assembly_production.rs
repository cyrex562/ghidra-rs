//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction`.

use crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction;

/// Defines a production for parsing mnemonic assembly.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction`, a concrete class
/// extending `AbstractAssemblyProduction<AssemblyNonTerminal>` and overriding exactly one method,
/// `isConstructor()`, to unconditionally return `true` -- every mnemonic-assembly production is a
/// SLEIGH constructor application (unlike, e.g., a purely-recursive production, which
/// `AbstractAssemblyGrammar` tracks separately). Ported per this crate's
/// composition-over-inheritance convention as a trait extending [`AbstractAssemblyProduction`],
/// the same "cut-point" superclass used by
/// [`AssemblyExtendedProduction`](crate::app::seam_stubs::AssemblyExtendedProduction) -- a sibling
/// concrete subclass parameterized over a different non-terminal type, not one extending the other
/// (see `AbstractAssemblyProduction`'s own doc comment).
///
/// No constructor is modeled: as with [`AbstractAssemblyProduction`] itself,
/// [`lhs`](AbstractAssemblyProduction::lhs)/[`rhs`](AbstractAssemblyProduction::rhs) are required
/// accessor hooks a concrete implementer supplies from whatever fields it stores them in, rather
/// than a Rust equivalent of Java's two-argument `AssemblyProduction(AssemblyNonTerminal,
/// AssemblySentential<AssemblyNonTerminal>)` constructor.
pub trait AssemblyProduction: AbstractAssemblyProduction {
    /// Mirrors `AssemblyProduction.isConstructor()`, which unconditionally returns `true`.
    fn is_constructor(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblySentential;
    use crate::app::seam_stubs::{AssemblyNonTerminal, AssemblySymbol};
    use std::sync::Arc;

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

    /// A concrete production, holding `lhs`/`rhs`/`idx` exactly like Java's constructor-assigned
    /// fields -- standing in for `AssemblyProduction` itself, the same way
    /// `AbstractAssemblyProduction`'s own tests use a `MockProduction`.
    struct Production {
        idx: i32,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl Production {
        fn new(lhs: Arc<dyn AssemblyNonTerminal>, rhs: Arc<dyn AssemblySentential>) -> Self {
            // Mirrors `AssemblyProduction(AssemblyNonTerminal, AssemblySentential)`, which passes
            // both straight to `super(lhs, rhs)`; `idx` starts at Java's `AbstractAssemblyProduction`
            // default (unset until a grammar assigns one via `set_index`).
            Self { idx: -1, lhs, rhs }
        }
    }

    impl AbstractAssemblyProduction for Production {
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

    impl AssemblyProduction for Production {}

    fn make(name: &'static str) -> Production {
        let mut rhs = MockSentential::default();
        rhs.add_symbol(Arc::new(MockSymbol(name)));
        Production::new(Arc::new(MockNonTerminal(name)), Arc::new(rhs))
    }

    /// Java: `isConstructor()` unconditionally returns `true`, regardless of the production's own
    /// state (unlike `AssemblyExtendedProduction`, which has no such override at all).
    #[test]
    fn is_constructor_is_always_true() {
        let prod = make("insn");
        assert!(prod.is_constructor());
    }

    /// The constructor stores `lhs`/`rhs` exactly as given, reachable through the inherited
    /// `AbstractAssemblyProduction` accessors.
    #[test]
    fn constructor_stores_lhs_and_rhs() {
        let prod = make("insn");
        assert_eq!(prod.lhs().get_name(), "insn");
        assert_eq!(prod.rhs().get_symbols().len(), 1);
    }

    /// Inherited `AbstractAssemblyProduction` default methods (`display_string`) work unchanged
    /// through an `AssemblyProduction` reference.
    #[test]
    fn inherits_abstract_assembly_production_defaults() {
        let mut prod = make("insn");
        prod.set_index(4);
        assert_eq!(prod.display_string(), "4. [insn] => insn");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let prod = make("insn");
        let as_dyn: &dyn AssemblyProduction = &prod;
        assert!(as_dyn.is_constructor());
        assert_eq!(as_dyn.get_name(), "insn");
    }
}
