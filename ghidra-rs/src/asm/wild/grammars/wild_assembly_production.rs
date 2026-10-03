//! Port of `ghidra.asm.wild.grammars.WildAssemblyProduction`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::{
    AbstractAssemblyProduction, AssemblyProduction, AssemblySentential,
};
use crate::app::seam_stubs::AssemblyNonTerminal;

/// A production for parsing wildcarded assembly.
///
/// Port of `ghidra.asm.wild.grammars.WildAssemblyProduction`, a concrete class extending
/// `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction` and overriding exactly one
/// method, `isConstructor()`, to unconditionally return `false` -- the opposite of its superclass,
/// since a wildcarded production never corresponds to an actual SLEIGH constructor application.
///
/// Ported per this crate's composition-over-inheritance convention: this struct stores the
/// `lhs`/`rhs`/`idx` fields [`AbstractAssemblyProduction`] requires directly (mirroring how the
/// crate's own [`AssemblyProduction`] port's tests model a concrete implementer, since
/// `AssemblyProduction` itself is a trait with no fields of its own to compose over), then
/// implements [`AssemblyProduction`] with the overridden `is_constructor`.
pub struct WildAssemblyProduction {
    idx: i32,
    lhs: Arc<dyn AssemblyNonTerminal>,
    rhs: Arc<dyn AssemblySentential>,
}

impl WildAssemblyProduction {
    /// Port of `WildAssemblyProduction(AssemblyNonTerminal lhs, AssemblySentential<AssemblyNonTerminal> rhs)`,
    /// which just calls `super(lhs, rhs)`. `idx` starts at `AbstractAssemblyProduction`'s Java
    /// default (`int idx = -1`), unset until a grammar assigns one via
    /// [`AbstractAssemblyProduction::set_index`].
    pub fn new(lhs: Arc<dyn AssemblyNonTerminal>, rhs: Arc<dyn AssemblySentential>) -> Self {
        Self { idx: -1, lhs, rhs }
    }
}

impl AbstractAssemblyProduction for WildAssemblyProduction {
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

impl AssemblyProduction for WildAssemblyProduction {
    /// Port of `WildAssemblyProduction.isConstructor()`, which unconditionally returns `false`
    /// (overriding `AssemblyProduction.isConstructor()`'s unconditional `true`).
    fn is_constructor(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::AssemblySymbol;

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

    fn make(name: &'static str) -> WildAssemblyProduction {
        let mut rhs = MockSentential::default();
        rhs.add_symbol(Arc::new(MockSymbol(name)));
        WildAssemblyProduction::new(Arc::new(MockNonTerminal(name)), Arc::new(rhs))
    }

    /// Java: `isConstructor()` unconditionally returns `false`, the opposite of the plain
    /// `AssemblyProduction` superclass it extends.
    #[test]
    fn is_constructor_is_always_false() {
        let prod = make("wild_insn");
        assert!(!prod.is_constructor());
    }

    #[test]
    fn constructor_stores_lhs_and_rhs() {
        let prod = make("wild_insn");
        assert_eq!(prod.lhs().get_name(), "wild_insn");
        assert_eq!(prod.rhs().get_symbols().len(), 1);
    }

    #[test]
    fn index_defaults_to_negative_one_until_set() {
        let mut prod = make("wild_insn");
        assert_eq!(prod.index(), -1);
        prod.set_index(2);
        assert_eq!(prod.index(), 2);
    }

    #[test]
    fn inherits_abstract_assembly_production_defaults() {
        let mut prod = make("wild_insn");
        prod.set_index(4);
        assert_eq!(prod.display_string(), "4. [wild_insn] => wild_insn");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let prod = make("wild_insn");
        let as_dyn: &dyn AssemblyProduction = &prod;
        assert!(!as_dyn.is_constructor());
        assert_eq!(as_dyn.get_name(), "wild_insn");
    }
}
