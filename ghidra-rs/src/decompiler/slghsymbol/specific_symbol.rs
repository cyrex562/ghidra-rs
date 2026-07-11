//! Models `ghidra.pcodeCPort.slghsymbol.SpecificSymbol`.

use crate::decompiler::seam_stubs::{TripleSymbol, VarnodeTpl};

/// A symbol that resolves to a concrete varnode during constructor semantics (as opposed to
/// symbols that only participate in parsing/printing).
///
/// Models the abstract class `ghidra.pcodeCPort.slghsymbol.SpecificSymbol`, which extends
/// `TripleSymbol` (stubbed as [`TripleSymbol`] pending its own port).
pub trait SpecificSymbol: TripleSymbol {
    /// The varnode template this symbol resolves to.
    fn get_varnode(&self) -> Box<dyn VarnodeTpl>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial mock proving the trait is object-safe and usable through a trait object.
    struct MockVarnode;
    impl VarnodeTpl for MockVarnode {}

    struct FixedSymbol;
    impl TripleSymbol for FixedSymbol {}

    impl SpecificSymbol for FixedSymbol {
        fn get_varnode(&self) -> Box<dyn VarnodeTpl> {
            Box::new(MockVarnode)
        }
    }

    #[test]
    fn get_varnode_returns_varnode_tpl() {
        let symbol = FixedSymbol;
        let dyn_symbol: &dyn SpecificSymbol = &symbol;
        let _varnode = dyn_symbol.get_varnode();
    }
}
