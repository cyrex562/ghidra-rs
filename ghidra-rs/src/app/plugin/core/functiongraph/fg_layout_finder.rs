//! Port of `ghidra.app.plugin.core.functiongraph.FGLayoutFinder`.

use crate::app::seam_stubs::FGLayoutProvider;

/// An interface that allows clients to control how the function graph locates its layout
/// providers.
///
/// Port of `ghidra.app.plugin.core.functiongraph.FGLayoutFinder`. The production implementor
/// (`DiscoverableFGLayoutFinder`) discovers providers via the class searcher; other clients
/// (e.g. the code-compare function graph display) supply a fixed set, so this stays an open
/// trait.
pub trait FGLayoutFinder {
    /// Finds and returns the layout providers to use for the function graph.
    ///
    /// Port of `findLayouts()`.
    fn find_layouts(&self) -> Vec<FGLayoutProvider>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedFinder(usize);

    impl FGLayoutFinder for FixedFinder {
        fn find_layouts(&self) -> Vec<FGLayoutProvider> {
            vec![FGLayoutProvider; self.0]
        }
    }

    #[test]
    fn finders_supply_their_own_provider_lists() {
        let finders: Vec<Box<dyn FGLayoutFinder>> =
            vec![Box::new(FixedFinder(0)), Box::new(FixedFinder(2))];
        let counts: Vec<usize> = finders.iter().map(|f| f.find_layouts().len()).collect();
        assert_eq!(counts, [0, 2]);
    }
}
