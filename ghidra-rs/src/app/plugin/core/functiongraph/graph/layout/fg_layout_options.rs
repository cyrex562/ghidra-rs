use crate::framework::options::options::Options;

/// The owner name for FG layout options, matching `FunctionGraphPlugin.getSimpleName()`.
/// Port of `FGLayoutOptions.OWNER`.
pub const OWNER: &str = "FunctionGraphPlugin";

/// An interface for [`FGLayout`] options.
///
/// Port of `ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutOptions`.
pub trait FGLayoutOptions {
    /// Called during setup for this class to register its options with the given [`Options`]
    /// object.
    ///
    /// Port of `FGLayoutOptions.registerOptions(Options)`.
    fn register_options(&mut self, options: &mut dyn Options);

    /// Called when the given [`Options`] object has changed. This class will update its
    /// options with the values from the given options object.
    ///
    /// Port of `FGLayoutOptions.loadOptions(Options)`.
    fn load_options(&mut self, options: &dyn Options);

    /// Returns true if the given option name, when changed, requires that the current graph be
    /// reloaded for the change to take effect.
    ///
    /// Port of `FGLayoutOptions.optionChangeRequiresRelayout(String)`.
    fn option_change_requires_relayout(&self, option_name: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fg_layout_options_owner_constant() {
        assert_eq!(OWNER, "FunctionGraphPlugin");
    }
}
