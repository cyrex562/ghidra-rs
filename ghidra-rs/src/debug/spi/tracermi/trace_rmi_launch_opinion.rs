//! Port of `ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion`.

use crate::app::seam_stubs::TraceRmiLaunchOffer;
use crate::debug::seam_stubs::TraceRmiLauncherServicePlugin;
use crate::framework::options::options::Options;
use crate::program::model::listing::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// A factory of launch offers.
///
/// Each opinion is instantiated only once for the entire application, even when multiple tools
/// are open.
pub trait TraceRmiLaunchOpinion: ExtensionPoint {
    /// Register any options. The default registers nothing.
    fn register_options(&self, options: &mut dyn Options) {
        let _ = options;
    }

    /// Check if a change in the given option requires a refresh of offers. The default is
    /// `false`.
    fn requires_refresh(&self, option_name: &str) -> bool {
        let _ = option_name;
        false
    }

    /// Generate or retrieve a collection of offers based on the current program.
    ///
    /// Take care trying to "validate" a particular mechanism. For example, it is *not*
    /// appropriate to check that GDB exists, nor to execute it to derive its version:
    ///
    /// 1. It's possible the user has dependencies installed in non-standard locations; the user
    ///    needs a chance to configure things *before* the UI decides whether or not to display
    ///    them.
    /// 2. The menus are meant to display *all* possibilities installed in Ghidra, even if some
    ///    dependencies are missing on the local system.
    /// 3. An offer is only promoted to the quick-launch menu upon *successful* connection.
    ///
    /// `plugin` is the Trace RMI launcher service plugin. To reach the Trace RMI (connection)
    /// service, offers should use the `InternalTraceRmiService`, so that they can register the
    /// connection's resources. `program` is the current program, or `None` (Java `null`) for no
    /// image. The order of the returned offers is ignored, since items are displayed
    /// alphabetically.
    fn get_offers(
        &self,
        plugin: &TraceRmiLauncherServicePlugin,
        program: Option<&dyn Program>,
    ) -> Vec<Box<dyn TraceRmiLaunchOffer>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOffer;
    impl TraceRmiLaunchOffer for MockOffer {}

    struct MockOptions;
    impl Options for MockOptions {}

    /// An opinion that relies on every default method, like most Java implementers.
    struct DefaultsOpinion;
    impl ExtensionPoint for DefaultsOpinion {}
    impl TraceRmiLaunchOpinion for DefaultsOpinion {
        fn get_offers(
            &self,
            _plugin: &TraceRmiLauncherServicePlugin,
            program: Option<&dyn Program>,
        ) -> Vec<Box<dyn TraceRmiLaunchOffer>> {
            // Offer one "no image" launcher even when there is no current program.
            match program {
                None => vec![Box::new(MockOffer)],
                Some(_) => vec![Box::new(MockOffer), Box::new(MockOffer)],
            }
        }
    }

    /// An opinion that refreshes when its own option changes, like
    /// `AbstractTraceRmiLaunchOpinion` subclasses do for script-path options.
    struct RefreshingOpinion;
    impl ExtensionPoint for RefreshingOpinion {}
    impl TraceRmiLaunchOpinion for RefreshingOpinion {
        fn requires_refresh(&self, option_name: &str) -> bool {
            option_name == "Script Paths"
        }

        fn get_offers(
            &self,
            _plugin: &TraceRmiLauncherServicePlugin,
            _program: Option<&dyn Program>,
        ) -> Vec<Box<dyn TraceRmiLaunchOffer>> {
            Vec::new()
        }
    }

    #[test]
    fn defaults_never_require_refresh() {
        let opinion = DefaultsOpinion;
        assert!(!opinion.requires_refresh("Script Paths"));
        assert!(!opinion.requires_refresh(""));
    }

    #[test]
    fn default_register_options_is_a_no_op() {
        let mut options = MockOptions;
        DefaultsOpinion.register_options(&mut options);
        assert!(options.get_leaf_option_names().is_empty());
    }

    #[test]
    fn get_offers_accepts_no_program() {
        let plugin = TraceRmiLauncherServicePlugin;
        let opinions: Vec<Box<dyn TraceRmiLaunchOpinion>> =
            vec![Box::new(DefaultsOpinion), Box::new(RefreshingOpinion)];
        let total: usize = opinions.iter().map(|o| o.get_offers(&plugin, None).len()).sum();
        assert_eq!(total, 1);
    }

    #[test]
    fn overridden_requires_refresh_is_dispatched() {
        let opinion: Box<dyn TraceRmiLaunchOpinion> = Box::new(RefreshingOpinion);
        assert!(opinion.requires_refresh("Script Paths"));
        assert!(!opinion.requires_refresh("Other"));
    }
}
