//! Port of `ghidra.framework.plugintool.testplugins.CircularPluginA`.
//!
//! Test-only plugin used to exercise circular plugin/service dependency resolution (see
//! `PluginManagerTest#testCircularDependency()`). Selected as a dependency-cycle cut-point, so it
//! is ported as a marker trait rather than tied to a concrete implementation.
//!
//! In Java this `extends Plugin implements CircularServiceA, TestingPlugin` and is annotated
//! `@PluginInfo(servicesProvided = { CircularServiceA.class }, servicesRequired = {
//! CircularServiceB.class })`. The `extends`/`implements` relationships are mirrored as supertrait
//! bounds below; the `servicesRequired` annotation dependency on `CircularServiceB` is not (it is
//! metadata read by the plugin manager at tool-construction time, not a member this type's own API
//! needs), matching how [`CircularServiceB`](super::CircularServiceB) records its own
//! `defaultProvider` association as a doc reference only.

use crate::framework::plugintool::testing_plugin::TestingPlugin;
use crate::framework::seam_stubs::{CircularServiceALike, PluginLike};

/// Marker trait for the `CircularPluginA` test plugin.
///
/// Mirrors `ghidra.framework.plugintool.testplugins.CircularPluginA`, which adds no members beyond
/// its supertypes, so this trait declares no methods of its own.
pub trait CircularPluginA: PluginLike + TestingPlugin + CircularServiceALike {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCircularPluginA;

    impl PluginLike for MockCircularPluginA {}
    impl TestingPlugin for MockCircularPluginA {}
    impl CircularServiceALike for MockCircularPluginA {}
    impl CircularPluginA for MockCircularPluginA {}

    fn requires_circular_plugin_a<T: CircularPluginA>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_all_supertraits() {
        let plugin = MockCircularPluginA;
        requires_circular_plugin_a(&plugin);
    }

    #[test]
    fn trait_is_object_safe() {
        let plugin = MockCircularPluginA;
        let _boxed: Box<dyn CircularPluginA> = Box::new(plugin);
    }
}
