/// Marker trait to signal that the implementing type is a test plugin and should
/// not be considered as 'real'.
///
/// Mirrors `ghidra.framework.plugintool.TestingPlugin`.
pub trait TestingPlugin {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTestPlugin;
    impl TestingPlugin for MockTestPlugin {}

    #[test]
    fn can_implement_testing_plugin_trait() {
        let _plugin = MockTestPlugin;
        let _: &dyn TestingPlugin = &_plugin;
    }

    #[test]
    fn marker_trait_is_object_safe() {
        fn accepts_plugin(_: &dyn TestingPlugin) {}
        accepts_plugin(&MockTestPlugin);
    }
}
