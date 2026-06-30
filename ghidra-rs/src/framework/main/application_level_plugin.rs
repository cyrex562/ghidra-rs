/// Marker trait signaling the implementing plugin can be added to the system at the
/// application level.
///
/// Some applications have only a single tool while other applications may have multiple
/// tools, with a top-level tool that manages other sub-tools. A type implementing this
/// trait can be used in any of these tools.
pub trait ApplicationLevelPlugin {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcretePlugin;

    impl ApplicationLevelPlugin for ConcretePlugin {}

    fn requires_application_level<T: ApplicationLevelPlugin>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let plugin = ConcretePlugin;
        requires_application_level(&plugin);
    }

    #[test]
    fn trait_is_object_safe() {
        let plugin = ConcretePlugin;
        let _boxed: Box<dyn ApplicationLevelPlugin> = Box::new(plugin);
    }
}
