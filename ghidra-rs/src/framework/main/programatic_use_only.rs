/// Marker trait for plugins that are only constructed programmatically for specific purposes.
///
/// Plugins implementing this trait should never be added via the configuration GUIs.
pub trait ProgramaticUseOnly {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ProgramaticPlugin;

    impl ProgramaticUseOnly for ProgramaticPlugin {}

    fn requires_programatic_use_only<T: ProgramaticUseOnly>(_: &T) {}

    #[test]
    fn concrete_type_satisfies_marker_trait() {
        let plugin = ProgramaticPlugin;
        requires_programatic_use_only(&plugin);
    }

    #[test]
    fn trait_is_object_safe() {
        let plugin = ProgramaticPlugin;
        let _boxed: Box<dyn ProgramaticUseOnly> = Box::new(plugin);
    }
}
