use crate::app::services::HoverService;

/// Port of `ghidra.app.decompiler.component.hover.DecompilerHoverService`.
///
/// # Shape
///
/// An empty marker subinterface of [`HoverService`] (rule R8b-marker): the Java tree never
/// narrows on it with `instanceof`, only compares `.class` tokens to pick it out of the tool's
/// service registry (`registerServiceProvided(DecompilerHoverService.class, impl)`,
/// `getServices(DecompilerHoverService.class)`) so decompiler-panel hover popups don't mix with
/// listing-panel ones. Rust has no `Class<T>` token to key that lookup with, so the marker
/// carries no members and the registry keys on `TypeId::of::<dyn DecompilerHoverService>()`
/// instead -- see [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin),
/// which already resolves hover services this way.
pub trait DecompilerHoverService: HoverService {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    use crate::app::seam_stubs::{Field, FieldLocation};
    use crate::program::model::listing::Program;
    use crate::program::util::program_location::ProgramLocation;

    struct MockDecompilerHoverService;

    impl HoverService for MockDecompilerHoverService {
        fn priority(&self) -> i32 {
            0
        }
        fn scroll(&self, _amount: i32) {}
        fn hover_mode_selected(&self) -> bool {
            true
        }
        fn hover_component(
            &self,
            _program: &dyn Program,
            _program_location: &dyn ProgramLocation,
            _field_location: &dyn FieldLocation,
            _field: &dyn Field,
        ) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }
        fn component_hidden(&self) {}
        fn component_shown(&self) {}
    }

    impl DecompilerHoverService for MockDecompilerHoverService {}

    #[test]
    fn implementor_carries_the_parent_trait_surface() {
        let svc = MockDecompilerHoverService;
        assert!(svc.hover_mode_selected());
    }

    #[test]
    fn type_id_is_the_registry_key_and_it_is_distinct_from_other_markers() {
        assert_ne!(
            TypeId::of::<dyn DecompilerHoverService>(),
            TypeId::of::<dyn HoverService>()
        );
    }
}
