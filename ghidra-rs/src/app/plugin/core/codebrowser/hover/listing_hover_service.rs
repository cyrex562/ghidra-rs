use crate::app::services::HoverService;

/// Port of `ghidra.app.plugin.core.codebrowser.hover.ListingHoverService`.
///
/// # Shape
///
/// An empty marker subinterface of [`HoverService`] (rule R8b-marker), the listing-panel
/// counterpart of
/// [`DecompilerHoverService`](crate::app::decompiler::component::hover::DecompilerHoverService).
/// The Java tree never narrows on it with `instanceof`, only compares `.class` tokens to pick it
/// out of the tool's service registry (`registerServiceProvided(ListingHoverService.class,
/// impl)`, `getServices(ListingHoverService.class)`) so listing-panel hover popups don't mix with
/// decompiler-panel ones. Rust has no `Class<T>` token to key that lookup with, so the marker
/// carries no members and the registry keys on `TypeId::of::<dyn ListingHoverService>()`
/// instead, the same recipe `DecompilerHoverService` already established.
pub trait ListingHoverService: HoverService {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    use crate::app::decompiler::component::hover::DecompilerHoverService;
    use crate::app::seam_stubs::{Field, FieldLocation};
    use crate::program::model::listing::Program;
    use crate::program::util::program_location::ProgramLocation;

    struct MockListingHoverService;

    impl HoverService for MockListingHoverService {
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

    impl ListingHoverService for MockListingHoverService {}

    #[test]
    fn implementor_carries_the_parent_trait_surface() {
        let svc = MockListingHoverService;
        assert!(svc.hover_mode_selected());
    }

    #[test]
    fn type_id_is_distinct_from_the_decompiler_panel_marker() {
        // The whole point of the marker: a hover service registered for one panel must not be
        // handed back when the other panel asks its registry for its own kind.
        assert_ne!(
            TypeId::of::<dyn ListingHoverService>(),
            TypeId::of::<dyn DecompilerHoverService>()
        );
    }
}
