//! Port of `ghidra.app.plugin.core.functiongraph.mvc.CurrentFunctionGraphViewSettings`.

use std::sync::Arc;

use crate::app::seam_stubs::{FGView, FunctionGraphViewSettings, GraphPerspectiveInfo, ProgramSelection};
use crate::program::util::program_location::ProgramLocation;

/// This settings object is created after a graph has been loaded. Further, creating this object
/// will apply the perspective information, if any has been specified.
///
/// This settings object is what exists when a graph is being displayed. Changing attributes on
/// this settings object will apply those values directly to the graph. Contrastingly, when a
/// graph is being built, a [`FunctionGraphViewSettings`] (a "pending" settings object, in Java
/// `PendingFunctionGraphViewSettings`) is in place instead, and changing attributes of that
/// object will apply the changed value only after the graph has been loaded.
///
/// Port of `ghidra.app.plugin.core.functiongraph.mvc.CurrentFunctionGraphViewSettings`. Rust has
/// no class inheritance, so the Java superclass `FunctionGraphViewSettings`'s state is composed
/// (`base`) rather than extended.
pub struct CurrentFunctionGraphViewSettings {
    base: FunctionGraphViewSettings,
    view: Arc<FGView>,
}

impl CurrentFunctionGraphViewSettings {
    /// Port of `CurrentFunctionGraphViewSettings(FGView, FunctionGraphViewSettings)`.
    pub fn new(view: Arc<FGView>, copy_settings: &FunctionGraphViewSettings) -> Self {
        let mut settings = CurrentFunctionGraphViewSettings {
            base: FunctionGraphViewSettings::default(),
            view,
        };
        settings.set_location(copy_settings.get_location());
        settings.set_selection(copy_settings.get_selection());
        settings.set_highlight(copy_settings.get_highlight());
        settings.set_function_graph_perspective_info(
            copy_settings.get_function_graph_perspective_info(),
        );
        settings
    }

    /// Port of `CurrentFunctionGraphViewSettings.setLocation(ProgramLocation)`.
    pub fn set_location(&mut self, new_location: Option<Arc<dyn ProgramLocation + Send + Sync>>) {
        if locations_equal(new_location.as_deref(), self.base.get_location().as_deref()) {
            return;
        }

        self.base.set_location(new_location.clone());
        self.view.set_location(new_location);
    }

    /// Port of `CurrentFunctionGraphViewSettings.setSelection(ProgramSelection)`.
    pub fn set_selection(&mut self, selection: Option<Arc<dyn ProgramSelection>>) {
        self.base.set_selection(selection.clone());
        self.view.set_selection(selection);
    }

    /// Port of `CurrentFunctionGraphViewSettings.setHighlight(ProgramSelection)`.
    pub fn set_highlight(&mut self, highlight: Option<Arc<dyn ProgramSelection>>) {
        self.base.set_highlight(highlight.clone());
        self.view.set_highlight(highlight);
    }

    /// Port of
    /// `CurrentFunctionGraphViewSettings.setFunctionGraphPerspectiveInfo(GraphPerspectiveInfo)`.
    pub fn set_function_graph_perspective_info(&mut self, info: GraphPerspectiveInfo) {
        self.base.set_function_graph_perspective_info(info);
        if !info.is_invalid() {
            self.view.set_graph_perspective(info);
        }
    }

    /// Port of the inherited `FunctionGraphViewSettings.getLocation()`.
    pub fn get_location(&self) -> Option<Arc<dyn ProgramLocation + Send + Sync>> {
        self.base.get_location()
    }

    /// Port of the inherited `FunctionGraphViewSettings.getSelection()`.
    pub fn get_selection(&self) -> Option<Arc<dyn ProgramSelection>> {
        self.base.get_selection()
    }

    /// Port of the inherited `FunctionGraphViewSettings.getHighlight()`.
    pub fn get_highlight(&self) -> Option<Arc<dyn ProgramSelection>> {
        self.base.get_highlight()
    }

    /// Port of the inherited `FunctionGraphViewSettings.getFunctionGraphPerspectiveInfo()`.
    pub fn get_function_graph_perspective_info(&self) -> GraphPerspectiveInfo {
        self.base.get_function_graph_perspective_info()
    }
}

/// Structural stand-in for `Objects.equals(ProgramLocation, ProgramLocation)`, which in Java
/// delegates to `ProgramLocation.equals()`. That method is intentionally not modeled on the
/// [`ProgramLocation`] trait itself (see that module's docs: it is Java `Object`-identity
/// boilerplate left to each concrete subclass), so this compares every field the trait actually
/// exposes instead. This omits Java's leading `getClass() != obj.getClass()` check, which has no
/// clean trait-object equivalent; two distinct location subclasses that happen to expose the same
/// fields will compare equal here where Java would not.
fn locations_equal(
    a: Option<&(dyn ProgramLocation + Send + Sync)>,
    b: Option<&(dyn ProgramLocation + Send + Sync)>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.get_address() == b.get_address()
                && a.get_byte_address() == b.get_byte_address()
                && a.get_ref_address() == b.get_ref_address()
                && a.get_component_path() == b.get_component_path()
                && a.get_row() == b.get_row()
                && a.get_column() == b.get_column()
                && a.get_char_offset() == b.get_char_offset()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock-program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct FixedLocation {
        address: Address,
    }

    impl ProgramLocation for FixedLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn addr(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn set_location_skips_view_when_unchanged() {
        let view = Arc::new(FGView::default());
        let base = FunctionGraphViewSettings::default();
        let mut settings = CurrentFunctionGraphViewSettings::new(view.clone(), &base);

        let loc: Arc<dyn ProgramLocation + Send + Sync> =
            Arc::new(FixedLocation { address: addr(0x1000) });
        settings.set_location(Some(loc.clone()));
        assert_eq!(view.get_location().unwrap().get_address(), addr(0x1000));

        // Pushing an equal-but-distinct location must not re-push to the view (mirrors the
        // `Objects.equals` early return in `CurrentFunctionGraphViewSettings.setLocation`).
        let same: Arc<dyn ProgramLocation + Send + Sync> =
            Arc::new(FixedLocation { address: addr(0x1000) });
        settings.set_location(Some(same));
        assert_eq!(view.get_location().unwrap().get_address(), addr(0x1000));
        assert_eq!(settings.get_location().unwrap().get_address(), addr(0x1000));

        // A genuinely different location does propagate to the view.
        let different: Arc<dyn ProgramLocation + Send + Sync> =
            Arc::new(FixedLocation { address: addr(0x2000) });
        settings.set_location(Some(different));
        assert_eq!(view.get_location().unwrap().get_address(), addr(0x2000));
    }

    #[test]
    fn set_function_graph_perspective_info_only_pushes_valid_info_to_the_view() {
        let view = Arc::new(FGView::default());
        let base = FunctionGraphViewSettings::default();
        let mut settings = CurrentFunctionGraphViewSettings::new(view.clone(), &base);

        // The constructor copies the (invalid) perspective from `base`, so the view should never
        // have been touched, mirroring `if (!info.isInvalid()) { view.setGraphPerspective(info); }`.
        assert!(view.get_graph_perspective().is_none());
        assert!(settings.get_function_graph_perspective_info().is_invalid());

        // An invalid perspective is recorded on the settings but never pushed to the view.
        let invalid = GraphPerspectiveInfo::create_invalid();
        settings.set_function_graph_perspective_info(invalid);
        assert!(view.get_graph_perspective().is_none());

        // A valid perspective propagates to the view.
        let valid = GraphPerspectiveInfo { invalid: false };
        settings.set_function_graph_perspective_info(valid);
        assert!(!view.get_graph_perspective().unwrap().is_invalid());
        assert!(!settings.get_function_graph_perspective_info().is_invalid());
    }
}
