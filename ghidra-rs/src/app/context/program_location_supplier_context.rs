use std::sync::Arc;

use crate::docking::action_context::ActionContext;
use crate::program::util::program_location::ProgramLocation;

/// A "mix-in" trait that specific implementers of [`ActionContext`] may also implement if they
/// can supply a program location in their action context. Actions that want to work on locations
/// can look for this trait, which can be used in a variety of contexts.
///
/// Port of `ghidra.app.context.ProgramLocationSupplierContext`.
pub trait ProgramLocationSupplierContext: ActionContext {
    /// Returns the program location.
    ///
    /// Port of `ProgramLocationSupplierContext.getLocation()`.
    fn get_location(&self) -> Arc<dyn ProgramLocation>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use std::any::Any;

    struct MockProgram {
        name: String,
    }

    impl crate::framework::model::domain_object::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockProgramLocation {
        program: Arc<dyn Program>,
        address: Address,
    }

    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct MockProgramLocationSupplierContext {
        location: Arc<dyn ProgramLocation>,
    }

    impl ActionContext for MockProgramLocationSupplierContext {
        fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>> {
            None
        }

        fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }

        fn set_context_object(&mut self, _context_object: Option<Arc<dyn Any + Send + Sync>>) {}

        fn set_event_click_modifiers(&mut self, _modifiers: i32) {}

        fn event_click_modifiers(&self) -> i32 {
            0
        }

        fn has_any_event_click_modifiers(&self, _modifiers_mask: i32) -> bool {
            false
        }

        fn set_source_object(&mut self, _source_object: Option<Arc<dyn Any + Send + Sync>>) {}

        fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }

        fn set_context_provider(&mut self, _provider: Option<Arc<dyn ActionContextProvider>>) {}

        fn context_provider(&self) -> Option<Arc<dyn ActionContextProvider>> {
            None
        }

        fn set_mouse_event(&mut self, _event: Option<Arc<dyn MouseEvent>>) {}

        fn mouse_event(&self) -> Option<Arc<dyn MouseEvent>> {
            None
        }

        fn source_component(&self) -> Option<Arc<dyn Component>> {
            None
        }

        fn set_source_component(&mut self, _component: Option<Arc<dyn Component>>) {}
    }

    impl ProgramLocationSupplierContext for MockProgramLocationSupplierContext {
        fn get_location(&self) -> Arc<dyn ProgramLocation> {
            self.location.clone()
        }
    }

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_context(offset: i64) -> MockProgramLocationSupplierContext {
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "mock.exe".to_string(),
        });
        let location: Arc<dyn ProgramLocation> = Arc::new(MockProgramLocation {
            program,
            address: make_address(offset),
        });
        MockProgramLocationSupplierContext { location }
    }

    #[test]
    fn get_location_returns_the_supplied_location() {
        let ctx = make_context(42);
        assert_eq!(ctx.get_location().get_address(), make_address(42));
    }

    #[test]
    fn object_is_usable_as_trait_object() {
        let ctx: Box<dyn ProgramLocationSupplierContext> = Box::new(make_context(7));
        assert_eq!(ctx.get_location().get_address(), make_address(7));
    }
}
