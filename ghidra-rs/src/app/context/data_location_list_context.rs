use std::sync::Arc;

use crate::program::model::listing::{Data, Program};
use crate::program::util::program_location::ProgramLocation;

/// A "mix-in" trait that `ActionContext` implementers can also implement if they can provide a
/// list of [`Data`] object's [`ProgramLocation`]'s.
///
/// Port of `ghidra.app.context.DataLocationListContext`.
pub trait DataLocationListContext {
    /// Returns the number of [`Data`] objects for the current action context.
    ///
    /// Port of `DataLocationListContext.getCount()`.
    fn get_count(&self) -> i32;

    /// Returns a list of the locations of the current [`Data`] objects in the current action
    /// context.
    ///
    /// Port of `DataLocationListContext.getDataLocationList()`.
    fn get_data_location_list(&self) -> Vec<Arc<dyn ProgramLocation>>;

    /// Returns a list of the locations of the current [`Data`] objects in the current action
    /// context that pass the given filter. `None` implies all elements match.
    ///
    /// Port of `DataLocationListContext.getDataLocationList(Predicate<Data>)`.
    fn get_data_location_list_filtered(
        &self,
        filter: Option<&dyn Fn(&dyn Data) -> bool>,
    ) -> Vec<Arc<dyn ProgramLocation>>;

    /// Returns the program for the current action context.
    ///
    /// Port of `DataLocationListContext.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

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

    struct MockDataLocationListContext {
        program: Arc<dyn Program>,
        locations: Vec<Arc<dyn ProgramLocation>>,
    }

    impl DataLocationListContext for MockDataLocationListContext {
        fn get_count(&self) -> i32 {
            self.locations.len() as i32
        }

        fn get_data_location_list(&self) -> Vec<Arc<dyn ProgramLocation>> {
            self.locations.clone()
        }

        fn get_data_location_list_filtered(
            &self,
            filter: Option<&dyn Fn(&dyn Data) -> bool>,
        ) -> Vec<Arc<dyn ProgramLocation>> {
            match filter {
                None => self.locations.clone(),
                Some(_) => Vec::new(),
            }
        }

        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
    }

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_context(count: usize) -> MockDataLocationListContext {
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "mock.exe".to_string(),
        });
        let locations = (0..count)
            .map(|i| {
                Arc::new(MockProgramLocation {
                    program: program.clone(),
                    address: make_address(i as i64),
                }) as Arc<dyn ProgramLocation>
            })
            .collect();
        MockDataLocationListContext { program, locations }
    }

    #[test]
    fn get_count_matches_location_list_len() {
        let ctx = make_context(3);
        assert_eq!(ctx.get_count(), 3);
        assert_eq!(ctx.get_data_location_list().len(), 3);
    }

    #[test]
    fn filtered_list_returns_all_when_no_filter() {
        let ctx = make_context(2);
        let result = ctx.get_data_location_list_filtered(None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn get_program_returns_the_context_program() {
        let ctx = make_context(0);
        assert_eq!(Program::get_name(&*ctx.get_program()), "mock.exe");
    }

    #[test]
    fn object_is_usable_as_trait_object() {
        let ctx: Box<dyn DataLocationListContext> = Box::new(make_context(1));
        assert_eq!(ctx.get_count(), 1);
    }
}
