use std::sync::Arc;

use crate::app::services::ProgramManager;
use crate::framework::model::{DomainFile, DomainObjectConsumer};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// A stub of the [`ProgramManager`] trait. This can be used to supply a test program manager
/// or to spy on system internals by overriding methods as needed.
///
/// Mirrors `ghidra.app.services.TestDummyProgramManager`.
pub struct TestDummyProgramManager;

impl ProgramManager for TestDummyProgramManager {
    fn get_current_program(&self) -> Option<Arc<dyn Program>> {
        None
    }

    fn is_visible(&self, _program: &dyn Program) -> bool {
        false
    }

    fn close_current_program(&mut self) -> bool {
        false
    }

    fn open_program_url(&mut self, _ghidra_url: &str, _state: i32) -> Option<Arc<dyn Program>> {
        None
    }

    fn open_program(&mut self, _domain_file: &dyn DomainFile) -> Option<Arc<dyn Program>> {
        None
    }

    fn open_cached_program(
        &mut self,
        _domain_file: &dyn DomainFile,
        _consumer: DomainObjectConsumer,
    ) -> Option<Arc<dyn Program>> {
        None
    }

    fn open_cached_program_url(
        &mut self,
        _ghidra_url: &str,
        _consumer: DomainObjectConsumer,
    ) -> Option<Arc<dyn Program>> {
        None
    }

    fn open_program_version(
        &mut self,
        _domain_file: &dyn DomainFile,
        _version: i32,
    ) -> Option<Arc<dyn Program>> {
        None
    }

    fn open_program_with_state(
        &mut self,
        _domain_file: &dyn DomainFile,
        _version: i32,
        _state: i32,
    ) -> Option<Arc<dyn Program>> {
        None
    }

    fn register_program(&mut self, _program: Arc<dyn Program>) {
        // stub
    }

    fn register_program_with_state(&mut self, _program: Arc<dyn Program>, _state: i32) {
        // stub
    }

    fn save_program(&mut self) {
        // stub
    }

    fn save_program_for(&mut self, _program: &dyn Program) {
        // stub
    }

    fn save_program_as(&mut self) {
        // stub
    }

    fn save_program_as_for(&mut self, _program: &dyn Program) {
        // stub
    }

    fn set_persistent_owner(
        &mut self,
        _program: &dyn Program,
        _owner: DomainObjectConsumer,
    ) -> bool {
        false
    }

    fn release_program(&mut self, _program: &dyn Program, _persistent_owner: DomainObjectConsumer) {
        // stub
    }

    fn close_program(&mut self, _program: &dyn Program, _ignore_changes: bool) -> bool {
        false
    }

    fn close_other_programs(&mut self, _ignore_changes: bool) -> bool {
        false
    }

    fn close_all_programs(&mut self, _ignore_changes: bool) -> bool {
        false
    }

    fn set_current_program(&mut self, _program: Arc<dyn Program>) {
        // stub
    }

    fn get_program(&self, _addr: &Address) -> Option<Arc<dyn Program>> {
        None
    }

    fn get_all_open_programs(&self) -> Vec<Arc<dyn Program>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Listing;

    struct MockProgram;

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }

        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            None
        }
    }

    struct MockDomainFile;

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            "mock_file".to_string()
        }
    }

    #[test]
    fn all_query_methods_return_empty_or_false() {
        let mut mgr = TestDummyProgramManager;
        let program = MockProgram;
        let domain_file = MockDomainFile;

        assert!(mgr.get_current_program().is_none());
        assert!(!mgr.is_visible(&program));
        assert!(!mgr.close_current_program());
        assert!(mgr.open_program_url("ghidra://host/repo", 0).is_none());
        assert!(mgr.open_program(&domain_file).is_none());
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0);
        assert!(mgr.get_program(&addr).is_none());
        assert!(mgr.get_all_open_programs().is_empty());
        assert!(!mgr.close_program(&program, true));
        assert!(!mgr.close_other_programs(true));
        assert!(!mgr.close_all_programs(true));
    }

    #[test]
    fn mutating_methods_are_no_ops() {
        let mut mgr = TestDummyProgramManager;
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        mgr.register_program(program.clone());
        mgr.register_program_with_state(program.clone(), 0);
        mgr.save_program();
        mgr.save_program_for(program.as_ref());
        mgr.save_program_as();
        mgr.save_program_as_for(program.as_ref());
        mgr.set_current_program(program.clone());

        assert!(mgr.get_current_program().is_none());
        assert!(mgr.get_all_open_programs().is_empty());
    }

    #[test]
    fn is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<TestDummyProgramManager>();
        assert_sync::<TestDummyProgramManager>();
    }
}
