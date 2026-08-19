//! Service for managing programs. Multiple programs may be open in a tool, but only one is
//! active at any given time.
//!
//! Port of `ghidra.app.services.ProgramManager`. Java's overloaded `openProgram`/
//! `openCachedProgram`/`saveProgram`/`saveProgramAs`/`closeProgram` methods are each given a
//! distinct Rust name, since Rust traits cannot overload on parameter type/arity alone. The
//! `URL`-based overloads become `*_url` methods; the `Object consumer`-taking overloads use
//! [`DomainObjectConsumer`]. The `int` open-mode constants (`OPEN_HIDDEN`/`OPEN_CURRENT`/
//! `OPEN_VISIBLE`) are hoisted to module-level constants, since associated constants are not
//! permitted on object-safe traits.

use std::sync::Arc;

use crate::framework::model::{DomainFile, DomainObjectConsumer};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// Program will be open in a Hidden state if not already open. This mode is generally used in
/// conjunction with a persistent program owner.
pub const OPEN_HIDDEN: i32 = 0;

/// Program will be open as the currently active program within the tool.
pub const OPEN_CURRENT: i32 = 1;

/// Program will be open within the tool but no change will be made to the currently active
/// program. If this is the only program open, it will become the currently active program.
pub const OPEN_VISIBLE: i32 = 2;

/// Service for managing programs. Multiple programs may be open in a tool, but only one is
/// active at any given time.
pub trait ProgramManager: Send + Sync {
    /// Return the program that is currently active, or `None` if no program is open.
    fn get_current_program(&self) -> Option<Arc<dyn Program>>;

    /// Returns true if the specified program is open and considered visible to the user.
    fn is_visible(&self, program: &dyn Program) -> bool;

    /// Closes the currently active program.
    ///
    /// Returns `true` if the close is successful, `false` if the close fails or if there is no
    /// program currently active.
    fn close_current_program(&mut self) -> bool;

    /// Open the program corresponding to the given Ghidra URL.
    ///
    /// `state` is the initial open state ([`OPEN_HIDDEN`], [`OPEN_CURRENT`], [`OPEN_VISIBLE`]).
    /// The visibility states will be ignored if the program is already open.
    ///
    /// Returns the opened program, or `None` if the user canceled the "open" or an error
    /// occurred.
    fn open_program_url(&mut self, ghidra_url: &str, state: i32) -> Option<Arc<dyn Program>>;

    /// Open the program for the given domain file. Once open it will become the active program.
    ///
    /// Returns the opened program, or `None` if the user canceled the "open" or an error
    /// occurred.
    fn open_program(&mut self, domain_file: &dyn DomainFile) -> Option<Arc<dyn Program>>;

    /// Opens a program or retrieves it from a cache. If the program is in the cache, the
    /// consumer will be added to the program before returning it. Otherwise, the program will be
    /// opened with the consumer. Calling this method does not open the program in the tool.
    ///
    /// Returns the program for the given domain file, or `None` if unable to open the program.
    fn open_cached_program(
        &mut self,
        domain_file: &dyn DomainFile,
        consumer: DomainObjectConsumer,
    ) -> Option<Arc<dyn Program>>;

    /// Opens a program or retrieves it from a cache, by Ghidra URL. See
    /// [`ProgramManager::open_cached_program`] for cache semantics. Calling this method does not
    /// open the program in the tool.
    ///
    /// Returns the program for the given URL, or `None` if unable to open the program.
    fn open_cached_program_url(
        &mut self,
        ghidra_url: &str,
        consumer: DomainObjectConsumer,
    ) -> Option<Arc<dyn Program>>;

    /// Opens the specified version of the program represented by the given domain file. This
    /// method should be used for shared domain files. The newly opened file will be made the
    /// active program.
    ///
    /// Returns the opened program, or `None` if the user canceled the "open" or an error
    /// occurred.
    fn open_program_version(
        &mut self,
        domain_file: &dyn DomainFile,
        version: i32,
    ) -> Option<Arc<dyn Program>>;

    /// Open the program for the given domain file.
    ///
    /// `state` is the initial open state ([`OPEN_HIDDEN`], [`OPEN_CURRENT`], [`OPEN_VISIBLE`]).
    /// The visibility states will be ignored if the program is already open.
    ///
    /// Returns the opened program, or `None` if the user canceled the "open" or an error
    /// occurred.
    fn open_program_with_state(
        &mut self,
        domain_file: &dyn DomainFile,
        version: i32,
        state: i32,
    ) -> Option<Arc<dyn Program>>;

    /// Registers an already-open program with the tool. The program is made the active program.
    fn register_program(&mut self, program: Arc<dyn Program>);

    /// Registers an already-open program with the tool.
    ///
    /// `state` is the initial open state ([`OPEN_HIDDEN`], [`OPEN_CURRENT`], [`OPEN_VISIBLE`]).
    /// The visibility states will be ignored if the program is already open.
    fn register_program_with_state(&mut self, program: Arc<dyn Program>, state: i32);

    /// Saves the current program, possibly prompting the user for a new name.
    fn save_program(&mut self);

    /// Saves the specified program, possibly prompting the user for a new name.
    fn save_program_for(&mut self, program: &dyn Program);

    /// Prompts the user to save the current program to a selected file.
    fn save_program_as(&mut self);

    /// Prompts the user to save the specified program to a selected file.
    fn save_program_as_for(&mut self, program: &dyn Program);

    /// Establish a persistent owner on an open program. This will cause the program manager to
    /// make a program hidden if it is closed.
    ///
    /// Returns `true` if program is open and another object is not already the owner, or the
    /// specified owner is already the owner.
    ///
    /// # Deprecated
    /// This method is no longer used by the system.
    #[deprecated(note = "this method is no longer used by the system")]
    fn set_persistent_owner(&mut self, program: &dyn Program, owner: DomainObjectConsumer)
        -> bool;

    /// Release the persistent ownership of a program.
    ///
    /// The program will automatically be closed if it is hidden or was marked as temporary. If
    /// `persistent_owner` is not the correct owner, the method will have no effect.
    ///
    /// # Deprecated
    /// This method is no longer used by the system.
    #[deprecated(note = "this method is no longer used by the system")]
    fn release_program(&mut self, program: &dyn Program, persistent_owner: DomainObjectConsumer);

    /// Closes the given program with the option of saving any changes.
    ///
    /// Returns `true` if the program was closed. Returns `false` if the user canceled the close
    /// while being prompted to save.
    fn close_program(&mut self, program: &dyn Program, ignore_changes: bool) -> bool;

    /// Closes all open programs in this tool except the current program.
    ///
    /// Returns `true` if all other programs were closed. Returns `false` if the user canceled
    /// the close while being prompted to save.
    fn close_other_programs(&mut self, ignore_changes: bool) -> bool;

    /// Closes all open programs in this tool.
    ///
    /// Returns `true` if all programs were closed. Returns `false` if the user canceled the
    /// close while being prompted to save.
    fn close_all_programs(&mut self, ignore_changes: bool) -> bool;

    /// Sets the given program to be the current active program in the tool.
    fn set_current_program(&mut self, program: Arc<dyn Program>);

    /// Returns the first program in the list of open programs that contains the given address.
    fn get_program(&self, addr: &Address) -> Option<Arc<dyn Program>>;

    /// Returns a list of all open programs.
    fn get_all_open_programs(&self) -> Vec<Arc<dyn Program>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::listing::Listing;

    struct MockProgram {
        name: String,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }

        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            None
        }
    }

    struct MockProgramManager {
        current: Option<Arc<dyn Program>>,
        open_programs: Vec<Arc<dyn Program>>,
    }

    impl ProgramManager for MockProgramManager {
        fn get_current_program(&self) -> Option<Arc<dyn Program>> {
            self.current.clone()
        }

        fn is_visible(&self, program: &dyn Program) -> bool {
            self.open_programs
                .iter()
                .any(|p| Program::get_name(p.as_ref()) == Program::get_name(program))
        }

        fn close_current_program(&mut self) -> bool {
            if self.current.take().is_some() {
                true
            } else {
                false
            }
        }

        fn open_program_url(&mut self, _ghidra_url: &str, _state: i32) -> Option<Arc<dyn Program>> {
            None
        }

        fn open_program(&mut self, domain_file: &dyn DomainFile) -> Option<Arc<dyn Program>> {
            let program: Arc<dyn Program> = Arc::new(MockProgram {
                name: domain_file.get_name(),
            });
            self.open_programs.push(program.clone());
            self.current = Some(program.clone());
            Some(program)
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

        fn register_program(&mut self, program: Arc<dyn Program>) {
            self.open_programs.push(program.clone());
            self.current = Some(program);
        }

        fn register_program_with_state(&mut self, program: Arc<dyn Program>, _state: i32) {
            self.register_program(program);
        }

        fn save_program(&mut self) {}

        fn save_program_for(&mut self, _program: &dyn Program) {}

        fn save_program_as(&mut self) {}

        fn save_program_as_for(&mut self, _program: &dyn Program) {}

        fn set_persistent_owner(
            &mut self,
            _program: &dyn Program,
            _owner: DomainObjectConsumer,
        ) -> bool {
            false
        }

        fn release_program(
            &mut self,
            _program: &dyn Program,
            _persistent_owner: DomainObjectConsumer,
        ) {
        }

        fn close_program(&mut self, program: &dyn Program, _ignore_changes: bool) -> bool {
            let before = self.open_programs.len();
            self.open_programs
                .retain(|p| Program::get_name(p.as_ref()) != Program::get_name(program));
            before != self.open_programs.len()
        }

        fn close_other_programs(&mut self, _ignore_changes: bool) -> bool {
            if let Some(current) = self.current.clone() {
                self.open_programs
                    .retain(|p| Program::get_name(p.as_ref()) == Program::get_name(current.as_ref()));
            }
            true
        }

        fn close_all_programs(&mut self, _ignore_changes: bool) -> bool {
            self.open_programs.clear();
            self.current = None;
            true
        }

        fn set_current_program(&mut self, program: Arc<dyn Program>) {
            self.current = Some(program);
        }

        fn get_program(&self, addr: &Address) -> Option<Arc<dyn Program>> {
            let _ = addr;
            self.open_programs.first().cloned()
        }

        fn get_all_open_programs(&self) -> Vec<Arc<dyn Program>> {
            self.open_programs.clone()
        }
    }

    struct MockDomainFile {
        name: String,
    }

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    #[test]
    fn smoke_open_close_and_query() {
        let mut mgr = MockProgramManager {
            current: None,
            open_programs: Vec::new(),
        };

        assert!(mgr.get_current_program().is_none());
        assert!(!mgr.close_current_program());

        let df = MockDomainFile {
            name: "prog1".to_string(),
        };
        let opened = mgr.open_program(&df).expect("program should open");
        assert_eq!(Program::get_name(opened.as_ref()), "prog1");
        assert!(mgr.is_visible(opened.as_ref()));
        assert_eq!(mgr.get_all_open_programs().len(), 1);

        assert!(mgr.close_current_program());
        assert!(mgr.get_current_program().is_none());
        assert!(mgr.close_program(opened.as_ref(), true));
        assert!(mgr.get_all_open_programs().is_empty());
    }
}
