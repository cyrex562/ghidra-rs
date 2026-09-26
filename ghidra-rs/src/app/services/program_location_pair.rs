//! Port of `ghidra.app.services.ProgramLocationPair`.
//!
//! The Java class is a small immutable data holder pairing a `Program` with a `ProgramLocation`
//! inside it. Both fields are already ported to object-safe traits in this crate --
//! [`Program`](crate::program::model::listing::Program) and
//! [`ProgramLocation`](crate::program::util::ProgramLocation) -- so this holder stores them as
//! trait objects: `Arc<dyn Program>` (matching the return type of
//! [`ProgramLocation::get_program`], which already hands back a shared, reference-counted
//! `Program`) and `Box<dyn ProgramLocation>` (an owned location, matching how other ported
//! `*FieldLocation` call sites construct and hand off locations).

use std::sync::Arc;

use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// A simple object that contains a `ProgramLocation` and its associated `Program`.
///
/// Port of `ghidra.app.services.ProgramLocationPair`.
pub struct ProgramLocationPair {
    program: Arc<dyn Program>,
    location: Box<dyn ProgramLocation>,
}

impl ProgramLocationPair {
    /// Port of `ProgramLocationPair(Program, ProgramLocation)`.
    ///
    /// Java null-checks both arguments and throws `NullPointerException` with a message specific
    /// to each ("Program cannot be null" / "ProgramLocation cannot be null"); that has no port
    /// since neither `Arc<dyn Program>` nor `Box<dyn ProgramLocation>` can be null in Rust -- the
    /// type system already rules it out.
    pub fn new(program: Arc<dyn Program>, location: Box<dyn ProgramLocation>) -> Self {
        Self { program, location }
    }

    /// Port of `ProgramLocationPair.getProgram()`.
    pub fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    /// Port of `ProgramLocationPair.getProgramLocation()`.
    pub fn get_program_location(&self) -> &dyn ProgramLocation {
        self.location.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};

    struct MockProgram {
        name: String,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
    }

    struct FixedLocation {
        address: Address,
    }

    impl ProgramLocation for FixedLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn accessors_round_trip_constructor_arguments() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "prog1".to_string() });
        let addr = ram_address(0x400);
        let location: Box<dyn ProgramLocation> = Box::new(FixedLocation { address: addr.clone() });

        let pair = ProgramLocationPair::new(program.clone(), location);

        assert_eq!(Program::get_name(pair.get_program().as_ref()), "prog1");
        assert_eq!(pair.get_program_location().get_address(), addr);
    }

    #[test]
    fn get_program_returns_a_clone_of_the_shared_arc() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "shared".to_string() });
        let location: Box<dyn ProgramLocation> =
            Box::new(FixedLocation { address: ram_address(0) });
        let pair = ProgramLocationPair::new(program.clone(), location);

        // Both Arcs point at the same underlying Program.
        assert!(Arc::ptr_eq(&program, &pair.get_program()));
    }
}
