//! Port of `ghidra.program.util.AddressFieldLocation`.
//!
//! The Java class is a thin data holder that extends
//! [`CodeUnitLocation`](crate::program::util::code_unit_location::CodeUnitLocation) (itself a
//! subclass of `ProgramLocation`) and adds a single `addrRepresentation` string field. It was
//! selected as a dependency-cycle cut-point, so it is ported here as an object-safe trait rather
//! than a concrete struct: implementors provide whatever `Program`/`Address`/component-path state
//! the Java constructors captured, and expose it (plus the one accessor,
//! `getAddressRepresentation()`) through trait methods. Java's three constructors (populating with
//! an explicit representation, populating with `addr.toString()` as the representation, and the
//! XML-restore default) don't map onto trait methods and are left to implementors.
//!
//! `saveState`/`restoreState` are omitted for the same reason [`ProgramLocation`]'s are: they
//! round-trip through [`SaveState`](crate::framework::seam_stubs::SaveState), which the base trait
//! already doesn't expose a hook for. `equals`/`hashCode`/`toString` are Java `Object`-identity
//! boilerplate that implementors can derive/implement directly on their concrete type instead of
//! through this trait.

use crate::program::util::code_unit_location::CodeUnitLocation;

/// Provides specific information about a program location within the ADDRESS field.
///
/// Port of `ghidra.program.util.AddressFieldLocation`.
pub trait AddressFieldLocation: CodeUnitLocation {
    /// Returns the standard string representation of the address in the address field. If there
    /// is no address, then `None` should be returned.
    ///
    /// Port of `AddressFieldLocation.getAddressRepresentation()`.
    fn get_address_representation(&self) -> Option<&str>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe and that `get_address_representation`
    /// round-trips the value it was built with, exercising both the `Some` (explicit
    /// representation) and `None` (no address) cases through a `dyn AddressFieldLocation`.
    struct FixedAddressFieldLocation {
        address: Address,
        addr_representation: Option<String>,
    }

    impl ProgramLocation for FixedAddressFieldLocation {
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

    impl CodeUnitLocation for FixedAddressFieldLocation {}

    impl AddressFieldLocation for FixedAddressFieldLocation {
        fn get_address_representation(&self) -> Option<&str> {
            self.addr_representation.as_deref()
        }
    }

    #[test]
    fn trait_object_reports_its_address_representation() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram.clone(), 0x400);
        let expected_rep = addr.to_string();

        let with_rep: Box<dyn AddressFieldLocation> = Box::new(FixedAddressFieldLocation {
            address: addr.clone(),
            addr_representation: Some(expected_rep.clone()),
        });
        let without_rep: Box<dyn AddressFieldLocation> = Box::new(FixedAddressFieldLocation {
            address: addr,
            addr_representation: None,
        });

        assert_eq!(with_rep.get_address_representation(), Some(expected_rep.as_str()));
        assert_eq!(without_rep.get_address_representation(), None);
    }
}
