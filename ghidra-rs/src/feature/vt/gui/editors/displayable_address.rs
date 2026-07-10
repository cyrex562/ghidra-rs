use crate::docking::widgets::table::DisplayStringProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use std::sync::Arc;

/// A displayable address that provides access to an address and its associated program.
///
/// This trait is implemented by classes that represent addresses in version tracking,
/// providing both a display string for UI rendering and underlying address/program data.
/// Implementors are expected to be comparable via standard ordering traits.
///
/// Corresponds to `ghidra.feature.vt.gui.editors.DisplayableAddress` in the Java source.
pub trait DisplayableAddress: DisplayStringProvider + Ord {
    /// A constant string representing "No Address".
    const NO_ADDRESS: &'static str = "No Address";

    /// Returns the address associated with this displayable address.
    fn get_address(&self) -> Address;

    /// Returns the program associated with this displayable address.
    fn get_program(&self) -> Arc<dyn Program>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    struct MockDisplayableAddress {
        address: Address,
        program: Arc<dyn Program>,
        display: String,
        order_key: u64,
    }

    impl DisplayStringProvider for MockDisplayableAddress {
        fn display_string(&self) -> String {
            self.display.clone()
        }
    }

    impl Ord for MockDisplayableAddress {
        fn cmp(&self, other: &Self) -> Ordering {
            self.order_key.cmp(&other.order_key)
        }
    }

    impl PartialOrd for MockDisplayableAddress {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Eq for MockDisplayableAddress {}

    impl PartialEq for MockDisplayableAddress {
        fn eq(&self, other: &Self) -> bool {
            self.order_key == other.order_key
        }
    }

    impl DisplayableAddress for MockDisplayableAddress {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::clone(&self.program)
        }
    }

    struct MockProgram {
        name: String,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    #[test]
    fn test_no_address_constant() {
        assert_eq!(MockDisplayableAddress::NO_ADDRESS, "No Address");
    }

    #[test]
    fn test_display_string_from_provider() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "test_prog".to_string(),
        });

        let displayable = MockDisplayableAddress {
            address: addr,
            program,
            display: "test_display".to_string(),
            order_key: 1,
        };

        assert_eq!(displayable.display_string(), "test_display");
    }

    #[test]
    fn test_get_address_returns_correct_value() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x2000);
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "test_prog".to_string(),
        });

        let displayable = MockDisplayableAddress {
            address: addr.clone(),
            program,
            display: "test".to_string(),
            order_key: 1,
        };

        assert_eq!(displayable.get_address(), addr);
    }

    #[test]
    fn test_get_program_returns_correct_value() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x3000);
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "test_prog".to_string(),
        });

        let displayable = MockDisplayableAddress {
            address: addr,
            program: Arc::clone(&program),
            display: "test".to_string(),
            order_key: 1,
        };

        assert_eq!(Program::get_name(&*displayable.get_program()), "test_prog");
    }

    #[test]
    fn test_comparable_ordering() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "test_prog".to_string(),
        });

        let displayable1 = MockDisplayableAddress {
            address: space.address(0x1000),
            program: Arc::clone(&program),
            display: "addr1".to_string(),
            order_key: 1,
        };

        let displayable2 = MockDisplayableAddress {
            address: space.address(0x2000),
            program: Arc::clone(&program),
            display: "addr2".to_string(),
            order_key: 2,
        };

        assert!(displayable1 < displayable2);
        assert_eq!(displayable1.cmp(&displayable2), Ordering::Less);
    }

    #[test]
    fn test_comparable_equality() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "test_prog".to_string(),
        });

        let displayable1 = MockDisplayableAddress {
            address: space.address(0x1000),
            program: Arc::clone(&program),
            display: "addr1".to_string(),
            order_key: 1,
        };

        let displayable2 = MockDisplayableAddress {
            address: space.address(0x1000),
            program: Arc::clone(&program),
            display: "addr1".to_string(),
            order_key: 1,
        };

        assert!(displayable1 == displayable2);
    }
}
