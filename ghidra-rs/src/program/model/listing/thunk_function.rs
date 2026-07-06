use crate::program::model::address::Address;
use crate::program::model::listing::Function;

/// Represents a function that simply passes control to a destination function.
///
/// A thunk function corresponds to a fragment of code which simply passes control
/// to a destination function. All Function behaviors are mapped through to the current
/// destination function.
///
/// Port of `ghidra.program.model.listing.ThunkFunction`.
pub trait ThunkFunction: Function {
    /// Set the destination function which corresponds to this thunk.
    fn set_destination_function(&mut self, function: &dyn Function);

    /// Returns the current destination function entry point address.
    ///
    /// A function should exist at the specified address although there is no guarantee.
    /// If the address is within the EXTERNAL space, this is a place-holder for an external
    /// library function.
    fn get_destination_function_entry_point(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::Namespace;
    use std::cmp::Ordering;

    struct MockFunction {
        entry_point: Address,
    }

    impl Namespace for MockFunction {
        fn get_name(&self) -> &str {
            "mock_func"
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn compare_to(&self, _other: &dyn Namespace) -> Ordering {
            Ordering::Equal
        }
    }

    impl Function for MockFunction {
        fn get_entry_point(&self) -> Address {
            self.entry_point
        }
    }

    struct MockThunkFunction {
        entry_point: Address,
        destination_entry_point: Address,
        destination: Option<Box<dyn Function>>,
    }

    impl MockThunkFunction {
        fn new(entry_point: Address, destination_entry_point: Address) -> Self {
            Self {
                entry_point,
                destination_entry_point,
                destination: None,
            }
        }
    }

    impl Namespace for MockThunkFunction {
        fn get_name(&self) -> &str {
            "mock_thunk"
        }

        fn get_id(&self) -> i64 {
            1
        }

        fn compare_to(&self, _other: &dyn Namespace) -> Ordering {
            Ordering::Equal
        }
    }

    impl Function for MockThunkFunction {
        fn get_entry_point(&self) -> Address {
            self.entry_point
        }
    }

    impl ThunkFunction for MockThunkFunction {
        fn set_destination_function(&mut self, _function: &dyn Function) {
            self.destination = Some(Box::new(MockFunction {
                entry_point: self.destination_entry_point,
            }));
        }

        fn get_destination_function_entry_point(&self) -> Address {
            self.destination_entry_point
        }
    }

    fn create_test_address(offset: u64) -> Address {
        Address::new(AddressSpace::new_default(AddressSpaceType::RAM), offset)
    }

    #[test]
    fn get_destination_function_entry_point_returns_set_address() {
        let entry = create_test_address(0x1000);
        let dest = create_test_address(0x2000);
        let thunk = MockThunkFunction::new(entry, dest);
        assert_eq!(thunk.get_destination_function_entry_point(), dest);
    }

    #[test]
    fn set_destination_function_stores_destination() {
        let entry = create_test_address(0x1000);
        let dest = create_test_address(0x2000);
        let mut thunk = MockThunkFunction::new(entry, dest);
        let destination = MockFunction {
            entry_point: dest,
        };
        thunk.set_destination_function(&destination);
        assert!(thunk.destination.is_some());
    }

    #[test]
    fn thunk_preserves_own_entry_point() {
        let entry = create_test_address(0x1000);
        let dest = create_test_address(0x2000);
        let thunk = MockThunkFunction::new(entry, dest);
        assert_eq!(thunk.get_entry_point(), entry);
    }

    #[test]
    fn thunk_different_entry_and_destination() {
        let entry = create_test_address(0x5000);
        let dest = create_test_address(0x6000);
        let thunk = MockThunkFunction::new(entry, dest);
        assert_ne!(thunk.get_entry_point(), thunk.get_destination_function_entry_point());
    }
}
