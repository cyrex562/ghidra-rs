use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::{Function, Program};
use crate::util::datastruct::duo::Side;
use std::sync::Arc;

/// A correlator that associates addresses from one program with addresses from another program,
/// or associates addresses from one part of a program with addresses from another part of the
/// same program. Given an address from one program, it can provide the corresponding address
/// for the other program. The two programs are referred to as the LEFT program and the RIGHT
/// program. See [`Side`].
pub trait ListingAddressCorrelation: Send + Sync {
    /// Gets the program for the given side.
    ///
    /// # Arguments
    /// * `side` - LEFT or RIGHT
    ///
    /// # Returns
    /// The program for the given side.
    fn get_program(&self, side: Side) -> Arc<dyn Program>;

    /// Gets the function for the given side. This will be `None` if the addresses are not
    /// function based.
    ///
    /// # Arguments
    /// * `side` - LEFT or RIGHT
    ///
    /// # Returns
    /// The function for the given side or `None` if not function based.
    fn get_function(&self, side: Side) -> Option<Arc<dyn Function>>;

    /// Gets the addresses that are part of the correlator for the given side.
    ///
    /// # Arguments
    /// * `side` - LEFT or RIGHT
    ///
    /// # Returns
    /// The addresses that are part of the correlator for the given side.
    fn get_addresses(&self, side: Side) -> Arc<dyn AddressSetView>;

    /// Gets the address for the given side that matches the given address from the other side.
    ///
    /// # Arguments
    /// * `side` - The side to get an address for
    /// * `other_side_address` - The address from the other side to find a match for
    ///
    /// # Returns
    /// The address for the given side that matches the given address from the other side.
    fn get_address(&self, side: Side, other_side_address: &Address) -> Option<Address>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleTestCorrelation;

    impl ListingAddressCorrelation for SimpleTestCorrelation {
        fn get_program(&self, _side: Side) -> Arc<dyn Program> {
            unimplemented!("test implementation")
        }

        fn get_function(&self, _side: Side) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_addresses(&self, _side: Side) -> Arc<dyn AddressSetView> {
            unimplemented!("test implementation")
        }

        fn get_address(&self, _side: Side, _other_side_address: &Address) -> Option<Address> {
            None
        }
    }

    #[test]
    fn test_trait_object_creation() {
        let _corr: Arc<dyn ListingAddressCorrelation> = Arc::new(SimpleTestCorrelation);
    }

    #[test]
    fn test_get_function_returns_none() {
        let corr = SimpleTestCorrelation;
        assert!(corr.get_function(Side::Left).is_none());
        assert!(corr.get_function(Side::Right).is_none());
    }

    #[test]
    fn test_get_address_returns_none() {
        let space = crate::program::model::address::AddressSpace::new("test", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        let corr = SimpleTestCorrelation;
        assert_eq!(corr.get_address(Side::Left, &addr), None);
    }
}
