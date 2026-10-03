use crate::app::seam_stubs::Navigatable;
use crate::framework::seam_stubs::HelpLocation;
use crate::program::util::program_location::ProgramLocation;

/// A service that provides a GUI listing of all *from* locations that refer to a given *to*
/// location.
///
/// Port of `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService`.
///
/// A genuine open extension point (per `scripts/shape_rules.py`): the one in-repo implementor is
/// [`LocationReferencesPlugin`](crate::app::plugin::core::navigation::locationreferences::location_references_plugin::LocationReferencesPlugin).
///
/// # Deviations from Java
///
/// * `getHelpLocation()`'s return isn't annotated non-null in Java, and this crate's established
///   convention for the still-unported `HelpLocation` (see
///   [`Options::get_help_location`](crate::framework::options::Options::get_help_location)) is to
///   wrap it in `Option`, so this does too.
/// * `Navigatable` and `HelpLocation` are both unported; both already have crate-wide placeholders
///   (`crate::app::seam_stubs::Navigatable`, a real trait with two members already grown for other
///   callers; `crate::framework::seam_stubs::HelpLocation`, a marker trait) reused here as-is.
pub trait LocationReferencesService {
    /// Java: `public static final String MENU_GROUP = "References"`.
    const MENU_GROUP: &'static str = "References";

    /// Returns the help location for help content that describes this service.
    ///
    /// Java: `getHelpLocation()`.
    fn get_help_location(&self) -> Option<Box<dyn HelpLocation>>;

    /// Shows a `ComponentProvider` containing a table of references that refer to the given
    /// location.
    ///
    /// Java: `showReferencesToLocation(ProgramLocation, Navigatable)`. Java throws
    /// `NullPointerException` if `location` is null; a `&dyn ProgramLocation` reference cannot be
    /// null, so that precondition is enforced by the type system instead.
    fn show_references_to_location(&self, location: &dyn ProgramLocation, navigatable: &dyn Navigatable);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Arc;

    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;

    struct FakeHelpLocation;
    impl HelpLocation for FakeHelpLocation {}

    struct FakeNavigatable;
    impl Navigatable for FakeNavigatable {
        fn is_connected(&self) -> bool {
            true
        }
        fn get_program(&self) -> Box<dyn Program> {
            unimplemented!("not exercised by this test")
        }
    }

    struct FakeLocation {
        address: Address,
    }
    impl ProgramLocation for FakeLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_ref_address(&self) -> Option<Address> {
            None
        }
        fn get_component_path(&self) -> Option<&[i32]> {
            None
        }
        fn get_row(&self) -> i32 {
            0
        }
        fn get_column(&self) -> i32 {
            0
        }
        fn get_char_offset(&self) -> i32 {
            0
        }
        fn is_valid(&self, _test_program: &dyn Program) -> bool {
            true
        }
    }

    /// A minimal implementor recording the last location/navigatable it was asked to show
    /// references for, sufficient to prove the trait's contract without a real GUI provider.
    #[derive(Default)]
    struct RecordingService {
        shown_addresses: RefCell<Vec<Address>>,
    }

    impl LocationReferencesService for RecordingService {
        fn get_help_location(&self) -> Option<Box<dyn HelpLocation>> {
            Some(Box::new(FakeHelpLocation))
        }
        fn show_references_to_location(&self, location: &dyn ProgramLocation, _navigatable: &dyn Navigatable) {
            self.shown_addresses.borrow_mut().push(location.get_address());
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn menu_group_matches_java_constant() {
        assert_eq!(RecordingService::MENU_GROUP, "References");
    }

    #[test]
    fn show_references_to_location_records_the_address() {
        let service = RecordingService::default();
        let location = FakeLocation { address: addr(0x400) };

        service.show_references_to_location(&location, &FakeNavigatable);

        assert_eq!(service.shown_addresses.borrow().as_slice(), &[addr(0x400)]);
    }

    #[test]
    fn get_help_location_returns_something() {
        let service = RecordingService::default();
        assert!(service.get_help_location().is_some());
    }
}
