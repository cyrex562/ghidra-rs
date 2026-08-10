//! Model displaying program data in a `FieldPanel`.
//!
//! Port of `ghidra.app.util.viewer.listingpanel.ListingModel`. This is a genuine open extension
//! point (three in-repo implementors: `ProgramBigListingModel`, `EmptyListingModel`,
//! `ListingModelConverter`), so it is ported as a trait; call sites that are polymorphic over
//! implementors should use `&dyn ListingModel`/`Box<dyn ListingModel>`.
//!
//! `FieldPanel` is only referenced in this interface's class-level Javadoc, not in any method
//! signature, so it is not stubbed here. `Layout` and `FormatManager` are unported dependencies:
//! `Layout` is added to [`crate::app::seam_stubs`] here; `FormatManager` already has a placeholder
//! there (added for
//! [`CodeFormatService`](crate::app::services::code_format_service::CodeFormatService)) and is
//! reused as-is.

use std::sync::Arc;

use crate::app::seam_stubs::{FormatManager, Layout};
use crate::app::util::viewer::listingpanel::listing_model_listener::ListingModelListener;
use crate::framework::options::options::DELIMITER;
use crate::program::model::address::address_set::AddressSet;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::data::Data;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Option group name under which the function-pointer display options are registered.
///
/// Port of `ListingModel.FUNCTION_POINTER_OPTION_GROUP_NAME`.
pub const FUNCTION_POINTER_OPTION_GROUP_NAME: &str = "Function Pointers";

/// Option name controlling whether the external-function-pointer header is displayed.
///
/// Port of `ListingModel.DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME`, which Java builds as
/// `FUNCTION_POINTER_OPTION_GROUP_NAME + Options.DELIMITER + "Display External Function Pointer
/// Header"`; that concatenation is precomputed here since Rust `const` strings cannot be built
/// from `format!` at compile time (see this module's tests for a runtime check that it still
/// matches).
pub const DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME: &str =
    "Function Pointers.Display External Function Pointer Header";

/// Option name controlling whether the non-external-function-pointer header is displayed.
///
/// Port of `ListingModel.DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME`; see
/// [`DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME`] for why the concatenation is precomputed.
pub const DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME: &str =
    "Function Pointers.Display Non-External Function Pointer Header";

/// Model displaying program data in a `FieldPanel`.
///
/// Port of `ghidra.app.util.viewer.listingpanel.ListingModel`.
pub trait ListingModel {
    /// {@return the address set of all addresses in the model}
    ///
    /// Port of `ListingModel.getAddressSet()`.
    fn get_address_set(&self) -> Box<dyn AddressSetView>;

    /// Returns the next address that has displayable information after the given address. This
    /// allows the listing to efficiently skip over large sections of undisplayable addresses such
    /// as those consumed by large data or addresses part of a closed function.
    ///
    /// Returns `None` when there is no next address with displayable information.
    ///
    /// Port of `ListingModel.getAddressAfter(Address)`.
    fn get_address_after(&self, address: &Address) -> Option<Address>;

    /// Returns the previous address that has displayable information before the given address.
    /// This allows the listing to efficiently skip over large sections of undisplayable addresses
    /// such as those consumed by large data or addresses part of a closed function.
    ///
    /// Returns `None` when there is no previous address with displayable information.
    ///
    /// Port of `ListingModel.getAddressBefore(Address)`.
    fn get_address_before(&self, address: &Address) -> Option<Address>;

    /// Returns a layout with displayable information for the given address, or `None` if there is
    /// nothing to display at that address.
    ///
    /// `is_gap_address` true implies there is a gap of missing addresses before this address. Note
    /// that this is different from addresses that are hidden due to collapsed functions or closed
    /// data. These gaps are not even in consideration to display information such as undefined
    /// memory or a fragmented program view.
    ///
    /// Port of `ListingModel.getLayout(Address, boolean)`.
    fn get_layout(&mut self, address: &Address, is_gap_address: bool) -> Option<Box<dyn Layout>>;

    /// {@return the width of the longest layout this model can produce.}
    ///
    /// Port of `ListingModel.getMaxWidth()`.
    fn get_max_width(&self) -> i32;

    /// Returns true if the data is open.
    ///
    /// Port of `ListingModel.isOpen(Data)`.
    fn is_open(&self, data: &dyn Data) -> bool;

    /// Changes the open state of the given data (open -> closes; closed -> open).
    ///
    /// Port of `ListingModel.toggleOpen(Data)`.
    fn toggle_open(&mut self, data: &dyn Data);

    /// Sets whether or not to display function variables for the function at the given address.
    /// `open`: if true, the variables are displayed, otherwise they are hidden.
    ///
    /// Port of `ListingModel.setFunctionVariablesOpen(Address, boolean)`.
    fn set_function_variables_open(&mut self, function_address: &Address, open: bool);

    /// Checks if the function variables are being displayed at the given address.
    ///
    /// Port of `ListingModel.areFunctionVariablesOpen(Address)`.
    fn are_function_variables_open(&self, function_address: &Address) -> bool;

    /// Sets the display of variables for all functions. This basically sets the default state,
    /// but the state can be overridden for individual functions. Changing this value erases all
    /// individually set values.
    ///
    /// Port of `ListingModel.setAllFunctionVariablesOpen(boolean)`.
    fn set_all_function_variables_open(&mut self, open: bool);

    /// Opens the given data, but not any sub-components.
    ///
    /// Returns true if the data was opened (will return false if the data is already open or has
    /// no children).
    ///
    /// Port of `ListingModel.openData(Data)`.
    fn open_data(&mut self, data: &dyn Data) -> bool;

    /// Recursively open the given data and its sub-components.
    ///
    /// Port of `ListingModel.openAllData(Data, TaskMonitor)`.
    fn open_all_data(&mut self, data: &dyn Data, monitor: &dyn TaskMonitor);

    /// Opens all data found within the given addresses. Each data is fully opened.
    ///
    /// Port of `ListingModel.openAllData(AddressSetView, TaskMonitor)`.
    fn open_all_data_in_addresses(&mut self, addresses: &dyn AddressSetView, monitor: &dyn TaskMonitor);

    /// Closes the given data, but not any sub-components.
    ///
    /// Port of `ListingModel.closeData(Data)`.
    fn close_data(&mut self, data: &dyn Data);

    /// Recursively close the given data and its sub-components.
    ///
    /// Port of `ListingModel.closeAllData(Data, TaskMonitor)`.
    fn close_all_data(&mut self, data: &dyn Data, monitor: &dyn TaskMonitor);

    /// Closes all data found within the given addresses. Each data is fully closed.
    ///
    /// Port of `ListingModel.closeAllData(AddressSetView, TaskMonitor)`.
    fn close_all_data_in_addresses(&mut self, addresses: &dyn AddressSetView, monitor: &dyn TaskMonitor);

    /// Adds a listener for changes to this model.
    ///
    /// Port of `ListingModel.addListener(ListingModelListener)`.
    fn add_listener(&mut self, listener: Box<dyn ListingModelListener>);

    /// Removes a listener from those being notified of model changes.
    ///
    /// Port of `ListingModel.removeListener(ListingModelListener)`.
    fn remove_listener(&mut self, listener: &dyn ListingModelListener);

    /// {@return the program being displayed by this model.}
    ///
    /// Port of `ListingModel.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// {@return true if the program being displayed by this listing has been closed (and
    /// therefore the model is invalid.)}
    ///
    /// Port of `ListingModel.isClosed()`.
    fn is_closed(&self) -> bool;

    /// Sets the `FormatManager` for this model which determines the layout of the fields.
    ///
    /// Port of `ListingModel.setFormatManager(FormatManager)`.
    fn set_format_manager(&mut self, format_manager: Box<dyn FormatManager>);

    /// Disposes this model.
    ///
    /// Port of `ListingModel.dispose()`.
    fn dispose(&mut self);

    /// Adjusts each range in the given address set to be on code unit boundaries.
    ///
    /// Returns a new `AddressSet` where each range is on a code unit boundary.
    ///
    /// Port of `ListingModel.adjustAddressSetToCodeUnitBoundaries(AddressSet)`.
    fn adjust_address_set_to_code_unit_boundaries(&self, address_set: &AddressSet) -> AddressSet;

    /// Makes a copy of this model.
    ///
    /// Port of `ListingModel.copy()`.
    fn copy(&self) -> Box<dyn ListingModel>;

    /// Checks if the function at the given entry point is open or not.
    ///
    /// Port of `ListingModel.isFunctionOpen(Address)`.
    fn is_function_open(&self, function_address: &Address) -> bool;

    /// Sets the function at the given address to be open or not.
    ///
    /// Port of `ListingModel.setFunctionOpen(Address, boolean)`.
    fn set_function_open(&mut self, function_address: &Address, open: bool);

    /// Sets all functions to open or closed.
    ///
    /// Port of `ListingModel.setAllFunctionsOpen(boolean)`.
    fn set_all_functions_open(&mut self, open: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc as StdArc;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockModel {
        closed: bool,
        function_open: bool,
    }

    impl ListingModel for MockModel {
        fn get_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn get_address_after(&self, address: &Address) -> Option<Address> {
            address.add(1).ok()
        }

        fn get_address_before(&self, address: &Address) -> Option<Address> {
            if address.offset() == 0 {
                None
            } else {
                address.subtract_no_wrap(1).ok()
            }
        }

        fn get_layout(&mut self, _address: &Address, _is_gap_address: bool) -> Option<Box<dyn Layout>> {
            None
        }

        fn get_max_width(&self) -> i32 {
            100
        }

        fn is_open(&self, _data: &dyn Data) -> bool {
            false
        }

        fn toggle_open(&mut self, _data: &dyn Data) {}

        fn set_function_variables_open(&mut self, _function_address: &Address, _open: bool) {}

        fn are_function_variables_open(&self, _function_address: &Address) -> bool {
            true
        }

        fn set_all_function_variables_open(&mut self, _open: bool) {}

        fn open_data(&mut self, _data: &dyn Data) -> bool {
            true
        }

        fn open_all_data(&mut self, _data: &dyn Data, _monitor: &dyn TaskMonitor) {}

        fn open_all_data_in_addresses(
            &mut self,
            _addresses: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) {
        }

        fn close_data(&mut self, _data: &dyn Data) {}

        fn close_all_data(&mut self, _data: &dyn Data, _monitor: &dyn TaskMonitor) {}

        fn close_all_data_in_addresses(
            &mut self,
            _addresses: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) {
        }

        fn add_listener(&mut self, _listener: Box<dyn ListingModelListener>) {}

        fn remove_listener(&mut self, _listener: &dyn ListingModelListener) {}

        fn get_program(&self) -> StdArc<dyn Program> {
            StdArc::new(MockProgram)
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn set_format_manager(&mut self, _format_manager: Box<dyn FormatManager>) {}

        fn dispose(&mut self) {
            self.closed = true;
        }

        fn adjust_address_set_to_code_unit_boundaries(&self, address_set: &AddressSet) -> AddressSet {
            address_set.clone()
        }

        fn copy(&self) -> Box<dyn ListingModel> {
            Box::new(MockModel { closed: self.closed, function_open: self.function_open })
        }

        fn is_function_open(&self, _function_address: &Address) -> bool {
            self.function_open
        }

        fn set_function_open(&mut self, _function_address: &Address, open: bool) {
            self.function_open = open;
        }

        fn set_all_functions_open(&mut self, open: bool) {
            self.function_open = open;
        }
    }

    #[test]
    fn option_names_match_java_concatenation() {
        assert_eq!(
            DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME,
            format!(
                "{}{}{}",
                FUNCTION_POINTER_OPTION_GROUP_NAME, DELIMITER, "Display External Function Pointer Header"
            )
        );
        assert_eq!(
            DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME,
            format!(
                "{}{}{}",
                FUNCTION_POINTER_OPTION_GROUP_NAME, DELIMITER,
                "Display Non-External Function Pointer Header"
            )
        );
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut model: Box<dyn ListingModel> = Box::new(MockModel { closed: false, function_open: false });

        assert!(!model.is_closed());
        model.dispose();
        assert!(model.is_closed());

        let a = addr(10);
        assert_eq!(model.get_address_after(&a), Some(addr(11)));
        assert_eq!(model.get_address_before(&a), Some(addr(9)));
        assert_eq!(model.get_address_before(&addr(0)), None);

        model.set_function_open(&a, true);
        assert!(model.is_function_open(&a));

        let copy = model.copy();
        assert!(copy.is_function_open(&a));
        assert!(copy.is_closed());
    }
}
