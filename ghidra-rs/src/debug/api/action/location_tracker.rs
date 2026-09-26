use crate::debug::api::action::go_to_input::GoToInput;
use crate::debug::api::tracemgr::debugger_coordinates::DebuggerCoordinates;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::util::program_location::ProgramLocation;
use crate::trace::model::stack::trace_stack::TraceStack;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;

/// The actual tracking logic for a location tracking spec.
///
/// Port of `ghidra.debug.api.action.LocationTracker`. Java is an `interface` with 5 abstract
/// methods and 5 in-repo implementors, so this becomes a `trait` (rule R-interface-open-ext-point
/// / cycle cut point).
///
/// In simple cases, the spec can implement this trait and return itself from
/// `LocationTrackingSpec::get_tracker`. If the tracker needs some state, the spec should create a
/// separate tracker.
pub trait LocationTracker {
    /// Compute the trace address to "goto".
    ///
    /// If the coordinates indicate emulation, i.e., the schedule is non-empty, the trace manager
    /// will already have performed the emulation and stored the results in a "scratch" snap. In
    /// general, the location should be computed using that snap, i.e.,
    /// [`DebuggerCoordinates::get_view_snap`] rather than [`DebuggerCoordinates::get_snap`]. The
    /// address returned must be in the host platform's language, i.e., please use
    /// [`TracePlatform::map_guest_to_host`](crate::trace::model::guest::trace_platform::TracePlatform::map_guest_to_host).
    fn compute_trace_address(
        &self,
        provider: &dyn ServiceProvider,
        coordinates: &DebuggerCoordinates,
    ) -> Option<Address>;

    /// Get the suggested input if the user activates "Go To" while this tracker is active.
    fn get_default_go_to_input(
        &self,
        provider: &dyn ServiceProvider,
        coordinates: &DebuggerCoordinates,
        location: &dyn ProgramLocation,
    ) -> GoToInput;

    /// Check if the address should be recomputed given the indicated value change.
    ///
    /// * `space` - the space (address space, thread, frame) where the change occurred
    /// * `range` - the range (time and space) where the change occurred
    /// * `coordinates` - the provider's current coordinates
    ///
    /// Returns `true` if re-computation and "goto" is warranted.
    fn affected_by_bytes_change(
        &self,
        space: &AddressSpace,
        range: &dyn TraceAddressSnapRange,
        coordinates: &DebuggerCoordinates,
    ) -> bool;

    /// Check if the address should be recomputed given the indicated stack change.
    ///
    /// * `stack` - the stack that changed (usually it's PC / return offset)
    /// * `coordinates` - the provider's current coordinates
    ///
    /// Returns `true` if re-computation and "goto" is warranted.
    fn affected_by_stack_change(
        &self,
        stack: &dyn TraceStack,
        coordinates: &DebuggerCoordinates,
    ) -> bool;

    /// Indicates whether the user should expect instructions at the tracked location.
    ///
    /// Essentially, is this tracking the program counter? Returns `true` to disassemble, `false`
    /// not to.
    fn should_disassemble(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal tracker that always tracks a fixed address and never wants recomputation,
    /// exercised only to prove the trait's contract (mirrors `NoneLocationTrackingSpec`'s
    /// "there is nothing to track" behavior).
    struct FixedLocationTracker {
        address: Option<Address>,
        disassemble: bool,
    }

    impl LocationTracker for FixedLocationTracker {
        fn compute_trace_address(
            &self,
            _provider: &dyn ServiceProvider,
            _coordinates: &DebuggerCoordinates,
        ) -> Option<Address> {
            self.address.clone()
        }

        fn get_default_go_to_input(
            &self,
            _provider: &dyn ServiceProvider,
            _coordinates: &DebuggerCoordinates,
            _location: &dyn ProgramLocation,
        ) -> GoToInput {
            match &self.address {
                Some(address) => GoToInput::from_address(address),
                None => GoToInput::offset_only(""),
            }
        }

        fn affected_by_bytes_change(
            &self,
            _space: &AddressSpace,
            _range: &dyn TraceAddressSnapRange,
            _coordinates: &DebuggerCoordinates,
        ) -> bool {
            false
        }

        fn affected_by_stack_change(
            &self,
            _stack: &dyn TraceStack,
            _coordinates: &DebuggerCoordinates,
        ) -> bool {
            false
        }

        fn should_disassemble(&self) -> bool {
            self.disassemble
        }
    }

    struct StubServiceProvider;
    impl ServiceProvider for StubServiceProvider {
        fn get_service(
            &self,
            _service_class: &str,
        ) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn add_service_listener(
            &mut self,
            _listener: Box<dyn crate::framework::plugintool::util::ServiceListener>,
        ) {
        }
        fn remove_service_listener(
            &mut self,
            _listener: Box<dyn crate::framework::plugintool::util::ServiceListener>,
        ) {
        }
    }

    #[test]
    fn should_disassemble_reflects_pc_tracking() {
        let pc_tracker = FixedLocationTracker {
            address: None,
            disassemble: true,
        };
        assert!(pc_tracker.should_disassemble());

        let stack_tracker = FixedLocationTracker {
            address: None,
            disassemble: false,
        };
        assert!(!stack_tracker.should_disassemble());
    }

    #[test]
    fn compute_trace_address_returns_fixed_address() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = space.address(0x1000);
        let tracker = FixedLocationTracker {
            address: Some(address.clone()),
            disassemble: true,
        };
        let provider = StubServiceProvider;
        let coordinates = DebuggerCoordinates::nowhere();
        assert_eq!(
            tracker.compute_trace_address(&provider, &coordinates),
            Some(address)
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let tracker: Box<dyn LocationTracker> = Box::new(FixedLocationTracker {
            address: None,
            disassemble: false,
        });
        assert!(!tracker.should_disassemble());
    }
}
