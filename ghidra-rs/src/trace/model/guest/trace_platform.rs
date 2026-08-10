//! A platform within a trace.
//!
//! Port of `ghidra.trace.model.guest.TracePlatform`.
//!
//! Traces can model systems where multiple processors or languages are involved. Every trace has
//! a "host" platform. There may also be zero or more "guest" platforms. The guest platforms'
//! memories and registers must be mapped into the host platform to be used in the trace. This
//! trait provides access to the properties of a platform and mechanisms for translating
//! addresses between this and the host platform. If this is the host platform, the translation
//! methods are the identity function.
//!
//! This promotes a placeholder that was grown across several prior ports (see e.g.
//! [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)).
//! Every method here keeps a default so the many existing `impl TracePlatform for T {}` marker
//! implementors scattered across the crate's test modules keep compiling unchanged.
//!
//! A handful of Java abstract methods are intentionally not mirrored here:
//!
//! * `getLanguage()` is [`Self::platform_language`] here (not `get_language`), and
//!   `getCompilerSpec()` is [`Self::platform_compiler_spec`] (not `get_compiler_spec`):
//!   [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)
//!   extends both this trait and
//!   [`ProgramArchitecture`](crate::program::model::lang::program_architecture::ProgramArchitecture),
//!   whose same-named abstract methods would otherwise make `self.get_language()`/
//!   `self.get_compiler_spec()` ambiguous on any type implementing both.
//! * `getAddressFactory()`'s Java default (`getLanguage().getAddressFactory()`) is
//!   [`Self::platform_address_factory`] here, for the same reason.
//! * `getConventionalRegisterObjectNames`, the three `getConventionalRegisterPath` overloads, and
//!   `addRegisterMapOverride` are not redeclared here. Nothing in the crate calls them through a
//!   bare `&dyn TracePlatform`; every real caller reaches them through
//!   [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform),
//!   which already declares (and, for `get_conventional_register_path_for_names`/
//!   `add_register_map_override`, requires) the working versions. Redeclaring them here under the
//!   same names would create the same self-call ambiguity described above, for no caller that
//!   needs it.

use std::sync::Arc;

use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressSet, AddressSetView, AddressSpace,
};
use crate::program::model::lang::{CompilerSpec, Language, Register};
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::InstructionSet;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceBasedDataTypeManager;

/// A platform within a trace.
///
/// Port of `ghidra.trace.model.guest.TracePlatform`. See the module documentation for the
/// Rust-specific method-naming deviations and omissions.
pub trait TracePlatform: Send + Sync {
    /// Check if this is a guest platform. Mirrors `TracePlatform.isGuest()`.
    ///
    /// Real Java method, abstract (no default). Defaults to `false` (host), matching the crate's
    /// established host-identity growth convention (see [`Self::map_guest_to_host`]'s default).
    fn is_guest(&self) -> bool {
        false
    }

    /// Check if this is the host platform. Mirrors `TracePlatform.isHost()`: `!isGuest()`.
    fn is_host(&self) -> bool {
        !self.is_guest()
    }

    /// Get the trace this platform belongs to. Mirrors `TracePlatform.getTrace()`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching this crate's
    /// other grown-but-not-yet-implemented placeholder members, so existing marker
    /// (`impl TracePlatform for T {}`) implementors keep compiling unchanged.
    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("TracePlatform::get_trace placeholder not overridden")
    }

    /// Get the language this platform disassembles/decodes with. Mirrors
    /// `TracePlatform.getLanguage()`. See the module documentation for why this is not named
    /// `get_language`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn platform_language(&self) -> Box<dyn Language> {
        unimplemented!("TracePlatform::platform_language placeholder not overridden")
    }

    /// Get the address factory of this platform. Mirrors the Java default `getAddressFactory()`:
    /// `getLanguage().getAddressFactory()`. See the module documentation for why this is not
    /// named `get_address_factory`.
    fn platform_address_factory(&self) -> Box<dyn AddressFactory> {
        self.platform_language().get_address_factory()
    }

    /// Get the compiler specification of this platform. Mirrors
    /// `TracePlatform.getCompilerSpec()`. See the module documentation for why this is not named
    /// `get_compiler_spec`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn platform_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        unimplemented!("TracePlatform::platform_compiler_spec placeholder not overridden")
    }

    /// Get the data type manager for this platform. Mirrors `TracePlatform.getDataTypeManager()`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn get_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
        unimplemented!("TracePlatform::get_data_type_manager placeholder not overridden")
    }

    /// Get the addresses in the host which are mapped to somewhere in the guest. Mirrors
    /// `TracePlatform.getHostAddressSet()`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn get_host_address_set(&self) -> Box<dyn AddressSetView> {
        unimplemented!("TracePlatform::get_host_address_set placeholder not overridden")
    }

    /// Get the addresses in the guest which are mapped to somewhere in the host. Mirrors
    /// `TracePlatform.getGuestAddressSet()`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn get_guest_address_set(&self) -> Box<dyn AddressSetView> {
        unimplemented!("TracePlatform::get_guest_address_set placeholder not overridden")
    }

    /// Translate an address from host to guest. Mirrors `TracePlatform.mapHostToGuest(Address)`.
    /// Defaults to the identity mapping, matching the host platform's behavior.
    fn map_host_to_guest(&self, host_address: Address) -> Option<Address> {
        Some(host_address)
    }

    /// Translate a range from host to guest. Mirrors
    /// `TracePlatform.mapHostToGuest(AddressRange)`. Defaults to the identity mapping, matching
    /// the host platform's behavior.
    fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange> {
        Some(host_range.clone())
    }

    /// Translate a set from host to guest. Mirrors
    /// `TracePlatform.mapHostToGuest(AddressSetView)`. Defaults to the identity mapping,
    /// matching the host platform's behavior.
    fn map_host_to_guest_set(&self, host_set: &dyn AddressSetView) -> Box<dyn AddressSetView> {
        Box::new(AddressSet::from_set(host_set))
    }

    /// Translate an address from guest to host. Mirrors `TracePlatform.mapGuestToHost(Address)`.
    /// Defaults to the identity mapping, matching the host platform's behavior.
    fn map_guest_to_host(&self, address: Address) -> Option<Address> {
        Some(address)
    }

    /// Translate a range from guest to host. Mirrors
    /// `TracePlatform.mapGuestToHost(AddressRange)`. Defaults to the identity mapping, matching
    /// the host platform's behavior.
    ///
    /// Grown for
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform),
    /// whose `getConventionalRegisterRange` default needs the range-taking overload.
    fn map_guest_to_host_range(&self, range: &AddressRange) -> Option<AddressRange> {
        Some(range.clone())
    }

    /// Translate a set from guest to host. Mirrors
    /// `TracePlatform.mapGuestToHost(AddressSetView)`. Defaults to the identity mapping,
    /// matching the host platform's behavior.
    fn map_guest_to_host_set(&self, guest_set: &dyn AddressSetView) -> Box<dyn AddressSetView> {
        Box::new(AddressSet::from_set(guest_set))
    }

    /// Get the conventional (register-space-overlay) address range for the given platform
    /// register, within the given overlay address space. Mirrors
    /// `TracePlatform.getConventionalRegisterRange(AddressSpace, Register)`, used by
    /// [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView)'s
    /// register-taking defaults.
    ///
    /// The Java method is abstract with no default (its mapping depends on platform-specific
    /// guest/host register layout, not yet ported). This placeholder defaults to re-basing the
    /// register's own offset and byte length into the given overlay space, matching a host
    /// platform's identity mapping (see [`Self::map_guest_to_host`]'s default for the same
    /// convention).
    fn get_conventional_register_range(
        &self,
        overlay: &Arc<AddressSpace>,
        register: &Register,
    ) -> AddressRange {
        let start = overlay.address(register.address().offset());
        AddressRange::from_start_len(start.clone(), register.num_bytes() as u64)
            .unwrap_or_else(|_| AddressRange::new(start.clone(), start))
    }

    /// Get a memory buffer, which presents the host bytes in the guest address space. Mirrors
    /// `TracePlatform.getMappedMemBuffer(long, Address)`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn get_mapped_mem_buffer(&self, snap: i64, guest_address: Address) -> Box<dyn MemBuffer> {
        let _ = (snap, guest_address);
        unimplemented!("TracePlatform::get_mapped_mem_buffer placeholder not overridden")
    }

    /// Copy the given instruction set, but with addresses mapped from the guest space to the
    /// host space. Mirrors `TracePlatform.mapGuestInstructionAddressesToHost(InstructionSet)`.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention.
    fn map_guest_instruction_addresses_to_host(
        &self,
        set: Box<dyn InstructionSet>,
    ) -> Box<dyn InstructionSet> {
        let _ = set;
        unimplemented!(
            "TracePlatform::map_guest_instruction_addresses_to_host placeholder not overridden"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn make_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct HostPlatform;
    impl TracePlatform for HostPlatform {}

    struct GuestPlatform;
    impl TracePlatform for GuestPlatform {
        fn is_guest(&self) -> bool {
            true
        }
    }

    #[test]
    fn is_host_defaults_to_true_and_derives_from_is_guest() {
        // Mirrors `TracePlatform.isHost()`'s default: `!isGuest()`.
        assert!(!HostPlatform.is_guest());
        assert!(HostPlatform.is_host());

        assert!(GuestPlatform.is_guest());
        assert!(!GuestPlatform.is_host());
    }

    #[test]
    fn identity_mapping_defaults_round_trip_addresses_and_ranges() {
        let space = make_space();
        let addr = space.address(0x1000);

        assert_eq!(HostPlatform.map_guest_to_host(addr.clone()), Some(addr.clone()));
        assert_eq!(HostPlatform.map_host_to_guest(addr.clone()), Some(addr.clone()));

        let range = AddressRange::new(space.address(0x1000), space.address(0x1010));
        assert_eq!(HostPlatform.map_guest_to_host_range(&range), Some(range.clone()));
        assert_eq!(HostPlatform.map_host_to_guest_range(&range), Some(range.clone()));
    }

    #[test]
    fn get_conventional_register_range_rebases_into_overlay_by_default() {
        let space = make_space();
        let overlay = make_space();
        let reg = Register::new("R0", "", space.address(0x10), 4, false, 0);

        let range = HostPlatform.get_conventional_register_range(&overlay, &reg.borrow());

        assert_eq!(range.min_address(), &overlay.address(0x10));
        assert_eq!(range.max_address(), &overlay.address(0x13));
    }
}
