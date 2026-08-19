//! A range of memory mapped from a guest platform into the host platform.
//!
//! Port of `ghidra.trace.model.guest.TraceGuestPlatformMappedRange`.

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::guest::trace_guest_platform::TraceGuestPlatform;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use std::sync::Arc;

/// A range of mapped memory from guest platform to host platform.
///
/// Port of `ghidra.trace.model.guest.TraceGuestPlatformMappedRange`. The sole in-repo
/// implementor, `DBTraceGuestPlatformMappedRange`, is not yet ported (see `STUBS.tsv`), so every
/// method here is required, matching the Java interface's all-abstract shape.
pub trait TraceGuestPlatformMappedRange {
    /// Get the host platform. Mirrors `TraceGuestPlatformMappedRange.getHostPlatform()`.
    fn get_host_platform(&self) -> Box<dyn TracePlatform>;

    /// Get the address range in the host. Mirrors
    /// `TraceGuestPlatformMappedRange.getHostRange()`.
    fn get_host_range(&self) -> AddressRange;

    /// Get the guest platform. Mirrors `TraceGuestPlatformMappedRange.getGuestPlatform()`.
    fn get_guest_platform(&self) -> Box<dyn TraceGuestPlatform>;

    /// Get the address range in the guest. Mirrors
    /// `TraceGuestPlatformMappedRange.getGuestRange()`.
    fn get_guest_range(&self) -> AddressRange;

    /// Translate an address from host to guest, if in the host range. Mirrors
    /// `TraceGuestPlatformMappedRange.mapHostToGuest(Address)`.
    fn map_host_to_guest(&self, host_address: Address) -> Option<Address>;

    /// Translate an address range from host to guest, if wholly contained in the host range.
    /// Mirrors the `mapHostToGuest(AddressRange)` overload.
    fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange>;

    /// Translate an address from guest to host, if in the guest range. Mirrors
    /// `TraceGuestPlatformMappedRange.mapGuestToHost(Address)`.
    fn map_guest_to_host(&self, guest_address: Address) -> Option<Address>;

    /// Translate an address range from guest to host, if wholly contained in the guest range.
    /// Mirrors the `mapGuestToHost(AddressRange)` overload.
    fn map_guest_to_host_range(&self, guest_range: &AddressRange) -> Option<AddressRange>;

    /// Delete this mapping entry. Mirrors
    /// `TraceGuestPlatformMappedRange.delete(TaskMonitor)`, whose checked
    /// `CancelledException` becomes an `Err`.
    fn delete(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;
}

/// A shared handle to a mapped range, which is itself a [`TraceGuestPlatformMappedRange`].
///
/// Java hands the *same* `DBTraceGuestPlatformMappedRange` instance to its two owning maps and to
/// the caller of `addMappedRange`. Rust cannot copy a `Box<dyn TraceGuestPlatformMappedRange>` out
/// of a stored one, so
/// [`DBTraceGuestPlatform`](crate::trace::database::guest::db_trace_guest_platform::DBTraceGuestPlatform)
/// stores the range as an `Arc` and returns it wrapped in this delegating handle -- preserving
/// Java's aliasing (all three refer to one range) where a deep copy would not.
pub struct SharedMappedRange(Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>);

impl SharedMappedRange {
    /// Wrap a shared mapped range so it can be handed out as an owned
    /// [`TraceGuestPlatformMappedRange`].
    pub fn new(range: Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>) -> Self {
        Self(range)
    }

    /// The underlying shared range.
    pub fn inner(&self) -> &Arc<dyn TraceGuestPlatformMappedRange + Send + Sync> {
        &self.0
    }
}

impl TraceGuestPlatformMappedRange for SharedMappedRange {
    fn get_host_platform(&self) -> Box<dyn TracePlatform> {
        self.0.get_host_platform()
    }

    fn get_host_range(&self) -> AddressRange {
        self.0.get_host_range()
    }

    fn get_guest_platform(&self) -> Box<dyn TraceGuestPlatform> {
        self.0.get_guest_platform()
    }

    fn get_guest_range(&self) -> AddressRange {
        self.0.get_guest_range()
    }

    fn map_host_to_guest(&self, host_address: Address) -> Option<Address> {
        self.0.map_host_to_guest(host_address)
    }

    fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange> {
        self.0.map_host_to_guest_range(host_range)
    }

    fn map_guest_to_host(&self, guest_address: Address) -> Option<Address> {
        self.0.map_guest_to_host(guest_address)
    }

    fn map_guest_to_host_range(&self, guest_range: &AddressRange) -> Option<AddressRange> {
        self.0.map_guest_to_host_range(guest_range)
    }

    fn delete(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        self.0.delete(monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::cell::Cell;
    use std::sync::Arc;

    struct MockPlatform;
    impl TracePlatform for MockPlatform {}

    struct MockGuestPlatform;
    impl TracePlatform for MockGuestPlatform {
        fn is_guest(&self) -> bool {
            true
        }
    }
    impl TraceGuestPlatform for MockGuestPlatform {
        fn add_mapped_range(
            &self,
            _host_start: Address,
            _guest_start: Address,
            _length: i64,
        ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, crate::program::model::address::AddressOverflowException> {
            Err(crate::program::model::address::AddressOverflowException::new("test"))
        }

        fn add_mapped_register_range(
            &self,
        ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, crate::program::model::address::AddressOverflowException> {
            Err(crate::program::model::address::AddressOverflowException::new("test"))
        }

        fn delete(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
    }

    /// Maps `host_range` to `guest_range` by a constant offset, mirroring
    /// `DBTraceGuestPlatformMappedRange`'s straight-line translation between the two spaces.
    struct MockMappedRange {
        host_range: AddressRange,
        guest_range: AddressRange,
        deleted: Cell<bool>,
    }

    impl TraceGuestPlatformMappedRange for MockMappedRange {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            Box::new(MockPlatform)
        }

        fn get_host_range(&self) -> AddressRange {
            self.host_range.clone()
        }

        fn get_guest_platform(&self) -> Box<dyn TraceGuestPlatform> {
            Box::new(MockGuestPlatform)
        }

        fn get_guest_range(&self) -> AddressRange {
            self.guest_range.clone()
        }

        fn map_host_to_guest(&self, host_address: Address) -> Option<Address> {
            if !self.host_range.contains(&host_address) {
                return None;
            }
            let delta = host_address.subtract(self.host_range.min_address());
            Some(self.guest_range.min_address().add_wrap(delta))
        }

        fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange> {
            if !self.host_range.contains(host_range.min_address())
                || !self.host_range.contains(host_range.max_address())
            {
                return None;
            }
            let min = self.map_host_to_guest(host_range.min_address().clone())?;
            let max = self.map_host_to_guest(host_range.max_address().clone())?;
            Some(AddressRange::new(min, max))
        }

        fn map_guest_to_host(&self, guest_address: Address) -> Option<Address> {
            if !self.guest_range.contains(&guest_address) {
                return None;
            }
            let delta = guest_address.subtract(self.guest_range.min_address());
            Some(self.host_range.min_address().add_wrap(delta))
        }

        fn map_guest_to_host_range(&self, guest_range: &AddressRange) -> Option<AddressRange> {
            if !self.guest_range.contains(guest_range.min_address())
                || !self.guest_range.contains(guest_range.max_address())
            {
                return None;
            }
            let min = self.map_guest_to_host(guest_range.min_address().clone())?;
            let max = self.map_guest_to_host(guest_range.max_address().clone())?;
            Some(AddressRange::new(min, max))
        }

        fn delete(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.deleted.set(true);
            Ok(())
        }
    }

    fn make_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn mock_range() -> MockMappedRange {
        let space = make_space();
        MockMappedRange {
            host_range: AddressRange::new(space.address(0x1000), space.address(0x1FFF)),
            guest_range: AddressRange::new(space.address(0x0), space.address(0xFFF)),
            deleted: Cell::new(false),
        }
    }

    #[test]
    fn is_object_safe() {
        let range = mock_range();
        let _dyn_ref: &dyn TraceGuestPlatformMappedRange = &range;
    }

    #[test]
    fn map_host_to_guest_translates_addresses_inside_the_host_range() {
        let range = mock_range();
        let space = make_space();

        assert_eq!(
            range.map_host_to_guest(space.address(0x1050)),
            Some(space.address(0x50))
        );
        // Outside the host range: no mapping.
        assert_eq!(range.map_host_to_guest(space.address(0x2000)), None);
    }

    #[test]
    fn map_guest_to_host_translates_addresses_inside_the_guest_range() {
        let range = mock_range();
        let space = make_space();

        assert_eq!(
            range.map_guest_to_host(space.address(0x50)),
            Some(space.address(0x1050))
        );
        // Outside the guest range: no mapping.
        assert_eq!(range.map_guest_to_host(space.address(0x1000)), None);
    }

    #[test]
    fn map_host_to_guest_range_requires_whole_containment() {
        let range = mock_range();
        let space = make_space();

        let inner = AddressRange::new(space.address(0x1010), space.address(0x1020));
        assert_eq!(
            range.map_host_to_guest_range(&inner),
            Some(AddressRange::new(space.address(0x10), space.address(0x20)))
        );

        // Partially outside the host range: no mapping.
        let straddling = AddressRange::new(space.address(0x1FF0), space.address(0x2010));
        assert_eq!(range.map_host_to_guest_range(&straddling), None);
    }

    #[test]
    fn get_host_and_guest_ranges_round_trip() {
        let range = mock_range();
        assert_eq!(range.get_host_range(), range.host_range);
        assert_eq!(range.get_guest_range(), range.guest_range);
        assert!(range.get_host_platform().is_host());
    }

    #[test]
    fn delete_marks_the_range_deleted_unless_cancelled() {
        use crate::util::task::DummyMonitor;

        let range = mock_range();
        assert!(range.delete(&DummyMonitor).is_ok());
        assert!(range.deleted.get());

        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let cancel_deleted = mock_range();
        assert!(cancel_deleted.delete(&CancelledMonitor).is_err());
        assert!(!cancel_deleted.deleted.get());
    }
}
