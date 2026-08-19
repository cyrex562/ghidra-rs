//! A guest platform in a trace.
//!
//! Port of `ghidra.trace.model.guest.TraceGuestPlatform`.

use crate::program::model::address::{Address, AddressOverflowException};
use crate::trace::model::guest::trace_guest_platform_mapped_range::TraceGuestPlatformMappedRange;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A guest platform in a trace.
///
/// Port of `ghidra.trace.model.guest.TraceGuestPlatform`. A guest platform is a secondary
/// platform within a trace whose memory and registers must be mapped into the host platform.
pub trait TraceGuestPlatform: TracePlatform {
    /// Add an address mapping from host to guest.
    ///
    /// # Arguments
    ///
    /// * `host_start` - the starting host address (mapped to `guest_start`)
    /// * `guest_start` - the starting guest address (mapped to `host_start`)
    /// * `length` - the length of the range to map
    ///
    /// # Returns
    ///
    /// The mapped range.
    ///
    /// # Errors
    ///
    /// Returns `AddressOverflowException` if `length` is too long for either start address.
    ///
    /// Mirrors `TraceGuestPlatform.addMappedRange(Address, Address, long)`.
    fn add_mapped_range(
        &self,
        host_start: Address,
        guest_start: Address,
        length: i64,
    ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, AddressOverflowException>;

    /// Add an address mapping from host register space to guest register space.
    ///
    /// In guest space, the mapping is placed at 0 and has length large enough to accommodate all
    /// registers in the guest language. In host space, the mapping is placed after every other
    /// register mapping for every platform.
    ///
    /// # Returns
    ///
    /// The mapped range.
    ///
    /// # Errors
    ///
    /// Returns `AddressOverflowException` if host register space was exhausted.
    ///
    /// Mirrors `TraceGuestPlatform.addMappedRegisterRange()`.
    fn add_mapped_register_range(
        &self,
    ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, AddressOverflowException>;

    /// Remove the mapped language, including all code units of the language.
    ///
    /// # Arguments
    ///
    /// * `monitor` - to monitor task progress
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the task is cancelled by the monitor.
    ///
    /// Mirrors `TraceGuestPlatform.delete(TaskMonitor)`.
    fn delete(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockGuestPlatform {
        add_mapped_range_called: Arc<AtomicBool>,
    }

    impl MockGuestPlatform {
        fn new() -> Self {
            MockGuestPlatform {
                add_mapped_range_called: Arc::new(AtomicBool::new(false)),
            }
        }
    }

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
        ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, AddressOverflowException> {
            self.add_mapped_range_called.store(true, Ordering::SeqCst);
            Err(AddressOverflowException::new("test error"))
        }

        fn add_mapped_register_range(
            &self,
        ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, AddressOverflowException> {
            Err(AddressOverflowException::new("test error"))
        }

        fn delete(&self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    fn make_space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn guest_platform_is_guest() {
        let platform = MockGuestPlatform::new();
        assert!(platform.is_guest());
        assert!(!platform.is_host());
    }

    #[test]
    fn add_mapped_range_can_return_error() {
        let space = make_space();
        let platform = MockGuestPlatform::new();

        let result = platform.add_mapped_range(
            space.address(0x1000),
            space.address(0x0),
            0x1000,
        );

        assert!(result.is_err());
        assert!(platform.add_mapped_range_called.load(Ordering::SeqCst));
    }

    #[test]
    fn delete_returns_ok() {
        use crate::util::task::DummyMonitor;

        let platform = MockGuestPlatform::new();

        let result = platform.delete(&DummyMonitor);
        assert!(result.is_ok());
    }
}
