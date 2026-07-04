use crate::program::model::address::Address;

/// Handler for memory faults encountered during pcode execution.
///
/// This trait provides a callback mechanism to handle two types of memory access faults:
/// uninitialized memory reads and unknown address translations. Implementations can
/// define custom behavior for these situations, such as logging, emulation, or
/// returning default values.
///
/// Corresponds to `ghidra.pcode.memstate.MemoryFaultHandler`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub trait MemoryFaultHandler {
    /// Called when an attempt is made to read uninitialized memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The uninitialized storage address (memory, register, or unique).
    /// * `size` - The number of uninitialized bytes being read.
    /// * `buf` - The storage buffer for the read data.
    /// * `buf_offset` - The read offset within the buffer.
    ///
    /// # Returns
    ///
    /// `true` if the data should be treated as initialized; `false` if it should be
    /// treated as uninitialized.
    fn uninitialized_read(&self, address: &Address, size: i32, buf: &mut [u8], buf_offset: i32) -> bool;

    /// Called when unable to translate a specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address which failed to be translated.
    /// * `write` - `true` if the memory operation was a write; `false` if a read.
    ///
    /// # Returns
    ///
    /// `true` if the fault was handled; `false` otherwise.
    fn unknown_address(&self, address: &Address, write: bool) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct TestFaultHandler {
        handle_uninitialized: bool,
        handle_unknown: bool,
    }

    #[allow(deprecated)]
    impl MemoryFaultHandler for TestFaultHandler {
        fn uninitialized_read(&self, _address: &Address, _size: i32, _buf: &mut [u8], _buf_offset: i32) -> bool {
            self.handle_uninitialized
        }

        fn unknown_address(&self, _address: &Address, _write: bool) -> bool {
            self.handle_unknown
        }
    }

    #[test]
    fn uninitialized_read_handler_true() {
        let handler = TestFaultHandler {
            handle_uninitialized: true,
            handle_unknown: false,
        };

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x1000);
        let mut buf = [0u8; 8];

        let result = handler.uninitialized_read(&addr, 4, &mut buf, 0);
        assert!(result);
    }

    #[test]
    fn uninitialized_read_handler_false() {
        let handler = TestFaultHandler {
            handle_uninitialized: false,
            handle_unknown: false,
        };

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x2000);
        let mut buf = [0u8; 8];

        let result = handler.uninitialized_read(&addr, 2, &mut buf, 4);
        assert!(!result);
    }

    #[test]
    fn unknown_address_write_handled() {
        let handler = TestFaultHandler {
            handle_uninitialized: false,
            handle_unknown: true,
        };

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x3000);

        let result = handler.unknown_address(&addr, true);
        assert!(result);
    }

    #[test]
    fn unknown_address_read_handled() {
        let handler = TestFaultHandler {
            handle_uninitialized: false,
            handle_unknown: true,
        };

        let register = AddressSpace::new("Register", 32, 1, AddressSpaceType::Register, 0);
        let addr = Address::new(register, 0);

        let result = handler.unknown_address(&addr, false);
        assert!(result);
    }

    #[test]
    fn unknown_address_unhandled() {
        let handler = TestFaultHandler {
            handle_uninitialized: true,
            handle_unknown: false,
        };

        let stack = AddressSpace::new("Stack", 32, 1, AddressSpaceType::Stack, 0);
        let addr = Address::new(stack, 0);

        let result = handler.unknown_address(&addr, true);
        assert!(!result);
    }

    #[test]
    fn multiple_addresses() {
        let handler = TestFaultHandler {
            handle_uninitialized: true,
            handle_unknown: true,
        };

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr1 = Address::new(ram.clone(), 0x1000);
        let addr2 = Address::new(ram.clone(), 0x2000);
        let addr3 = Address::new(ram, 0x3000);

        let mut buf = [0u8; 16];

        let result1 = handler.uninitialized_read(&addr1, 4, &mut buf, 0);
        let result2 = handler.unknown_address(&addr2, false);
        let result3 = handler.uninitialized_read(&addr3, 8, &mut buf, 8);

        assert!(result1);
        assert!(result2);
        assert!(result3);
    }
}
