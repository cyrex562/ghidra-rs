use crate::program::model::address::Address;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::seam_stubs::MemBuffer;

/// Port of `ghidra.app.plugin.processors.generic.Position`.
///
/// A container holding the current parsing position information including memory buffer,
/// start address, next address, and processor context state.
pub struct Position {
    buf: Box<dyn MemBuffer>,
    start_addr: Address,
    next_addr: Address,
    context: Box<dyn ProcessorContext>,
}

impl Position {
    /// Creates a new Position with the specified buffer, addresses, and context.
    pub fn new(
        buf: Box<dyn MemBuffer>,
        start: Address,
        next: Address,
        context: Box<dyn ProcessorContext>,
    ) -> Self {
        Self {
            buf,
            start_addr: start,
            next_addr: next,
            context,
        }
    }

    /// Returns a reference to the memory buffer.
    pub fn buffer(&self) -> &dyn MemBuffer {
        &*self.buf
    }

    /// Returns the start address.
    pub fn start_addr(&self) -> Address {
        self.start_addr.clone()
    }

    /// Returns the next address.
    pub fn next_addr(&self) -> Address {
        self.next_addr.clone()
    }

    /// Returns a reference to the processor context.
    pub fn context(&self) -> &dyn ProcessorContext {
        &*self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::lang::register::Register;

    /// Mock implementation of MemBuffer for testing.
    struct TestMemBuffer {
        addr_offset: i64,
    }

    impl TestMemBuffer {
        fn new(addr_offset: i64) -> Self {
            Self { addr_offset }
        }
    }

    impl MemBuffer for TestMemBuffer {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            Address::new(space, self.addr_offset)
        }

        fn is_initialized_memory(&self) -> bool {
            true
        }

        fn is_at_initialized_memory_address(&self) -> bool {
            true
        }
    }

    /// Mock implementation of ProcessorContext for testing.
    struct TestProcessorContext;

    impl ProcessorContextView for TestProcessorContext {
        fn get_base_context_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(
            &self,
            _register: &Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for TestProcessorContext {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn set_register_value(
            &mut self,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    #[test]
    fn position_stores_and_retrieves_buffer() {
        let buf = Box::new(TestMemBuffer::new(100));
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space.clone(), 100);
        let next = Address::new(space, 104);
        let context = Box::new(TestProcessorContext);

        let pos = Position::new(buf, start, next, context);

        assert_eq!(pos.buffer().get_address().offset(), 100);
    }

    #[test]
    fn position_stores_and_retrieves_addresses() {
        let buf = Box::new(TestMemBuffer::new(100));
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space.clone(), 100);
        let next = Address::new(space, 104);
        let context = Box::new(TestProcessorContext);

        let pos = Position::new(buf, start, next, context);

        assert_eq!(pos.start_addr().offset(), 100);
        assert_eq!(pos.next_addr().offset(), 104);
    }

    #[test]
    fn position_stores_and_retrieves_context() {
        let buf = Box::new(TestMemBuffer::new(100));
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space.clone(), 100);
        let next = Address::new(space, 104);
        let context = Box::new(TestProcessorContext);

        let pos = Position::new(buf, start, next, context);

        let _ = pos.context();
    }

    #[test]
    fn position_with_different_address_values() {
        let buf = Box::new(TestMemBuffer::new(0));
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space.clone(), 0);
        let next = Address::new(space, 1000);
        let context = Box::new(TestProcessorContext);

        let pos = Position::new(buf, start, next, context);

        assert_eq!(pos.start_addr().offset(), 0);
        assert_eq!(pos.next_addr().offset(), 1000);
    }
}
