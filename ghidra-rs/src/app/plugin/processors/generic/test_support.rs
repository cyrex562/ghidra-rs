//! Shared test fixtures for the generic-processor operand/expression tests: a [`MemBuffer`] that
//! only knows its address, a no-op [`ProcessorContext`], and [`Position`] construction.

use std::sync::Arc;

use crate::app::plugin::processors::generic::position::Position;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};

/// A 32-bit `ram` space.
pub(crate) fn ram_space() -> Arc<AddressSpace> {
    AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
}

/// A 64-bit `const` space.
pub(crate) fn const_space() -> Arc<AddressSpace> {
    AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0)
}

/// A buffer positioned at `ram:addr_offset`. Generic-processor expressions in these tests never
/// read bytes, so the byte accessors are not implemented.
pub(crate) struct TestMemBuffer {
    pub addr_offset: i64,
}

impl MemBuffer for TestMemBuffer {
    fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
        unimplemented!("not exercised by these tests")
    }
    fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
        unimplemented!("not exercised by these tests")
    }
    fn is_big_endian(&self) -> bool {
        unimplemented!("not exercised by these tests")
    }
    fn get_address(&self) -> Address {
        Address::new(ram_space(), self.addr_offset)
    }
    fn is_initialized_memory(&self) -> bool {
        true
    }
    fn is_at_initialized_memory_address(&self) -> bool {
        true
    }
}

/// A context with no registers.
pub(crate) struct TestProcessorContext;

impl ProcessorContextView for TestProcessorContext {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        None
    }
    fn get_registers(&self) -> Vec<RegisterRef> {
        Vec::new()
    }
    fn get_register(&self, _name: &str) -> Option<RegisterRef> {
        None
    }
    fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
        None
    }
    fn get_register_value(
        &self,
        _register: &Register,
    ) -> Option<crate::program::model::lang::register_value::RegisterValue> {
        None
    }
    fn has_value(&self, _register: &Register) -> bool {
        false
    }
}

impl ProcessorContext for TestProcessorContext {
    fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
        Ok(())
    }
    fn set_register_value(
        &mut self,
        _value: crate::program::model::lang::register_value::RegisterValue,
    ) -> Result<(), ContextChangeException> {
        Ok(())
    }
    fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
        Ok(())
    }
}

/// A position whose buffer and start address are `ram:addr_offset` and whose next address is
/// `length` bytes later.
pub(crate) fn make_position(addr_offset: i64, length: i64) -> Position {
    let space = ram_space();
    Position::new(
        Box::new(TestMemBuffer { addr_offset }),
        Address::new(space.clone(), addr_offset),
        Address::new(space, addr_offset + length),
        Box::new(TestProcessorContext),
    )
}
