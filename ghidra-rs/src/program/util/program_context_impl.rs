//! Port of `ghidra.program.util.ProgramContextImpl`.
//!
//! The in-memory processor context over an address space: an
//! [`AbstractStoredProgramContext`] whose value stores are backed by
//! [`InMemoryRangeMapAdapter`]s. It is what a language's context settings are applied to when
//! there is no program (`Disassembler`'s language-only constructor, the emulator's default
//! context).
//!
//! Java's class `extends AbstractStoredProgramContext` and only supplies
//! `createNewRangeMapAdapter`; this port composes the stored context (the crate's convention for
//! `extends`), passes that factory to its constructor, and delegates both context traits to it.
//! [`Deref`]/[`DerefMut`] expose the inherited public methods (`flushProcessorContextWriteCache`,
//! `deleteAddressRange`, ...).

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::program::database::register::in_memory_range_map_adapter::InMemoryRangeMapAdapter;
use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressSetView};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::util::abstract_stored_program_context::AbstractStoredProgramContext;
use crate::program::util::RangeMapAdapter;

/// Implementation for a processor context over the address space.
///
/// Port of `ghidra.program.util.ProgramContextImpl`; see the module docs.
pub struct ProgramContextImpl {
    stored: AbstractStoredProgramContext,
}

impl ProgramContextImpl {
    /// Construct a new program context. Port of `ProgramContextImpl(Language)`.
    pub fn new(language: Arc<dyn Language>) -> Self {
        ProgramContextImpl {
            stored: AbstractStoredProgramContext::new(
                language,
                // Port of the `createNewRangeMapAdapter(Register)` override.
                Box::new(|_base_register: &RegisterRef| {
                    Box::new(InMemoryRangeMapAdapter::new()) as Box<dyn RangeMapAdapter>
                }),
            ),
        }
    }
}

impl Deref for ProgramContextImpl {
    type Target = AbstractStoredProgramContext;

    fn deref(&self) -> &AbstractStoredProgramContext {
        &self.stored
    }
}

impl DerefMut for ProgramContextImpl {
    fn deref_mut(&mut self) -> &mut AbstractStoredProgramContext {
        &mut self.stored
    }
}

impl ProgramContext for ProgramContextImpl {
    fn has_non_flowing_context(&self) -> bool {
        self.stored.has_non_flowing_context()
    }

    fn get_flow_value(&self, value: RegisterValue) -> RegisterValue {
        self.stored.get_flow_value(value)
    }

    fn get_non_flow_value(&self, value: RegisterValue) -> Option<RegisterValue> {
        self.stored.get_non_flow_value(value)
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        ProgramContext::get_register(&self.stored, name)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        ProgramContext::get_registers(&self.stored)
    }

    fn get_registers_with_values(&self) -> Vec<RegisterRef> {
        self.stored.get_registers_with_values()
    }

    fn get_value(&self, register: &Register, address: &Address, signed: bool) -> Option<i128> {
        ProgramContext::get_value(&self.stored, register, address, signed)
    }

    fn get_register_value(&self, register: &Register, address: &Address) -> Option<RegisterValue> {
        ProgramContext::get_register_value(&self.stored, register, address)
    }

    fn set_register_value(
        &mut self,
        start: &Address,
        end: &Address,
        value: RegisterValue,
    ) -> Result<(), ContextChangeException> {
        ProgramContext::set_register_value(&mut self.stored, start, end, value)
    }

    fn get_non_default_value(&self, register: &Register, address: &Address) -> Option<RegisterValue> {
        self.stored.get_non_default_value(register, address)
    }

    fn set_value(
        &mut self,
        register: &Register,
        start: &Address,
        end: &Address,
        value: Option<i128>,
    ) -> Result<(), ContextChangeException> {
        ProgramContext::set_value(&mut self.stored, register, start, end, value)
    }

    fn get_register_value_address_ranges(&self, register: &Register) -> Box<dyn AddressRangeIterator> {
        self.stored.get_register_value_address_ranges(register)
    }

    fn get_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        self.stored.get_register_value_address_ranges_in_range(register, start, end)
    }

    fn get_register_value_range_containing(&self, register: &Register, addr: &Address) -> AddressRange {
        self.stored.get_register_value_range_containing(register, addr)
    }

    fn get_default_register_value_address_ranges(&self, register: &Register) -> Box<dyn AddressRangeIterator> {
        self.stored.get_default_register_value_address_ranges(register)
    }

    fn get_default_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        self.stored.get_default_register_value_address_ranges_in_range(register, start, end)
    }

    fn get_context_registers(&self) -> Vec<RegisterRef> {
        ProgramContext::get_context_registers(&self.stored)
    }

    fn remove(&mut self, start: &Address, end: &Address, register: &Register) -> Result<(), ContextChangeException> {
        ProgramContext::remove(&mut self.stored, start, end, register)
    }

    fn get_register_names(&self) -> Vec<String> {
        ProgramContext::get_register_names(&self.stored)
    }

    fn has_value_over_range(&self, reg: &Register, value: i128, addr_set: &dyn AddressSetView) -> bool {
        self.stored.has_value_over_range(reg, value, addr_set)
    }

    fn get_default_value(&self, register: &Register, address: &Address) -> Option<RegisterValue> {
        ProgramContext::get_default_value(&self.stored, register, address)
    }

    fn get_base_context_register(&self) -> RegisterRef {
        ProgramContext::get_base_context_register(&self.stored)
    }

    fn get_default_disassembly_context(&self) -> RegisterValue {
        ProgramContext::get_default_disassembly_context(&self.stored)
    }

    fn set_default_disassembly_context(&mut self, value: RegisterValue) {
        ProgramContext::set_default_disassembly_context(&mut self.stored, value)
    }

    fn get_disassembly_context(&self, address: &Address) -> RegisterValue {
        self.stored.get_disassembly_context(address)
    }
}

impl DefaultProgramContext for ProgramContextImpl {
    fn set_default_value(&mut self, register_value: RegisterValue, start: &Address, end: &Address) {
        self.stored.set_default_value(register_value, start, end)
    }

    fn get_default_value(&self, register: &Register, address: &Address) -> Option<RegisterValue> {
        DefaultProgramContext::get_default_value(&self.stored, register, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::register_value::RegisterValue;
    use crate::program::util::abstract_stored_program_context::test_support::{
        ram_space, test_language, test_language_with_context,
    };

    #[test]
    fn values_are_stored_in_memory_per_range() {
        let mut ctx = ProgramContextImpl::new(Arc::new(test_language()));
        let ram = ram_space();
        let eax = ProgramContext::get_register(&ctx, "eax").unwrap();

        ProgramContext::set_value(&mut ctx, &eax, &ram.address(0x1000), &ram.address(0x1fff), Some(0x1234))
            .unwrap();
        assert_eq!(ProgramContext::get_value(&ctx, &eax, &ram.address(0x1800), false), Some(0x1234));
        assert_eq!(ProgramContext::get_value(&ctx, &eax, &ram.address(0x2000), false), None);
        let range = ctx.get_register_value_range_containing(&eax, &ram.address(0x1800));
        assert_eq!((range.min_address().offset(), range.max_address().offset()), (0x1000, 0x1fff));
        assert_eq!(
            ctx.get_registers_with_values().iter().map(|r| r.name().to_string()).collect::<Vec<_>>().contains(&"eax".to_string()),
            true
        );
    }

    #[test]
    fn default_values_back_the_stored_ones() {
        let mut ctx = ProgramContextImpl::new(Arc::new(test_language()));
        let ram = ram_space();
        let eax = ProgramContext::get_register(&ctx, "eax").unwrap();

        ctx.set_default_value(
            RegisterValue::with_value(eax.clone(), 7),
            &ram.address(0),
            &ram.address(0xffff),
        );
        assert_eq!(ProgramContext::get_value(&ctx, &eax, &ram.address(0x10), false), Some(7));
        assert!(ctx.get_non_default_value(&eax, &ram.address(0x10)).is_none());
        let default = ProgramContext::get_default_value(&ctx, &eax, &ram.address(0x10)).unwrap();
        assert_eq!(default.unsigned_value_ignore_mask(), 7);
    }

    #[test]
    fn the_disassembly_context_starts_from_the_default_disassembly_context() {
        let mut ctx = ProgramContextImpl::new(Arc::new(test_language_with_context()));
        let ram = ram_space();
        let contextreg = ctx.get_base_context_register();
        assert_eq!(contextreg.name(), "contextreg");

        ctx.set_default_disassembly_context(RegisterValue::with_value(contextreg.clone(), 3));
        let at = ctx.get_disassembly_context(&ram.address(0x40));
        assert_eq!(at.unsigned_value(), Some(3));

        ProgramContext::set_register_value(
            &mut ctx,
            &ram.address(0x40),
            &ram.address(0x4f),
            RegisterValue::with_value(contextreg.clone(), 5),
        )
        .unwrap();
        let at = ctx.get_disassembly_context(&ram.address(0x40));
        assert_eq!(at.unsigned_value(), Some(5));
    }
}
