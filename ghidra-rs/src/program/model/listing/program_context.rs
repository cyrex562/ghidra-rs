use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressSetView};
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::seam_stubs::RegisterValue;

/// Interface to define a processor register context over the address space.
///
/// Port of `ghidra.program.model.listing.ProgramContext`.
pub trait ProgramContext {
    /// Returns true if one or more non-flowing context register fields have been defined
    /// within the base processor context register.
    fn has_non_flowing_context(&self) -> bool;

    /// Modify register value to eliminate non-flowing bits, returning a value suitable for
    /// flowing.
    fn get_flow_value(&self, value: Box<dyn RegisterValue>) -> Box<dyn RegisterValue>;

    /// Modify register value to only include non-flowing bits, returning `None` if no bits
    /// remain.
    fn get_non_flow_value(&self, value: Box<dyn RegisterValue>) -> Option<Box<dyn RegisterValue>>;

    /// Get a Register object given the name of a register, or `None` if no register has that
    /// name.
    fn get_register(&self, name: &str) -> Option<RegisterRef>;

    /// Get all the register descriptions defined for this program context.
    fn get_registers(&self) -> Vec<RegisterRef>;

    /// Returns all registers that have at least one value associated with an address.
    fn get_registers_with_values(&self) -> Vec<RegisterRef>;

    /// Returns the value assigned to a register at a given address. This method will return any
    /// default value assigned to the register at the given address if no explicit value has
    /// been set at that address. Returns `None` if no value has been assigned.
    ///
    /// # Arguments
    /// * `signed` - if true, interprets the fixed-bit-size register value as a signed value.
    fn get_value(&self, register: &Register, address: &Address, signed: bool) -> Option<i128>;

    /// Returns a register value and mask for the given register at the given address.
    fn get_register_value(
        &self,
        register: &Register,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>;

    /// Sets the register context over the given range to the given value.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] if failed to modify context across the specified
    /// range (e.g. instruction exists).
    fn set_register_value(
        &mut self,
        start: &Address,
        end: &Address,
        value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException>;

    /// Returns the (non-default) value assigned to a register at a given address, or possibly
    /// `None` if no value has been assigned.
    fn get_non_default_value(
        &self,
        register: &Register,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>;

    /// Associates a value with a register over a given address range (inclusive of `end`). Any
    /// previous values will be overwritten. A `value` of `None` will effectively clear any
    /// existing values.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] if failed to modify context across the specified
    /// range (e.g. instruction exists).
    fn set_value(
        &mut self,
        register: &Register,
        start: &Address,
        end: &Address,
        value: Option<i128>,
    ) -> Result<(), ContextChangeException>;

    /// Returns an iterator over all addresses that have an associated value for the given
    /// register. Each range returned will have the same value associated with the register for
    /// all addresses in that range.
    fn get_register_value_address_ranges(
        &self,
        register: &Register,
    ) -> Box<dyn AddressRangeIterator>;

    /// Returns an iterator over all addresses that have an associated value within the given
    /// range for the given register. Each range returned will have the same value associated
    /// with the register for all addresses in that range.
    fn get_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator>;

    /// Returns the bounding address-range containing `addr` with the same RegisterValue
    /// throughout. The range returned may be limited by other value changes associated with the
    /// register's base register.
    fn get_register_value_range_containing(&self, register: &Register, addr: &Address) -> AddressRange;

    /// Returns an iterator over all addresses that have an associated default value for the
    /// given register. Each range returned will have the same default value associated with the
    /// register for all addresses in that range.
    fn get_default_register_value_address_ranges(
        &self,
        register: &Register,
    ) -> Box<dyn AddressRangeIterator>;

    /// Returns an iterator over all addresses that have an associated default value within the
    /// given range for the given register. Each range returned will have the same default
    /// value associated with the register for all addresses in that range.
    fn get_default_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator>;

    /// Gets the registers for this context that are used for processor context states.
    fn get_context_registers(&self) -> Vec<RegisterRef>;

    /// Remove (unset) the register values for a given address range.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] if context change is not permitted over the specified
    /// range (e.g. instructions exist).
    fn remove(
        &mut self,
        start: &Address,
        end: &Address,
        register: &Register,
    ) -> Result<(), ContextChangeException>;

    /// Get an alphabetically sorted, unmodifiable list of original register names (including
    /// context registers). Names correspond to the original register name and not aliases which
    /// may be defined.
    fn get_register_names(&self) -> Vec<String>;

    /// Returns true if the given register has the value over the entire address set.
    fn has_value_over_range(&self, reg: &Register, value: i128, addr_set: &dyn AddressSetView) -> bool;

    /// Returns the default value of a register at a given address, or `None` if no default
    /// value has been assigned.
    fn get_default_value(
        &self,
        register: &Register,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>;

    /// Returns the base context register.
    fn get_base_context_register(&self) -> RegisterRef;

    /// Get the current default disassembly context to be used when initiating disassembly.
    fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue>;

    /// Set the initial disassembly context to be used when initiating disassembly.
    fn set_default_disassembly_context(&mut self, value: Box<dyn RegisterValue>);

    /// Get the disassembly context for a specified address. This context is formed from the
    /// default disassembly context and the context register value stored at the specified
    /// address. Those bits specified by the stored context value take precedence.
    fn get_disassembly_context(&self, address: &Address) -> Box<dyn RegisterValue>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, EmptyAddressRangeIterator};

    struct MockRegisterValue;
    impl RegisterValue for MockRegisterValue {}

    struct MockProgramContext;

    impl ProgramContext for MockProgramContext {
        fn has_non_flowing_context(&self) -> bool {
            false
        }

        fn get_flow_value(&self, value: Box<dyn RegisterValue>) -> Box<dyn RegisterValue> {
            value
        }

        fn get_non_flow_value(
            &self,
            _value: Box<dyn RegisterValue>,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_registers_with_values(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            Some(Box::new(MockRegisterValue))
        }

        fn set_register_value(
            &mut self,
            _start: &Address,
            _end: &Address,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn get_non_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn set_value(
            &mut self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
            _value: Option<i128>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn get_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn get_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn get_register_value_range_containing(
            &self,
            _register: &Register,
            addr: &Address,
        ) -> AddressRange {
            AddressRange::new(addr.clone(), addr.clone())
        }

        fn get_default_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn get_default_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn remove(
            &mut self,
            _start: &Address,
            _end: &Address,
            _register: &Register,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn has_value_over_range(
            &self,
            _reg: &Register,
            _value: i128,
            _addr_set: &dyn AddressSetView,
        ) -> bool {
            false
        }

        fn get_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_base_context_register(&self) -> RegisterRef {
            panic!("no base context register in mock")
        }

        fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue)
        }

        fn set_default_disassembly_context(&mut self, _value: Box<dyn RegisterValue>) {}

        fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue)
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let mut ctx: Box<dyn ProgramContext> = Box::new(MockProgramContext);

        let reg_ref = mock_register();
        let reg = reg_ref.borrow();

        assert!(!ctx.has_non_flowing_context());
        assert!(ctx.get_registers().is_empty());
        assert!(ctx.get_value(&reg, &mock_address(0x100), false).is_none());

        let addr = mock_address(0x100);
        assert!(ctx
            .set_register_value(&addr, &addr, Box::new(MockRegisterValue))
            .is_ok());
        assert!(ctx.get_register_value(&reg, &addr).is_some());
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(
            "r0",
            "General purpose register 0",
            Address::new(space, 0),
            4,
            false,
            0,
        )
    }
}
