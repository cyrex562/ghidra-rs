use crate::program::model::address::Address;
use crate::program::model::lang::register::Register;
use crate::program::model::lang::register_value::RegisterValue;

/// Interface for associating default register values with address ranges.
///
/// Port of `ghidra.program.model.listing.DefaultProgramContext`.
pub trait DefaultProgramContext {
    /// Associates a default value with the given register over the given range (inclusive of
    /// `end`).
    fn set_default_value(&mut self, register_value: RegisterValue, start: &Address, end: &Address);

    /// Returns the default value of a register at a given address, or `None` if no default
    /// value has been assigned.
    fn get_default_value(&self, register: &Register, address: &Address) -> Option<RegisterValue>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::RegisterRef;
    struct MockDefaultProgramContext {
        last_set: Option<(Address, Address)>,
    }

    impl DefaultProgramContext for MockDefaultProgramContext {
        fn set_default_value(
            &mut self,
            _register_value: RegisterValue,
            start: &Address,
            end: &Address,
        ) {
            self.last_set = Some((start.clone(), end.clone()));
        }

        fn get_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<RegisterValue> {
            Some(RegisterValue::new(mock_register()))
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
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

    #[test]
    fn usable_as_trait_object() {
        let mut ctx: Box<dyn DefaultProgramContext> =
            Box::new(MockDefaultProgramContext { last_set: None });

        let reg_ref = mock_register();
        let reg = reg_ref;
        let start = mock_address(0x100);
        let end = mock_address(0x200);

        ctx.set_default_value(RegisterValue::new(mock_register()), &start, &end);
        assert!(ctx.get_default_value(&reg, &start).is_some());
    }
}
