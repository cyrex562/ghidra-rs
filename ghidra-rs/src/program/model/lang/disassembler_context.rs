use crate::program::model::address::Address;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::seam_stubs::RegisterValue;

/// Extends [`ProcessorContext`] with the ability to save register values that will take effect
/// at a future address, for use during disassembly flow analysis.
///
/// Port of `ghidra.program.model.lang.DisassemblerContext`.
pub trait DisassemblerContext: ProcessorContext {
    /// Combines `value` with any previously saved future register value at `address`, or any
    /// value stored in the program if there is no previously saved future value. Use this method
    /// when multiple flows to the same address don't matter or the flowing-from address is
    /// unknown.
    ///
    /// When `value` has conflicting bits with the previously saved value, `value` takes
    /// precedence.
    ///
    /// If the register value is the value for the processor context register and a previously
    /// saved value does not exist, the user-saved values in the stored context of the program
    /// will be used as the existing value.
    fn set_future_register_value(&mut self, address: Address, value: Box<dyn RegisterValue>);

    /// Combines `value` with any previously saved future register value at `from_addr`/
    /// `to_addr`, or any value stored in the program if there is no previously saved future
    /// value.
    ///
    /// When `value` has conflicting bits with the previously saved value, `value` takes
    /// precedence.
    ///
    /// If the register value is the value for the processor context register and a previously
    /// saved value does not exist, the user-saved values in the stored context of the program
    /// will be used as the existing value.
    ///
    /// Port of the `setFutureRegisterValue(Address, Address, RegisterValue)` overload.
    fn set_future_register_value_for_flow(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        value: Box<dyn RegisterValue>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockRegisterValue {
        register: RegisterRef,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }

        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
            })
        }

        fn has_any_value(&self) -> bool {
            true
        }

        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            0
        }
    }

    struct MockDisassemblerContext {
        base_register: RegisterRef,
        values: RefCell<HashMap<String, i128>>,
        future_values: RefCell<Vec<(Address, Option<Address>)>>,
    }

    impl ProcessorContextView for MockDisassemblerContext {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            Some(self.base_register.clone())
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            vec![self.base_register.clone()]
        }

        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            if self.base_register.borrow().name() == name {
                Some(self.base_register.clone())
            } else {
                None
            }
        }

        fn get_value(&self, register: &Register, _signed: bool) -> Option<i128> {
            self.values.borrow().get(register.name()).copied()
        }

        fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValue>> {
            if self.has_value(register) {
                Some(Box::new(MockRegisterValue {
                    register: self.base_register.clone(),
                }))
            } else {
                None
            }
        }

        fn has_value(&self, register: &Register) -> bool {
            self.values.borrow().contains_key(register.name())
        }
    }

    impl ProcessorContext for MockDisassemblerContext {
        fn set_value(
            &mut self,
            register: &Register,
            value: i128,
        ) -> Result<(), ContextChangeException> {
            self.values
                .borrow_mut()
                .insert(register.name().to_string(), value);
            Ok(())
        }

        fn set_register_value(
            &mut self,
            value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            let register = value.get_register();
            let name = register.borrow().name().to_string();
            self.values.borrow_mut().insert(name, 1);
            Ok(())
        }

        fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
            self.values.borrow_mut().remove(register.name());
            Ok(())
        }
    }

    impl DisassemblerContext for MockDisassemblerContext {
        fn set_future_register_value(&mut self, address: Address, _value: Box<dyn RegisterValue>) {
            self.future_values.borrow_mut().push((address, None));
        }

        fn set_future_register_value_for_flow(
            &mut self,
            from_addr: Address,
            to_addr: Address,
            _value: Box<dyn RegisterValue>,
        ) {
            self.future_values
                .borrow_mut()
                .push((from_addr, Some(to_addr)));
        }
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(
            "context",
            "Processor context register",
            Address::new(space, 0),
            4,
            false,
            0,
        )
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 8, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let base_register = mock_register();
        let mut ctx: Box<dyn DisassemblerContext> = Box::new(MockDisassemblerContext {
            base_register: base_register.clone(),
            values: RefCell::new(HashMap::new()),
            future_values: RefCell::new(Vec::new()),
        });

        ctx.set_future_register_value(
            mock_address(0x100),
            Box::new(MockRegisterValue {
                register: base_register.clone(),
            }),
        );
        ctx.set_future_register_value_for_flow(
            mock_address(0x200),
            mock_address(0x204),
            Box::new(MockRegisterValue {
                register: base_register,
            }),
        );

        assert_eq!(ctx.get_registers().len(), 1);
    }
}
