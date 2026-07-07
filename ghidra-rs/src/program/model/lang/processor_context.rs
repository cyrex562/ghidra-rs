use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::Register;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::seam_stubs::RegisterValue;

/// Defines the interface for an object containing the state of all processor registers
/// relative to a specific address.
///
/// Port of `ghidra.program.model.lang.ProcessorContext`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
pub trait ProcessorContext: ProcessorContextView {
    /// Sets the value for a register. Unlike Java's nullable `BigInteger`, `value` is not
    /// optional here -- the Java source explicitly disallows a `null` value for this method.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] on an illegal attempt to change context.
    fn set_value(
        &mut self,
        register: &Register,
        value: i128,
    ) -> Result<(), ContextChangeException>;

    /// Sets the specified register value within this context.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] on an illegal attempt to change context.
    fn set_register_value(
        &mut self,
        value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException>;

    /// Clears the register within this context.
    ///
    /// # Errors
    /// Returns [`ContextChangeException`] on an illegal attempt to change context.
    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::RegisterRef;
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

    struct MockProcessorContext {
        base_register: RegisterRef,
        values: RefCell<HashMap<String, i128>>,
    }

    impl ProcessorContextView for MockProcessorContext {
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

    impl ProcessorContext for MockProcessorContext {
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

    #[test]
    fn usable_as_trait_object() {
        let base_register = mock_register();
        let mut ctx: Box<dyn ProcessorContext> = Box::new(MockProcessorContext {
            base_register: base_register.clone(),
            values: RefCell::new(HashMap::new()),
        });

        let reg = base_register.borrow();
        assert!(!ctx.has_value(&reg));

        ctx.set_value(&reg, 42).unwrap();
        assert!(ctx.has_value(&reg));
        assert_eq!(ctx.get_value(&reg, false), Some(42));

        ctx.clear_register(&reg).unwrap();
        assert!(!ctx.has_value(&reg));

        ctx.set_register_value(Box::new(MockRegisterValue {
            register: base_register.clone(),
        }))
        .unwrap();
        assert!(ctx.has_value(&reg));
    }
}
