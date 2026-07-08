use crate::program::model::address::Address;
use crate::program::model::lang::disassembler_context::DisassemblerContext;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::seam_stubs::RegisterValue;

/// Provides default "unsupported operation" implementations for every method inherited from
/// [`DisassemblerContext`] (and, transitively, `ProcessorContext`/`ProcessorContextView`), so
/// that an implementer only needs to override the handful of methods it actually cares about.
///
/// Port of `ghidra.program.model.lang.DisassemblerContextAdapter`.
///
/// Unlike Java's default-method inheritance, Rust does not let a subtrait's default method
/// satisfy a supertrait's required method. A type that wants the adapter's "only override what
/// you need" behavior must still implement [`DisassemblerContext`] directly, with each method
/// delegating to the matching `DisassemblerContextAdapter` method via a fully qualified call,
/// e.g. `<Self as DisassemblerContextAdapter>::get_base_context_register(self)`.
pub trait DisassemblerContextAdapter: DisassemblerContext {
    /// Port of `getBaseContextRegister()`; unsupported unless overridden.
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        unimplemented!("DisassemblerContextAdapter::get_base_context_register")
    }

    /// Port of `getRegisters()`; unsupported unless overridden.
    fn get_registers(&self) -> Vec<RegisterRef> {
        unimplemented!("DisassemblerContextAdapter::get_registers")
    }

    /// Port of `getRegister(String)`; unsupported unless overridden.
    fn get_register(&self, _name: &str) -> Option<RegisterRef> {
        unimplemented!("DisassemblerContextAdapter::get_register")
    }

    /// Port of `getValue(Register, boolean)`; unsupported unless overridden.
    fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
        unimplemented!("DisassemblerContextAdapter::get_value")
    }

    /// Port of `getRegisterValue(Register)`; unsupported unless overridden.
    fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
        unimplemented!("DisassemblerContextAdapter::get_register_value")
    }

    /// Port of `hasValue(Register)`; unsupported unless overridden.
    fn has_value(&self, _register: &Register) -> bool {
        unimplemented!("DisassemblerContextAdapter::has_value")
    }

    /// Port of `setValue(Register, BigInteger)`; unsupported unless overridden.
    ///
    /// # Errors
    /// Never returns `Ok`; panics unless overridden.
    fn set_value(
        &mut self,
        _register: &Register,
        _value: i128,
    ) -> Result<(), ContextChangeException> {
        unimplemented!("DisassemblerContextAdapter::set_value")
    }

    /// Port of `setRegisterValue(RegisterValue)`; unsupported unless overridden.
    ///
    /// # Errors
    /// Never returns `Ok`; panics unless overridden.
    fn set_register_value(
        &mut self,
        _value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException> {
        unimplemented!("DisassemblerContextAdapter::set_register_value")
    }

    /// Port of `clearRegister(Register)`; unsupported unless overridden.
    ///
    /// # Errors
    /// Never returns `Ok`; panics unless overridden.
    fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
        unimplemented!("DisassemblerContextAdapter::clear_register")
    }

    /// Port of `setFutureRegisterValue(Address, RegisterValue)`; unsupported unless overridden.
    fn set_future_register_value(&mut self, _address: Address, _value: Box<dyn RegisterValue>) {
        unimplemented!("DisassemblerContextAdapter::set_future_register_value")
    }

    /// Port of `setFutureRegisterValue(Address, Address, RegisterValue)`; unsupported unless
    /// overridden.
    fn set_future_register_value_for_flow(
        &mut self,
        _from_addr: Address,
        _to_addr: Address,
        _value: Box<dyn RegisterValue>,
    ) {
        unimplemented!("DisassemblerContextAdapter::set_future_register_value_for_flow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::processor_context_view::ProcessorContextView;

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

    /// Minimal `DisassemblerContext` whose only job is to prove
    /// `DisassemblerContextAdapter` compiles as a supertrait and is object-safe. It never calls
    /// its own `DisassemblerContext` methods from the adapter's defaults (Rust can't wire that up
    /// automatically the way Java's default-method inheritance does).
    struct MockContext {
        base_register: RegisterRef,
    }

    impl ProcessorContextView for MockContext {
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

        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockContext {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn set_register_value(
            &mut self,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl DisassemblerContext for MockContext {
        fn set_future_register_value(&mut self, _address: Address, _value: Box<dyn RegisterValue>) {
        }

        fn set_future_register_value_for_flow(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _value: Box<dyn RegisterValue>,
        ) {
        }
    }

    /// Overrides only `get_registers`, leaving every other `DisassemblerContextAdapter` method on
    /// the default "unsupported" implementation -- mirroring how a Java class extending
    /// `DisassemblerContextAdapter` would override just the methods it cares about.
    impl DisassemblerContextAdapter for MockContext {
        fn get_registers(&self) -> Vec<RegisterRef> {
            vec![self.base_register.clone()]
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
        let ctx: Box<dyn DisassemblerContextAdapter> = Box::new(MockContext {
            base_register: mock_register(),
        });

        assert_eq!(
            DisassemblerContextAdapter::get_registers(ctx.as_ref()).len(),
            1
        );
    }

    #[test]
    #[should_panic(expected = "DisassemblerContextAdapter::get_register")]
    fn unoverridden_methods_are_unsupported() {
        let ctx: Box<dyn DisassemblerContextAdapter> = Box::new(MockContext {
            base_register: mock_register(),
        });

        let _ = DisassemblerContextAdapter::get_register(ctx.as_ref(), "context");
    }
}
