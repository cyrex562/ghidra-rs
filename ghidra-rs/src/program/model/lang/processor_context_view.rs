use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::seam_stubs::RegisterValue;

/// Defines the interface for an object containing the state of all processor registers relative
/// to a specific address.
///
/// Port of `ghidra.program.model.lang.ProcessorContextView`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
pub trait ProcessorContextView {
    /// Returns the base processor context register, or `None` if one has not been defined.
    fn get_base_context_register(&self) -> Option<RegisterRef>;

    /// Returns all the registers for the processor as an unmodifiable list.
    fn get_registers(&self) -> Vec<RegisterRef>;

    /// Get a register given the name of a register.
    fn get_register(&self, name: &str) -> Option<RegisterRef>;

    /// Get the contents of a processor register, or `None` if no value exists.
    fn get_value(&self, register: &Register, signed: bool) -> Option<i128>;

    /// Get the [`RegisterValue`] for the given register, or `None` if no value exists.
    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValue>>;

    /// Returns true if a value is defined for the given register.
    fn has_value(&self, register: &Register) -> bool;
}

/// Formats `value` and the values of its child registers as a human-readable string.
///
/// Port of `ProcessorContextView.dumpContextValue(RegisterValue, String)`.
pub fn dump_context_value(value: &dyn RegisterValue, indent: Option<&str>) -> String {
    let mut buf = String::new();
    dump_context_value_into(value, indent, &mut buf);
    buf
}

/// Port of `ProcessorContextView.dumpContextValue(RegisterValue, String, StringBuilder)`.
pub fn dump_context_value_into(value: &dyn RegisterValue, indent: Option<&str>, buf: &mut String) {
    let indent = indent.unwrap_or("");
    let base_reg = value.get_register();
    let base_reg_size = base_reg.borrow().minimum_byte_size() * 8;
    for child_reg in base_reg.borrow().child_registers() {
        let reg = child_reg.borrow();
        let child_value = value.get_register_value(&reg);
        if child_value.has_any_value() {
            let v = child_value.get_unsigned_value_ignore_mask();
            let msb = base_reg_size - reg.least_significant_bit_in_base_register() - 1;
            let lsb = msb - reg.bit_length() + 1;
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(&format!(
                "{indent}{}({lsb},{msb}) = 0x{:x}",
                reg.name(),
                v as u64
            ));
            if reg.has_children() {
                let child_indent = format!("{indent}   ");
                dump_context_value_into(&*child_value, Some(&child_indent), buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

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
            false
        }

        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            0
        }
    }

    struct MockProcessorContextView {
        base_register: RegisterRef,
    }

    impl ProcessorContextView for MockProcessorContextView {
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
            Some(Box::new(MockRegisterValue {
                register: self.base_register.clone(),
            }))
        }

        fn has_value(&self, _register: &Register) -> bool {
            false
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
        let ctx: Box<dyn ProcessorContextView> = Box::new(MockProcessorContextView {
            base_register: mock_register(),
        });

        assert!(ctx.get_base_context_register().is_some());
        assert_eq!(ctx.get_registers().len(), 1);
        assert!(ctx.get_register("context").is_some());
        assert!(ctx.get_register("missing").is_none());
        assert!(!ctx.has_value(&ctx.get_base_context_register().unwrap().borrow()));
    }

    #[test]
    fn dump_context_value_handles_no_children() {
        let value = MockRegisterValue {
            register: mock_register(),
        };
        assert_eq!(dump_context_value(&value, None), "");
    }
}
