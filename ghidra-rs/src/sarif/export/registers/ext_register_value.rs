use crate::program::model::data::isf::IsfObject;
use crate::program::model::lang::RegisterRef;

/// Represents an extended register value for SARIF export.
///
/// Mirrors `ExtRegisterValue` from Ghidra's `sarif.export.registers` package.
/// Holds a register name and its associated value string for serialization.
#[derive(Debug, Clone)]
pub struct ExtRegisterValue {
    pub name: String,
    pub value: String,
}

impl ExtRegisterValue {
    /// Creates a new `ExtRegisterValue` from a register reference and value string.
    ///
    /// Extracts the register's name and stores it along with the provided value.
    pub fn new(reg: &RegisterRef, value: impl Into<String>) -> Self {
        let name = {
            let register = reg.borrow();
            register.name().to_string()
        };

        Self {
            name,
            value: value.into(),
        }
    }
}

impl IsfObject for ExtRegisterValue {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;

    fn default_space() -> std::sync::Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    use crate::program::model::lang::Register;

    #[test]
    fn constructs_from_register_and_value() {
        let reg = Register::new("RAX", "Accumulator", default_space().address(0), 8, false, Register::TYPE_NONE);
        let ext = ExtRegisterValue::new(&reg, "0x1234");
        assert_eq!(ext.name, "RAX");
        assert_eq!(ext.value, "0x1234");
    }

    #[test]
    fn extracts_register_name() {
        let reg = Register::new("RBX", "Base", default_space().address(8), 8, false, Register::TYPE_NONE);
        let ext = ExtRegisterValue::new(&reg, "0x5678");
        assert_eq!(ext.name, "RBX");
    }

    #[test]
    fn stores_value_string() {
        let reg = Register::new("RCX", "Counter", default_space().address(16), 8, false, Register::TYPE_NONE);
        let ext = ExtRegisterValue::new(&reg, "arbitrary_value");
        assert_eq!(ext.value, "arbitrary_value");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let reg = Register::new("RDX", "Data", default_space().address(24), 8, false, Register::TYPE_NONE);
        let ext = ExtRegisterValue::new(&reg, "0xABCD");
        accepts_isf_object(&ext);
    }

    #[test]
    fn clone_preserves_fields() {
        let reg = Register::new("RSI", "Source", default_space().address(32), 8, false, Register::TYPE_NONE);
        let ext1 = ExtRegisterValue::new(&reg, "0xDEAD");
        let ext2 = ext1.clone();
        assert_eq!(ext1.name, ext2.name);
        assert_eq!(ext1.value, ext2.value);
    }
}
