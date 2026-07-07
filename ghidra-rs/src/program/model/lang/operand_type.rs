use std::fmt;

/// Bit-flag constants and helper functions for testing operand-related flags in an integer.
pub struct OperandType;

impl OperandType {
    /// Bit set if operand refers to an address being read.
    pub const READ: u32 = 0x00000001;
    /// Bit set if operand refers to an address being written to.
    pub const WRITE: u32 = 0x00000002;
    /// Bit set if operand is an indirect reference.
    pub const INDIRECT: u32 = 0x00000004;
    /// Bit set if operand is an immediate value.
    pub const IMMEDIATE: u32 = 0x00000008;
    /// Bit set if operand depends on the instruction's address.
    pub const RELATIVE: u32 = 0x00000010;
    /// Bit set if operand is implicit.
    pub const IMPLICIT: u32 = 0x00000020;
    /// Bit set if the address referred to contains code.
    pub const CODE: u32 = 0x00000040;
    /// Bit set if the address referred to contains data.
    pub const DATA: u32 = 0x00000080;
    /// Bit set if the operand is a port.
    pub const PORT: u32 = 0x00000100;
    /// Bit set if the operand is a register.
    pub const REGISTER: u32 = 0x00000200;
    /// Bit set if the operand is a list.
    pub const LIST: u32 = 0x00000400;
    /// Bit set if the operand is a flag.
    pub const FLAG: u32 = 0x00000800;
    /// Bit set if the operand is text.
    pub const TEXT: u32 = 0x00001000;
    /// Bit set if the operand is used as an address; if not set, assume scalar.
    pub const ADDRESS: u32 = 0x00002000;
    /// Bit set if the operand is a scalar value.
    pub const SCALAR: u32 = 0x00004000;
    /// Bit set if the operand is a bit value.
    pub const BIT: u32 = 0x00008000;
    /// Bit set if the operand is a byte value.
    pub const BYTE: u32 = 0x00010000;
    /// Bit set if the operand is a 2-byte value.
    pub const WORD: u32 = 0x00020000;
    /// Bit set if the operand is an 8-byte value.
    pub const QUADWORD: u32 = 0x00040000;
    /// Bit set if the operand is a signed value.
    pub const SIGNED: u32 = 0x00080000;
    /// Bit set if the operand is a float value.
    pub const FLOAT: u32 = 0x00100000;
    /// Bit set if the operand is a co-processor value.
    pub const COP: u32 = 0x00200000;
    /// Bit set if the operand is dynamically defined given some processor context.
    /// When set, either [`SCALAR`](Self::SCALAR) or [`ADDRESS`](Self::ADDRESS) must also be set.
    pub const DYNAMIC: u32 = 0x00400000;

    /// Returns `true` if the `READ` flag is set.
    pub fn does_read(operand_type: u32) -> bool {
        operand_type & Self::READ != 0
    }

    /// Returns `true` if the `WRITE` flag is set.
    pub fn does_write(operand_type: u32) -> bool {
        operand_type & Self::WRITE != 0
    }

    /// Returns `true` if the `INDIRECT` flag is set.
    pub fn is_indirect(operand_type: u32) -> bool {
        operand_type & Self::INDIRECT != 0
    }

    /// Returns `true` if the `IMMEDIATE` flag is set.
    pub fn is_immediate(operand_type: u32) -> bool {
        operand_type & Self::IMMEDIATE != 0
    }

    /// Returns `true` if the `RELATIVE` flag is set.
    pub fn is_relative(operand_type: u32) -> bool {
        operand_type & Self::RELATIVE != 0
    }

    /// Returns `true` if the `IMPLICIT` flag is set.
    pub fn is_implicit(operand_type: u32) -> bool {
        operand_type & Self::IMPLICIT != 0
    }

    /// Returns `true` if the `CODE` flag is set.
    pub fn is_code_reference(operand_type: u32) -> bool {
        operand_type & Self::CODE != 0
    }

    /// Returns `true` if the `DATA` flag is set.
    pub fn is_data_reference(operand_type: u32) -> bool {
        operand_type & Self::DATA != 0
    }

    /// Returns `true` if the `PORT` flag is set.
    pub fn is_port(operand_type: u32) -> bool {
        operand_type & Self::PORT != 0
    }

    /// Returns `true` if the `REGISTER` flag is set.
    pub fn is_register(operand_type: u32) -> bool {
        operand_type & Self::REGISTER != 0
    }

    /// Returns `true` if the `LIST` flag is set.
    pub fn is_list(operand_type: u32) -> bool {
        operand_type & Self::LIST != 0
    }

    /// Returns `true` if the condition `FLAG` flag is set.
    pub fn is_flag(operand_type: u32) -> bool {
        operand_type & Self::FLAG != 0
    }

    /// Returns `true` if the `TEXT` flag is set.
    pub fn is_text(operand_type: u32) -> bool {
        operand_type & Self::TEXT != 0
    }

    /// Returns `true` if the `ADDRESS` flag is set.
    pub fn is_address(operand_type: u32) -> bool {
        operand_type & Self::ADDRESS != 0
    }

    /// Returns `true` if the `SCALAR` flag is set.
    pub fn is_scalar(operand_type: u32) -> bool {
        operand_type & Self::SCALAR != 0
    }

    /// Returns `true` if the `BIT` flag is set.
    pub fn is_bit(operand_type: u32) -> bool {
        operand_type & Self::BIT != 0
    }

    /// Returns `true` if the `BYTE` flag is set.
    pub fn is_byte(operand_type: u32) -> bool {
        operand_type & Self::BYTE != 0
    }

    /// Returns `true` if the `WORD` flag is set.
    pub fn is_word(operand_type: u32) -> bool {
        operand_type & Self::WORD != 0
    }

    /// Returns `true` if the `QUADWORD` flag is set.
    pub fn is_quad_word(operand_type: u32) -> bool {
        operand_type & Self::QUADWORD != 0
    }

    /// Returns `true` if the `SIGNED` flag is set.
    pub fn is_signed(operand_type: u32) -> bool {
        operand_type & Self::SIGNED != 0
    }

    /// Returns `true` if the `FLOAT` flag is set.
    pub fn is_float(operand_type: u32) -> bool {
        operand_type & Self::FLOAT != 0
    }

    /// Returns `true` if the `COP` (co-processor) flag is set.
    pub fn is_co_processor(operand_type: u32) -> bool {
        operand_type & Self::COP != 0
    }

    /// Returns `true` if the `DYNAMIC` flag is set.
    pub fn is_dynamic(operand_type: u32) -> bool {
        operand_type & Self::DYNAMIC != 0
    }

    /// Returns `true` if both the `ADDRESS` and `SCALAR` flags are set.
    pub fn is_scalar_as_address(operand_type: u32) -> bool {
        Self::is_address(operand_type) && Self::is_scalar(operand_type)
    }

    /// Returns a human-readable string representation of the active flags.
    pub fn to_string(operand_type: u32) -> String {
        let mut parts: Vec<&str> = Vec::new();

        if Self::is_address(operand_type) {
            parts.push("ADDR");
        }
        if Self::is_scalar(operand_type) {
            parts.push("SCAL");
        }
        if Self::is_port(operand_type) {
            parts.push("PORT");
        }
        if Self::is_register(operand_type) {
            parts.push("REG ");
        }
        if Self::is_list(operand_type) {
            parts.push("LIST");
        }
        if Self::is_flag(operand_type) {
            parts.push("FLAG");
        }
        if Self::is_text(operand_type) {
            parts.push("TEXT");
        }
        if Self::is_code_reference(operand_type) {
            parts.push("CODE");
        }
        if Self::is_data_reference(operand_type) {
            parts.push("DATA");
        }
        if Self::is_bit(operand_type) {
            parts.push("BIT ");
        }
        if Self::is_byte(operand_type) {
            parts.push("BYTE");
        }
        if Self::is_word(operand_type) {
            parts.push("WORD");
        }
        if Self::is_quad_word(operand_type) {
            parts.push("QUAD");
        }
        if Self::is_signed(operand_type) {
            parts.push("SIGN");
        }
        if Self::is_float(operand_type) {
            parts.push("FLT ");
        }
        if Self::is_indirect(operand_type) {
            parts.push("IND ");
        }
        if Self::is_immediate(operand_type) {
            parts.push("IMM ");
        }
        if Self::is_relative(operand_type) {
            parts.push("REL ");
        }
        if Self::is_implicit(operand_type) {
            parts.push("IMPL");
        }
        if Self::does_read(operand_type) {
            parts.push("READ");
        }
        if Self::does_write(operand_type) {
            parts.push("WRTE");
        }
        if Self::is_co_processor(operand_type) {
            parts.push("COP ");
        }
        if Self::is_dynamic(operand_type) {
            parts.push("DYN ");
        }

        parts.join(" | ")
    }
}

impl fmt::Display for OperandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OperandType")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn individual_flag_constants_are_distinct_powers_of_two() {
        let flags = [
            OperandType::READ,
            OperandType::WRITE,
            OperandType::INDIRECT,
            OperandType::IMMEDIATE,
            OperandType::RELATIVE,
            OperandType::IMPLICIT,
            OperandType::CODE,
            OperandType::DATA,
            OperandType::PORT,
            OperandType::REGISTER,
            OperandType::LIST,
            OperandType::FLAG,
            OperandType::TEXT,
            OperandType::ADDRESS,
            OperandType::SCALAR,
            OperandType::BIT,
            OperandType::BYTE,
            OperandType::WORD,
            OperandType::QUADWORD,
            OperandType::SIGNED,
            OperandType::FLOAT,
            OperandType::COP,
            OperandType::DYNAMIC,
        ];
        for &f in &flags {
            assert_eq!(f.count_ones(), 1, "flag {f:#010x} is not a single bit");
        }
        // All distinct
        let mut seen = std::collections::HashSet::new();
        for &f in &flags {
            assert!(seen.insert(f), "duplicate flag value {f:#010x}");
        }
    }

    #[test]
    fn does_read_only_when_bit_set() {
        assert!(OperandType::does_read(OperandType::READ));
        assert!(!OperandType::does_read(0));
        assert!(!OperandType::does_read(OperandType::WRITE));
    }

    #[test]
    fn does_write_only_when_bit_set() {
        assert!(OperandType::does_write(OperandType::WRITE));
        assert!(!OperandType::does_write(0));
        assert!(!OperandType::does_write(OperandType::READ));
    }

    #[test]
    fn is_indirect() {
        assert!(OperandType::is_indirect(OperandType::INDIRECT));
        assert!(!OperandType::is_indirect(OperandType::READ));
    }

    #[test]
    fn is_immediate() {
        assert!(OperandType::is_immediate(OperandType::IMMEDIATE));
        assert!(!OperandType::is_immediate(0));
    }

    #[test]
    fn is_relative() {
        assert!(OperandType::is_relative(OperandType::RELATIVE));
        assert!(!OperandType::is_relative(0));
    }

    #[test]
    fn is_implicit() {
        assert!(OperandType::is_implicit(OperandType::IMPLICIT));
        assert!(!OperandType::is_implicit(0));
    }

    #[test]
    fn is_code_reference() {
        assert!(OperandType::is_code_reference(OperandType::CODE));
        assert!(!OperandType::is_code_reference(0));
    }

    #[test]
    fn is_data_reference() {
        assert!(OperandType::is_data_reference(OperandType::DATA));
        assert!(!OperandType::is_data_reference(0));
    }

    #[test]
    fn is_port() {
        assert!(OperandType::is_port(OperandType::PORT));
        assert!(!OperandType::is_port(0));
    }

    #[test]
    fn is_register() {
        assert!(OperandType::is_register(OperandType::REGISTER));
        assert!(!OperandType::is_register(0));
    }

    #[test]
    fn is_list() {
        assert!(OperandType::is_list(OperandType::LIST));
        assert!(!OperandType::is_list(0));
    }

    #[test]
    fn is_flag() {
        assert!(OperandType::is_flag(OperandType::FLAG));
        assert!(!OperandType::is_flag(0));
    }

    #[test]
    fn is_text() {
        assert!(OperandType::is_text(OperandType::TEXT));
        assert!(!OperandType::is_text(0));
    }

    #[test]
    fn is_address() {
        assert!(OperandType::is_address(OperandType::ADDRESS));
        assert!(!OperandType::is_address(0));
    }

    #[test]
    fn is_scalar() {
        assert!(OperandType::is_scalar(OperandType::SCALAR));
        assert!(!OperandType::is_scalar(0));
    }

    #[test]
    fn is_bit() {
        assert!(OperandType::is_bit(OperandType::BIT));
        assert!(!OperandType::is_bit(0));
    }

    #[test]
    fn is_byte() {
        assert!(OperandType::is_byte(OperandType::BYTE));
        assert!(!OperandType::is_byte(0));
    }

    #[test]
    fn is_word() {
        assert!(OperandType::is_word(OperandType::WORD));
        assert!(!OperandType::is_word(0));
    }

    #[test]
    fn is_quad_word() {
        assert!(OperandType::is_quad_word(OperandType::QUADWORD));
        assert!(!OperandType::is_quad_word(0));
    }

    #[test]
    fn is_signed() {
        assert!(OperandType::is_signed(OperandType::SIGNED));
        assert!(!OperandType::is_signed(0));
    }

    #[test]
    fn is_float() {
        assert!(OperandType::is_float(OperandType::FLOAT));
        assert!(!OperandType::is_float(0));
    }

    #[test]
    fn is_co_processor() {
        assert!(OperandType::is_co_processor(OperandType::COP));
        assert!(!OperandType::is_co_processor(0));
    }

    #[test]
    fn is_dynamic() {
        assert!(OperandType::is_dynamic(OperandType::DYNAMIC));
        assert!(!OperandType::is_dynamic(0));
    }

    #[test]
    fn is_scalar_as_address_requires_both() {
        assert!(OperandType::is_scalar_as_address(
            OperandType::ADDRESS | OperandType::SCALAR
        ));
        assert!(!OperandType::is_scalar_as_address(OperandType::ADDRESS));
        assert!(!OperandType::is_scalar_as_address(OperandType::SCALAR));
        assert!(!OperandType::is_scalar_as_address(0));
    }

    #[test]
    fn to_string_empty_flags() {
        assert_eq!(OperandType::to_string(0), "");
    }

    #[test]
    fn to_string_single_flag() {
        assert_eq!(OperandType::to_string(OperandType::READ), "READ");
        assert_eq!(OperandType::to_string(OperandType::WRITE), "WRTE");
        assert_eq!(OperandType::to_string(OperandType::ADDRESS), "ADDR");
    }

    #[test]
    fn to_string_multiple_flags_ordered() {
        let flags = OperandType::READ | OperandType::WRITE;
        assert_eq!(OperandType::to_string(flags), "READ | WRTE");
    }

    #[test]
    fn to_string_address_and_scalar() {
        let flags = OperandType::ADDRESS | OperandType::SCALAR;
        assert_eq!(OperandType::to_string(flags), "ADDR | SCAL");
    }

    #[test]
    fn multiple_flags_combine_correctly() {
        let flags = OperandType::REGISTER | OperandType::READ | OperandType::CODE;
        assert!(OperandType::is_register(flags));
        assert!(OperandType::does_read(flags));
        assert!(OperandType::is_code_reference(flags));
        assert!(!OperandType::does_write(flags));
        assert!(!OperandType::is_scalar(flags));
    }
}
