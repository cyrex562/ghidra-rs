/// Debug state machine opcodes for the DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.DebugStateMachineOpCodes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugStateMachineOpCodes;

impl DebugStateMachineOpCodes {
    /// Terminates a debug info sequence for a `code_item`.
    pub const DBG_END_SEQUENCE: i8 = 0x00;
    /// Advances the address register without emitting a positions entry.
    /// Operand: `uleb128 addr_diff`.
    pub const DBG_ADVANCE_PC: i8 = 0x01;
    /// Advances the line register without emitting a positions entry.
    /// Operand: `sleb128 line_diff`.
    pub const DBG_ADVANCE_LINE: i8 = 0x02;
    /// Introduces a local variable at the current address.
    /// Operands: `uleb128 register_num`, `uleb128p1 name_idx`, `uleb128p1 type_idx`.
    pub const DBG_START_LOCAL: i8 = 0x03;
    /// Introduces a local with a type signature at the current address.
    /// Operands: `uleb128 register_num`, `uleb128p1 name_idx`, `uleb128p1 type_idx`, `uleb128p1 sig_idx`.
    pub const DBG_START_LOCAL_EXTENDED: i8 = 0x04;
    /// Marks a currently-live local variable as out of scope at the current address.
    /// Operand: `uleb128 register_num`.
    pub const DBG_END_LOCAL: i8 = 0x05;
    /// Re-introduces a local variable at the current address.
    /// Operand: `uleb128 register_num`.
    pub const DBG_RESTART_LOCAL: i8 = 0x06;
    /// Sets the `prologue_end` state machine register.
    pub const DBG_SET_PROLOGUE_END: i8 = 0x07;
    /// Sets the `epilogue_begin` state machine register.
    pub const DBG_SET_EPILOGUE_BEGIN: i8 = 0x08;
    /// Sets the current source file name for subsequent line number entries.
    /// Operand: `uleb128p1 name_idx`.
    pub const DBG_SET_FILE: i8 = 0x09;

    /// Returns `true` if `opcode` is a special opcode (0x0a–0xff).
    ///
    /// Special opcodes advance the line and address registers, emit a position
    /// entry, and clear `prologue_end` and `epilogue_begin`.
    pub fn is_special_opcode(opcode: i8) -> bool {
        (opcode as u8) >= 0x0a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(DebugStateMachineOpCodes::DBG_END_SEQUENCE, 0x00);
        assert_eq!(DebugStateMachineOpCodes::DBG_ADVANCE_PC, 0x01);
        assert_eq!(DebugStateMachineOpCodes::DBG_ADVANCE_LINE, 0x02);
        assert_eq!(DebugStateMachineOpCodes::DBG_START_LOCAL, 0x03);
        assert_eq!(DebugStateMachineOpCodes::DBG_START_LOCAL_EXTENDED, 0x04);
        assert_eq!(DebugStateMachineOpCodes::DBG_END_LOCAL, 0x05);
        assert_eq!(DebugStateMachineOpCodes::DBG_RESTART_LOCAL, 0x06);
        assert_eq!(DebugStateMachineOpCodes::DBG_SET_PROLOGUE_END, 0x07);
        assert_eq!(DebugStateMachineOpCodes::DBG_SET_EPILOGUE_BEGIN, 0x08);
        assert_eq!(DebugStateMachineOpCodes::DBG_SET_FILE, 0x09);
    }

    #[test]
    fn opcodes_are_sequential() {
        assert_eq!(
            DebugStateMachineOpCodes::DBG_ADVANCE_PC,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE + 1
        );
        assert_eq!(
            DebugStateMachineOpCodes::DBG_ADVANCE_LINE,
            DebugStateMachineOpCodes::DBG_ADVANCE_PC + 1
        );
        assert_eq!(
            DebugStateMachineOpCodes::DBG_START_LOCAL,
            DebugStateMachineOpCodes::DBG_ADVANCE_LINE + 1
        );
        assert_eq!(
            DebugStateMachineOpCodes::DBG_SET_FILE,
            DebugStateMachineOpCodes::DBG_SET_EPILOGUE_BEGIN + 1
        );
    }

    #[test]
    fn is_special_opcode_boundary() {
        assert!(!DebugStateMachineOpCodes::is_special_opcode(0x09));
        assert!(DebugStateMachineOpCodes::is_special_opcode(0x0a));
    }

    #[test]
    fn is_special_opcode_non_special_range() {
        for v in 0x00i8..=0x09i8 {
            assert!(
                !DebugStateMachineOpCodes::is_special_opcode(v),
                "opcode {v:#04x} should not be special"
            );
        }
    }

    #[test]
    fn is_special_opcode_max_byte() {
        // 0xff as i8 is -1; as u8 it is 255, which is >= 0x0a.
        assert!(DebugStateMachineOpCodes::is_special_opcode(-1i8));
    }

    #[test]
    fn is_special_opcode_negative_values_are_special() {
        // All negative i8 values correspond to unsigned values 0x80..=0xff, all >= 0x0a.
        assert!(DebugStateMachineOpCodes::is_special_opcode(i8::MIN));
    }
}
