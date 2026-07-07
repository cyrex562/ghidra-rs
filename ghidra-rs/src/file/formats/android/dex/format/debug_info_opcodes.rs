/// Debug info opcodes and constants for the DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.DebugInfoOpcodes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugInfoOpcodes;

impl DebugInfoOpcodes {
    pub const DBG_END_SEQUENCE: i8 = 0x00;
    pub const DBG_ADVANCE_PC: i8 = 0x01;
    pub const DBG_ADVANCE_LINE: i8 = 0x02;
    pub const DBG_START_LOCAL: i8 = 0x03;
    pub const DBG_START_LOCAL_EXTENDED: i8 = 0x04;
    pub const DBG_END_LOCAL: i8 = 0x05;
    pub const DBG_RESTART_LOCAL: i8 = 0x06;
    pub const DBG_SET_PROLOGUE_END: i8 = 0x07;
    pub const DBG_SET_EPILOGUE_BEGIN: i8 = 0x08;
    pub const DBG_SET_FILE: i8 = 0x09;
    pub const DBG_FIRST_SPECIAL: i8 = 0x0a;
    /// Signed line base used in special opcode line delta calculation.
    pub const DBG_LINE_BASE: i8 = -4;
    pub const DBG_LINE_RANGE: i8 = 15;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_values() {
        assert_eq!(DebugInfoOpcodes::DBG_END_SEQUENCE, 0x00);
        assert_eq!(DebugInfoOpcodes::DBG_ADVANCE_PC, 0x01);
        assert_eq!(DebugInfoOpcodes::DBG_ADVANCE_LINE, 0x02);
        assert_eq!(DebugInfoOpcodes::DBG_START_LOCAL, 0x03);
        assert_eq!(DebugInfoOpcodes::DBG_START_LOCAL_EXTENDED, 0x04);
        assert_eq!(DebugInfoOpcodes::DBG_END_LOCAL, 0x05);
        assert_eq!(DebugInfoOpcodes::DBG_RESTART_LOCAL, 0x06);
        assert_eq!(DebugInfoOpcodes::DBG_SET_PROLOGUE_END, 0x07);
        assert_eq!(DebugInfoOpcodes::DBG_SET_EPILOGUE_BEGIN, 0x08);
        assert_eq!(DebugInfoOpcodes::DBG_SET_FILE, 0x09);
        assert_eq!(DebugInfoOpcodes::DBG_FIRST_SPECIAL, 0x0a);
        assert_eq!(DebugInfoOpcodes::DBG_LINE_BASE, -4i8);
        assert_eq!(DebugInfoOpcodes::DBG_LINE_RANGE, 15i8);
    }

    #[test]
    fn opcodes_are_sequential() {
        assert_eq!(DebugInfoOpcodes::DBG_ADVANCE_PC, DebugInfoOpcodes::DBG_END_SEQUENCE + 1);
        assert_eq!(DebugInfoOpcodes::DBG_ADVANCE_LINE, DebugInfoOpcodes::DBG_ADVANCE_PC + 1);
        assert_eq!(DebugInfoOpcodes::DBG_START_LOCAL, DebugInfoOpcodes::DBG_ADVANCE_LINE + 1);
        assert_eq!(DebugInfoOpcodes::DBG_FIRST_SPECIAL, DebugInfoOpcodes::DBG_SET_FILE + 1);
    }

    #[test]
    fn line_base_is_negative() {
        assert!(DebugInfoOpcodes::DBG_LINE_BASE < 0);
    }

    #[test]
    fn first_special_follows_set_file() {
        assert_eq!(
            DebugInfoOpcodes::DBG_FIRST_SPECIAL as i16,
            DebugInfoOpcodes::DBG_SET_FILE as i16 + 1
        );
    }
}
