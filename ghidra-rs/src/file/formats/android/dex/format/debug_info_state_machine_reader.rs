use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::file::formats::android::dex::format::debug_state_machine_op_codes::DebugStateMachineOpCodes;

/// The maximum number of bytes a debug info state machine sequence is allowed to span (64k).
const MAX_SIZE: u64 = 0x10000;

/// Reads and measures a DEX debug info state machine byte sequence without interpreting it.
///
/// Mirrors `ghidra.file.formats.android.dex.format.DebugInfoStateMachineReader`.
pub(crate) struct DebugInfoStateMachineReader;

impl DebugInfoStateMachineReader {
    /// Walks the debug info state machine opcodes starting at `reader`'s current position
    /// until a `DBG_END_SEQUENCE` opcode is found, returning the number of bytes consumed.
    ///
    /// Returns `0` if `DBG_END_SEQUENCE` is not found within [`MAX_SIZE`] bytes.
    pub(crate) fn compute_length(reader: &mut BinaryReader) -> io::Result<i32> {
        let start = reader.get_pointer_index();

        while reader.get_pointer_index() - start < MAX_SIZE {
            let opcode = reader.read_next_byte()? as i8;

            match opcode {
                DebugStateMachineOpCodes::DBG_END_SEQUENCE => {
                    return Ok((reader.get_pointer_index() - start) as i32); // done!
                }
                DebugStateMachineOpCodes::DBG_ADVANCE_PC => {
                    LEB128Info::unsigned(reader)?;
                }
                DebugStateMachineOpCodes::DBG_ADVANCE_LINE => {
                    LEB128Info::unsigned(reader)?;
                }
                DebugStateMachineOpCodes::DBG_START_LOCAL => {
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // register
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // name (TODO uleb128p1)
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // type (TODO uleb128p1)
                }
                DebugStateMachineOpCodes::DBG_START_LOCAL_EXTENDED => {
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // register
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // name (TODO uleb128p1)
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // type (TODO uleb128p1)
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // signature (TODO uleb128p1)
                }
                DebugStateMachineOpCodes::DBG_END_LOCAL => {
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // register
                }
                DebugStateMachineOpCodes::DBG_RESTART_LOCAL => {
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // register
                }
                DebugStateMachineOpCodes::DBG_SET_PROLOGUE_END => {}
                DebugStateMachineOpCodes::DBG_SET_EPILOGUE_BEGIN => {}
                DebugStateMachineOpCodes::DBG_SET_FILE => {
                    LEB128Info::unsigned(reader)?.as_u_int32()?; // name (TODO uleb128p1)
                }
                _ => {}
            }
        }

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn end_sequence_only() {
        let mut r = BinaryReader::from_bytes(vec![DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8], true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 1);
    }

    #[test]
    fn advance_pc_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_ADVANCE_PC as u8,
            0x05, // uleb128 addr_diff
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn advance_line_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_ADVANCE_LINE as u8,
            0x02,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn start_local_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_START_LOCAL as u8,
            0x01, // register
            0x02, // name
            0x03, // type
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 5);
    }

    #[test]
    fn start_local_extended_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_START_LOCAL_EXTENDED as u8,
            0x01, // register
            0x02, // name
            0x03, // type
            0x04, // signature
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 6);
    }

    #[test]
    fn end_local_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_END_LOCAL as u8,
            0x01,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn restart_local_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_RESTART_LOCAL as u8,
            0x01,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn set_prologue_end_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_SET_PROLOGUE_END as u8,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 2);
    }

    #[test]
    fn set_epilogue_begin_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_SET_EPILOGUE_BEGIN as u8,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 2);
    }

    #[test]
    fn set_file_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_SET_FILE as u8,
            0x01,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn special_opcode_is_a_no_op_advance() {
        // 0x0a is the first "special" opcode; it has no operand bytes of its own.
        let data = vec![0x0au8, DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 2);
    }

    #[test]
    fn starts_from_nonzero_pointer_index() {
        let data = vec![
            0xff, // leading byte before the sequence starts
            DebugStateMachineOpCodes::DBG_ADVANCE_PC as u8,
            0x05,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(1);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn returns_zero_when_end_sequence_never_found() {
        let data = vec![DebugStateMachineOpCodes::DBG_SET_PROLOGUE_END as u8; MAX_SIZE as usize];
        let mut r = BinaryReader::from_bytes(data, true);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 0);
    }
}
