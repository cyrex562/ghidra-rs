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
    pub(crate) fn compute_length(reader: &mut dyn BinaryReader) -> io::Result<i32> {
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn end_sequence_only() {
        let mut r = MockReader::new(vec![DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8]);
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
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn set_prologue_end_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_SET_PROLOGUE_END as u8,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = MockReader::new(data);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 2);
    }

    #[test]
    fn set_epilogue_begin_then_end_sequence() {
        let data = vec![
            DebugStateMachineOpCodes::DBG_SET_EPILOGUE_BEGIN as u8,
            DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8,
        ];
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
    }

    #[test]
    fn special_opcode_is_a_no_op_advance() {
        // 0x0a is the first "special" opcode; it has no operand bytes of its own.
        let data = vec![0x0au8, DebugStateMachineOpCodes::DBG_END_SEQUENCE as u8];
        let mut r = MockReader::new(data);
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
        let mut r = MockReader::new(data);
        r.set_pointer_index(1);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 3);
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn returns_zero_when_end_sequence_never_found() {
        let data = vec![DebugStateMachineOpCodes::DBG_SET_PROLOGUE_END as u8; MAX_SIZE as usize];
        let mut r = MockReader::new(data);
        let len = DebugInfoStateMachineReader::compute_length(&mut r).unwrap();
        assert_eq!(len, 0);
    }
}
