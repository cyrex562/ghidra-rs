use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::{ImageRuntimeFunctionEntryX86, NTHeader, PEx64UnwindInfoDataType};
use crate::program::model::data::data_type::DataType;

/// PE x86-64 exception unwind opcodes (`UNWIND_CODE.UnwindOp`).
///
/// Mirrors `ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnwindCodeOpcode {
    UwopPushNonvol,
    UwopAllocLarge,
    UwopAllocSmall,
    UwopSetFpreg,
    UwopSaveNonvol,
    UwopSaveNonvolFar,
    UwopSaveXmm,
    UwopSaveXmmFar,
    UwopSaveXmm128,
    UwopSaveXmm128Far,
    UwopPushMachframe,
}

impl UnwindCodeOpcode {
    /// All variants in declaration order, mirroring the Java `values()` array.
    pub const ALL: &'static [UnwindCodeOpcode] = &[
        UnwindCodeOpcode::UwopPushNonvol,
        UnwindCodeOpcode::UwopAllocLarge,
        UnwindCodeOpcode::UwopAllocSmall,
        UnwindCodeOpcode::UwopSetFpreg,
        UnwindCodeOpcode::UwopSaveNonvol,
        UnwindCodeOpcode::UwopSaveNonvolFar,
        UnwindCodeOpcode::UwopSaveXmm,
        UnwindCodeOpcode::UwopSaveXmmFar,
        UnwindCodeOpcode::UwopSaveXmm128,
        UnwindCodeOpcode::UwopSaveXmm128Far,
        UnwindCodeOpcode::UwopPushMachframe,
    ];

    /// Returns the numeric id associated with this opcode.
    pub fn id(self) -> u8 {
        match self {
            UnwindCodeOpcode::UwopPushNonvol => 0x00,
            UnwindCodeOpcode::UwopAllocLarge => 0x01,
            UnwindCodeOpcode::UwopAllocSmall => 0x02,
            UnwindCodeOpcode::UwopSetFpreg => 0x03,
            UnwindCodeOpcode::UwopSaveNonvol => 0x04,
            UnwindCodeOpcode::UwopSaveNonvolFar => 0x05,
            UnwindCodeOpcode::UwopSaveXmm => 0x06,
            UnwindCodeOpcode::UwopSaveXmmFar => 0x07,
            UnwindCodeOpcode::UwopSaveXmm128 => 0x08,
            UnwindCodeOpcode::UwopSaveXmm128Far => 0x09,
            UnwindCodeOpcode::UwopPushMachframe => 0x0A,
        }
    }

    /// Returns the [`UnwindCodeOpcode`] for the given numeric id, or `None` if it does not
    /// correspond to a known opcode, mirroring the Java `fromInt(int)` method (which returns
    /// `null`).
    pub fn from_id(id: u8) -> Option<UnwindCodeOpcode> {
        UnwindCodeOpcode::ALL.iter().copied().find(|op| op.id() == id)
    }
}

/// A single `UNWIND_CODE` entry.
///
/// Mirrors `ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE`.
#[derive(Debug, Clone)]
pub struct UnwindCode {
    pub offset_in_prolog: u8,
    /// `None` when the encoded opcode id does not correspond to a known [`UnwindCodeOpcode`],
    /// mirroring the Java field being left `null` by `UNWIND_CODE_OPCODE.fromInt`.
    pub op_code: Option<UnwindCodeOpcode>,
    /// Encoding varies based upon `op_code`.
    pub op_info: u8,
}

/// PE x86-64 exception `UNWIND_INFO` structure, found via the `.pdata` section's runtime
/// function table entries.
///
/// Mirrors `ghidra.app.util.bin.format.pe.PEx64UnwindInfo`.
#[derive(Debug, Clone)]
pub struct PEx64UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u32,
    pub count_of_unwind_codes: u32,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub unwind_codes: Vec<UnwindCode>,
    pub exception_handler_function: i32,
    pub unwind_handler_chain_info: Option<ImageRuntimeFunctionEntryX86>,
    pub start_offset: i64,
}

impl PEx64UnwindInfo {
    pub const UNW_FLAG_NHANDLER: u8 = 0x0;
    pub const UNW_FLAG_EHANDLER: u8 = 0x1;
    pub const UNW_FLAG_UHANDLER: u8 = 0x2;
    pub const UNW_FLAG_CHAININFO: u8 = 0x4;

    const UNWIND_INFO_VERSION_MASK: u8 = 0x07;
    const UNWIND_INFO_FLAGS_MASK: u8 = 0x1F;
    const UNWIND_INFO_FLAGS_SHIFT: u8 = 0x03;
    const UNWIND_INFO_FRAME_REGISTER_MASK: u8 = 0x0F;
    const UNWIND_INFO_FRAME_OFFSET_SHIFT: u8 = 0x04;
    const UNWIND_INFO_OPCODE_MASK: u8 = 0x0F;
    const UNWIND_INFO_OPCODE_INFO_SHIFT: u8 = 0x04;
    const UNWIND_INFO_OPCODE_INFO_MASK: u8 = 0x0F;

    /// Port of `PEx64UnwindInfo(long offset)`.
    pub fn new(offset: i64) -> Self {
        PEx64UnwindInfo {
            version: 0,
            flags: 0,
            size_of_prolog: 0,
            count_of_unwind_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            unwind_codes: Vec::new(),
            exception_handler_function: 0,
            unwind_handler_chain_info: None,
            start_offset: offset,
        }
    }

    pub fn has_exception_handler(&self) -> bool {
        (self.flags & Self::UNW_FLAG_EHANDLER) == Self::UNW_FLAG_EHANDLER
    }

    pub fn has_unwind_handler(&self) -> bool {
        (self.flags & Self::UNW_FLAG_UHANDLER) == Self::UNW_FLAG_UHANDLER
    }

    pub fn has_chained_unwind_info(&self) -> bool {
        (self.flags & Self::UNW_FLAG_CHAININFO) == Self::UNW_FLAG_CHAININFO
    }

    /// Reads a `PEx64UnwindInfo` at the given RVA `offset`, following the chained-unwind-info
    /// link recursively.
    ///
    /// Port of `PEx64UnwindInfo.readUnwindInfo(BinaryReader, long, NTHeader)`.
    pub fn read_unwind_info(
        reader: &mut dyn BinaryReader,
        offset: i64,
        nt_header: &dyn NTHeader,
    ) -> io::Result<PEx64UnwindInfo> {
        let orig_index = reader.get_pointer_index();

        let pointer = nt_header.rva_to_pointer_long(offset);
        let mut unwind_info = PEx64UnwindInfo::new(pointer);

        if pointer < 0 {
            return Ok(unwind_info);
        }

        reader.set_pointer_index(pointer as u64);
        let mut split_byte = reader.read_next_byte()?;
        unwind_info.version = split_byte & Self::UNWIND_INFO_VERSION_MASK;
        unwind_info.flags =
            (split_byte >> Self::UNWIND_INFO_FLAGS_SHIFT) & Self::UNWIND_INFO_FLAGS_MASK;

        unwind_info.size_of_prolog = reader.read_next_unsigned_byte()? as u32;
        unwind_info.count_of_unwind_codes = reader.read_next_unsigned_byte()? as u32;

        split_byte = reader.read_next_byte()?;
        unwind_info.frame_register = split_byte & Self::UNWIND_INFO_FRAME_REGISTER_MASK;
        unwind_info.frame_offset = split_byte >> Self::UNWIND_INFO_FRAME_OFFSET_SHIFT;

        let mut unwind_codes = Vec::with_capacity(unwind_info.count_of_unwind_codes as usize);
        for _ in 0..unwind_info.count_of_unwind_codes {
            let offset_in_prolog = reader.read_next_byte()?;

            let op_code_data = reader.read_next_unsigned_byte()? as u32;
            let op_code =
                UnwindCodeOpcode::from_id((op_code_data & Self::UNWIND_INFO_OPCODE_MASK as u32) as u8);
            let op_info = ((op_code_data >> Self::UNWIND_INFO_OPCODE_INFO_SHIFT)
                & Self::UNWIND_INFO_OPCODE_INFO_MASK as u32) as u8;

            unwind_codes.push(UnwindCode {
                offset_in_prolog,
                op_code,
                op_info,
            });
        }
        unwind_info.unwind_codes = unwind_codes;

        // You can have an exception handler or you can have chained exception handling info only.
        if unwind_info.has_exception_handler() || unwind_info.has_unwind_handler() {
            unwind_info.exception_handler_function = reader.read_next_int()?;
        } else if unwind_info.has_chained_unwind_info() {
            let begin_address = reader.read_next_unsigned_int()?;
            let end_address = reader.read_next_unsigned_int()?;
            let unwind_info_address_or_data = reader.read_next_unsigned_int()?;

            // Follow the chain to the referenced UNWIND_INFO structure until we get to the end.
            let info = PEx64UnwindInfo::read_unwind_info(
                reader,
                unwind_info_address_or_data as i64,
                nt_header,
            )?;
            unwind_info.unwind_handler_chain_info = Some(ImageRuntimeFunctionEntryX86::new(
                begin_address,
                end_address,
                unwind_info_address_or_data,
                info,
            ));
        }

        reader.set_pointer_index(orig_index);

        Ok(unwind_info)
    }
}

impl StructConverter for PEx64UnwindInfo {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(PEx64UnwindInfoDataType::instance()))
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct FixtureReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl FixtureReader {
        fn new(data: Vec<u8>) -> Self {
            FixtureReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for FixtureReader {
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
            Box::new(FixtureReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    struct FixtureNtHeader;

    impl NTHeader for FixtureNtHeader {
        fn get_name(&self) -> String {
            String::new()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> Box<dyn crate::format::seam_stubs::FileHeader> {
            unimplemented!()
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
            unimplemented!()
        }
        fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            rva
        }
        // Identity mapping: RVA == pointer, mirroring an unrelocated single-section image.
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            if rva < 0 {
                -1
            } else {
                rva
            }
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, _rva: i64) -> bool {
            true
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    #[test]
    fn flag_predicates_match_java_bitmask_semantics() {
        let mut info = PEx64UnwindInfo::new(0);
        info.flags = PEx64UnwindInfo::UNW_FLAG_EHANDLER;
        assert!(info.has_exception_handler());
        assert!(!info.has_unwind_handler());
        assert!(!info.has_chained_unwind_info());

        info.flags = PEx64UnwindInfo::UNW_FLAG_CHAININFO;
        assert!(!info.has_exception_handler());
        assert!(info.has_chained_unwind_info());
    }

    #[test]
    fn unwind_code_opcode_from_id_matches_java_from_int() {
        assert_eq!(
            UnwindCodeOpcode::from_id(0x03),
            Some(UnwindCodeOpcode::UwopSetFpreg)
        );
        assert_eq!(
            UnwindCodeOpcode::from_id(0x0A),
            Some(UnwindCodeOpcode::UwopPushMachframe)
        );
        // Java's fromInt returns null for unrecognized ids.
        assert_eq!(UnwindCodeOpcode::from_id(0x0B), None);
    }

    #[test]
    fn reads_simple_unwind_info_with_exception_handler() {
        // version=1, flags=UNW_FLAG_EHANDLER (0x1) packed into one byte: (flags<<3)|version
        let split_byte = (PEx64UnwindInfo::UNW_FLAG_EHANDLER << 3) | 1;
        let size_of_prolog: u8 = 0x10;
        let count_of_unwind_codes: u8 = 1;
        // frameRegister=0, frameOffset=0
        let frame_byte: u8 = 0x00;
        // One UNWIND_CODE: offsetInProlog=0x05, opCode=UWOP_PUSH_NONVOL(0x00), opInfo=0x3 (nibble)
        let code_offset_in_prolog: u8 = 0x05;
        let code_op_byte: u8 = (0x3 << 4) | 0x00;
        let exception_handler_function: i32 = 0x1234_5678;

        let mut bytes = vec![
            split_byte,
            size_of_prolog,
            count_of_unwind_codes,
            frame_byte,
            code_offset_in_prolog,
            code_op_byte,
        ];
        bytes.extend_from_slice(&exception_handler_function.to_le_bytes());

        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader;

        let info = PEx64UnwindInfo::read_unwind_info(&mut reader, 0, &nt_header).unwrap();

        assert_eq!(info.version, 1);
        assert_eq!(info.flags, PEx64UnwindInfo::UNW_FLAG_EHANDLER);
        assert_eq!(info.size_of_prolog, 0x10);
        assert_eq!(info.count_of_unwind_codes, 1);
        assert_eq!(info.frame_register, 0);
        assert_eq!(info.frame_offset, 0);
        assert_eq!(info.unwind_codes.len(), 1);
        assert_eq!(info.unwind_codes[0].offset_in_prolog, 0x05);
        assert_eq!(
            info.unwind_codes[0].op_code,
            Some(UnwindCodeOpcode::UwopPushNonvol)
        );
        assert_eq!(info.unwind_codes[0].op_info, 0x3);
        assert_eq!(info.exception_handler_function, exception_handler_function);
        assert!(info.unwind_handler_chain_info.is_none());
        // Reader position must be restored to where it started.
        assert_eq!(reader.get_pointer_index(), 0);
    }

    #[test]
    fn invalid_rva_returns_early_with_negative_start_offset() {
        let mut reader = FixtureReader::new(vec![0u8; 16]);
        struct AlwaysInvalidNtHeader;
        impl NTHeader for AlwaysInvalidNtHeader {
            fn get_name(&self) -> String {
                String::new()
            }
            fn is_rva_resoltion_section_aligned(&self) -> bool {
                true
            }
            fn get_file_header(&self) -> Box<dyn crate::format::seam_stubs::FileHeader> {
                unimplemented!()
            }
            fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
                unimplemented!()
            }
            fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
                unimplemented!()
            }
            fn rva_to_pointer(&self, rva: i32) -> i32 {
                rva
            }
            fn rva_to_pointer_long(&self, _rva: i64) -> i64 {
                -1
            }
            fn check_pointer(&self, _ptr: i64) -> bool {
                false
            }
            fn check_rva(&self, _rva: i64) -> bool {
                false
            }
            fn va_to_pointer(&self, va: i32) -> i32 {
                va
            }
        }

        let info =
            PEx64UnwindInfo::read_unwind_info(&mut reader, 0x100, &AlwaysInvalidNtHeader).unwrap();

        assert_eq!(info.start_offset, -1);
        assert_eq!(info.count_of_unwind_codes, 0);
        assert!(info.unwind_codes.is_empty());
        // Reader must not have consumed any bytes.
        assert_eq!(reader.get_pointer_index(), 0);
    }

    #[test]
    fn to_data_type_returns_ok() {
        let info = PEx64UnwindInfo::new(0);
        assert!(info.to_data_type().is_ok());
    }
}
