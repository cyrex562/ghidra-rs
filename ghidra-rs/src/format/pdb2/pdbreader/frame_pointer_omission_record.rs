use std::fmt;

use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::pdb_reader_utils::{dump_head, dump_tail};

/// The frame type of a [`FramePointerOmissionRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// FPO frame.
    Fpo,
    /// Trap frame.
    Trap,
    /// TSS frame.
    Tss,
    /// Non-FPO frame.
    NonFpo,
}

impl FrameType {
    /// Returns the display label for this frame type.
    pub fn label(self) -> &'static str {
        match self {
            FrameType::Fpo => "fpo",
            FrameType::Trap => "trap",
            FrameType::Tss => "tss",
            FrameType::NonFpo => "std",
        }
    }

    /// Returns the numeric value for this frame type.
    pub fn value(self) -> i32 {
        match self {
            FrameType::Fpo => 0,
            FrameType::Trap => 1,
            FrameType::Tss => 2,
            FrameType::NonFpo => 3,
        }
    }

    /// Returns the [`FrameType`] corresponding to `val`, or [`FrameType::Fpo`] if `val` does
    /// not correspond to a known frame type.
    pub fn from_value(val: i32) -> Self {
        match val {
            0 => FrameType::Fpo,
            1 => FrameType::Trap,
            2 => FrameType::Tss,
            3 => FrameType::NonFpo,
            _ => FrameType::Fpo,
        }
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Frame Pointer Omission Data, according to API, represents stack frame layout on x86 when
/// frame pointer omission optimization is used. This structure is used to locate the call
/// frame.
///
/// See [MSFT Documentation](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_fpo_data),
/// which specifies:
/// ```text
///   typedef struct _FPO_DATA {
///     DWORD ulOffStart;
///     DWORD cbProcSize;
///     DWORD cdwLocals;
///     WORD  cdwParams;
///     WORD  cbProlog : 8;
///     WORD  cbRegs : 3;
///     WORD  fHasSEH : 1;
///     WORD  fUseBP : 1;
///     WORD  reserved : 1;
///     WORD  cbFrame : 2;
///   } FPO_DATA, *PFPO_DATA;
///
///   where...
///   ulOffStart = The offset of the first byte of the function code.
///   cbProcSize = The number of bytes in the function.
///   cdwLocals = the number of local variables.
///   cdwParams = The size of the parameters, in DWORDs.
///   cbProlog = The number of bytes in the function prolog code.
///   cbRegs = The number of registers saved.
///   fHasSEH = A variable that indicates whether the function used structured exeception handling.
///   fUseBP = A variable that indicates whether the EBP register has been allocated.
///   reserved = Reserved for future use.
///   cbFrame = A variable that indicates the frame type, where...
///     FRAME_FPO (0) = FPO frame
///     FRAME_TRAP (1) = Trap frame
///     FRAME_TSS (2) = TSS frame
///     FRAME_NONFPO (3) = non-FPO frame
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePointerOmissionRecord {
    first_function_byte_offset: u32,
    num_function_bytes: u32,
    num_local_variables: u32,
    size_of_parameters_in_dwords: u16,
    num_function_prolog_bytes: u8,
    has_structured_exception_handling: bool,
    ebp_allocated_and_used: bool,
    reserved: u8,
    frame_type: FrameType,
}

impl FramePointerOmissionRecord {
    /// Parses a `FramePointerOmissionRecord` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the record.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        if reader.num_remaining() < 16 {
            return Err(PdbException::new("Not enough data for FramePointerOmissionRecord"));
        }
        let first_function_byte_offset = reader.parse_unsigned_int_val()?;
        let num_function_bytes = reader.parse_unsigned_int_val()?;
        let num_local_variables = reader.parse_unsigned_int_val()?;
        let size_of_parameters_in_dwords = reader.parse_unsigned_short_val()?;
        let mut data = reader.parse_unsigned_short_val()?;
        let num_function_prolog_bytes = (data & 0xff) as u8;
        data >>= 8;
        let has_structured_exception_handling = (data & 0x01) == 0x01;
        data >>= 1;
        let ebp_allocated_and_used = (data & 0x01) == 0x01;
        data >>= 1;
        let reserved = (data & 0x01) as u8;
        data >>= 1;
        let frame_type = FrameType::from_value((data & 0x03) as i32);

        Ok(FramePointerOmissionRecord {
            first_function_byte_offset,
            num_function_bytes,
            num_local_variables,
            size_of_parameters_in_dwords,
            num_function_prolog_bytes,
            has_structured_exception_handling,
            ebp_allocated_and_used,
            reserved,
            frame_type,
        })
    }

    /// Returns the offset of the first byte of the function.
    pub fn first_function_byte_offset(&self) -> u32 {
        self.first_function_byte_offset
    }

    /// Returns the number of bytes in the function.
    pub fn number_of_function_bytes(&self) -> u32 {
        self.num_function_bytes
    }

    /// Returns the number of local variables.
    pub fn number_local_variables(&self) -> u32 {
        self.num_local_variables
    }

    /// Returns the size of the parameters as the number of DWORDs.
    pub fn size_of_parameters_in_dwords(&self) -> u16 {
        self.size_of_parameters_in_dwords
    }

    /// Returns the number of bytes in the function prolog.
    pub fn number_function_prolog_bytes(&self) -> u8 {
        self.num_function_prolog_bytes
    }

    /// Returns whether the function has structured exception handling.
    pub fn has_structured_exception_handling(&self) -> bool {
        self.has_structured_exception_handling
    }

    /// Returns whether the EBP is allocated/used.
    pub fn ebp_allocated_and_used(&self) -> bool {
        self.ebp_allocated_and_used
    }

    /// Returns the value of the reserved 1-bit field.
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Returns the [`FrameType`] being specified.
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// Dumps the `FramePointerOmissionRecord`. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    pub(crate) fn dump(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        dump_head(writer, "FramePointerOmissionRecord")?;
        write!(writer, "firstFunctionByteOffset: 0X{:08X}\n", self.first_function_byte_offset)?;
        write!(writer, "numFunctionBytes: 0X{:08X}\n", self.num_function_bytes)?;
        write!(writer, "numLocalVariables: 0X{:08X}\n", self.num_local_variables)?;
        write!(
            writer,
            "sizeOfParametersInDwords: 0X{:08X}\n",
            self.size_of_parameters_in_dwords
        )?;
        write!(writer, "numFunctionPrologBytes: 0X{:04X}\n", self.num_function_prolog_bytes)?;
        write!(
            writer,
            "hasStructuredExceptionHandling: {}\n",
            self.has_structured_exception_handling
        )?;
        write!(writer, "EBPAllocatedAndUsed: {}\n", self.ebp_allocated_and_used)?;
        write!(writer, "reserved: 0X{:01X}\n", self.reserved)?;
        write!(writer, "frameType: {}\n", self.frame_type)?;
        dump_tail(writer, "FramePointerOmissionRecord")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x00, 0x10, // firstFunctionByteOffset = 0x10000000
            0x20, 0x00, 0x00, 0x00, // numFunctionBytes = 0x20
            0x03, 0x00, 0x00, 0x00, // numLocalVariables = 3
            0x02, 0x00, // sizeOfParametersInDwords = 2
            0x00, 0x00, // data field: prolog=0, all flags 0, frameType FPO
        ]
    }

    #[test]
    fn frame_type_label_matches_java_source() {
        assert_eq!(FrameType::Fpo.label(), "fpo");
        assert_eq!(FrameType::Trap.label(), "trap");
        assert_eq!(FrameType::Tss.label(), "tss");
        assert_eq!(FrameType::NonFpo.label(), "std");
    }

    #[test]
    fn frame_type_value_roundtrips() {
        let cases = [
            (FrameType::Fpo, 0),
            (FrameType::Trap, 1),
            (FrameType::Tss, 2),
            (FrameType::NonFpo, 3),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.value(), expected);
            assert_eq!(FrameType::from_value(expected), variant);
        }
    }

    #[test]
    fn frame_type_from_value_unknown_defaults_to_fpo() {
        assert_eq!(FrameType::from_value(-1), FrameType::Fpo);
        assert_eq!(FrameType::from_value(99), FrameType::Fpo);
    }

    #[test]
    fn frame_type_display_equals_label() {
        assert_eq!(FrameType::Trap.to_string(), "trap");
        assert_eq!(FrameType::NonFpo.to_string(), "std");
    }

    #[test]
    fn parse_valid_record() {
        let mut reader = PdbByteReader::new(record_bytes());
        let record = FramePointerOmissionRecord::parse(&mut reader).unwrap();
        assert_eq!(record.first_function_byte_offset(), 0x10000000);
        assert_eq!(record.number_of_function_bytes(), 0x20);
        assert_eq!(record.number_local_variables(), 3);
        assert_eq!(record.size_of_parameters_in_dwords(), 2);
        assert_eq!(record.number_function_prolog_bytes(), 0);
        assert!(!record.has_structured_exception_handling());
        assert!(!record.ebp_allocated_and_used());
        assert_eq!(record.reserved(), 0);
        assert_eq!(record.frame_type(), FrameType::Fpo);
    }

    #[test]
    fn parse_decodes_bitfields() {
        // data = 0b11_1_1_1_10000001 (prolog=0x81, SEH=1, EBP=1, reserved=1, frameType=3)
        let data: u16 = 0x81 | (0x01 << 8) | (0x01 << 9) | (0x01 << 10) | (0x03 << 11);
        let mut bytes = vec![
            0x00, 0x00, 0x00, 0x00, // firstFunctionByteOffset
            0x00, 0x00, 0x00, 0x00, // numFunctionBytes
            0x00, 0x00, 0x00, 0x00, // numLocalVariables
            0x00, 0x00, // sizeOfParametersInDwords
        ];
        bytes.extend_from_slice(&data.to_le_bytes());
        let mut reader = PdbByteReader::new(bytes);
        let record = FramePointerOmissionRecord::parse(&mut reader).unwrap();
        assert_eq!(record.number_function_prolog_bytes(), 0x81);
        assert!(record.has_structured_exception_handling());
        assert!(record.ebp_allocated_and_used());
        assert_eq!(record.reserved(), 1);
        assert_eq!(record.frame_type(), FrameType::NonFpo);
    }

    #[test]
    fn parse_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PdbByteReader::new(bytes);
        let result = FramePointerOmissionRecord::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_exactly_16_bytes_succeeds() {
        let bytes = vec![0x00; 16];
        let mut reader = PdbByteReader::new(bytes);
        let result = FramePointerOmissionRecord::parse(&mut reader);
        assert!(result.is_ok());
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let record = FramePointerOmissionRecord::parse(&mut reader).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("FramePointerOmissionRecord"));
        assert!(output.contains("firstFunctionByteOffset: 0X10000000"));
        assert!(output.contains("numFunctionBytes: 0X00000020"));
        assert!(output.contains("numLocalVariables: 0X00000003"));
        assert!(output.contains("sizeOfParametersInDwords: 0X00000002"));
        assert!(output.contains("frameType: fpo"));
        assert!(output.ends_with("End FramePointerOmissionRecord------------------------------\n"));
    }
}
