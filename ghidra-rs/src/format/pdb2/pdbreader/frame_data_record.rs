use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::pdb_reader_utils::{dump_head, dump_tail};

/// FRAMEDATA from cvinfo.h.
///
/// Most members are coded as unsigned long or unsigned long bit-fields; two are coded as
/// unsigned short: prolog and saved regs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameDataRecord {
    rva_start: u32,
    num_block_bytes: u32,
    num_local_bytes: u32,
    num_param_bytes: u32,
    max_stack_bytes: u32,
    frame_func: u32,
    num_prolog_bytes: u16,
    num_saved_reg_bytes: u16,
    has_seh: bool,
    has_eh: bool,
    is_function_start: bool,
    reserved: u32,
}

impl FrameDataRecord {
    /// Parses a `FrameDataRecord` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the record.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        if reader.num_remaining() < 32 {
            return Err(PdbException::new("Not enough data for FrameDataRecord"));
        }
        let rva_start = reader.parse_unsigned_int_val()?;
        let num_block_bytes = reader.parse_unsigned_int_val()?;
        let num_local_bytes = reader.parse_unsigned_int_val()?;
        let num_param_bytes = reader.parse_unsigned_int_val()?;
        let max_stack_bytes = reader.parse_unsigned_int_val()?;
        let frame_func = reader.parse_unsigned_int_val()?;
        let num_prolog_bytes = reader.parse_unsigned_short_val()?;
        let num_saved_reg_bytes = reader.parse_unsigned_short_val()?;
        let mut reserved = reader.parse_unsigned_int_val()?;
        let has_seh = (reserved & 0x01) == 0x01;
        reserved >>= 1;
        let has_eh = (reserved & 0x01) == 0x01;
        reserved >>= 1;
        let is_function_start = (reserved & 0x01) == 0x01;
        reserved >>= 1;
        reserved &= 0x01ffffff;

        Ok(FrameDataRecord {
            rva_start,
            num_block_bytes,
            num_local_bytes,
            num_param_bytes,
            max_stack_bytes,
            frame_func,
            num_prolog_bytes,
            num_saved_reg_bytes,
            has_seh,
            has_eh,
            is_function_start,
            reserved,
        })
    }

    /// Returns the RVA start.
    pub fn rva_start(&self) -> u32 {
        self.rva_start
    }

    /// Returns the number of bytes in the block (function).
    pub fn number_block_bytes(&self) -> u32 {
        self.num_block_bytes
    }

    /// Returns the number of bytes used by local variables.
    pub fn number_local_bytes(&self) -> u32 {
        self.num_local_bytes
    }

    /// Returns the number of bytes used by the parameters.
    pub fn number_parameter_bytes(&self) -> u32 {
        self.num_param_bytes
    }

    /// Returns max number of stack bytes.
    pub fn max_stack_bytes(&self) -> u32 {
        self.max_stack_bytes
    }

    /// Returns the frame func... not yet sure what this is.
    pub fn frame_func(&self) -> u32 {
        self.frame_func
    }

    /// Returns the number of bytes in the function prolog.
    pub fn number_function_prolog_bytes(&self) -> u16 {
        self.num_prolog_bytes
    }

    /// Returns the number of bytes for saved registers.
    pub fn number_saved_register_bytes(&self) -> u16 {
        self.num_saved_reg_bytes
    }

    /// Returns whether has SEH.
    pub fn has_seh(&self) -> bool {
        self.has_seh
    }

    /// Returns whether has EH.
    pub fn has_eh(&self) -> bool {
        self.has_eh
    }

    /// Returns whether is function start.
    pub fn is_function_start(&self) -> bool {
        self.is_function_start
    }

    /// Returns the value of the reserved, remaining 29 bit-field bits.
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Dumps the `FrameDataRecord`. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    pub(crate) fn dump(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        dump_head(writer, "FrameDataRecord")?;
        write!(writer, "rvaStart: 0X{:08X}\n", self.rva_start)?;
        write!(writer, "numBlockBytes: 0X{:08X}\n", self.num_block_bytes)?;
        write!(writer, "numLocalBytes: 0X{:08X}\n", self.num_local_bytes)?;
        write!(writer, "numParamBytes: 0X{:08X}\n", self.num_param_bytes)?;
        write!(writer, "maxStackBytes: 0X{:08X}\n", self.max_stack_bytes)?;
        write!(writer, "frameFunc: 0X{:08X}\n", self.frame_func)?;
        write!(writer, "numPrologBytes: 0X{:04X}\n", self.num_prolog_bytes)?;
        write!(writer, "numSavedRegBytes: 0X{:04X}\n", self.num_saved_reg_bytes)?;
        write!(writer, "hasStructuedExceptionHandling: {}\n", self.has_seh)?;
        write!(writer, "hasExceptionHandling: {}\n", self.has_eh)?;
        write!(writer, "isFunctionStart: {}\n", self.is_function_start)?;
        dump_tail(writer, "FrameDataRecord")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x00, 0x10, // rvaStart = 0x10000000
            0x20, 0x00, 0x00, 0x00, // numBlockBytes = 0x20
            0x03, 0x00, 0x00, 0x00, // numLocalBytes = 3
            0x04, 0x00, 0x00, 0x00, // numParamBytes = 4
            0x40, 0x00, 0x00, 0x00, // maxStackBytes = 0x40
            0x05, 0x00, 0x00, 0x00, // frameFunc = 5
            0x08, 0x00, // numPrologBytes = 8
            0x0c, 0x00, // numSavedRegBytes = 12
            0x00, 0x00, 0x00, 0x00, // reserved field: all flags 0
        ]
    }

    #[test]
    fn parse_valid_record() {
        let mut reader = PdbByteReader::new(record_bytes());
        let record = FrameDataRecord::parse(&mut reader).unwrap();
        assert_eq!(record.rva_start(), 0x10000000);
        assert_eq!(record.number_block_bytes(), 0x20);
        assert_eq!(record.number_local_bytes(), 3);
        assert_eq!(record.number_parameter_bytes(), 4);
        assert_eq!(record.max_stack_bytes(), 0x40);
        assert_eq!(record.frame_func(), 5);
        assert_eq!(record.number_function_prolog_bytes(), 8);
        assert_eq!(record.number_saved_register_bytes(), 12);
        assert!(!record.has_seh());
        assert!(!record.has_eh());
        assert!(!record.is_function_start());
        assert_eq!(record.reserved(), 0);
    }

    #[test]
    fn parse_decodes_bitfields() {
        // SEH=1 (bit0), EH=0 (bit1), isFunctionStart=1 (bit2), remaining reserved bits = 0x03
        let reserved: u32 = 0x01 | (0x00 << 1) | (0x01 << 2) | (0x03 << 3);
        let mut bytes = vec![
            0x00, 0x00, 0x00, 0x00, // rvaStart
            0x00, 0x00, 0x00, 0x00, // numBlockBytes
            0x00, 0x00, 0x00, 0x00, // numLocalBytes
            0x00, 0x00, 0x00, 0x00, // numParamBytes
            0x00, 0x00, 0x00, 0x00, // maxStackBytes
            0x00, 0x00, 0x00, 0x00, // frameFunc
            0x00, 0x00, // numPrologBytes
            0x00, 0x00, // numSavedRegBytes
        ];
        bytes.extend_from_slice(&reserved.to_le_bytes());
        let mut reader = PdbByteReader::new(bytes);
        let record = FrameDataRecord::parse(&mut reader).unwrap();
        assert!(record.has_seh());
        assert!(!record.has_eh());
        assert!(record.is_function_start());
        assert_eq!(record.reserved(), 0x03);
    }

    #[test]
    fn parse_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PdbByteReader::new(bytes);
        let result = FrameDataRecord::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_exactly_32_bytes_succeeds() {
        let bytes = vec![0x00; 32];
        let mut reader = PdbByteReader::new(bytes);
        let result = FrameDataRecord::parse(&mut reader);
        assert!(result.is_ok());
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let record = FrameDataRecord::parse(&mut reader).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("FrameDataRecord"));
        assert!(output.contains("rvaStart: 0X10000000"));
        assert!(output.contains("numBlockBytes: 0X00000020"));
        assert!(output.contains("numLocalBytes: 0X00000003"));
        assert!(output.contains("numParamBytes: 0X00000004"));
        assert!(output.contains("maxStackBytes: 0X00000040"));
        assert!(output.contains("frameFunc: 0X00000005"));
        assert!(output.contains("numPrologBytes: 0X0008"));
        assert!(output.contains("numSavedRegBytes: 0X000C"));
        assert!(output.contains("End FrameDataRecord"));
        assert!(output.ends_with('\n'));
    }
}
