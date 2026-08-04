//! Instruction annotation used for certain PDB symbols for inlined functions.
//!
//! Corresponds to the Java class
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.InstructionAnnotation`.
//!
//! Ported as a trait (rather than a struct extending `AbstractParsableItem`) because this type
//! was selected as a dependency-cycle cut-point: `InlinedFunctionCallsiteMsSymbol` and
//! `InlinedFunctionCallsiteExtendedMsSymbol` (not yet ported) can depend on
//! `dyn InstructionAnnotation` instead of a concrete class, so their crates don't need to see
//! the full parsing machinery. [`parse_instruction_annotation`] is the free-function equivalent
//! of the Java constructor, and does not depend on any not-yet-ported types, so no
//! `seam_stubs` placeholders were needed for this port.

use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// The opcode of an [`InstructionAnnotation`].
///
/// Corresponds to the Java nested enum `InstructionAnnotation.Opcode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Invalid,
    CodeOffset,
    ChangeCodeOffsetBase,
    ChangeCodeOffset,
    ChangeCodeLength,
    ChangeFile,
    ChangeLineOffset,
    ChangeLineEndDelta,
    ChangeRangeKind,
    ChangeColumnStart,
    ChangeColumnEndDelta,
    ChangeCodeOffsetAndLineOffset,
    ChangeCodeLengthAndCodeOffset,
    ChangeColumnEnd,
}

impl Opcode {
    /// The display label, matching the Java enum's `label` field / `toString()`.
    pub fn label(self) -> &'static str {
        match self {
            Opcode::Invalid => "Illegal",
            Opcode::CodeOffset => "Offset",
            Opcode::ChangeCodeOffsetBase => "CodeOffsetBase",
            Opcode::ChangeCodeOffset => "CodeOffset",
            Opcode::ChangeCodeLength => "CodeLength",
            Opcode::ChangeFile => "File",
            Opcode::ChangeLineOffset => "LineOffset",
            Opcode::ChangeLineEndDelta => "LineEndDelta",
            Opcode::ChangeRangeKind => "RangeKind",
            Opcode::ChangeColumnStart => "ColumnStart",
            Opcode::ChangeColumnEndDelta => "ColumnEndDelta",
            Opcode::ChangeCodeOffsetAndLineOffset => "CodeOffsetAndLineOffset",
            Opcode::ChangeCodeLengthAndCodeOffset => "CodeLengthAndCodeOffset",
            Opcode::ChangeColumnEnd => "ColumnEnd",
        }
    }

    /// The wire value, matching the Java enum's `value` field.
    pub fn value(self) -> i32 {
        match self {
            Opcode::Invalid => 0,
            Opcode::CodeOffset => 1,
            Opcode::ChangeCodeOffsetBase => 2,
            Opcode::ChangeCodeOffset => 3,
            Opcode::ChangeCodeLength => 0x04,
            Opcode::ChangeFile => 0x05,
            Opcode::ChangeLineOffset => 0x06,
            Opcode::ChangeLineEndDelta => 0x07,
            Opcode::ChangeRangeKind => 0x08,
            Opcode::ChangeColumnStart => 0x09,
            Opcode::ChangeColumnEndDelta => 0x0a,
            Opcode::ChangeCodeOffsetAndLineOffset => 0x0b,
            Opcode::ChangeCodeLengthAndCodeOffset => 0x0c,
            Opcode::ChangeColumnEnd => 0x0d,
        }
    }

    /// Looks up the [`Opcode`] for a wire value, matching Java's `Opcode.fromValue(int)`, which
    /// returns [`Opcode::Invalid`] for any value with no matching entry.
    pub fn from_value(val: i32) -> Self {
        match val {
            1 => Opcode::CodeOffset,
            2 => Opcode::ChangeCodeOffsetBase,
            3 => Opcode::ChangeCodeOffset,
            0x04 => Opcode::ChangeCodeLength,
            0x05 => Opcode::ChangeFile,
            0x06 => Opcode::ChangeLineOffset,
            0x07 => Opcode::ChangeLineEndDelta,
            0x08 => Opcode::ChangeRangeKind,
            0x09 => Opcode::ChangeColumnStart,
            0x0a => Opcode::ChangeColumnEndDelta,
            0x0b => Opcode::ChangeCodeOffsetAndLineOffset,
            0x0c => Opcode::ChangeCodeLengthAndCodeOffset,
            0x0d => Opcode::ChangeColumnEnd,
            _ => Opcode::Invalid,
        }
    }
}

impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Instruction annotation used for certain PDB symbols for inlined functions.
///
/// Corresponds to the public API of the Java class `InstructionAnnotation`.
pub trait InstructionAnnotation {
    /// Returns the instruction opcode.
    fn instruction_code(&self) -> Opcode;

    /// Returns the first parameter (private `parameter1` field in Java), needed by the default
    /// [`emit`](Self::emit) implementation.
    fn parameter1(&self) -> i64;

    /// Returns the second parameter (private `parameter2` field in Java), needed by the default
    /// [`emit`](Self::emit) implementation.
    fn parameter2(&self) -> i64;

    /// Emits string output of this class into `builder`, matching Java's override of
    /// `AbstractParsableItem.emit(StringBuilder)`.
    fn emit(&self, builder: &mut String) {
        match self.instruction_code() {
            Opcode::ChangeCodeLengthAndCodeOffset => {
                builder.push_str(&format!(
                    "  {} {:x} {:x}",
                    self.instruction_code(),
                    self.parameter1(),
                    self.parameter2()
                ));
            }
            Opcode::ChangeCodeOffsetAndLineOffset => {
                // CodeDelta is lower 4 bits, SourceDelta rest of the bits.
                builder.push_str(&format!(
                    "  {} {:x} {:x}",
                    self.instruction_code(),
                    (self.parameter1() >> 4) & 0x0fffffff,
                    self.parameter1() & 0x0f
                ));
            }
            _ => {
                builder.push_str(&format!(
                    "  {} {:x}",
                    self.instruction_code(),
                    self.parameter1() as i32
                ));
            }
        }
    }
}

/// Decodes a variable-length compressed integer from `reader`, matching Java's private
/// `InstructionAnnotation.decompressData(PdbByteReader)`.
fn decompress_data(reader: &mut PdbByteReader) -> Result<i32, PdbException> {
    let val = reader.parse_unsigned_byte_val()? as i32;
    let result = if val < 0x80 {
        val
    } else if (val & 0xc0) == 0x80 {
        let mut r = (val & 0x3f) << 8;
        r |= reader.parse_unsigned_byte_val()? as i32;
        r
    } else if (val & 0xe0) == 0xc0 {
        let mut r = (val & 0x1f) << 24;
        r |= (reader.parse_unsigned_byte_val()? as i32) << 16;
        r |= (reader.parse_unsigned_byte_val()? as i32) << 8;
        r |= reader.parse_unsigned_byte_val()? as i32;
        r
    } else {
        i32::MIN
    };
    Ok(result)
}

/// Decodes a zig-zag-style signed integer from a decompressed value, matching Java's private
/// `InstructionAnnotation.decodeSignedInt32(int)`.
fn decode_signed_int32(input: i32) -> i32 {
    if (input & 0x01) == 0x01 {
        -(input >> 1)
    } else {
        input >> 1
    }
}

/// Parses an `(Opcode, parameter1, parameter2)` triple from `reader`, matching Java's
/// `InstructionAnnotation(PdbByteReader)` constructor.
pub fn parse_instruction_annotation(
    reader: &mut PdbByteReader,
) -> Result<(Opcode, i64, i64), PdbException> {
    let instruction_code = Opcode::from_value(decompress_data(reader)?);
    let (parameter1, parameter2) = match instruction_code {
        Opcode::Invalid => {
            reader.align4();
            (0i64, 0i64)
        }
        Opcode::ChangeCodeLengthAndCodeOffset => {
            let p1 = decompress_data(reader)? as i64;
            let p2 = decompress_data(reader)? as i64;
            (p1, p2)
        }
        Opcode::ChangeLineOffset | Opcode::ChangeColumnEndDelta => {
            let p1 = decode_signed_int32(decompress_data(reader)?) as i64;
            (p1, -1i64)
        }
        _ => {
            let p1 = decompress_data(reader)? as i64;
            (p1, -1i64)
        }
    };
    Ok((instruction_code, parameter1, parameter2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock impl proving the trait is object-safe and usable by a caller that only knows about
    /// `dyn InstructionAnnotation`, matching how a cycle-breaking cut-point trait is consumed.
    /// Populated via [`parse_instruction_annotation`], exercising the real parsing logic rather
    /// than hand-setting fields.
    struct MockInstructionAnnotation {
        instruction_code: Opcode,
        parameter1: i64,
        parameter2: i64,
    }

    impl InstructionAnnotation for MockInstructionAnnotation {
        fn instruction_code(&self) -> Opcode {
            self.instruction_code
        }

        fn parameter1(&self) -> i64 {
            self.parameter1
        }

        fn parameter2(&self) -> i64 {
            self.parameter2
        }
    }

    fn parse(bytes: Vec<u8>) -> MockInstructionAnnotation {
        let (instruction_code, parameter1, parameter2) =
            parse_instruction_annotation(&mut PdbByteReader::new(bytes)).unwrap();
        MockInstructionAnnotation { instruction_code, parameter1, parameter2 }
    }

    #[test]
    fn parse_single_byte_opcode_and_parameter() {
        // opcode = CodeOffset (1), parameter1 = 42 (single-byte compressed encoding).
        let sym = parse(vec![0x01, 0x2a]);
        assert_eq!(sym.instruction_code, Opcode::CodeOffset);
        assert_eq!(sym.parameter1, 42);
        assert_eq!(sym.parameter2, -1);
    }

    #[test]
    fn parse_invalid_opcode_aligns_to_4() {
        let mut reader = PdbByteReader::new(vec![0x00, 0x00, 0x00, 0x00]);
        let (instruction_code, parameter1, parameter2) =
            parse_instruction_annotation(&mut reader).unwrap();
        assert_eq!(instruction_code, Opcode::Invalid);
        assert_eq!(parameter1, 0);
        assert_eq!(parameter2, 0);
        assert_eq!(reader.get_index(), 4);
    }

    #[test]
    fn parse_change_code_length_and_code_offset_reads_two_parameters() {
        let sym = parse(vec![0x0c, 0x10, 0x20]);
        assert_eq!(sym.instruction_code, Opcode::ChangeCodeLengthAndCodeOffset);
        assert_eq!(sym.parameter1, 0x10);
        assert_eq!(sym.parameter2, 0x20);
    }

    #[test]
    fn parse_change_line_offset_decodes_signed_parameter() {
        // Raw compressed value 5 (odd) decodes to -(5 >> 1) = -2.
        let sym = parse(vec![0x06, 0x05]);
        assert_eq!(sym.instruction_code, Opcode::ChangeLineOffset);
        assert_eq!(sym.parameter1, -2);
        assert_eq!(sym.parameter2, -1);
    }

    #[test]
    fn parse_change_column_end_delta_decodes_signed_parameter() {
        // Raw compressed value 4 (even) decodes to 4 >> 1 = 2.
        let sym = parse(vec![0x0a, 0x04]);
        assert_eq!(sym.instruction_code, Opcode::ChangeColumnEndDelta);
        assert_eq!(sym.parameter1, 2);
    }

    #[test]
    fn parse_two_byte_compressed_parameter() {
        // opcode byte 0x01 -> CodeOffset (single-byte). Parameter compressed as two bytes:
        // 0x81 0x02 -> ((0x81 & 0x3f) << 8) | 0x02 = 0x100 | 0x02 = 0x102 = 258.
        let sym = parse(vec![0x01, 0x81, 0x02]);
        assert_eq!(sym.instruction_code, Opcode::CodeOffset);
        assert_eq!(sym.parameter1, 258);
    }

    #[test]
    fn parse_four_byte_compressed_parameter() {
        // Parameter compressed as four bytes: 0xC1 0x00 0x00 0x05
        // -> ((0xC1 & 0x1f) << 24) | (0x00 << 16) | (0x00 << 8) | 0x05 = 0x01000005.
        let sym = parse(vec![0x01, 0xc1, 0x00, 0x00, 0x05]);
        assert_eq!(sym.instruction_code, Opcode::CodeOffset);
        assert_eq!(sym.parameter1, 0x01000005);
    }

    #[test]
    fn parse_errors_on_empty_buffer() {
        let mut reader = PdbByteReader::new(vec![]);
        assert!(parse_instruction_annotation(&mut reader).is_err());
    }

    #[test]
    fn opcode_from_value_defaults_to_invalid() {
        assert_eq!(Opcode::from_value(0xff), Opcode::Invalid);
        assert_eq!(Opcode::from_value(0x0d), Opcode::ChangeColumnEnd);
    }

    #[test]
    fn emit_matches_java_format_for_default_branch() {
        let sym = parse(vec![0x01, 0x2a]);
        let mut builder = String::new();
        sym.emit(&mut builder);
        assert_eq!(builder, "  Offset 2a");
    }

    #[test]
    fn emit_matches_java_format_for_negative_parameter() {
        let sym = parse(vec![0x06, 0x05]);
        let mut builder = String::new();
        sym.emit(&mut builder);
        assert_eq!(builder, "  LineOffset fffffffe");
    }

    #[test]
    fn emit_matches_java_format_for_code_length_and_code_offset() {
        let sym = parse(vec![0x0c, 0x10, 0x20]);
        let mut builder = String::new();
        sym.emit(&mut builder);
        assert_eq!(builder, "  CodeLengthAndCodeOffset 10 20");
    }

    #[test]
    fn emit_matches_java_format_for_code_offset_and_line_offset() {
        // opcode 0x0b (ChangeCodeOffsetAndLineOffset) is not specially handled during parsing,
        // so it takes the general single-parameter path: parameter1 = 0x25 (37).
        let sym = parse(vec![0x0b, 0x25]);
        let mut builder = String::new();
        sym.emit(&mut builder);
        // (37 >> 4) & 0x0fffffff = 2, 37 & 0x0f = 5.
        assert_eq!(builder, "  CodeOffsetAndLineOffset 2 5");
    }

    #[test]
    fn is_object_safe() {
        let sym: Box<dyn InstructionAnnotation> = Box::new(parse(vec![0x01, 0x2a]));
        assert_eq!(sym.instruction_code(), Opcode::CodeOffset);
        let mut builder = String::new();
        sym.emit(&mut builder);
        assert_eq!(builder, "  Offset 2a");
    }
}
