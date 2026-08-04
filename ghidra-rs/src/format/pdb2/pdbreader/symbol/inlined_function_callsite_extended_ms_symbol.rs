//! Inlined Function Callsite Extended PDB symbol.
//!
//! Corresponds to the Java class
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.InlinedFunctionCallsiteExtendedMsSymbol`.
//!
//! Note: we do not necessarily understand each of these symbol type classes. Refer to the
//! base class for more information.
//!
//! Ported as a trait (rather than a struct extending a concrete `AbstractMsSymbol` parsing
//! pipeline) because this type was selected as a dependency-cycle cut-point: callers can depend
//! on `dyn InlinedFunctionCallsiteExtendedMsSymbol` instead of a concrete class, so their crates
//! don't need to see `AbstractMsSymbol`/`AbstractPdb`/`PdbByteReader`'s full parsing machinery.
//! `AbstractMsSymbol` itself is not yet ported, so this trait does not extend it, matching the
//! precedent set by `AbstractCompile2MsSymbol`. `AbstractPdb` and `RecordNumber` are already
//! represented as placeholders in [`seam_stubs`](crate::format::seam_stubs) (see `STUBS.tsv` for
//! provenance), so no new placeholders were needed for this port.

use crate::format::pdb2::pdbreader::symbol::instruction_annotation::InstructionAnnotation;
use crate::format::seam_stubs::{AbstractPdb, RecordNumber};

/// The unique PDB identifier for this symbol type, matching the Java `PDB_ID` constant.
pub const PDB_ID: i32 = 0x115d;

/// The Inlined Function Callsite Extended symbol.
pub trait InlinedFunctionCallsiteExtendedMsSymbol {
    /// Returns the unique PDB identifier for this symbol type.
    fn pdb_id(&self) -> i32 {
        PDB_ID
    }

    /// Returns the pointer to inliner.
    fn pointer_to_inliner(&self) -> u32;

    /// Returns the pointer to this block end.
    fn pointer_to_this_block_end(&self) -> u32;

    /// Returns inlinee record number.
    fn inlinee_record_number(&self) -> RecordNumber;

    /// Returns the invocations count.
    fn invocations_count(&self) -> u32;

    /// Returns the binary annotation opcode list.
    fn binary_annotation_opcode_list(&self) -> &[Box<dyn InstructionAnnotation>];

    /// Returns the string representation of the symbol type name, matching the Java
    /// (protected, overridden) `AbstractMsSymbol.getSymbolTypeName()`.
    fn symbol_type_name(&self) -> String {
        "INLINESITE2".to_string()
    }

    /// Emits string output of this class into `builder`, matching the Java override of
    /// `AbstractMsSymbol.emit(StringBuilder)`.
    fn emit(&self, builder: &mut String, pdb: &dyn AbstractPdb) {
        builder.push_str(&self.symbol_type_name());
        builder.push_str(&format!(
            ": Parent: {:08X},  End: {:08X}, PGO Edge Count: {}, Inlinee: {}\n",
            self.pointer_to_inliner(),
            self.pointer_to_this_block_end(),
            self.invocations_count(),
            pdb.get_type_record(self.inlinee_record_number()).to_display_string(),
        ));

        // Mirrors Java's `if (count++ == 4) { builder.append("\n"); count = 0; }` post-increment
        // check: test the pre-increment value, always increment, then reset+newline on trigger.
        let mut count = 0;
        for instruction in self.binary_annotation_opcode_list() {
            let trigger = count == 4;
            count += 1;
            if trigger {
                builder.push('\n');
                count = 0;
            }
            instruction.emit(builder);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
    use crate::format::pdb2::pdbreader::id_ms_parsable::IdMsParsable;
    use crate::format::pdb2::pdbreader::r#type::abstract_ms_type::AbstractMsType;
    use crate::format::pdb2::pdbreader::r#type::ms_type::MsType;
    use crate::format::pdb2::pdbreader::symbol::instruction_annotation::Opcode;
    use crate::format::seam_stubs::PdbReaderOptions;
    use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset;

    struct MockInstruction {
        opcode: Opcode,
        parameter1: i64,
        parameter2: i64,
    }

    impl InstructionAnnotation for MockInstruction {
        fn instruction_code(&self) -> Opcode {
            self.opcode
        }

        fn parameter1(&self) -> i64 {
            self.parameter1
        }

        fn parameter2(&self) -> i64 {
            self.parameter2
        }
    }

    fn code_offset(value: i64) -> Box<dyn InstructionAnnotation> {
        Box::new(MockInstruction { opcode: Opcode::CodeOffset, parameter1: value, parameter2: -1 })
    }

    struct MockInlineeType;
    impl AbstractParsableItem for MockInlineeType {
        fn emit(&self, builder: &mut String) {
            builder.push_str("InlineeType");
        }
    }
    impl IdMsParsable for MockInlineeType {
        fn pdb_id(&self) -> i32 {
            0x1001
        }
    }
    impl MsType for MockInlineeType {}
    impl AbstractMsType for MockInlineeType {}

    struct MockPdb {
        options: PdbReaderOptions,
    }
    impl AbstractPdb for MockPdb {
        fn pdb_reader_options(&self) -> &PdbReaderOptions {
            &self.options
        }

        fn get_type_record(&self, _record_number: RecordNumber) -> Box<dyn AbstractMsType> {
            Box::new(MockInlineeType)
        }
    }

    fn mock_pdb() -> MockPdb {
        MockPdb {
            options: PdbReaderOptions {
                one_byte_charset: PdbCharset::OneByte,
                two_byte_charset: PdbCharset::Utf16Le,
            },
        }
    }

    struct MockCallsite {
        pointer_to_inliner: u32,
        pointer_to_this_block_end: u32,
        inlinee_record_number: RecordNumber,
        invocations_count: u32,
        binary_annotation_opcode_list: Vec<Box<dyn InstructionAnnotation>>,
    }

    impl InlinedFunctionCallsiteExtendedMsSymbol for MockCallsite {
        fn pointer_to_inliner(&self) -> u32 {
            self.pointer_to_inliner
        }

        fn pointer_to_this_block_end(&self) -> u32 {
            self.pointer_to_this_block_end
        }

        fn inlinee_record_number(&self) -> RecordNumber {
            self.inlinee_record_number
        }

        fn invocations_count(&self) -> u32 {
            self.invocations_count
        }

        fn binary_annotation_opcode_list(&self) -> &[Box<dyn InstructionAnnotation>] {
            &self.binary_annotation_opcode_list
        }
    }

    #[test]
    fn accessors_match_fields() {
        let sym = MockCallsite {
            pointer_to_inliner: 0x1000,
            pointer_to_this_block_end: 0x2000,
            inlinee_record_number: RecordNumber { number: 7 },
            invocations_count: 42,
            binary_annotation_opcode_list: vec![],
        };
        assert_eq!(sym.pdb_id(), 0x115d);
        assert_eq!(sym.pointer_to_inliner(), 0x1000);
        assert_eq!(sym.pointer_to_this_block_end(), 0x2000);
        assert_eq!(sym.inlinee_record_number(), RecordNumber { number: 7 });
        assert_eq!(sym.invocations_count(), 42);
        assert_eq!(sym.symbol_type_name(), "INLINESITE2");
    }

    #[test]
    fn emit_matches_java_format_header() {
        let sym = MockCallsite {
            pointer_to_inliner: 0x1000,
            pointer_to_this_block_end: 0x2000,
            inlinee_record_number: RecordNumber { number: 7 },
            invocations_count: 42,
            binary_annotation_opcode_list: vec![],
        };
        let pdb = mock_pdb();
        let mut builder = String::new();
        sym.emit(&mut builder, &pdb);
        assert_eq!(
            builder,
            "INLINESITE2: Parent: 00001000,  End: 00002000, PGO Edge Count: 42, Inlinee: InlineeType\n"
        );
    }

    #[test]
    fn emit_inserts_newline_before_fifth_and_tenth_instruction() {
        let sym = MockCallsite {
            pointer_to_inliner: 0,
            pointer_to_this_block_end: 0,
            inlinee_record_number: RecordNumber::no_type(),
            invocations_count: 0,
            binary_annotation_opcode_list: (1..=10).map(code_offset).collect(),
        };
        let pdb = mock_pdb();
        let mut builder = String::new();
        sym.emit(&mut builder, &pdb);

        let body = builder.split_once('\n').unwrap().1;
        let expected_body = "  Offset 1  Offset 2  Offset 3  Offset 4\n  Offset 5  Offset 6  Offset 7  Offset 8  Offset 9\n  Offset a";
        assert_eq!(body, expected_body);
    }

    #[test]
    fn is_object_safe() {
        let sym: Box<dyn InlinedFunctionCallsiteExtendedMsSymbol> = Box::new(MockCallsite {
            pointer_to_inliner: 0,
            pointer_to_this_block_end: 0,
            inlinee_record_number: RecordNumber::no_type(),
            invocations_count: 0,
            binary_annotation_opcode_list: vec![code_offset(1)],
        });
        assert_eq!(sym.pdb_id(), 0x115d);
        let pdb = mock_pdb();
        let mut builder = String::new();
        sym.emit(&mut builder, &pdb);
        assert!(builder.contains("INLINESITE2"));
    }
}
