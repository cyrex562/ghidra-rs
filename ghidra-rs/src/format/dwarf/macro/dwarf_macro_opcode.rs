//! Port of `ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode`.
//!
//! DWARF macro entry opcodes and their expected operand types (DWARF5).

use std::collections::HashMap;

use crate::format::dwarf::attribs::dwarf_attribute_def::DWARFAttributeDef;
use crate::format::dwarf::attribs::dwarf_form::DWARFForm;

/// DWARF macro entry opcodes, and their expected operands.
///
/// `DWARFMacroOpcode` is a Java enum (not an interface), so it is modeled here as a concrete Rust
/// enum carrying the real `DW_MACRO_*` raw opcode and description values, rather than a trait
/// object. Variant names use Rust's `CamelCase` convention (matching sibling DWARF enums such as
/// [`DWARFForm`]) rather than the verbatim Java constant spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFMacroOpcode {
    /// Not an official opcode in the DWARF standard, but represents the entry with opcode 0 that
    /// terminates a macro unit. Mirrors `MACRO_UNIT_TERMINATOR`.
    MacroUnitTerminator,
    /// Mirrors `DW_MACRO_define`.
    DwMacroDefine,
    /// Mirrors `DW_MACRO_undef`.
    DwMacroUndef,
    /// Mirrors `DW_MACRO_start_file`.
    DwMacroStartFile,
    /// Mirrors `DW_MACRO_end_file`.
    DwMacroEndFile,
    /// Mirrors `DW_MACRO_define_strp`.
    DwMacroDefineStrp,
    /// Mirrors `DW_MACRO_undef_strp`.
    DwMacroUndefStrp,
    /// Mirrors `DW_MACRO_import`.
    DwMacroImport,
    /// Mirrors `DW_MACRO_define_sup`.
    DwMacroDefineSup,
    /// Mirrors `DW_MACRO_undef_sup`.
    DwMacroUndefSup,
    /// Mirrors `DW_MACRO_import_sup`.
    DwMacroImportSup,
    /// Mirrors `DW_MACRO_define_strx`.
    DwMacroDefineStrx,
    /// Mirrors `DW_MACRO_undef_strx`.
    DwMacroUndefStrx,
}

impl DWARFMacroOpcode {
    /// All variants, in Java enum declaration order; used by [`Self::of`] to mirror Java's
    /// `values()`-based linear search. `DWARFMacroOpcode` is small enough that a linear search is
    /// fast enough, matching the Java implementation's own comment.
    const VALUES: [DWARFMacroOpcode; 13] = [
        DWARFMacroOpcode::MacroUnitTerminator,
        DWARFMacroOpcode::DwMacroDefine,
        DWARFMacroOpcode::DwMacroUndef,
        DWARFMacroOpcode::DwMacroStartFile,
        DWARFMacroOpcode::DwMacroEndFile,
        DWARFMacroOpcode::DwMacroDefineStrp,
        DWARFMacroOpcode::DwMacroUndefStrp,
        DWARFMacroOpcode::DwMacroImport,
        DWARFMacroOpcode::DwMacroDefineSup,
        DWARFMacroOpcode::DwMacroUndefSup,
        DWARFMacroOpcode::DwMacroImportSup,
        DWARFMacroOpcode::DwMacroDefineStrx,
        DWARFMacroOpcode::DwMacroUndefStrx,
    ];

    /// Mirrors `DWARFMacroOpcode.getRawOpcode()`.
    pub fn get_raw_opcode(&self) -> i32 {
        match self {
            Self::MacroUnitTerminator => 0,
            Self::DwMacroDefine => 0x1,
            Self::DwMacroUndef => 0x2,
            Self::DwMacroStartFile => 0x3,
            Self::DwMacroEndFile => 0x4,
            Self::DwMacroDefineStrp => 0x5,
            Self::DwMacroUndefStrp => 0x6,
            Self::DwMacroImport => 0x7,
            Self::DwMacroDefineSup => 0x8,
            Self::DwMacroUndefSup => 0x9,
            Self::DwMacroImportSup => 0xa,
            Self::DwMacroDefineStrx => 0xb,
            Self::DwMacroUndefStrx => 0xc,
        }
    }

    /// Mirrors `DWARFMacroOpcode.getDescription()`.
    pub fn get_description(&self) -> String {
        match self {
            Self::MacroUnitTerminator => "unknown",
            Self::DwMacroDefine
            | Self::DwMacroDefineStrp
            | Self::DwMacroDefineSup
            | Self::DwMacroDefineStrx => "#define",
            Self::DwMacroUndef
            | Self::DwMacroUndefStrp
            | Self::DwMacroUndefSup
            | Self::DwMacroUndefStrx => "#undef",
            Self::DwMacroStartFile => "startfile",
            Self::DwMacroEndFile => "endfile",
            Self::DwMacroImport | Self::DwMacroImportSup => "#include",
        }
        .to_string()
    }

    /// Mirrors `DWARFMacroOpcode.getOperandForms()`: the form each of this opcode's operands is
    /// encoded with, from the Java constructor's varargs `operandForms`.
    pub fn get_operand_forms(&self) -> &'static [DWARFForm] {
        use DWARFForm::*;
        match self {
            Self::MacroUnitTerminator | Self::DwMacroEndFile => &[],
            Self::DwMacroDefine | Self::DwMacroUndef => &[DwFormUdata, DwFormString],
            Self::DwMacroStartFile => &[DwFormUdata, DwFormUdata],
            Self::DwMacroDefineStrp | Self::DwMacroUndefStrp => &[DwFormUdata, DwFormStrp],
            Self::DwMacroImport | Self::DwMacroImportSup => &[DwFormSecOffset],
            Self::DwMacroDefineSup | Self::DwMacroUndefSup => &[DwFormUdata, DwFormStrpSup],
            Self::DwMacroDefineStrx | Self::DwMacroUndefStrx => &[DwFormUdata, DwFormStrx],
        }
    }

    /// Mirrors `DWARFMacroOpcode.of(int)`: a linear search over the enum's values, returning
    /// `None` (Java `null`) if no variant matches.
    pub fn of(opcode_val: i32) -> Option<Self> {
        Self::VALUES.into_iter().find(|opcode| opcode.get_raw_opcode() == opcode_val)
    }

    /// Mirrors `DWARFMacroOpcode.defaultOpcodeOperandMap`, used by `DWARFMacroHeader::read_v5` as
    /// the starting opcode table before an optional per-unit table (if present) overrides it.
    pub fn default_opcode_operand_map() -> HashMap<i32, Vec<DWARFForm>> {
        Self::VALUES
            .iter()
            .map(|opcode| (opcode.get_raw_opcode(), opcode.get_operand_forms().to_vec()))
            .collect()
    }
}

/// Port of the nested `DWARFMacroOpcode.Def` (a `DWARFAttributeDef<DWARFMacroOpcode>`). Mirrors
/// the three fields the Java constructor forwards to `DWARFAttributeDef`'s constructor
/// (`attributeId`, `rawAttributeId`, `attributeForm`); the fourth (`implicitValue`) is always `-1`
/// ("N/A") for a macro opcode def, matching [`DWARFAttributeDef::get_implicit_value`]'s default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFMacroOpcodeDef {
    pub opcode: DWARFMacroOpcode,
    pub raw_opcode: i32,
    pub form: DWARFForm,
}

impl DWARFMacroOpcodeDef {
    pub fn new(opcode: DWARFMacroOpcode, raw_opcode: i32, form: DWARFForm) -> Self {
        DWARFMacroOpcodeDef { opcode, raw_opcode, form }
    }
}

impl DWARFAttributeDef for DWARFMacroOpcodeDef {
    fn get_attribute_form(&self) -> DWARFForm {
        self.form
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_raw_opcode_matches_dwarf5_spec_values() {
        assert_eq!(DWARFMacroOpcode::MacroUnitTerminator.get_raw_opcode(), 0);
        assert_eq!(DWARFMacroOpcode::DwMacroDefine.get_raw_opcode(), 0x1);
        assert_eq!(DWARFMacroOpcode::DwMacroUndef.get_raw_opcode(), 0x2);
        assert_eq!(DWARFMacroOpcode::DwMacroStartFile.get_raw_opcode(), 0x3);
        assert_eq!(DWARFMacroOpcode::DwMacroEndFile.get_raw_opcode(), 0x4);
        assert_eq!(DWARFMacroOpcode::DwMacroDefineStrp.get_raw_opcode(), 0x5);
        assert_eq!(DWARFMacroOpcode::DwMacroUndefStrp.get_raw_opcode(), 0x6);
        assert_eq!(DWARFMacroOpcode::DwMacroImport.get_raw_opcode(), 0x7);
        assert_eq!(DWARFMacroOpcode::DwMacroDefineSup.get_raw_opcode(), 0x8);
        assert_eq!(DWARFMacroOpcode::DwMacroUndefSup.get_raw_opcode(), 0x9);
        assert_eq!(DWARFMacroOpcode::DwMacroImportSup.get_raw_opcode(), 0xa);
        assert_eq!(DWARFMacroOpcode::DwMacroDefineStrx.get_raw_opcode(), 0xb);
        assert_eq!(DWARFMacroOpcode::DwMacroUndefStrx.get_raw_opcode(), 0xc);
    }

    #[test]
    fn get_description_matches_java_source_strings() {
        assert_eq!(DWARFMacroOpcode::MacroUnitTerminator.get_description(), "unknown");
        assert_eq!(DWARFMacroOpcode::DwMacroDefine.get_description(), "#define");
        assert_eq!(DWARFMacroOpcode::DwMacroDefineStrp.get_description(), "#define");
        assert_eq!(DWARFMacroOpcode::DwMacroDefineSup.get_description(), "#define");
        assert_eq!(DWARFMacroOpcode::DwMacroDefineStrx.get_description(), "#define");
        assert_eq!(DWARFMacroOpcode::DwMacroUndef.get_description(), "#undef");
        assert_eq!(DWARFMacroOpcode::DwMacroUndefStrp.get_description(), "#undef");
        assert_eq!(DWARFMacroOpcode::DwMacroUndefSup.get_description(), "#undef");
        assert_eq!(DWARFMacroOpcode::DwMacroUndefStrx.get_description(), "#undef");
        assert_eq!(DWARFMacroOpcode::DwMacroStartFile.get_description(), "startfile");
        assert_eq!(DWARFMacroOpcode::DwMacroEndFile.get_description(), "endfile");
        assert_eq!(DWARFMacroOpcode::DwMacroImport.get_description(), "#include");
        assert_eq!(DWARFMacroOpcode::DwMacroImportSup.get_description(), "#include");
    }

    #[test]
    fn get_operand_forms_matches_java_source_tables() {
        assert!(DWARFMacroOpcode::MacroUnitTerminator.get_operand_forms().is_empty());
        assert!(DWARFMacroOpcode::DwMacroEndFile.get_operand_forms().is_empty());
        assert_eq!(
            DWARFMacroOpcode::DwMacroDefine.get_operand_forms(),
            &[DWARFForm::DwFormUdata, DWARFForm::DwFormString]
        );
        assert_eq!(
            DWARFMacroOpcode::DwMacroStartFile.get_operand_forms(),
            &[DWARFForm::DwFormUdata, DWARFForm::DwFormUdata]
        );
        assert_eq!(
            DWARFMacroOpcode::DwMacroDefineStrp.get_operand_forms(),
            &[DWARFForm::DwFormUdata, DWARFForm::DwFormStrp]
        );
        assert_eq!(
            DWARFMacroOpcode::DwMacroImport.get_operand_forms(),
            &[DWARFForm::DwFormSecOffset]
        );
        assert_eq!(
            DWARFMacroOpcode::DwMacroImportSup.get_operand_forms(),
            &[DWARFForm::DwFormSecOffset]
        );
        assert_eq!(
            DWARFMacroOpcode::DwMacroDefineSup.get_operand_forms(),
            &[DWARFForm::DwFormUdata, DWARFForm::DwFormStrpSup]
        );
        assert_eq!(
            DWARFMacroOpcode::DwMacroDefineStrx.get_operand_forms(),
            &[DWARFForm::DwFormUdata, DWARFForm::DwFormStrx]
        );
    }

    #[test]
    fn of_finds_variant_by_raw_opcode() {
        assert_eq!(DWARFMacroOpcode::of(0x4), Some(DWARFMacroOpcode::DwMacroEndFile));
        assert_eq!(DWARFMacroOpcode::of(0x1), Some(DWARFMacroOpcode::DwMacroDefine));
        assert_eq!(DWARFMacroOpcode::of(0), Some(DWARFMacroOpcode::MacroUnitTerminator));
    }

    #[test]
    fn of_returns_none_for_unknown_opcode() {
        // 0xe0..0xff is the DW_MACRO_lo_user..hi_user vendor-extension range: no enum constant
        // covers it, mirroring Java's `of()` returning `null`.
        assert_eq!(DWARFMacroOpcode::of(0xe0), None);
        assert_eq!(DWARFMacroOpcode::of(0xff), None);
        assert_eq!(DWARFMacroOpcode::of(-1), None);
    }

    #[test]
    fn default_opcode_operand_map_covers_every_variant_by_raw_opcode() {
        let map = DWARFMacroOpcode::default_opcode_operand_map();
        assert_eq!(map.len(), 13);
        for opcode in DWARFMacroOpcode::VALUES {
            assert_eq!(map[&opcode.get_raw_opcode()], opcode.get_operand_forms().to_vec());
        }
    }

    #[test]
    fn macro_opcode_def_reports_its_form() {
        let def = DWARFMacroOpcodeDef::new(
            DWARFMacroOpcode::DwMacroDefine,
            0x1,
            DWARFForm::DwFormUdata,
        );
        assert_eq!(def.get_attribute_form(), DWARFForm::DwFormUdata);
        // Mirrors the always-"-1" implicitValue for a macro opcode def.
        assert_eq!(def.get_implicit_value(), -1);
    }
}
