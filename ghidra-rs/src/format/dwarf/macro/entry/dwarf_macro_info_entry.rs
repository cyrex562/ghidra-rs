//! Port of `ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroInfoEntry`.
//!
//! # Shape
//!
//! Java's `DWARFMacroInfoEntry` is a concrete class -- carrying the opcode/operand/header fields
//! plus every method -- that four sibling classes (`DWARFMacroDefine`, `DWARFMacroStartFile`,
//! `DWARFMacroEndFile`, `DWARFMacroImport`; a fifth, `DWARFMacroUndef`, extends `DWARFMacroDefine`
//! but is still constructed from a generic entry the same way) extend, each overriding at most
//! `toString()`. Rust splits the two:
//!
//! * [`DWARFMacroInfoEntryBase`] owns every field and every method Java does not override anywhere
//!   in the hierarchy.
//! * [`DWARFMacroInfoEntry`] declares only the overridable `to_string`, defaulting to
//!   [`DWARFMacroInfoEntryBase::to_display_string`]; [`DWARFMacroInfoEntryBase`] itself implements
//!   the trait, standing in for a "plain" (unspecialized) entry -- the `default -> genericEntry`
//!   arm of Java's `toSpecializedForm` switch.
//!
//! # Departures from the Java class
//!
//! * `DWARFMacroOpcode.Def` and the five macro-entry subclasses
//!   [`to_specialized_form`](DWARFMacroInfoEntryBase::to_specialized_form) dispatches to aren't
//!   ported yet; the five subclasses are stubbed in [`crate::format::seam_stubs`], each as a
//!   minimal wrapper offering only the copy-constructor shape `toSpecializedForm` needs.
//!   `DWARFMacroOpcode` is modeled as a real (non-stub) enum with the genuine `DW_MACRO_*` raw
//!   opcode/description table, in [`crate::format::seam_stubs`]. `DWARFMacroHeader` is the real
//!   port at [`crate::format::dwarf::r#macro::dwarf_macro_header::DWARFMacroHeader`]; it and
//!   `DWARFMacroInfoEntry` reference each other (a header reads/owns its entries; each entry keeps
//!   a back-reference to its header), which is a genuine forward cycle from `DWARFMacroHeader`'s
//!   own dependencies (`DWARFCompilationUnit`, `DIEContainer`), not from this pairing itself. See
//!   `STUBS.tsv`.
//! * `getOperand`'s `Class<T>` reflection becomes a generic downcast through
//!   [`DWARFAttributeValue::as_any`].
//! * The protected `DWARFMacroInfoEntry(DWARFMacroOpcode, DWARFMacroHeader)` constructor builds an
//!   `operandValues` array of `null`s sized to the opcode's operand count, for a subclass
//!   constructor to fill in afterwards; the Rust equivalent
//!   ([`DWARFMacroInfoEntryBase::new`]) models each unset slot as `None`, hence
//!   `operand_values: Vec<Option<Box<dyn DWARFAttributeValue>>>` rather than
//!   `Vec<Box<dyn DWARFAttributeValue>>`.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue;
use crate::format::dwarf::attribs::dwarf_form_context::DWARFFormContext;
use crate::format::dwarf::r#macro::dwarf_macro_header::DWARFMacroHeader;
use crate::format::seam_stubs::{self, DWARFAttributeDef, DWARFMacroOpcode, DWARFMacroOpcodeDef};

/// The shared state of a DWARF macro info entry, plus every method Java does not override in any
/// of its subclasses.
///
/// See the [module documentation](self) for why the state and the overridable behaviour are
/// split.
pub struct DWARFMacroInfoEntryBase {
    pub opcode: Option<DWARFMacroOpcode>,
    pub raw_opcode: i32,
    pub operand_values: Vec<Option<Box<dyn DWARFAttributeValue>>>,
    pub macro_header: Arc<DWARFMacroHeader>,
}

impl DWARFMacroInfoEntryBase {
    /// Mirrors the protected `DWARFMacroInfoEntry(DWARFMacroOpcode, DWARFMacroHeader)`
    /// constructor: builds an entry with an empty (all-`None`) operand array sized to the
    /// opcode's declared operand count, for a subclass constructor to fill in afterwards.
    pub fn new(opcode: DWARFMacroOpcode, macro_header: Arc<DWARFMacroHeader>) -> Self {
        let raw_opcode = opcode.get_raw_opcode();
        let operand_count = opcode.get_operand_forms().len();
        DWARFMacroInfoEntryBase {
            opcode: Some(opcode),
            raw_opcode,
            operand_values: (0..operand_count).map(|_| None).collect(),
            macro_header,
        }
    }

    /// Mirrors the public `DWARFMacroInfoEntry(DWARFMacroOpcode, int, DWARFAttributeValue[],
    /// DWARFMacroHeader)` constructor.
    pub fn with_values(
        opcode: Option<DWARFMacroOpcode>,
        raw_opcode: i32,
        operand_values: Vec<Box<dyn DWARFAttributeValue>>,
        macro_header: Arc<DWARFMacroHeader>,
    ) -> Self {
        DWARFMacroInfoEntryBase {
            opcode,
            raw_opcode,
            operand_values: operand_values.into_iter().map(Some).collect(),
            macro_header,
        }
    }

    /// Reads a DWARF macro info entry from `reader`, or `Ok(None)` if the element was the
    /// end-of-list marker. Mirrors `DWARFMacroInfoEntry.read(BinaryReader, DWARFMacroHeader)`.
    pub fn read(
        reader: &mut dyn BinaryReader,
        macro_header: Arc<DWARFMacroHeader>,
    ) -> io::Result<Option<Box<dyn DWARFMacroInfoEntry>>> {
        let mut opcode_map = macro_header.get_opcode_map();

        let start_offset = reader.get_pointer_index();
        let raw_opcode = reader.read_next_unsigned_byte()? as i32;
        let opcode = DWARFMacroOpcode::of(raw_opcode);
        let Some(operand_forms) = opcode_map.remove(&raw_opcode) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Unknown DW_MACRO opcode {raw_opcode:x} at position {start_offset} [0x{start_offset:x}]"
                ),
            ));
        };

        let cu = macro_header.get_compilation_unit();
        let dwarf_int_size = macro_header.get_int_size();

        let mut operand_values = Vec::with_capacity(operand_forms.len());
        for form in operand_forms {
            let opcode_value = opcode.expect(
                "DWARFMacroOpcode.of returned null for a raw opcode present in the header's \
                 opcode map (matches a Java NullPointerException from DWARFMacroOpcode.Def's \
                 constructor)",
            );
            let opcode_def = DWARFMacroOpcodeDef::new(opcode_value, raw_opcode, form);
            let mut context = DWARFFormContext {
                reader: &mut *reader,
                comp_unit: cu.as_ref(),
                def: &opcode_def,
                dwarf_int_size,
            };
            let value = opcode_def.get_attribute_form().read_value(&mut context)?;
            operand_values.push(value);
        }

        let generic_entry =
            DWARFMacroInfoEntryBase::with_values(opcode, raw_opcode, operand_values, macro_header);
        Ok(DWARFMacroInfoEntryBase::to_specialized_form(generic_entry))
    }

    /// Mirrors `DWARFMacroInfoEntry.toSpecializedForm(DWARFMacroInfoEntry)`: promotes a generic
    /// entry to its specialized subclass based on its opcode, or drops it (`None`, mirroring
    /// Java's `null`) if it's the unit terminator.
    ///
    /// # Panics
    /// Panics if `generic_entry.opcode` is `None`, mirroring the `NullPointerException` Java's
    /// pattern-matching `switch` throws when its selector is `null`.
    pub fn to_specialized_form(generic_entry: DWARFMacroInfoEntryBase) -> Option<Box<dyn DWARFMacroInfoEntry>> {
        use DWARFMacroOpcode::*;

        let opcode = generic_entry.opcode.expect(
            "DWARFMacroInfoEntry.toSpecializedForm: opcode is null (matches a Java \
             NullPointerException from switching on a null enum selector)",
        );
        match opcode {
            MacroUnitTerminator => None,
            DwMacroDefine | DwMacroDefineStrp | DwMacroDefineSup | DwMacroDefineStrx => {
                Some(Box::new(seam_stubs::DWARFMacroDefine::new(generic_entry)))
            }
            DwMacroUndef | DwMacroUndefStrp | DwMacroUndefSup | DwMacroUndefStrx => {
                Some(Box::new(seam_stubs::DWARFMacroUndef::new(generic_entry)))
            }
            DwMacroStartFile => Some(Box::new(seam_stubs::DWARFMacroStartFile::new(generic_entry))),
            DwMacroEndFile => Some(Box::new(seam_stubs::DWARFMacroEndFile::new(generic_entry))),
            DwMacroImport | DwMacroImportSup => Some(Box::new(seam_stubs::DWARFMacroImport::new(generic_entry))),
        }
    }

    /// Mirrors `DWARFMacroInfoEntry.getOpcode()`.
    pub fn get_opcode(&self) -> Option<DWARFMacroOpcode> {
        self.opcode
    }

    /// Mirrors `DWARFMacroInfoEntry.getName()`.
    pub fn get_name(&self) -> String {
        match self.opcode {
            Some(opcode) => opcode.get_description(),
            None => format!("DW_MACRO_unknown[{:x}]", self.raw_opcode),
        }
    }

    /// Mirrors `DWARFMacroInfoEntry.getOperand(int, Class<T>)`, using
    /// [`DWARFAttributeValue::as_any`] downcasting in place of Java's `Class<T>` reflection.
    pub fn get_operand<T: DWARFAttributeValue + 'static>(&self, index: usize) -> io::Result<&T> {
        let value = self.operand_values.get(index).and_then(|slot| slot.as_deref());
        match value.and_then(|v| v.as_any().downcast_ref::<T>()) {
            Some(typed) => Ok(typed),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Incompatible operand type {} for {}",
                    std::any::type_name::<T>(),
                    self.to_display_string()
                ),
            )),
        }
    }

    /// Mirrors the protected `DWARFMacroInfoEntry.operandDef(int)`.
    ///
    /// # Panics
    /// Panics if this entry's opcode is `None`, mirroring the Java `NullPointerException` from
    /// dereferencing a null `opcode` field (only reachable for a raw opcode registered in the
    /// header's opcode map without a matching `DWARFMacroOpcode` enum constant).
    pub fn operand_def(&self, operand_index: usize) -> DWARFMacroOpcodeDef {
        let opcode = self
            .opcode
            .expect("DWARFMacroInfoEntry.operandDef: opcode is null (matches a Java NullPointerException)");
        let form = opcode
            .get_operand_forms()
            .into_iter()
            .nth(operand_index)
            .expect("operand_index out of bounds for this opcode's operand forms");
        DWARFMacroOpcodeDef::new(opcode, self.raw_opcode, form)
    }

    /// Mirrors `DWARFMacroInfoEntry.toString()`.
    ///
    /// # Panics
    /// Panics if any operand slot is unset (`None`), mirroring the Java `NullPointerException`
    /// from calling `getValueString` on a null array element.
    pub fn to_display_string(&self) -> String {
        let mut result = self.get_name();
        if !self.operand_values.is_empty() {
            result.push_str(": ");
            let cu = self.macro_header.get_compilation_unit();
            for (i, value) in self.operand_values.iter().enumerate() {
                if i != 0 {
                    result.push_str(", ");
                }
                let value = value.as_deref().expect(
                    "DWARFMacroInfoEntry.toString: operand value is null (matches a Java \
                     NullPointerException)",
                );
                let def = self.operand_def(i);
                result.push_str(&value.get_value_string(cu.as_ref(), &def));
            }
        }
        result
    }
}

/// Declares the behaviour Java overrides in a `DWARFMacroInfoEntry` subclass; the shared state and
/// every non-overridden method live on [`DWARFMacroInfoEntryBase`] instead.
///
/// See the [module documentation](self) for why the state and the overridable behaviour are
/// split.
pub trait DWARFMacroInfoEntry: Send + Sync {
    /// The shared state this entry is built on.
    fn base(&self) -> &DWARFMacroInfoEntryBase;

    /// Mirrors `DWARFMacroInfoEntry.toString()`; overridden by (real ports of) `DWARFMacroDefine`
    /// and `DWARFMacroStartFile` to append field-specific detail, and by `DWARFMacroEndFile` (whose
    /// override is a no-op, calling `super.toString()` verbatim).
    fn to_string(&self) -> String {
        self.base().to_display_string()
    }
}

impl DWARFMacroInfoEntry for DWARFMacroInfoEntryBase {
    fn base(&self) -> &DWARFMacroInfoEntryBase {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::DWARFCompilationUnit;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0.get(index as usize).copied().ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
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

    /// Minimal `BinaryReader` implementation backed by an in-memory byte vector, for testing.
    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader { provider: Rc::new(RefCell::new(VecProvider(bytes))), index: 0, little_endian: true }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
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
            Box::new(TestReader { provider: Rc::clone(&self.provider), index: new_index, little_endian: self.little_endian })
        }
    }

    struct MockCompilationUnit;
    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
    }

    /// Builds a `DWARFMacroHeader` backed by an explicit `(raw opcode -> operand form codes)`
    /// table, so a test controls exactly which opcodes are "known" without needing a real
    /// `DWARFForm` port.
    fn mock_macro_header(opcodes: Vec<(i32, Vec<u32>)>) -> Arc<DWARFMacroHeader> {
        Arc::new(DWARFMacroHeader::new(
            0,
            5,
            0,
            -1,
            4,
            0,
            Some(Arc::new(MockCompilationUnit)),
            None,
            opcodes.into_iter().collect(),
        ))
    }

    #[test]
    fn read_recognizes_end_file_opcode_with_no_operands() {
        // DW_MACRO_end_file's raw opcode is 0x4 and it declares zero operand forms, matching
        // Java's `DW_MACRO_end_file(0x4, "endfile")` enum constant.
        let mut reader = TestReader::new(vec![0x04]);
        let header = mock_macro_header(vec![(0x04, vec![])]);

        let entry = DWARFMacroInfoEntryBase::read(&mut reader, header).unwrap().unwrap();

        assert_eq!(entry.base().opcode, Some(DWARFMacroOpcode::DwMacroEndFile));
        assert_eq!(entry.base().raw_opcode, 0x04);
        assert_eq!(entry.base().get_name(), "endfile");
        assert_eq!(entry.to_string(), "endfile");
    }

    #[test]
    fn read_returns_none_for_the_unit_terminator() {
        // Mirrors `toSpecializedForm`'s `case MACRO_UNIT_TERMINATOR -> null`.
        let mut reader = TestReader::new(vec![0x00]);
        let header = mock_macro_header(vec![(0x00, vec![])]);

        assert!(DWARFMacroInfoEntryBase::read(&mut reader, header).unwrap().is_none());
    }

    #[test]
    fn read_errors_on_an_opcode_missing_from_the_headers_opcode_map() {
        let mut reader = TestReader::new(vec![0xff]);
        let header = mock_macro_header(vec![]);

        let result = DWARFMacroInfoEntryBase::read(&mut reader, header);
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("expected an error for an opcode missing from the header's opcode map"),
        };
        assert!(err.to_string().contains("Unknown DW_MACRO opcode ff"));
    }

    #[test]
    fn get_name_falls_back_to_raw_opcode_when_unrecognized() {
        // A raw opcode registered in the header's opcode map (so `read` wouldn't error) but with
        // no matching `DWARFMacroOpcode` enum constant, mirroring a vendor extension opcode.
        let header = mock_macro_header(vec![]);
        let entry = DWARFMacroInfoEntryBase::with_values(None, 0xe0, vec![], header);

        assert_eq!(entry.get_name(), "DW_MACRO_unknown[e0]");
    }
}
