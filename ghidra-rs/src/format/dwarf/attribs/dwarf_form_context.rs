//! Port of `ghidra.app.util.bin.format.dwarf.attribs.DWARFFormContext`.
//!
//! Java models this as a `record` (an immutable value type) carrying the four pieces of state a
//! [`DWARFForm`](crate::format::dwarf::attribs::dwarf_form::DWARFForm)'s `read_value` needs to
//! decode one attribute value:
//! the stream to read from, the owning compilation unit, the attribute's definition (id + form),
//! and the size of DWARF-serialized ints in effect for this read (normally the compilation unit's
//! own int size, but callers such as `DWARFFile::read_v5` and `DWARFMacroInfoEntryBase::read` may
//! pass a different size when reading from a section governed by an independent unit header).
//!
//! `DWARFCompilationUnit` is still stubbed in [`crate::format::seam_stubs`]; `DWARFAttributeDef`
//! is ported at
//! [`dwarf_attribute_def`](crate::format::dwarf::attribs::dwarf_attribute_def::DWARFAttributeDef).
//! Both are borrowed here as trait objects rather than concrete Java-side types, since a form
//! context doesn't know which attribute-id enum `E` backs its def. `dprog` and `die_container`
//! mirror the two package-private accessor methods Java declares for use by `DWARFForm`'s enum
//! constants.

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::dwarf::attribs::dwarf_attribute_def::DWARFAttributeDef;
use crate::format::seam_stubs::{DIEContainer, DWARFCompilationUnit, DWARFProgram};

/// Context given to a `DWARFForm`'s `read_value` method to enable it to create
/// `DWARFAttributeValue`s.
pub struct DWARFFormContext<'r, 'a> {
    pub reader: &'r mut dyn BinaryReader,
    pub comp_unit: &'a dyn DWARFCompilationUnit,
    pub def: &'a dyn DWARFAttributeDef,
    /// Size of dwarf serialization ints, either 4 (32 bit dwarf) or 8 (64 bit dwarf). Can be
    /// different from `comp_unit`'s int size if this context is being used to read values from a
    /// non-".debuginfo" section that has unit headers that specify an independent int size.
    pub dwarf_int_size: i32,
}

impl<'r, 'a> DWARFFormContext<'r, 'a> {
    /// Mirrors the canonical `DWARFFormContext(BinaryReader, DWARFCompilationUnit,
    /// DWARFAttributeDef, int)` constructor.
    pub fn new(
        reader: &'r mut dyn BinaryReader,
        comp_unit: &'a dyn DWARFCompilationUnit,
        def: &'a dyn DWARFAttributeDef,
        dwarf_int_size: i32,
    ) -> Self {
        DWARFFormContext { reader, comp_unit, def, dwarf_int_size }
    }

    /// Mirrors the compact `DWARFFormContext(BinaryReader, DWARFCompilationUnit,
    /// DWARFAttributeDef)` constructor, which uses `comp_unit`'s own int size.
    pub fn with_comp_unit_int_size(
        reader: &'r mut dyn BinaryReader,
        comp_unit: &'a dyn DWARFCompilationUnit,
        def: &'a dyn DWARFAttributeDef,
    ) -> Self {
        let dwarf_int_size = comp_unit.get_int_size();
        DWARFFormContext { reader, comp_unit, def, dwarf_int_size }
    }

    /// Mirrors the package-private `DWARFFormContext.dprog()`.
    pub(crate) fn dprog(&self) -> Option<&'a dyn DWARFProgram> {
        self.comp_unit.get_program()
    }

    /// Mirrors the package-private `DWARFFormContext.dieContainer()`.
    pub(crate) fn die_container(&self) -> Option<&'a dyn DIEContainer> {
        self.comp_unit.get_die_container()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
    use std::cell::RefCell;
    use std::io;
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
            self.0.get(start..end).map(|s| s.to_vec()).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
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
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader { provider: Rc::new(RefCell::new(VecProvider(data))), current_index: 0 }
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
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
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
            Box::new(MockReader { provider: Rc::clone(&self.provider), current_index: new_index })
        }
    }

    struct MockCompUnit {
        int_size: i32,
    }
    impl DWARFCompilationUnit for MockCompUnit {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
        fn get_int_size(&self) -> i32 {
            self.int_size
        }
    }

    struct MockAttrDef {
        form: crate::format::dwarf::attribs::dwarf_form::DWARFForm,
    }
    impl DWARFAttributeDef for MockAttrDef {
        fn get_attribute_form(&self) -> crate::format::dwarf::attribs::dwarf_form::DWARFForm {
            self.form
        }
    }

    #[test]
    fn compact_constructor_uses_comp_units_int_size() {
        let mut reader = MockReader::new(vec![]);
        let cu = MockCompUnit { int_size: 8 };
        let def = MockAttrDef { form: DWARFForm::DwFormData4 };

        let ctx = DWARFFormContext::with_comp_unit_int_size(&mut reader, &cu, &def);

        assert_eq!(ctx.dwarf_int_size, 8);
    }

    #[test]
    fn full_constructor_can_diverge_from_comp_units_int_size() {
        let mut reader = MockReader::new(vec![]);
        let cu = MockCompUnit { int_size: 4 };
        let def = MockAttrDef { form: DWARFForm::DwFormData4 };

        // The full constructor lets a caller pass an int size that differs from the
        // compilation unit's own -- e.g. a section governed by an independent unit header.
        let ctx = DWARFFormContext::new(&mut reader, &cu, &def, 8);

        assert_eq!(ctx.dwarf_int_size, 8);
        assert_eq!(ctx.comp_unit.get_int_size(), 4);
    }

    #[test]
    fn dprog_and_die_container_default_to_none() {
        let mut reader = MockReader::new(vec![]);
        let cu = MockCompUnit { int_size: 4 };
        let def = MockAttrDef { form: DWARFForm::DwFormData4 };
        let ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);

        assert!(ctx.dprog().is_none());
        assert!(ctx.die_container().is_none());
    }
}
