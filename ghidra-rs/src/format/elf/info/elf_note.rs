//! Port of `ghidra.app.util.bin.format.elf.info.ElfNote`.
//!
//! ELF note sections have a well-defined format that combines identity information along with a
//! binary blob that is specific to each type of note. Notes are identified by the combination of
//! a name string and vendorType number, and are usually stored in an ELF section with a specific
//! name.
//!
//! The Java class is a concrete `class ElfNote implements ElfInfoItem` that 4 other classes
//! extend (`NoteAbiTag`, `NoteGnuBuildId`, `NoteGnuProperty`, `NoteGoBuildId` -- none of which are
//! part of this port), each overriding `getNoteTypeName()`/`toStructure(DataTypeManager)` (and, in
//! `NoteGnuBuildId`'s case, nothing else). Per this crate's shape rules for a Java abstract-in-
//! practice class carrying both state and overridable behavior, this is split into
//! [`ElfNoteBase`] (the shared `nameLen`/`name`/`vendorType`/`description` fields plus every
//! concrete method) and the [`ElfNote`] trait (the overridable operations, each given a default
//! matching this base class's own behavior, exactly as a future concrete subclass would inherit
//! it unless it overrides).
//!
//! [`ElfNoteBase`] itself directly implements [`ElfInfoItem`] (using its own default
//! `note_type_name`/`note_value_string`/`program_info_key`/`to_structure`), reproducing what
//! calling `markupProgram` on a bare (non-subclassed) `ElfNote` instance does in Java -- this lets
//! it satisfy [`read_item_from_section`]'s `T: ElfInfoItem` bound directly, so
//! [`read_from_program_helper`] can reuse that existing helper instead of re-implementing the
//! memory-block/reader setup it already does.
//!
//! `getNoteTypeName`/`getNoteValueString`/`getProgramInfoKey`/`markupProgram` share a name with
//! [`ElfNoteBase`]'s own inherent methods of the same shape; to keep call sites (and the shared
//! [`markup_elf_note`] helper both funnel through) unambiguous, the trait's overridable/virtual
//! operations are declared under their Java names as *trait* methods (`get_note_type_name`, etc.)
//! while [`ElfNoteBase`] exposes the identical default behavior under matching inherent method
//! names -- there is no naming clash because one set lives on the trait and the other on the
//! struct, and [`ElfNoteBase::elf_note_markup_program`] is named distinctly from the
//! [`ElfInfoItem::markup_program`] it implements to avoid the same self-referential-default
//! ambiguity documented throughout this crate (see e.g. `DynamicDataType`'s module docs).
//!
//! `NoteReaderFunc<T extends ElfNote>` (the `@FunctionalInterface` used by
//! `readFromProgramHelper`) has no direct Rust equivalent -- a plain `FnOnce(&ElfNoteBase, &dyn
//! Program) -> io::Result<T>` closure parameter on [`read_from_program_helper`] fills its role
//! idiomatically.
//!
//! `toStructure`'s `StructureDataType` return type has no concrete production port yet in this
//! crate (`Structure`/`Composite` are real traits, but the mutable *builder* class itself is still
//! `TODO`); rather than adding a third/fourth sibling placeholder, this reuses the existing
//! minimal placeholder at [`crate::sarif::seam_stubs::StructureDataType`] (built for
//! `DataTypesSarifMgr`'s identical need: construct-then-`add()` a structure before the real
//! builder exists). Its constructor drops the `DataTypeManager` parameter (never used for
//! anything the crate can do yet), matching the same drop already established for
//! `AndroidElfRelocationData`/`AndroidElfRelocationGroup`.
//!
//! `createNoteStructure`'s three field types (`DWordDataType`, `StringDataType.dataType`, `new
//! ArrayDataType(BYTE, ...)`) are each still trait-only cut points in this crate (no general
//! concrete singleton exists yet, only `Mock*` test types) -- mirroring the crate's own
//! `BytePlaceholderDataType`/`WordPlaceholderDataType`/`FallbackStringUtf8DataType` precedent for
//! this exact situation, minimal private stand-ins ([`DWordPlaceholderDataType`],
//! [`StringPlaceholderDataType`], [`ByteArrayPlaceholderDataType`]) are used instead of a full
//! port of any of those general-purpose singletons.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::elf::info::elf_info_item::{read_item_from_section, ElfInfoItem};
use crate::framework::options::Options;
use crate::program::model::address::Address;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::sarif::seam_stubs::StructureDataType;
use crate::util::msg::Msg;
use crate::util::seam_stubs::NumericUtilities;

/// Port of `ElfNote.MAX_SANE_NAME_LEN`.
const MAX_SANE_NAME_LEN: u32 = 1024;
/// Port of `ElfNote.MAX_SANE_DESC_LEN`.
const MAX_SANE_DESC_LEN: u32 = 1024 * 1024;

/// Minimal stand-in for `ghidra.program.model.data.DWordDataType.dataType`, used for the
/// `namesz`/`descsz`/`type` fields of [`create_note_structure`]. See the module docs for why the
/// real (trait-only) `DWordDataType` cut point cannot be constructed generically yet.
struct DWordPlaceholderDataType;

impl DataType for DWordPlaceholderDataType {
    fn get_name(&self) -> String {
        "dword".to_string()
    }
    fn get_length(&self) -> i32 {
        4
    }
}

/// Minimal stand-in for `ghidra.program.model.data.StringDataType.dataType`, used for the `name`
/// field of [`create_note_structure`]. See the module docs for why the real (trait-only)
/// `StringDataType` cut point cannot be constructed generically yet.
struct StringPlaceholderDataType;

impl DataType for StringPlaceholderDataType {
    fn get_name(&self) -> String {
        "string".to_string()
    }
    fn get_length(&self) -> i32 {
        -1
    }
}

/// Minimal stand-in for `new ArrayDataType(BYTE, noteDescLen, BYTE.getLength(), dtm)`, used for
/// the `description` field of [`create_note_structure`]. See the module docs for why the real
/// `ArrayDataType` element type (`ByteDataType`, itself a trait-only cut point) cannot be
/// constructed generically yet.
struct ByteArrayPlaceholderDataType {
    length: i32,
}

impl DataType for ByteArrayPlaceholderDataType {
    fn get_name(&self) -> String {
        format!("byte[{}]", self.length.max(0))
    }
    fn get_length(&self) -> i32 {
        self.length
    }
}

/// Zero-sized marker used purely to call the defaulted trait methods of [`DataUtilities`],
/// mirroring the identical marker in `elf_comment.rs`/`read_only_data_type_component.rs`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataUtilities for Utils {}

/// Minimal stand-in for `StandardElfInfoProducer.ELF_CATEGORYPATH` (`new CategoryPath("/ELF")`).
/// `StandardElfInfoProducer` itself is not yet ported; only this one constant value is needed
/// here, so the whole class is not stubbed out for it.
fn elf_category_path() -> CategoryPath {
    CategoryPath::parse("/ELF").expect("\"/ELF\" is a valid category path")
}

/// Builds the `StructureDataType` layout shared by [`ElfNoteBase`] and any [`ElfNote`]
/// implementor's default [`ElfNote::to_structure`].
///
/// Port of the protected static `ElfNote.createNoteStructure(CategoryPath, String, boolean, int,
/// int, DataTypeManager)`, minus the dropped `DataTypeManager` parameter (see the module docs).
fn create_note_structure(
    cp: Option<CategoryPath>,
    struct_name: &str,
    templated_name: bool,
    note_name_len: i32,
    note_desc_len: i32,
) -> StructureDataType {
    let name = if templated_name {
        format!("{struct_name}_{note_name_len}_{note_desc_len}")
    } else {
        struct_name.to_string()
    };
    let cp = cp.unwrap_or_else(elf_category_path);

    let mut result = StructureDataType::new(cp, &name, 0);
    result.add(
        Arc::new(DWordPlaceholderDataType),
        4,
        Some("namesz".to_string()),
        Some("Length of name field".to_string()),
    );
    result.add(
        Arc::new(DWordPlaceholderDataType),
        4,
        Some("descsz".to_string()),
        Some("Length of description field".to_string()),
    );
    result.add(
        Arc::new(DWordPlaceholderDataType),
        4,
        Some("type".to_string()),
        Some("Vendor specific type".to_string()),
    );
    if note_name_len > 0 {
        result.add(
            Arc::new(StringPlaceholderDataType),
            note_name_len,
            Some("name".to_string()),
            Some("Vendor name".to_string()),
        );
    }
    if note_desc_len > 0 {
        result.add(
            Arc::new(ByteArrayPlaceholderDataType { length: note_desc_len }),
            note_desc_len,
            Some("description".to_string()),
            Some("Blob value".to_string()),
        );
    }
    result
}

/// Shared body of `ElfNote.markupProgram(Program, Address)`, funneled through by both
/// [`ElfNoteBase::elf_note_markup_program`] and [`ElfNote::elf_note_markup_program`] with their
/// respective (possibly overridden) `note_value_string`/`program_info_key`/`to_structure` values.
fn markup_elf_note(
    program_info_key: &str,
    note_value_string: &str,
    structure: Option<StructureDataType>,
    program: &mut dyn Program,
    address: &Address,
) {
    let mut options = program.get_options(PROGRAM_INFO);
    options.set_string(&program_info_key.replace('.', "_"), note_value_string);

    if let Some(dt) = structure {
        let utils = Utils;
        if let Err(e) = utils.create_data(
            program,
            address,
            Box::new(dt),
            -1,
            ClearDataMode::ClearAllUndefinedConflictData,
        ) {
            Msg::error("ElfNote", &format!("Failed to markup Elf Note at {address}: {e}"));
        }
    }
}

/// A [`BinaryReader`] backed by an owned `Vec<u8>`, used by
/// [`ElfNoteBase::get_description_reader`] to mirror Java's `new BinaryReader(new
/// ByteArrayProvider(description), isLittleEndian)`. Kept private/local: `ByteArrayProvider` has
/// no concrete production port yet either (see the module docs' `ArrayDataType`/`DWordDataType`
/// note for the same situation with a different family of types).
struct VecByteProvider(Vec<u8>);

impl ByteProvider for VecByteProvider {
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
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "index out of range"))
    }
    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let start = index as usize;
        let end = start + length;
        self.0
            .get(start..end)
            .map(|s| s.to_vec())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range out of bounds"))
    }
    fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
        *self
            .0
            .get_mut(index as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "index out of range"))? = value;
        Ok(())
    }
    fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
        let start = index as usize;
        for (i, &b) in values.iter().enumerate() {
            *self
                .0
                .get_mut(start + i)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range out of bounds"))? = b;
        }
        Ok(())
    }
}

struct ByteArrayBinaryReader {
    provider: Rc<RefCell<VecByteProvider>>,
    is_little_endian: bool,
    current_index: u64,
}

impl BinaryReader for ByteArrayBinaryReader {
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
        let previous = self.current_index;
        self.current_index = index;
        previous
    }
    fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }
    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
    }
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.borrow_mut().read_byte(index)
    }
    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        self.provider.borrow_mut().read_bytes(index, n_elements)
    }
    fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::clone(&self.provider) as Rc<RefCell<dyn ByteProvider>>
    }
    fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
        Box::new(ByteArrayBinaryReader {
            provider: Rc::clone(&self.provider),
            is_little_endian: self.is_little_endian,
            current_index: new_index,
        })
    }
}

/// Shared state and concrete behavior of `ghidra.app.util.bin.format.elf.info.ElfNote`.
///
/// Port of the Java class's fields (`nameLen`/`name`/`vendorType`/`description`) and every
/// concrete (non-overridden) method. See the module docs for the struct/trait split rationale.
pub struct ElfNoteBase {
    name_len: i32,
    name: String,
    vendor_type: i32,
    description: Option<Vec<u8>>,
}

impl ElfNoteBase {
    /// Port of `ElfNote(int, String, int, byte[])`.
    pub fn new(name_len: i32, name: String, vendor_type: i32, description: Option<Vec<u8>>) -> Self {
        ElfNoteBase { name_len, name, vendor_type, description }
    }

    /// Port of `ElfNote(int, String, int)`, which forwards to the 4-arg constructor with a `null`
    /// description.
    pub fn without_description(name_len: i32, name: String, vendor_type: i32) -> Self {
        ElfNoteBase::new(name_len, name, vendor_type, None)
    }

    /// Reads a generic [`ElfNoteBase`] instance from the supplied [`BinaryReader`].
    ///
    /// Port of the static `ElfNote.read(BinaryReader)`.
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let mut name_len = reader.read_next_unsigned_int_exact()?;
        let desc_len = reader.read_next_unsigned_int_exact()?;
        let vendor_type = reader.read_next_int()?;
        if name_len > MAX_SANE_NAME_LEN || desc_len > MAX_SANE_DESC_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid Note lengths: {name_len}, {desc_len}"),
            ));
        }
        let name = reader.read_next_ascii_string_fixed(name_len as usize)?;
        name_len += reader.align(4) as u32;

        let desc = reader.read_next_byte_array(desc_len as usize)?;

        Ok(ElfNoteBase::new(name_len as i32, name, vendor_type, Some(desc)))
    }

    /// A helper for `read()` methods defined in specific Note types to attempt to read a specific
    /// Note type from a Program.
    ///
    /// Port of the protected static `ElfNote.readFromProgramHelper(Program, String,
    /// NoteReaderFunc)`. See the module docs for why `NoteReaderFunc` is just a closure here.
    pub fn read_from_program_helper<T>(
        program: &dyn Program,
        section_name: &str,
        reader_func: impl FnOnce(&ElfNoteBase, &dyn Program) -> io::Result<T>,
    ) -> Option<T> {
        let wrapped = read_item_from_section::<ElfNoteBase>(program, section_name, |br, _p| ElfNoteBase::read(br))?;
        reader_func(&wrapped.item, program).ok()
    }

    /// Shortcut test of `name == "GNU"`. Port of `ElfNote.isGnu()`.
    pub fn is_gnu(&self) -> bool {
        self.name == "GNU"
    }

    /// Port of `ElfNote.getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Port of `ElfNote.getNameLen()`.
    pub fn get_name_len(&self) -> i32 {
        self.name_len
    }

    /// Port of `ElfNote.getDescription()`.
    pub fn get_description(&self) -> Option<&[u8]> {
        self.description.as_deref()
    }

    /// Port of `ElfNote.getDescriptionLen()`.
    pub fn get_description_len(&self) -> i32 {
        self.description.as_ref().map_or(0, |d| d.len() as i32)
    }

    /// Port of `ElfNote.getDescriptionAsHexString()`. Returns an empty string when there is no
    /// description, rather than Java's `NullPointerException` from
    /// `NumericUtilities.convertBytesToString(null)` -- `ElfNote.read()` always supplies a
    /// description, so this only matters for a note built via
    /// [`without_description`](Self::without_description).
    pub fn get_description_as_hex_string(&self) -> String {
        match &self.description {
            Some(d) => NumericUtilities::convert_bytes_to_string(d, ""),
            None => String::new(),
        }
    }

    /// Returns a [`BinaryReader`] that reads from this note's description blob.
    ///
    /// Port of `ElfNote.getDescriptionReader(boolean)`.
    pub fn get_description_reader(&self, is_little_endian: bool) -> Box<dyn BinaryReader> {
        let provider = VecByteProvider(self.description.clone().unwrap_or_default());
        Box::new(ByteArrayBinaryReader {
            provider: Rc::new(RefCell::new(provider)),
            is_little_endian,
            current_index: 0,
        })
    }

    /// Port of `ElfNote.getVendorType()`.
    pub fn get_vendor_type(&self) -> i32 {
        self.vendor_type
    }

    /// Port of `ElfNote.getNoteTypeName()`'s default (non-overridden) behavior.
    pub fn note_type_name(&self) -> String {
        format!("{}, {}", self.name, self.vendor_type)
    }

    /// Port of `ElfNote.getNoteValueString()`'s default (non-overridden) behavior.
    pub fn note_value_string(&self) -> String {
        self.get_description_as_hex_string()
    }

    /// Port of `ElfNote.getProgramInfoKey()`'s default (non-overridden) behavior.
    pub fn program_info_key(&self) -> String {
        format!("ELF Note[{}]", self.note_type_name())
    }

    /// Port of `ElfNote.decorateProgramInfo(Options)`.
    pub fn decorate_program_info(&self, options: &mut dyn Options) {
        options.set_string(&self.program_info_key().replace('.', "_"), &self.note_value_string());
    }

    /// Port of `ElfNote.toStructure(DataTypeManager)`'s default (non-overridden) behavior. See
    /// the module docs for the dropped `DataTypeManager` parameter.
    pub fn to_structure(&self) -> Option<StructureDataType> {
        Some(create_note_structure(
            Some(elf_category_path()),
            "ElfNote",
            true,
            self.get_name_len(),
            self.get_description_len(),
        ))
    }

    /// Port of `ElfNote.markupProgram(Program, Address)`'s default (non-overridden) behavior.
    /// Named distinctly from [`ElfInfoItem::markup_program`] (which delegates to this) to avoid
    /// the self-referential-default ambiguity documented throughout this crate.
    pub fn elf_note_markup_program(&self, program: &mut dyn Program, address: &Address) {
        markup_elf_note(
            &self.program_info_key(),
            &self.note_value_string(),
            self.to_structure(),
            program,
            address,
        );
    }
}

impl ElfInfoItem for ElfNoteBase {
    fn markup_program(&self, program: &mut dyn Program, address: &Address) {
        self.elf_note_markup_program(program, address);
    }
}

/// Overridable operations of `ghidra.app.util.bin.format.elf.info.ElfNote`.
///
/// See the module docs for the struct/trait split rationale. Every default here reproduces
/// [`ElfNoteBase`]'s own (non-overridden) behavior exactly, via the required
/// [`elf_note_base`](Self::elf_note_base) accessor -- a concrete subclass overrides only the
/// methods it needs, exactly as in Java.
pub trait ElfNote: ElfInfoItem {
    /// Backing storage access, mirroring the `{name}_base` accessor convention used elsewhere in
    /// this crate for the identical struct/trait split (see e.g. `JobBase`/`Job::job_base`).
    fn elf_note_base(&self) -> &ElfNoteBase;

    /// Port of `ElfNote.getNoteTypeName()`.
    fn get_note_type_name(&self) -> String {
        self.elf_note_base().note_type_name()
    }

    /// Port of `ElfNote.getNoteValueString()`.
    fn get_note_value_string(&self) -> String {
        self.elf_note_base().note_value_string()
    }

    /// Port of `ElfNote.getProgramInfoKey()`.
    fn get_program_info_key(&self) -> String {
        format!("ELF Note[{}]", self.get_note_type_name())
    }

    /// Port of `ElfNote.toStructure(DataTypeManager)`. See the module docs for the dropped
    /// `DataTypeManager` parameter.
    fn to_structure(&self) -> Option<StructureDataType> {
        Some(create_note_structure(
            Some(elf_category_path()),
            "ElfNote",
            true,
            self.elf_note_base().get_name_len(),
            self.elf_note_base().get_description_len(),
        ))
    }

    /// Port of `ElfNote.markupProgram(Program, Address)`. A concrete implementor's
    /// `ElfInfoItem::markup_program` should delegate to this (see the module docs for why it is
    /// not declared under that name directly).
    fn elf_note_markup_program(&self, program: &mut dyn Program, address: &Address) {
        markup_elf_note(
            &self.get_program_info_key(),
            &self.get_note_value_string(),
            self.to_structure(),
            program,
            address,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_object::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn bytes_reader(bytes: Vec<u8>) -> ByteArrayBinaryReader {
        ByteArrayBinaryReader {
            provider: Rc::new(RefCell::new(VecByteProvider(bytes))),
            is_little_endian: true,
            current_index: 0,
        }
    }

    /// Encodes a minimal GNU-style note record: `namesz`, `descsz`, `type`, the name (padded to a
    /// 4-byte boundary), then the description bytes -- matching the layout `ElfNote::read`
    /// expects, and the same shape a real `.note.*` ELF section uses.
    fn encode_note(name: &str, vendor_type: i32, description: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend((name.len() as u32 + 1).to_le_bytes()); // namesz (name + NUL)
        bytes.extend((description.len() as u32).to_le_bytes()); // descsz
        bytes.extend(vendor_type.to_le_bytes()); // type
        bytes.extend(name.as_bytes());
        bytes.push(0); // NUL terminator included in namesz
        while bytes.len() % 4 != 0 {
            bytes.push(0); // padding to 4-byte alignment
        }
        bytes.extend(description);
        bytes
    }

    #[test]
    fn read_decodes_a_gnu_style_note() {
        let bytes = encode_note("GNU", 3, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut reader = bytes_reader(bytes);
        let note = ElfNoteBase::read(&mut reader).unwrap();

        assert!(note.is_gnu());
        assert_eq!(note.get_vendor_type(), 3);
        assert_eq!(note.get_description(), Some([0xDE, 0xAD, 0xBE, 0xEF].as_slice()));
        // "GNU\0" is 4 bytes already 4-byte aligned, so align(4) adds nothing.
        assert_eq!(note.get_name_len(), 4);
    }

    #[test]
    fn read_pads_name_len_to_four_byte_boundary() {
        // "AB\0" is 3 bytes -- not 4-byte aligned, so align(4) should add 1.
        let bytes = encode_note("AB", 0, &[]);
        let mut reader = bytes_reader(bytes);
        let note = ElfNoteBase::read(&mut reader).unwrap();
        assert_eq!(note.get_name_len(), 4);
        assert_eq!(note.get_name(), "AB");
    }

    #[test]
    fn read_rejects_insane_lengths() {
        let mut bytes = Vec::new();
        bytes.extend((MAX_SANE_NAME_LEN + 1).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0i32.to_le_bytes());
        let mut reader = bytes_reader(bytes);
        assert!(ElfNoteBase::read(&mut reader).is_err());
    }

    #[test]
    fn is_gnu_matches_only_the_exact_name() {
        assert!(ElfNoteBase::without_description(0, "GNU".to_string(), 0).is_gnu());
        assert!(!ElfNoteBase::without_description(0, "gnu".to_string(), 0).is_gnu());
        assert!(!ElfNoteBase::without_description(0, "Go".to_string(), 0).is_gnu());
    }

    #[test]
    fn description_as_hex_string_matches_java_format() {
        let note = ElfNoteBase::new(0, "GNU".to_string(), 0, Some(vec![0x0a, 0xff, 0x42]));
        assert_eq!(note.get_description_as_hex_string(), "0aff42");
        assert_eq!(note.get_description_len(), 3);
    }

    #[test]
    fn description_as_hex_string_is_empty_without_a_description() {
        let note = ElfNoteBase::without_description(0, "GNU".to_string(), 0);
        assert_eq!(note.get_description_as_hex_string(), "");
        assert_eq!(note.get_description_len(), 0);
    }

    #[test]
    fn note_type_name_and_program_info_key_match_java_defaults() {
        let note = ElfNoteBase::new(4, "GNU".to_string(), 3, Some(vec![0xAB]));
        assert_eq!(note.note_type_name(), "GNU, 3");
        assert_eq!(note.program_info_key(), "ELF Note[GNU, 3]");
    }

    #[test]
    fn description_reader_reads_back_the_stashed_bytes() {
        let note = ElfNoteBase::new(0, "GNU".to_string(), 0, Some(vec![0x01, 0x02, 0x03, 0x04]));
        let mut reader = note.get_description_reader(true);
        assert_eq!(reader.read_next_unsigned_int_exact().unwrap(), 0x04030201);
    }

    /// A concrete [`ElfNote`] implementor overriding only `get_note_type_name` (mirroring
    /// `NoteGnuBuildId`'s override shape), to confirm the trait's other defaults still fall
    /// through to [`ElfNoteBase`]'s behavior and that `elf_note_markup_program` picks up the
    /// override.
    struct OverridingNote(ElfNoteBase);

    impl ElfInfoItem for OverridingNote {
        fn markup_program(&self, program: &mut dyn Program, address: &Address) {
            self.elf_note_markup_program(program, address);
        }
    }

    impl ElfNote for OverridingNote {
        fn elf_note_base(&self) -> &ElfNoteBase {
            &self.0
        }

        fn get_note_type_name(&self) -> String {
            "Overridden".to_string()
        }
    }

    #[test]
    fn trait_default_program_info_key_uses_the_override() {
        let note = OverridingNote(ElfNoteBase::new(0, "GNU".to_string(), 1, Some(vec![0xAB])));
        assert_eq!(note.get_program_info_key(), "ELF Note[Overridden]");
        // Non-overridden default still delegates to the base.
        assert_eq!(note.get_note_value_string(), "ab");
    }

    struct FakeOptions {
        values: std::collections::HashMap<String, String>,
    }

    impl Options for FakeOptions {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn set_string(&mut self, option_name: &str, value: &str) {
            self.values.insert(option_name.to_string(), value.to_string());
        }
    }

    struct FakeProgram {
        options: FakeOptions,
    }

    impl DomainObject for FakeProgram {
        fn get_options(&self, _property_list_name: &str) -> Box<dyn Options> {
            // A real `Program`'s `get_options` returns a *connected* view; this fake just hands
            // back a disconnected snapshot copy, sufficient to observe what `decorate_program_info`
            // sets without needing full DB-backed Options plumbing.
            Box::new(FakeOptions { values: self.options.values.clone() })
        }
    }

    impl Program for FakeProgram {
        fn get_name(&self) -> String {
            "fake".to_string()
        }
        fn get_language_id(&self) -> String {
            "fake".to_string()
        }
    }

    #[test]
    fn decorate_program_info_replaces_dots_with_underscores() {
        let note = ElfNoteBase::new(0, "GNU.x".to_string(), 0, Some(vec![0xAB]));
        let mut options = FakeOptions { values: Default::default() };
        note.decorate_program_info(&mut options);
        assert_eq!(options.values.get("ELF Note[GNU_x, 0]"), Some(&"ab".to_string()));
    }

    #[test]
    fn base_note_is_usable_as_elf_info_item() {
        let note = ElfNoteBase::new(0, "GNU".to_string(), 0, Some(vec![0xAB]));
        let mut program = FakeProgram { options: FakeOptions { values: Default::default() } };
        let addr = ram_space().address(0);
        let item: &dyn ElfInfoItem = &note;
        // Should not panic; exercises the full markup_program -> markup_elf_note path (including
        // the `create_data`/`Utils` call, which will fail gracefully since `FakeProgram` has no
        // listing -- matching Java's own catch-and-log behavior on failure).
        item.markup_program(&mut program, &addr);
    }
}
