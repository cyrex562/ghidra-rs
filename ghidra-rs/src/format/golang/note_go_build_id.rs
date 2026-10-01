//! Port of `ghidra.app.util.bin.format.golang.NoteGoBuildId`.

use std::io;

use super::go_constants::GOLANG_CATEGORYPATH;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::elf::info::elf_info_item::ElfInfoItem;
use crate::format::elf::info::elf_note::{create_note_structure, ElfNote, ElfNoteBase};
use crate::program::model::address::Address;
use crate::program::model::data::string_utf8_data_type::StringUTF8DataType;
use crate::program::model::listing::Program;
use crate::sarif::seam_stubs::StructureDataType;

/// `SECTION_NAME`.
pub const SECTION_NAME: &str = ".note.go.buildid";
/// `PROGRAM_INFO_KEY`.
pub const PROGRAM_INFO_KEY: &str = "Golang BuildId";

/// An ELF note that specifies the Go build-id.
///
/// `toStructure` builds on [`create_note_structure`], which (like the rest of the `ElfNote`
/// port) still produces the sarif `StructureDataType` stand-in.
pub struct NoteGoBuildId {
    base: ElfNoteBase,
}

impl NoteGoBuildId {
    /// Reads a `NoteGoBuildId` from the reader (`read(BinaryReader, Program)`; the program is
    /// unused).
    ///
    /// # Errors
    /// Error reading the note, or a note not named `"Go"`.
    pub fn read(br: &mut BinaryReader, _unused_program: Option<&dyn Program>) -> io::Result<NoteGoBuildId> {
        let note = ElfNoteBase::read(br)?;
        if note.get_name() != "Go" {
            return Err(io::Error::other(format!("Invalid note name: {}", note.get_name())));
        }
        Ok(NoteGoBuildId { base: note })
    }

    /// `NoteGoBuildId(int, String, int, byte[])`.
    pub fn new(name_len: i32, name: String, vendor_type: i32, description: Vec<u8>) -> Self {
        NoteGoBuildId { base: ElfNoteBase::new(name_len, name, vendor_type, Some(description)) }
    }

    /// The Go buildid value (`getBuildId()`).
    pub fn get_build_id(&self) -> String {
        String::from_utf8_lossy(self.base.get_description().unwrap_or(&[])).to_string()
    }
}

impl ElfNote for NoteGoBuildId {
    fn elf_note_base(&self) -> &ElfNoteBase {
        &self.base
    }

    fn get_note_type_name(&self) -> String {
        SECTION_NAME.to_string()
    }

    fn get_program_info_key(&self) -> String {
        PROGRAM_INFO_KEY.to_string()
    }

    fn get_note_value_string(&self) -> String {
        self.get_build_id()
    }

    fn to_structure(&self) -> Option<StructureDataType> {
        let desc_len = self.base.get_description_len();
        let mut structure = create_note_structure(
            Some(GOLANG_CATEGORYPATH.clone()),
            &format!("NoteGoBuildId_{desc_len}"),
            false,
            self.base.get_name_len(),
            0,
        );
        structure.add(StringUTF8DataType::data_type(), desc_len, Some("BuildId".to_string()), None);
        Some(structure)
    }
}

impl ElfInfoItem for NoteGoBuildId {
    fn markup_program(&self, program: &mut dyn Program, address: &Address) {
        self.elf_note_markup_program(program, address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;

    /// A `.note.go.buildid` note: namesz=4 ("Go\0\0"), descsz, type=4, then the build id.
    fn note_bytes(build_id: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&(build_id.len() as u32).to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(b"Go\0\0");
        v.extend_from_slice(build_id.as_bytes());
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn reads_go_build_id_note() {
        let id = "q9hSEHp2rBl4Y1vbRx5y/3n0RuDLVSlKHfTIDeFsh/tY3JWS0Pn2EEuOqGkpby/wHxRhmEw0MCOw6lrr9Wv";
        let mut br = BinaryReader::from_bytes(note_bytes(id), true);
        let note = NoteGoBuildId::read(&mut br, None).unwrap();
        assert_eq!(note.get_build_id(), id);
        assert_eq!(note.get_note_type_name(), ".note.go.buildid");
        assert_eq!(note.get_program_info_key(), "Golang BuildId");
        assert_eq!(note.get_note_value_string(), id);
        let s = note.to_structure().unwrap();
        assert_eq!(s.get_name(), format!("NoteGoBuildId_{}", id.len()));
        // namesz + descsz + type + name(4) + BuildId
        assert_eq!(s.get_length(), 12 + 4 + id.len() as i32);
    }

    #[test]
    fn rejects_non_go_note() {
        let mut bytes = note_bytes("abc");
        bytes[12] = b'X';
        let err = NoteGoBuildId::read(&mut BinaryReader::from_bytes(bytes, true), None).err().unwrap();
        assert!(err.to_string().starts_with("Invalid note name: "), "{err}");
    }
}
