//! Port of `ghidra.app.util.bin.format.golang.GoBuildId`.

use std::io::{self, Read};
use std::rc::Rc;
use std::sync::Arc;

use super::go_constants::GOLANG_CATEGORYPATH;
use super::rtti::go_rtti_mapper;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::memory_byte_provider::MemoryByteProvider;
use crate::format::elf::info::elf_info_item::ItemWithAddress;
use crate::program::model::address::Address;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::program::model::mem::MemoryBlock;
use crate::program::seam_stubs::share_data_type;
use crate::util::msg::Msg;


use super::note_go_build_id::PROGRAM_INFO_KEY;

/// `"\xff Go build ID: \""`.
const GO_BUILDID_MAGIC: &[u8; 16] = b"\xff Go build ID: \"";
/// `"\"\n \xff"`.
const GO_BUILDID_TRAILING_MAGIC: &[u8; 4] = b"\"\n \xff";
const BUILDID_STR_LEN: usize = 83;

struct GoDataUtil;
impl DataUtilities for GoDataUtil {}

/// The Go build id string embedded at the start of the `.text` section of Go binaries (used when
/// the ELF note is missing, eg. in PE binaries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBuildId {
    build_id: String,
}

impl GoBuildId {
    /// Searches the Go `text` section for the build id (`findBuildId(Program)`).
    pub fn find_build_id(program: &dyn Program) -> Option<ItemWithAddress<GoBuildId>> {
        let txt_block = go_rtti_mapper::get_go_section(program, "text");
        read_item_from_section(program, txt_block.as_deref())
    }

    /// Reads the build id string at the reader's position, `None` if the magic values don't
    /// match or the read fails (`read(BinaryReader, Program)`).
    pub fn read(br: &mut BinaryReader) -> Option<GoBuildId> {
        let magic = br.read_next_byte_array(GO_BUILDID_MAGIC.len()).ok()?;
        if magic.as_slice() != GO_BUILDID_MAGIC {
            return None;
        }
        let build_id_str = br.read_next_ascii_string_fixed(BUILDID_STR_LEN).ok()?;
        let trailing_magic = br.read_next_byte_array(GO_BUILDID_TRAILING_MAGIC.len()).ok()?;
        if trailing_magic.as_slice() != GO_BUILDID_TRAILING_MAGIC {
            return None;
        }
        Some(GoBuildId::new(build_id_str))
    }

    /// Reads the build id from the start of a stream (`read(InputStream)`).
    pub fn read_stream(is: &mut dyn Read) -> Option<GoBuildId> {
        let mut buffer = vec![0u8; GO_BUILDID_MAGIC.len() + BUILDID_STR_LEN + GO_BUILDID_TRAILING_MAGIC.len()];
        // Java: a single is.read(buffer) that must fill the buffer
        let bytes_read = is.read(&mut buffer).ok()?;
        if bytes_read != buffer.len() {
            return None;
        }
        Self::read(&mut BinaryReader::from_bytes(buffer, false /* doesn't matter */))
    }

    /// `GoBuildId(String)`.
    pub fn new(build_id: impl Into<String>) -> Self {
        GoBuildId { build_id: build_id.into() }
    }

    /// `getBuildId()`.
    pub fn get_build_id(&self) -> &str {
        &self.build_id
    }

    /// Records the build id in the program info and lays down its structure
    /// (`markupProgram(Program, Address)`).
    pub fn markup_program(&self, program: &dyn Program, address: &Address) {
        program.get_options(PROGRAM_INFO).set_string(PROGRAM_INFO_KEY, self.get_build_id());

        let dtm = program.get_data_type_manager();
        let Ok(structure) = self.to_structure(dtm.as_deref()) else {
            return;
        };
        if GoDataUtil
            .create_data(program, address, Box::new(structure), -1, ClearDataMode::ClearAllDefaultConflictData)
            .is_err()
        {
            Msg::error("GoBuildId", &format!("Failed to markup GoBuildId at {address}: {self:?}"));
        }
    }

    fn to_structure(&self, dtm: Option<&dyn DataTypeManager>) -> Result<StructureDataType, String> {
        let mut result = StructureDataType::with_manager(GOLANG_CATEGORYPATH.clone(), "GoBuildId", 0, dtm);
        let string_dt: Arc<dyn DataType> = StringDataType::data_type();
        for (len, name) in [
            (GO_BUILDID_MAGIC.len(), "magic"),
            (BUILDID_STR_LEN, "buildId"),
            (GO_BUILDID_TRAILING_MAGIC.len(), "trailing_magic"),
        ] {
            result.add_with_length_and_name(share_data_type(&string_dt), len as i32, Some(name.to_string()), None)?;
        }
        Ok(result)
    }
}

/// `readItemFromSection(Program, MemoryBlock, ReaderFunc)`: reads the build id at the start of
/// the block.
fn read_item_from_section(program: &dyn Program, mem_block: Option<&dyn MemoryBlock>) -> Option<ItemWithAddress<GoBuildId>> {
    let mem_block = mem_block?;
    let memory = program.get_memory()?;
    let big_endian = memory.is_big_endian();
    let bp = MemoryByteProvider::create_memory_block_byte_provider(memory, mem_block);
    let mut br = BinaryReader::new(Rc::new(bp), !big_endian);
    let item = GoBuildId::read(&mut br)?;
    Some(ItemWithAddress { item, address: mem_block.get_start() })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD_ID: &str =
        "q9hSEHp2rBl4Y1vbRx5y/3n0RuDLVSlKHfTIDeFsh/tY3JWS0Pn2EEuOqGkpby/wHxRhmEw0MCOw6lrr9Wv";

    fn build_id_bytes(id: &str) -> Vec<u8> {
        let mut v = GO_BUILDID_MAGIC.to_vec();
        v.extend_from_slice(id.as_bytes());
        v.extend_from_slice(GO_BUILDID_TRAILING_MAGIC);
        v
    }

    #[test]
    fn reads_text_section_build_id() {
        assert_eq!(BUILD_ID.len(), BUILDID_STR_LEN);
        let mut bytes = build_id_bytes(BUILD_ID);
        bytes.extend_from_slice(&[0xcc; 8]); // following code
        let mut br = BinaryReader::from_bytes(bytes.clone(), true);
        let id = GoBuildId::read(&mut br).unwrap();
        assert_eq!(id.get_build_id(), BUILD_ID);
        assert_eq!(br.get_pointer_index() as usize, 16 + 83 + 4);

        let from_stream = GoBuildId::read_stream(&mut bytes.as_slice()).unwrap();
        assert_eq!(from_stream, id);
    }

    #[test]
    fn rejects_bad_magic_and_short_input() {
        let mut bytes = build_id_bytes(BUILD_ID);
        bytes[2] = b'g';
        assert!(GoBuildId::read(&mut BinaryReader::from_bytes(bytes, true)).is_none());

        let mut bytes = build_id_bytes(BUILD_ID);
        let n = bytes.len();
        bytes[n - 1] = 0;
        assert!(GoBuildId::read(&mut BinaryReader::from_bytes(bytes, true)).is_none());

        assert!(GoBuildId::read_stream(&mut &build_id_bytes(BUILD_ID)[..50]).is_none());
    }

    #[test]
    fn structure_layout() {
        let s = GoBuildId::new(BUILD_ID).to_structure(None).unwrap();
        assert_eq!(s.get_name(), "GoBuildId");
        assert_eq!(s.get_length(), 16 + 83 + 4);
        let names: Vec<Option<String>> = s.get_defined_components().iter().map(|c| c.get_field_name()).collect();
        assert_eq!(names, [Some("magic".into()), Some("buildId".into()), Some("trailing_magic".into())]);
    }
}
