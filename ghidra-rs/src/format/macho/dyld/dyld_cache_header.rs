//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader`.
//!
//! Represents a `dyld_cache_header` structure and the tables it locates (mappings, images,
//! local symbols, branch pools, image text info, subcaches, mapping-and-slide info, slide info and
//! accelerator info). See `dyld3/shared-cache/dyld_cache_format.h`.
//!
//! The header has grown over many DYLD versions: each field after `dyldBaseAddress` is present
//! only if the header (which ends where the mapping table begins) is long enough to hold it, and
//! [`to_structure`](DyldCacheHeader::to_structure) lays down only the fields that were present.
//!
//! Java keeps the `MemoryBlock` handed to `setFileBlock`; only its address space is ever used
//! (to place file offsets that no mapping covers), so that is what this port keeps.

use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::dyld::dyld_architecture::DyldArchitecture;
use crate::format::macho::dyld::dyld_cache_accelerate_info::DyldCacheAccelerateInfo;
use crate::format::macho::dyld::dyld_cache_image::DyldCacheImage;
use crate::format::macho::dyld::dyld_cache_image_info::DyldCacheImageInfo;
use crate::format::macho::dyld::dyld_cache_image_text_info::DyldCacheImageTextInfo;
use crate::format::macho::dyld::dyld_cache_local_symbols_info::DyldCacheLocalSymbolsInfo;
use crate::format::macho::dyld::dyld_cache_mapping_and_slide_info::DyldCacheMappingAndSlideInfo;
use crate::format::macho::dyld::dyld_cache_mapping_info::DyldCacheMappingInfo;
use crate::format::macho::dyld::dyld_cache_slide_info_common::{
    parse_slide_info, DyldCacheSlideInfoCommon, MemoryRangeByteProvider, DATA_PAGE_MAP_ENTRY,
};
use crate::format::macho::dyld::dyld_subcache_entry::DyldSubcacheEntry;
use crate::format::macho::struct_builder::{array_with_element_length, ascii, byte, dword, qword, MachStruct};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::pointer64_data_type::Pointer64DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryBlock;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

const LOG_ORIGIN: &str = "DyldCacheHeader";

/// A `dyld_cache_header`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader`.
pub struct DyldCacheHeader {
    magic: Vec<u8>,
    mapping_offset: i32,
    mapping_count: i32,
    images_offset_old: i32,
    images_count_old: i32,
    dyld_base_address: i64,
    code_signature_offset: i64,
    code_signature_size: i64,
    slide_info_offset: i64,
    slide_info_size: i64,
    local_symbols_offset: i64,
    local_symbols_size: i64,
    uuid: Option<Vec<u8>>,
    cache_type: i64,
    branch_pools_offset: i32,
    branch_pools_count: i32,
    accelerate_info_addr_dyld_in_cache_mh: i64,
    accelerate_info_size_dyld_in_cache_entry: i64,
    images_text_offset: i64,
    images_text_count: i64,
    patch_info_addr: i64,
    patch_info_size: i64,
    other_image_group_addr_unused: i64,
    other_image_group_size_unused: i64,
    prog_closures_addr: i64,
    prog_closures_size: i64,
    prog_closures_trie_addr: i64,
    prog_closures_trie_size: i64,
    platform: i32,
    dyld_info: i32,
    format_version: i32,
    dylibs_expected_on_disk: bool,
    simulator: bool,
    locally_built_cache: bool,
    built_from_chained_fixups: bool,
    shared_region_start: i64,
    shared_region_size: i64,
    max_slide: i64,
    dylibs_image_array_addr: i64,
    dylibs_image_array_size: i64,
    dylibs_trie_addr: i64,
    dylibs_trie_size: i64,
    other_image_array_addr: i64,
    other_image_array_size: i64,
    other_trie_addr: i64,
    other_trie_size: i64,
    mapping_with_slide_offset: i32,
    mapping_with_slide_count: i32,
    dylibs_pbl_state_array_addr_unused: i64,
    dylibs_pbl_set_addr: i64,
    programs_pbl_set_pool_addr: i64,
    programs_pbl_set_pool_size: i64,
    program_trie_addr: i64,
    program_trie_size: i32,
    os_version: i32,
    alt_platform: i32,
    alt_os_version: i32,
    swift_opts_offset: i64,
    swift_opts_size: i64,
    sub_cache_array_offset: i32,
    sub_cache_array_count: Option<i32>,
    symbol_file_uuid: Option<Vec<u8>>,
    rosetta_read_only_addr: i64,
    rosetta_read_only_size: i64,
    rosetta_read_write_addr: i64,
    rosetta_read_write_size: i64,
    images_offset: i32,
    images_count: i32,
    cache_sub_type: Option<i32>,
    padding: i32,
    objc_opts_offset: i64,
    objc_opts_size: i64,
    cache_atlas_offset: i64,
    cache_atlas_size: i64,
    dynamic_data_offset: i64,
    dynamic_data_max_size: i64,
    tpro_mappings_offset: i32,
    tpro_mappings_count: i32,
    function_variant_info_addr: i64,
    function_variant_info_size: i64,
    prewarming_data_offset: i64,
    prewarming_data_size: i64,
    header_size: i32,
    reader: BinaryReader,
    base_address: i64,
    mapping_info_list: Vec<DyldCacheMappingInfo>,
    image_info_list: Vec<DyldCacheImageInfo>,
    slide_info_list: Vec<Box<dyn DyldCacheSlideInfoCommon>>,
    local_symbols_info: Option<DyldCacheLocalSymbolsInfo>,
    branch_pool_list: Vec<i64>,
    accelerate_info: Option<DyldCacheAccelerateInfo>,
    image_text_info_list: Vec<DyldCacheImageTextInfo>,
    subcache_entry_list: Vec<DyldSubcacheEntry>,
    architecture: Option<DyldArchitecture>,
    cache_mapping_and_slide_info_list: Vec<DyldCacheMappingAndSlideInfo>,
    file_block_space: Option<Arc<AddressSpace>>,
}

impl fmt::Debug for DyldCacheHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DyldCacheHeader")
            .field("magic", &String::from_utf8_lossy(&self.magic))
            .field("mapping_offset", &self.mapping_offset)
            .field("base_address", &format_args!("{:#x}", self.base_address))
            .field("header_size", &self.header_size)
            .finish()
    }
}

impl DyldCacheHeader {
    /// Java: `DyldCacheHeader(BinaryReader)`. Reads the header at the reader's position; the
    /// reader is kept for [`parse_from_file`](Self::parse_from_file).
    pub fn new(reader: &BinaryReader) -> std::io::Result<Self> {
        let mut r = reader.clone_reader();
        let start_index = r.get_pointer_index();
        let magic = r.read_next_byte_array(16)?;
        let mapping_offset = r.read_next_int()?;
        let mapping_count = r.read_next_int()?;
        let images_offset_old = r.read_next_int()?;
        let images_count_old = r.read_next_int()?;
        let dyld_base_address = r.read_next_long()?;
        let mut h = DyldCacheHeader {
            magic,
            mapping_offset,
            mapping_count,
            images_offset_old,
            images_count_old,
            dyld_base_address,
            code_signature_offset: 0,
            code_signature_size: 0,
            slide_info_offset: 0,
            slide_info_size: 0,
            local_symbols_offset: 0,
            local_symbols_size: 0,
            uuid: None,
            cache_type: 0,
            branch_pools_offset: 0,
            branch_pools_count: 0,
            accelerate_info_addr_dyld_in_cache_mh: 0,
            accelerate_info_size_dyld_in_cache_entry: 0,
            images_text_offset: 0,
            images_text_count: 0,
            patch_info_addr: 0,
            patch_info_size: 0,
            other_image_group_addr_unused: 0,
            other_image_group_size_unused: 0,
            prog_closures_addr: 0,
            prog_closures_size: 0,
            prog_closures_trie_addr: 0,
            prog_closures_trie_size: 0,
            platform: 0,
            dyld_info: 0,
            format_version: 0,
            dylibs_expected_on_disk: false,
            simulator: false,
            locally_built_cache: false,
            built_from_chained_fixups: false,
            shared_region_start: 0,
            shared_region_size: 0,
            max_slide: 0,
            dylibs_image_array_addr: 0,
            dylibs_image_array_size: 0,
            dylibs_trie_addr: 0,
            dylibs_trie_size: 0,
            other_image_array_addr: 0,
            other_image_array_size: 0,
            other_trie_addr: 0,
            other_trie_size: 0,
            mapping_with_slide_offset: 0,
            mapping_with_slide_count: 0,
            dylibs_pbl_state_array_addr_unused: 0,
            dylibs_pbl_set_addr: 0,
            programs_pbl_set_pool_addr: 0,
            programs_pbl_set_pool_size: 0,
            program_trie_addr: 0,
            program_trie_size: 0,
            os_version: 0,
            alt_platform: 0,
            alt_os_version: 0,
            swift_opts_offset: 0,
            swift_opts_size: 0,
            sub_cache_array_offset: 0,
            sub_cache_array_count: None,
            symbol_file_uuid: None,
            rosetta_read_only_addr: 0,
            rosetta_read_only_size: 0,
            rosetta_read_write_addr: 0,
            rosetta_read_write_size: 0,
            images_offset: 0,
            images_count: 0,
            cache_sub_type: None,
            padding: 0,
            objc_opts_offset: 0,
            objc_opts_size: 0,
            cache_atlas_offset: 0,
            cache_atlas_size: 0,
            dynamic_data_offset: 0,
            dynamic_data_max_size: 0,
            tpro_mappings_offset: 0,
            tpro_mappings_count: 0,
            function_variant_info_addr: 0,
            function_variant_info_size: 0,
            prewarming_data_offset: 0,
            prewarming_data_size: 0,
            header_size: 0,
            reader: r.clone_reader(),
            base_address: 0,
            mapping_info_list: Vec::new(),
            image_info_list: Vec::new(),
            slide_info_list: Vec::new(),
            local_symbols_info: None,
            branch_pool_list: Vec::new(),
            accelerate_info: None,
            image_text_info_list: Vec::new(),
            subcache_entry_list: Vec::new(),
            architecture: None,
            cache_mapping_and_slide_info_list: Vec::new(),
            file_block_space: None,
        };
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.code_signature_offset = r.read_next_long()?;
            h.code_signature_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.slide_info_offset = r.read_next_long()?;
            h.slide_info_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.local_symbols_offset = r.read_next_long()?;
            h.local_symbols_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.uuid = Some(r.read_next_byte_array(16)?);
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.cache_type = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.branch_pools_offset = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.branch_pools_count = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.accelerate_info_addr_dyld_in_cache_mh = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.accelerate_info_size_dyld_in_cache_entry = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.images_text_offset = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.images_text_count = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.patch_info_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.patch_info_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.other_image_group_addr_unused = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.other_image_group_size_unused = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.prog_closures_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.prog_closures_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.prog_closures_trie_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.prog_closures_trie_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.platform = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dyld_info = r.read_next_int()?;
            h.format_version = h.dyld_info & 0xff;
            h.dylibs_expected_on_disk = ((h.dyld_info as u32) >> 8 & 1) == 1;
            h.simulator = ((h.dyld_info as u32) >> 9 & 1) == 1;
            h.locally_built_cache = (h.dyld_info >> 10 & 1) == 1;
            h.built_from_chained_fixups = (h.dyld_info >> 11 & 1) == 1;
            h.padding = (h.dyld_info >> 12) & 0xfffff;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.shared_region_start = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.shared_region_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.max_slide = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dylibs_image_array_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dylibs_image_array_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dylibs_trie_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dylibs_trie_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.other_image_array_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.other_image_array_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.other_trie_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.other_trie_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.mapping_with_slide_offset = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.mapping_with_slide_count = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dylibs_pbl_state_array_addr_unused = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dylibs_pbl_set_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.programs_pbl_set_pool_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.programs_pbl_set_pool_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.program_trie_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.program_trie_size = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.os_version = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.alt_platform = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.alt_os_version = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.swift_opts_offset = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.swift_opts_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.sub_cache_array_offset = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.sub_cache_array_count = Some(r.read_next_int()?);
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            let temp = r.read_next_byte_array(16)?;
            h.symbol_file_uuid = if temp.iter().any(|&b| b != 0) { Some(temp) } else { None };
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.rosetta_read_only_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.rosetta_read_only_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.rosetta_read_write_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.rosetta_read_write_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.images_offset = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.images_count = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.cache_sub_type = Some(r.read_next_int()?);
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.padding = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.objc_opts_offset = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.objc_opts_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.cache_atlas_offset = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.cache_atlas_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dynamic_data_offset = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.dynamic_data_max_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.tpro_mappings_offset = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.tpro_mappings_count = r.read_next_int()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.function_variant_info_addr = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.function_variant_info_size = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.prewarming_data_offset = r.read_next_long()?;
        }
        if (r.get_pointer_index() as i64) < h.mapping_offset as i64 {
            h.prewarming_data_size = r.read_next_long()?;
        }
        h.header_size = (r.get_pointer_index() - start_index) as i32;
        h.base_address = r.read_long(h.mapping_offset as i64 as u64)?;
        h.architecture = DyldArchitecture::get_architecture(java_trim(&String::from_utf8_lossy(&h.magic)));
        h.reader = r;
        Ok(h)
    }

    /// Java: `parseFromFile(boolean, MessageLog, TaskMonitor)`.
    pub fn parse_from_file(
        &mut self,
        parse_local_symbols: bool,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.parse_mapping_info(log, monitor)?;
        self.parse_image_info(log, monitor)?;
        self.parse_local_symbols_info(parse_local_symbols, log, monitor)?;
        self.parse_branch_pools(log, monitor)?;
        self.parse_image_text_info(log, monitor)?;
        self.parse_subcaches(log, monitor)?;
        self.parse_cache_mapping_slide_info(log, monitor)?;
        self.parse_slide_infos(log, monitor);
        Ok(())
    }

    /// Java: `parseFromMemory(Program, AddressSpace, MessageLog, TaskMonitor)`.
    pub fn parse_from_memory(
        &mut self,
        program: &dyn Program,
        space: &Arc<AddressSpace>,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.parse_accelerator_info(program, space, log, monitor)
    }

    /// Java: `markup(Program, boolean, AddressSpace, TaskMonitor, MessageLog)`.
    pub fn markup(
        &self,
        program: &dyn Program,
        markup_local_symbols: bool,
        space: &Arc<AddressSpace>,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        self.markup_header(program, space, monitor, log);
        self.markup_mapping_info(program, space, monitor, log)?;
        self.markup_image_info(program, space, monitor, log)?;
        self.markup_local_symbols_info(markup_local_symbols, program, space, monitor, log)?;
        self.markup_code_signature(program, space, monitor, log);
        self.markup_slide_info(program, space, monitor, log);
        self.markup_branch_pools(program, space, monitor, log)?;
        self.markup_accelerator_info(program, space, monitor, log)?;
        self.markup_image_text_info(program, space, monitor, log)?;
        self.markup_subcache_entries(program, space, monitor, log)?;
        self.markup_cache_mapping_slide_info(program, space, log, monitor)?;
        Ok(())
    }

    /// Java: `getMagic()`.
    pub fn get_magic(&self) -> &[u8] {
        &self.magic
    }

    /// Java: `getUUID()`; `None` when the header predates the field.
    pub fn get_uuid(&self) -> Option<&[u8]> {
        self.uuid.as_deref()
    }

    /// Java: `getSymbolFileUUID()`; `None` when absent or all zero.
    pub fn get_symbol_file_uuid(&self) -> Option<&[u8]> {
        self.symbol_file_uuid.as_deref()
    }

    /// Java: `getMappingOffset()`.
    pub fn get_mapping_offset(&self) -> i32 {
        self.mapping_offset
    }

    /// Java: `getMappingCount()`.
    pub fn get_mapping_count(&self) -> i32 {
        self.mapping_count
    }

    /// Java: `getImagesOffsetOld()`.
    pub fn get_images_offset_old(&self) -> i32 {
        self.images_offset_old
    }

    /// Java: `getImagesCountOld()`.
    pub fn get_images_count_old(&self) -> i32 {
        self.images_count_old
    }

    /// Java: `getDyldBaseAddress()`.
    pub fn get_dyld_base_address(&self) -> i64 {
        self.dyld_base_address
    }

    /// Java: `getCodeSignatureOffset()`.
    pub fn get_code_signature_offset(&self) -> i64 {
        self.code_signature_offset
    }

    /// Java: `getCodeSignatureSize()`.
    pub fn get_code_signature_size(&self) -> i64 {
        self.code_signature_size
    }

    /// Java: `getSlideInfoOffset()`.
    pub fn get_slide_info_offset(&self) -> i64 {
        self.slide_info_offset
    }

    /// Java: `getSlideInfoSize()`.
    pub fn get_slide_info_size(&self) -> i64 {
        self.slide_info_size
    }

    /// Java: `getLocalSymbolsOffset()`.
    pub fn get_local_symbols_offset(&self) -> i64 {
        self.local_symbols_offset
    }

    /// Java: `getLocalSymbolsSize()`.
    pub fn get_local_symbols_size(&self) -> i64 {
        self.local_symbols_size
    }

    /// Java: `getCacheType()`.
    pub fn get_cache_type(&self) -> i64 {
        self.cache_type
    }

    /// Java: `getBranchPoolsOffset()`.
    pub fn get_branch_pools_offset(&self) -> i32 {
        self.branch_pools_offset
    }

    /// Java: `getBranchPoolsCount()`.
    pub fn get_branch_pools_count(&self) -> i32 {
        self.branch_pools_count
    }

    /// Java: `getAccelerateInfoAddrOrDyldInCacheMH()`.
    pub fn get_accelerate_info_addr_or_dyld_in_cache_mh(&self) -> i64 {
        self.accelerate_info_addr_dyld_in_cache_mh
    }

    /// Java: `getAccelerateInfoSizeOrDyldInCacheEntry()`.
    pub fn get_accelerate_info_size_or_dyld_in_cache_entry(&self) -> i64 {
        self.accelerate_info_size_dyld_in_cache_entry
    }

    /// Java: `getImagesTextOffset()`.
    pub fn get_images_text_offset(&self) -> i64 {
        self.images_text_offset
    }

    /// Java: `getImagesTextCount()`.
    pub fn get_images_text_count(&self) -> i64 {
        self.images_text_count
    }

    /// Java: `getPatchInfoAddr()`.
    pub fn get_patch_info_addr(&self) -> i64 {
        self.patch_info_addr
    }

    /// Java: `getPatchInfoSize()`.
    pub fn get_patch_info_size(&self) -> i64 {
        self.patch_info_size
    }

    /// Java: `getOtherImageGroupAddrUnused()`.
    pub fn get_other_image_group_addr_unused(&self) -> i64 {
        self.other_image_group_addr_unused
    }

    /// Java: `getOtherImageGroupSizeUnused()`.
    pub fn get_other_image_group_size_unused(&self) -> i64 {
        self.other_image_group_size_unused
    }

    /// Java: `getProgClosuresAddr()`.
    pub fn get_prog_closures_addr(&self) -> i64 {
        self.prog_closures_addr
    }

    /// Java: `getProgClosuresSize()`.
    pub fn get_prog_closures_size(&self) -> i64 {
        self.prog_closures_size
    }

    /// Java: `getProgClosuresTrieAddr()`.
    pub fn get_prog_closures_trie_addr(&self) -> i64 {
        self.prog_closures_trie_addr
    }

    /// Java: `getProgClosuresTrieSize()`.
    pub fn get_prog_closures_trie_size(&self) -> i64 {
        self.prog_closures_trie_size
    }

    /// Java: `getPlatform()`.
    pub fn get_platform(&self) -> i32 {
        self.platform
    }

    /// Java: `getDyldInfo()`.
    pub fn get_dyld_info(&self) -> i32 {
        self.dyld_info
    }

    /// Java: `getFormatVersion()`.
    pub fn get_format_version(&self) -> i32 {
        self.format_version
    }

    /// Java: `getDylibsExpectedOnDisk()`.
    pub fn get_dylibs_expected_on_disk(&self) -> bool {
        self.dylibs_expected_on_disk
    }

    /// Java: `getSimulator()`.
    pub fn get_simulator(&self) -> bool {
        self.simulator
    }

    /// Java: `getLocallyBuildCache()`.
    pub fn get_locally_build_cache(&self) -> bool {
        self.locally_built_cache
    }

    /// Java: `getBuiltFromChainedFixups()`.
    pub fn get_built_from_chained_fixups(&self) -> bool {
        self.built_from_chained_fixups
    }

    /// Java: `getSharedRegionStart()`.
    pub fn get_shared_region_start(&self) -> i64 {
        self.shared_region_start
    }

    /// Java: `getSharedRegionSize()`.
    pub fn get_shared_region_size(&self) -> i64 {
        self.shared_region_size
    }

    /// Java: `getMaxSlide()`.
    pub fn get_max_slide(&self) -> i64 {
        self.max_slide
    }

    /// Java: `getDylibsImageArrayAddr()`.
    pub fn get_dylibs_image_array_addr(&self) -> i64 {
        self.dylibs_image_array_addr
    }

    /// Java: `getDylibsImageArraySize()`.
    pub fn get_dylibs_image_array_size(&self) -> i64 {
        self.dylibs_image_array_size
    }

    /// Java: `getDylibsTriAddr()`.
    pub fn get_dylibs_tri_addr(&self) -> i64 {
        self.dylibs_trie_addr
    }

    /// Java: `getDylibsTrieSize()`.
    pub fn get_dylibs_trie_size(&self) -> i64 {
        self.dylibs_trie_size
    }

    /// Java: `getOtherImageArrayAddr()`.
    pub fn get_other_image_array_addr(&self) -> i64 {
        self.other_image_array_addr
    }

    /// Java: `getOtherImageArraySize()`.
    pub fn get_other_image_array_size(&self) -> i64 {
        self.other_image_array_size
    }

    /// Java: `getOtherTriAddr()`.
    pub fn get_other_tri_addr(&self) -> i64 {
        self.other_trie_addr
    }

    /// Java: `getOtherTrieSize()`.
    pub fn get_other_trie_size(&self) -> i64 {
        self.other_trie_size
    }

    /// Java: `getMappingWithSlideOffset()`.
    pub fn get_mapping_with_slide_offset(&self) -> i32 {
        self.mapping_with_slide_offset
    }

    /// Java: `getMappingWithSlideCount()`.
    pub fn get_mapping_with_slide_count(&self) -> i32 {
        self.mapping_with_slide_count
    }

    /// Java: `getDylibsPBLStateArrayAddrUnused()`.
    pub fn get_dylibs_pbl_state_array_addr_unused(&self) -> i64 {
        self.dylibs_pbl_state_array_addr_unused
    }

    /// Java: `getDylibsPBLSetAddr()`.
    pub fn get_dylibs_pbl_set_addr(&self) -> i64 {
        self.dylibs_pbl_set_addr
    }

    /// Java: `getProgramsPBLSetPoolAddr()`.
    pub fn get_programs_pbl_set_pool_addr(&self) -> i64 {
        self.programs_pbl_set_pool_addr
    }

    /// Java: `getProgramsPBLSetPoolSize()`.
    pub fn get_programs_pbl_set_pool_size(&self) -> i64 {
        self.programs_pbl_set_pool_size
    }

    /// Java: `getProgramTrieAddr()`.
    pub fn get_program_trie_addr(&self) -> i64 {
        self.program_trie_addr
    }

    /// Java: `getProgramTrieSize()`.
    pub fn get_program_trie_size(&self) -> i32 {
        self.program_trie_size
    }

    /// Java: `getOsVersion()`.
    pub fn get_os_version(&self) -> i32 {
        self.os_version
    }

    /// Java: `getAltPlatform()`.
    pub fn get_alt_platform(&self) -> i32 {
        self.alt_platform
    }

    /// Java: `getAltOsVersion()`.
    pub fn get_alt_os_version(&self) -> i32 {
        self.alt_os_version
    }

    /// Java: `getSwiftOptsOffset()`.
    pub fn get_swift_opts_offset(&self) -> i64 {
        self.swift_opts_offset
    }

    /// Java: `getSwiftOptsSize()`.
    pub fn get_swift_opts_size(&self) -> i64 {
        self.swift_opts_size
    }

    /// Java: `getSubCacheArrayOffset()`.
    pub fn get_sub_cache_array_offset(&self) -> i32 {
        self.sub_cache_array_offset
    }

    /// Java: `getSubCacheArrayCount()`.
    pub fn get_sub_cache_array_count(&self) -> Option<i32> {
        self.sub_cache_array_count
    }

    /// Java: `getRosettaReadOnlyAddr()`.
    pub fn get_rosetta_read_only_addr(&self) -> i64 {
        self.rosetta_read_only_addr
    }

    /// Java: `getRosettaReadOnlySize()`.
    pub fn get_rosetta_read_only_size(&self) -> i64 {
        self.rosetta_read_only_size
    }

    /// Java: `getRosettaReadWriteAddr()`.
    pub fn get_rosetta_read_write_addr(&self) -> i64 {
        self.rosetta_read_write_addr
    }

    /// Java: `getRosettaReadWriteSize()`.
    pub fn get_rosetta_read_write_size(&self) -> i64 {
        self.rosetta_read_write_size
    }

    /// Java: `getImagesOffset()`.
    pub fn get_images_offset(&self) -> i32 {
        self.images_offset
    }

    /// Java: `getImagesCount()`.
    pub fn get_images_count(&self) -> i32 {
        self.images_count
    }

    /// Java: `getCacheSubType()`.
    pub fn get_cache_sub_type(&self) -> Option<i32> {
        self.cache_sub_type
    }

    /// Java: `getObjcOptsOffset()`.
    pub fn get_objc_opts_offset(&self) -> i64 {
        self.objc_opts_offset
    }

    /// Java: `getObjcOptsSize()`.
    pub fn get_objc_opts_size(&self) -> i64 {
        self.objc_opts_size
    }

    /// Java: `getCacheAtlasOffset()`.
    pub fn get_cache_atlas_offset(&self) -> i64 {
        self.cache_atlas_offset
    }

    /// Java: `getCacheAtlasSize()`.
    pub fn get_cache_atlas_size(&self) -> i64 {
        self.cache_atlas_size
    }

    /// Java: `getDynamicDataOffset()`.
    pub fn get_dynamic_data_offset(&self) -> i64 {
        self.dynamic_data_offset
    }

    /// Java: `getDynamicDataMaxSize()`.
    pub fn get_dynamic_data_max_size(&self) -> i64 {
        self.dynamic_data_max_size
    }

    /// Java: `getTproMappingsOffset()`.
    pub fn get_tpro_mappings_offset(&self) -> i32 {
        self.tpro_mappings_offset
    }

    /// Java: `getTproMappingsCount()`.
    pub fn get_tpro_mappings_count(&self) -> i32 {
        self.tpro_mappings_count
    }

    /// Java: `getFunctionVariantInfoAddr()`.
    pub fn get_function_variant_info_addr(&self) -> i64 {
        self.function_variant_info_addr
    }

    /// Java: `getFunctionVariantInfoSize()`.
    pub fn get_function_variant_info_size(&self) -> i64 {
        self.function_variant_info_size
    }

    /// Java: `getPreWarmingDataOffset()`.
    pub fn get_pre_warming_data_offset(&self) -> i64 {
        self.prewarming_data_offset
    }

    /// Java: `getPreWarmingDataSize()`.
    pub fn get_pre_warming_data_size(&self) -> i64 {
        self.prewarming_data_size
    }

    /// Java: `getReader()`.
    pub fn get_reader(&self) -> &BinaryReader {
        &self.reader
    }

    /// Java: `getBaseAddress()`: the address of the first mapping.
    pub fn get_base_address(&self) -> i64 {
        self.base_address
    }

    /// Java: `getMappingInfos()`.
    pub fn get_mapping_infos(&self) -> &[DyldCacheMappingInfo] {
        &self.mapping_info_list
    }

    /// Java: `getImageInfos()`.
    pub fn get_image_infos(&self) -> &[DyldCacheImageInfo] {
        &self.image_info_list
    }

    /// Java: `getSubcacheEntries()`.
    pub fn get_subcache_entries(&self) -> &[DyldSubcacheEntry] {
        &self.subcache_entry_list
    }

    /// Java: `getCacheMappingAndSlideInfos()`.
    pub fn get_cache_mapping_and_slide_infos(&self) -> &[DyldCacheMappingAndSlideInfo] {
        &self.cache_mapping_and_slide_info_list
    }

    /// Java: `getLocalSymbolsInfo()`.
    pub fn get_local_symbols_info(&self) -> Option<&DyldCacheLocalSymbolsInfo> {
        self.local_symbols_info.as_ref()
    }

    /// Java: `getSlideInfos()`.
    pub fn get_slide_infos(&self) -> &[Box<dyn DyldCacheSlideInfoCommon>] {
        &self.slide_info_list
    }

    /// Java: `getBranchPoolAddresses()`.
    pub fn get_branch_pool_addresses(&self) -> &[i64] {
        &self.branch_pool_list
    }

    /// Java: `getArchitecture()`; `None` for an unrecognized magic.
    pub fn get_architecture(&self) -> Option<DyldArchitecture> {
        self.architecture
    }

    /// The image text infos (Java keeps the list private).
    pub fn get_image_text_infos(&self) -> &[DyldCacheImageTextInfo] {
        &self.image_text_info_list
    }

    /// The accelerator info parsed by [`parse_from_memory`](Self::parse_from_memory).
    pub fn get_accelerate_info(&self) -> Option<&DyldCacheAccelerateInfo> {
        self.accelerate_info.as_ref()
    }

    /// Java: `setFileBlock(MemoryBlock)`.
    pub fn set_file_block(&mut self, block: &dyn MemoryBlock) {
        self.file_block_space = Some(Arc::clone(block.get_start().space()));
    }

    /// Java: `hasSlideInfo()`.
    pub fn has_slide_info(&self) -> bool {
        self.slide_info_size != 0
            || self.cache_mapping_and_slide_info_list.iter().any(|i| i.get_slide_info_file_size() != 0)
    }

    /// Java: `unslidLoadAddress()`, the first mapping's address.
    ///
    /// # Panics
    /// Panics (Java: `IndexOutOfBoundsException`) if no mappings were parsed.
    pub fn unslid_load_address(&self) -> i64 {
        self.mapping_info_list[0].get_address()
    }

    /// Java: `isSubcache()`.
    pub fn is_subcache(&self) -> bool {
        self.sub_cache_array_count == Some(0) && self.symbol_file_uuid.is_none()
    }

    /// Java: `hasAccelerateInfo()`: true for caches that predate `cacheSubType`.
    pub fn has_accelerate_info(&self) -> bool {
        self.cache_sub_type.is_none()
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_header");
        self.add_header_field(&mut s, array_with_element_length(ascii()?, 16, 1)?, "magic", "e.g. \"dyld_v0    i386\"")?;
        self.add_header_field(&mut s, dword(), "mappingOffset", "file offset to first dyld_cache_mapping_info")?;
        self.add_header_field(&mut s, dword(), "mappingCount", "number of dyld_cache_mapping_info entries")?;
        self.add_header_field(&mut s, dword(), "imagesOffsetOld", "UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing")?;
        self.add_header_field(&mut s, dword(), "imagesCountOld", "UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing")?;
        self.add_header_field(&mut s, qword(), "dyldBaseAddress", "base address of dyld when cache was built")?;
        self.add_header_field(&mut s, qword(), "codeSignatureOffset", "file offset of code signature blob")?;
        self.add_header_field(&mut s, qword(), "codeSignatureSize", "size of code signature blob (zero means to end of file)")?;
        self.add_header_field(&mut s, qword(), "slideInfoOffset", "file offset of kernel slid info")?;
        self.add_header_field(&mut s, qword(), "slideInfoSize", "size of kernel slid info")?;
        self.add_header_field(&mut s, qword(), "localSymbolsOffset", "file offset of where local symbols are stored")?;
        self.add_header_field(&mut s, qword(), "localSymbolsSize", "size of local symbols information")?;
        self.add_header_field(&mut s, array_with_element_length(byte(), 16, 1)?, "uuid", "unique value for each shared cache file")?;
        self.add_header_field(&mut s, qword(), "cacheType", "0 for development, 1 for production, 2 for multi-cache")?;
        self.add_header_field(&mut s, dword(), "branchPoolsOffset", "file offset to table of uint64_t pool addresses")?;
        self.add_header_field(&mut s, dword(), "branchPoolsCount", "number of uint64_t entries")?;
        if self.has_accelerate_info() {
            self.add_header_field(&mut s, qword(), "accelerateInfoAddr", "(unslid) address of optimization info")?;
            self.add_header_field(&mut s, qword(), "accelerateInfoSize", "size of optimization info")?;
        } else {
            self.add_header_field(&mut s, qword(), "dyldInCacheMH", "(unslid) address of mach_header of dyld in cache")?;
            self.add_header_field(&mut s, qword(), "dyldInCacheEntry", "(unslid) address of entry point (_dyld_start) of dyld in cache")?;
        }
        self.add_header_field(&mut s, qword(), "imagesTextOffset", "file offset to first dyld_cache_image_text_info")?;
        self.add_header_field(&mut s, qword(), "imagesTextCount", "number of dyld_cache_image_text_info entries")?;
        self.add_header_field(&mut s, qword(), "patchInfoAddr", "(unslid) address of dyld_cache_patch_info")?;
        self.add_header_field(&mut s, qword(), "patchInfoSize", "Size of all of the patch information pointed to via the dyld_cache_patch_info")?;
        self.add_header_field(&mut s, qword(), "otherImageGroupAddrUnused", "unused")?;
        self.add_header_field(&mut s, qword(), "otherImageGroupSizeUnused", "unused")?;
        self.add_header_field(&mut s, qword(), "progClosuresAddr", "(unslid) address of list of program launch closures")?;
        self.add_header_field(&mut s, qword(), "progClosuresSize", "size of list of program launch closures")?;
        self.add_header_field(&mut s, qword(), "progClosuresTrieAddr", "(unslid) address of trie of indexes into program launch closures")?;
        self.add_header_field(&mut s, qword(), "progClosuresTrieSize", "size of trie of indexes into program launch closures")?;
        self.add_header_field(&mut s, dword(), "platform", "platform number (macOS=1, etc)")?;
        self.add_header_field(&mut s, dword(), "dyld_info", "")?;
        self.add_header_field(&mut s, qword(), "sharedRegionStart", "base load address of cache if not slid")?;
        self.add_header_field(&mut s, qword(), "sharedRegionSize", "overall size of region cache can be mapped into")?;
        self.add_header_field(&mut s, qword(), "maxSlide", "runtime slide of cache can be between zero and this value")?;
        self.add_header_field(&mut s, qword(), "dylibsImageArrayAddr", "(unslid) address of ImageArray for dylibs in this cache")?;
        self.add_header_field(&mut s, qword(), "dylibsImageArraySize", "size of ImageArray for dylibs in this cache")?;
        self.add_header_field(&mut s, qword(), "dylibsTrieAddr", "(unslid) address of trie of indexes of all cached dylibs")?;
        self.add_header_field(&mut s, qword(), "dylibsTrieSize", "size of trie of cached dylib paths")?;
        self.add_header_field(&mut s, qword(), "otherImageArrayAddr", "(unslid) address of ImageArray for dylibs and bundles with dlopen closures")?;
        self.add_header_field(&mut s, qword(), "otherImageArraySize", "size of ImageArray for dylibs and bundles with dlopen closures")?;
        self.add_header_field(&mut s, qword(), "otherTrieAddr", "(unslid) address of trie of indexes of all dylibs and bundles with dlopen closures")?;
        self.add_header_field(&mut s, qword(), "otherTrieSize", "size of trie of dylibs and bundles with dlopen closures")?;
        self.add_header_field(&mut s, dword(), "mappingWithSlideOffset", "file offset to first dyld_cache_mapping_and_slide_info")?;
        self.add_header_field(&mut s, dword(), "mappingWithSlideCount", "number of dyld_cache_mapping_and_slide_info entries")?;
        self.add_header_field(&mut s, qword(), "dylibsPBLStateArrayAddrUnused", "unused")?;
        self.add_header_field(&mut s, qword(), "dylibsPBLSetAddr", "(unslid) address of PrebuiltLoaderSet of all cached dylibs")?;
        self.add_header_field(&mut s, qword(), "programsPBLSetPoolAddr", "(unslid) address of pool of PrebuiltLoaderSet for each program ")?;
        self.add_header_field(&mut s, qword(), "programsPBLSetPoolSize", "size of pool of PrebuiltLoaderSet for each program")?;
        self.add_header_field(&mut s, qword(), "programTrieAddr", "(unslid) address of trie mapping program path to PrebuiltLoaderSet")?;
        self.add_header_field(&mut s, dword(), "programTrieSize", "")?;
        self.add_header_field(&mut s, dword(), "osVersion", "OS Version of dylibs in this cache for the main platform")?;
        self.add_header_field(&mut s, dword(), "altPlatform", "e.g. iOSMac on macOS")?;
        self.add_header_field(&mut s, dword(), "altOsVersion", "e.g. 14.0 for iOSMac")?;
        self.add_header_field(&mut s, qword(), "swiftOptsOffset", "file offset to Swift optimizations header")?;
        self.add_header_field(&mut s, qword(), "swiftOptsOffset", "size of Swift optimizations header")?;
        self.add_header_field(&mut s, dword(), "subCacheArrayOffset", "file offset to first dyld_subcache_entry")?;
        self.add_header_field(&mut s, dword(), "subCacheArrayCount", "number of subcache entries")?;
        self.add_header_field(&mut s, array_with_element_length(byte(), 16, 1)?, "symbolFileUUID", "unique value for the shared cache file containing unmapped local symbols")?;
        self.add_header_field(&mut s, qword(), "rosettaReadOnlyAddr", "(unslid) address of the start of where Rosetta can add read-only/executable data")?;
        self.add_header_field(&mut s, qword(), "rosettaReadOnlySize", "maximum size of the Rosetta read-only/executable region")?;
        self.add_header_field(&mut s, qword(), "rosettaReadWriteAddr", "(unslid) address of the start of where Rosetta can add read-write data")?;
        self.add_header_field(&mut s, qword(), "rosettaReadWriteSize", "maximum size of the Rosetta read-write region")?;
        self.add_header_field(&mut s, dword(), "imagesOffset", "file offset to first dyld_cache_image_info")?;
        self.add_header_field(&mut s, dword(), "imagesCount", "number of dyld_cache_image_info entries")?;
        self.add_header_field(&mut s, dword(), "cacheSubType", "0 for development, 1 for production, when cacheType is multi-cache(2)")?;
        self.add_header_field(&mut s, dword(), "padding", "")?;
        self.add_header_field(&mut s, qword(), "objcOptsOffset", "VM offset from cache_header* to ObjC optimizations header")?;
        self.add_header_field(&mut s, qword(), "objcOptsSize", "size of ObjC optimizations header")?;
        self.add_header_field(&mut s, qword(), "cacheAtlasOffset", "VM offset from cache_header* to embedded cache atlas for process introspection")?;
        self.add_header_field(&mut s, qword(), "cacheAtlasSize", "size of embedded cache atlas")?;
        self.add_header_field(&mut s, qword(), "dynamicDataOffset", "VM offset from cache_header* to the location of dyld_cache_dynamic_data_header")?;
        self.add_header_field(&mut s, qword(), "dynamicDataMaxSize", "maximum size of space reserved from dynamic data")?;
        self.add_header_field(&mut s, dword(), "tproMappingsOffset", "file offset to first dyld_cache_tpro_mapping_info")?;
        self.add_header_field(&mut s, dword(), "tproMappingsCount", "number of dyld_cache_tpro_mapping_info entries")?;
        self.add_header_field(&mut s, qword(), "functionVariantInfoAddr", "(unslid) address of dyld_cache_function_variant_info")?;
        self.add_header_field(&mut s, qword(), "functionVariantInfoSize", "Size of all of the variant information pointed to via the dyld_cache_function_variant_info")?;
        self.add_header_field(&mut s, qword(), "prewarmingDataOffset", "file offset to dyld_prewarming_header")?;
        self.add_header_field(&mut s, qword(), "prewarmingDataSize", "byte size of prewarming data")?;
        s.finish_structure()
    }

    /// Java: the private `addHeaderField`: only fields the header actually contains are added.
    fn add_header_field(
        &self,
        s: &mut MachStruct,
        dt: Box<dyn DataType>,
        name: &str,
        comment: &str,
    ) -> Result<(), ToDataTypeError> {
        if self.header_size > s.len() {
            s.add(dt, name, Some(comment))?;
        }
        Ok(())
    }

    /// The shared shape of the Java `parse*` table readers: `count` entries from `offset`; an I/O
    /// error stops the table and logs `failure`.
    fn read_table<T>(
        reader: &mut BinaryReader,
        offset: i64,
        count: i64,
        read: impl Fn(&mut BinaryReader) -> std::io::Result<T>,
        failure: &str,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<T>, CancelledException> {
        reader.set_pointer_index(offset as u64);
        let mut out = Vec::new();
        for _ in 0..count {
            match read(reader) {
                Ok(v) => out.push(v),
                Err(_) => {
                    log.append_msg_from(Some(LOG_ORIGIN), failure);
                    break;
                }
            }
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
        }
        Ok(out)
    }

    fn parse_mapping_info(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        monitor.set_message("Parsing DYLD mapping info...");
        monitor.initialize(self.mapping_count as i64);
        self.mapping_info_list = Self::read_table(&mut self.reader, self.mapping_offset as i64,
            self.mapping_count as i64, DyldCacheMappingInfo::from_reader,
            "Failed to parse dyld_cache_mapping_info.", log, monitor)?;
        Ok(())
    }

    fn parse_image_info(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        let offset = if self.images_offset != 0 { self.images_offset } else { self.images_offset_old };
        let count = if self.images_offset != 0 { self.images_count } else { self.images_count_old };
        if offset == 0 {
            return Ok(());
        }
        monitor.set_message("Parsing DYLD image info...");
        monitor.initialize(count as i64);
        self.image_info_list = Self::read_table(&mut self.reader, offset as i64, count as i64,
            DyldCacheImageInfo::from_reader, "Failed to parse dyld_cache_image_info.", log, monitor)?;
        Ok(())
    }

    /// Java: `parseLocalSymbolsInfo(boolean, MessageLog, TaskMonitor)`.
    pub fn parse_local_symbols_info(
        &mut self,
        should_parse: bool,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        if !should_parse || self.local_symbols_offset == 0 {
            return Ok(());
        }
        monitor.set_message("Parsing DYLD local symbols info...");
        monitor.initialize(1);
        self.reader.set_pointer_index(self.local_symbols_offset as u64);
        let use64bit_offsets = self.images_offset_old == 0;
        let Some(architecture) = self.architecture else {
            // Java: NullPointerException from architecture.getCpuType().
            log.append_msg_from(Some(LOG_ORIGIN), "Failed to parse dyld_cache_local_symbols_info.");
            return Ok(());
        };
        match DyldCacheLocalSymbolsInfo::new(&self.reader, &architecture, use64bit_offsets) {
            Ok(mut info) => {
                info.parse(log, monitor)?;
                self.local_symbols_info = Some(info);
                monitor.increment_progress(1);
            }
            Err(_) => log.append_msg_from(Some(LOG_ORIGIN), "Failed to parse dyld_cache_local_symbols_info."),
        }
        Ok(())
    }

    fn parse_branch_pools(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        if self.branch_pools_offset == 0 {
            return Ok(());
        }
        monitor.set_message("Parsing DYLD branch pool addresses...");
        monitor.initialize(self.branch_pools_count as i64);
        self.branch_pool_list = Self::read_table(&mut self.reader, self.branch_pools_offset as i64,
            self.branch_pools_count as i64, |r| r.read_next_long(), "Failed to parse pool addresses.", log, monitor)?;
        Ok(())
    }

    fn parse_image_text_info(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        if self.images_text_offset == 0 {
            return Ok(());
        }
        monitor.set_message("Parsing DYLD image text info...");
        monitor.initialize(self.images_text_count);
        self.image_text_info_list = Self::read_table(&mut self.reader, self.images_text_offset,
            self.images_text_count, DyldCacheImageTextInfo::new, "Failed to parse dyld_cache_image_text_info.", log, monitor)?;
        Ok(())
    }

    fn parse_subcaches(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        if self.sub_cache_array_offset == 0 {
            return Ok(());
        }
        let count = self.sub_cache_array_count.unwrap_or(0) as i64;
        monitor.set_message("Parsing DYLD subcaches...");
        monitor.initialize(count);
        self.subcache_entry_list = Self::read_table(&mut self.reader, self.sub_cache_array_offset as i64,
            count, DyldSubcacheEntry::new, "Failed to parse dyld_subcache_entry.", log, monitor)?;
        Ok(())
    }

    fn parse_cache_mapping_slide_info(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        monitor.set_message("Parsing DYLD cache mapping and slide info...");
        monitor.initialize(self.mapping_with_slide_count as i64);
        if self.mapping_with_slide_count <= 0 {
            return Ok(());
        }
        self.cache_mapping_and_slide_info_list = Self::read_table(&mut self.reader,
            self.mapping_with_slide_offset as i64, self.mapping_with_slide_count as i64,
            DyldCacheMappingAndSlideInfo::from_reader, "Failed to parse dyld_cache_mapping_info.", log, monitor)?;
        Ok(())
    }

    fn parse_slide_infos(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) {
        if !self.has_slide_info() {
            return;
        }
        let page_map_entry = DATA_PAGE_MAP_ENTRY as usize;
        if self.slide_info_offset != 0 && self.mapping_info_list.len() > page_map_entry {
            let mapping_info = self.mapping_info_list[page_map_entry].clone();
            if let Some(info) = parse_slide_info(&mut self.reader, self.slide_info_offset, &mapping_info, log, monitor) {
                self.slide_info_list.push(info);
            }
        } else if !self.cache_mapping_and_slide_info_list.is_empty() {
            for i in 0..self.cache_mapping_and_slide_info_list.len() {
                let offset = self.cache_mapping_and_slide_info_list[i].get_slide_info_file_offset();
                if offset == 0 {
                    continue;
                }
                // Java: mappingInfoList.get(i) (IndexOutOfBounds if the lists disagree).
                let Some(mapping_info) = self.mapping_info_list.get(i).cloned() else { continue };
                if let Some(info) = parse_slide_info(&mut self.reader, offset, &mapping_info, log, monitor) {
                    self.slide_info_list.push(info);
                }
            }
        }
    }

    fn parse_accelerator_info(
        &mut self,
        program: &dyn Program,
        space: &Arc<AddressSpace>,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        if !self.has_accelerate_info() || self.accelerate_info_addr_dyld_in_cache_mh == 0 {
            return Ok(());
        }
        monitor.set_message("Parsing DYLD accelerateor info...");
        monitor.initialize(self.images_text_count);
        let addr = space.address(self.accelerate_info_addr_dyld_in_cache_mh);
        let (Some(memory), Some(language)) = (program.get_memory(), program.get_language()) else {
            log.append_msg_from(Some(LOG_ORIGIN), "Failed to parse dyld_cache_accelerator_info.");
            return Ok(());
        };
        let provider = Rc::new(MemoryRangeByteProvider::new(memory, addr.clone()));
        let memory_reader = BinaryReader::new(provider, !language.is_big_endian());
        match DyldCacheAccelerateInfo::new(&memory_reader) {
            Ok(mut info) => {
                info.parse(program, &addr, log, monitor)?;
                self.accelerate_info = Some(info);
                monitor.increment_progress(1);
            }
            Err(_) => log.append_msg_from(Some(LOG_ORIGIN), "Failed to parse dyld_cache_accelerator_info."),
        }
        Ok(())
    }

    /// Java: the private `fileOffsetToAddr(long, Program, AddressSpace)`: the mapped address of
    /// a file offset, else its address in the file block's space, else `None`.
    fn file_offset_to_addr(&self, offset: i64, space: &Arc<AddressSpace>) -> Option<Address> {
        for mapping_info in &self.mapping_info_list {
            if offset >= mapping_info.get_file_offset()
                && offset < mapping_info.get_file_offset() + mapping_info.get_size()
            {
                return Some(space.address(mapping_info.get_address() + (offset - mapping_info.get_file_offset())));
            }
        }
        self.file_block_space.as_ref().map(|s| s.address(offset))
    }

    /// Lays down `items` from file offset `offset`; `per_item` runs after each one is created.
    #[allow(clippy::too_many_arguments)]
    fn markup_table<T: StructConverter>(
        &self,
        program: &dyn Program,
        space: &Arc<AddressSpace>,
        offset: i64,
        items: &[T],
        failure: &str,
        mut per_item: impl FnMut(&Address, &T) -> Result<(), String>,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.initialize(items.len() as i64);
        let mut addr = self.file_offset_to_addr(offset, space);
        for item in items {
            let step: Result<Address, String> = (|| {
                let a = addr.clone().ok_or("no address for file offset")?;
                let dt = item.to_data_type().map_err(|e| e.to_string())?;
                let d = Du.create_data(program, &a, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())?;
                per_item(&a, item)?;
                a.add(d.get_length() as i64).map_err(|e| e.to_string())
            })();
            match step {
                Ok(next) => addr = Some(next),
                Err(_) => {
                    log.append_msg_from(Some(LOG_ORIGIN), failure);
                    return Ok(());
                }
            }
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
        }
        Ok(())
    }

    fn set_comment(program: &dyn Program, addr: &Address, kind: CommentType, text: &str) -> Result<(), String> {
        let mut listing = program.get_listing().ok_or("no listing")?;
        listing.set_comment(addr, kind, Some(text.to_string()));
        Ok(())
    }

    fn markup_header(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) {
        monitor.set_message("Marking up DYLD header...");
        monitor.initialize(1);
        let result: Result<(), String> = (|| {
            let dt = self.to_data_type().map_err(|e| e.to_string())?;
            Du.create_data(program, &space.address(self.base_address), dt, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        match result {
            Ok(()) => monitor.increment_progress(1),
            Err(_) => log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup dyld_cache_header."),
        }
    }

    fn markup_mapping_info(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD mapping info...");
        self.markup_table(program, space, self.mapping_offset as i64, &self.mapping_info_list,
            "Failed to markup dyld_cache_mapping_info.", |_, _| Ok(()), log, monitor)
    }

    fn markup_cache_mapping_slide_info(&self, program: &dyn Program, space: &Arc<AddressSpace>, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD cache mapping and slide info...");
        self.markup_table(program, space, self.mapping_with_slide_offset as i64, &self.cache_mapping_and_slide_info_list,
            "Failed to markup dyld_cache_mapping_info.", |_, _| Ok(()), log, monitor)
    }

    fn markup_image_info(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD image info...");
        let offset = if self.images_offset != 0 { self.images_offset } else { self.images_offset_old };
        self.markup_table(program, space, offset as i64, &self.image_info_list,
            "Failed to markup dyld_cache_image_info.",
            |a, info| Self::set_comment(program, a, CommentType::Eol, info.get_path()), log, monitor)
    }

    fn markup_code_signature(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) {
        monitor.set_message("Marking up DYLD code signature...");
        monitor.initialize(1);
        let size = format!("0x{:x}", self.code_signature_size);
        let result = match self.file_offset_to_addr(self.code_signature_offset, space) {
            Some(a) => Self::set_comment(program, &a, CommentType::Plate, &format!("Code Signature ({size} bytes)")),
            // Java: setComment(null, ...) throws IllegalArgumentException.
            None => Err("no address".into()),
        };
        match result {
            Ok(()) => monitor.increment_progress(1),
            Err(_) => log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup code signature."),
        }
    }

    fn markup_slide_info(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) {
        monitor.set_message("Marking up DYLD slide info...");
        monitor.initialize(1);
        let result: Result<(), String> = (|| {
            for info in &self.slide_info_list {
                let a = self.file_offset_to_addr(info.get_slide_info_offset(), space).ok_or("no address")?;
                let dt = info.to_data_type().map_err(|e| e.to_string())?;
                Du.create_data(program, &a, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => monitor.increment_progress(1),
            Err(_) => log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup dyld_cache_slide_info."),
        }
    }

    fn markup_local_symbols_info(&self, should_markup: bool, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        if !should_markup {
            return Ok(());
        }
        monitor.set_message("Marking up DYLD local symbols info...");
        monitor.initialize(1);
        if let Some(info) = &self.local_symbols_info {
            let created: Result<Address, String> = (|| {
                let a = self.file_offset_to_addr(self.local_symbols_offset, space).ok_or("no address")?;
                let dt = info.to_data_type().map_err(|e| e.to_string())?;
                Du.create_data(program, &a, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())?;
                Ok(a)
            })();
            match created {
                Ok(a) => info.markup(program, &a, monitor, log)?,
                Err(_) => {
                    log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup dyld_cache_local_symbols_info.");
                    return Ok(());
                }
            }
        }
        monitor.increment_progress(1);
        Ok(())
    }

    fn markup_branch_pools(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD branch pool addresses...");
        monitor.initialize(self.branch_pool_list.len() as i64);
        let mut addr = self.file_offset_to_addr(self.branch_pools_offset as i64, space);
        for _ in &self.branch_pool_list {
            let step: Result<Address, String> = (|| {
                let a = addr.clone().ok_or("no address")?;
                let dt = Pointer64DataType::new(None::<Box<dyn DataType>>).map_err(|e| e.to_string())?;
                let len = dt.get_length();
                let d = Du.create_data(program, &a, Box::new(dt), len, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())?;
                a.add(d.get_length() as i64).map_err(|e| e.to_string())
            })();
            match step {
                Ok(next) => addr = Some(next),
                Err(_) => {
                    log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup branch pool addresses.");
                    return Ok(());
                }
            }
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
        }
        Ok(())
    }

    fn markup_accelerator_info(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD accelerator info...");
        monitor.initialize(1);
        if self.has_accelerate_info() {
            if let Some(info) = &self.accelerate_info {
                let a = space.address(self.accelerate_info_addr_dyld_in_cache_mh);
                let created = info
                    .to_data_type()
                    .map_err(|e| e.to_string())
                    .and_then(|dt| Du.create_data(program, &a, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string()));
                if created.is_err() {
                    log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup dyld_cache_accelerator_info.");
                    return Ok(());
                }
                info.markup(program, &a, monitor, log)?;
            }
        }
        monitor.increment_progress(1);
        Ok(())
    }

    fn markup_image_text_info(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD image text info...");
        self.markup_table(program, space, self.images_text_offset, &self.image_text_info_list,
            "Failed to markup dyld_cache_image_text_info.",
            |a, info| Self::set_comment(program, a, CommentType::Eol, info.path()), log, monitor)
    }

    fn markup_subcache_entries(&self, program: &dyn Program, space: &Arc<AddressSpace>, monitor: &dyn TaskMonitor, log: &MessageLog) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD subcache entries...");
        self.markup_table(program, space, self.sub_cache_array_offset as i64, &self.subcache_entry_list,
            "Failed to markup dyld_subcache_entry.", |_, _| Ok(()), log, monitor)
    }
}

impl StructConverter for DyldCacheHeader {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

/// Java's `String.trim()`.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;
    use crate::util::task::DummyMonitor;

    /// A version-1-era cache: header through `cacheType`/branch pools (mapping table at 0x78),
    /// two mappings, one image (old-style offsets), one branch pool and an unparseable
    /// (version 9) slide info.
    fn old_cache() -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.name("dyld_v1  x86_64", 16).u32(0x78).u32(2).u32(0xb8).u32(1).u64(0x7fff_0000_0000);
        b.u64(0).u64(0); // code signature
        b.u64(0x200).u64(0x10); // slide info
        b.u64(0).u64(0); // local symbols
        b.raw(&[0x11; 16]); // uuid
        b.u64(1); // cache type
        b.u32(0xd8).u32(1); // branch pools
        assert_eq!(b.len(), 0x78);
        b.u64(0x7fff_2000_0000).u64(0x1000).u64(0).u32(5).u32(5);
        b.u64(0x7fff_4000_0000).u64(0x1000).u64(0x1000).u32(3).u32(3);
        assert_eq!(b.len(), 0xb8);
        b.u64(0x7fff_2000_1000).u64(0).u64(0).u32(0xe0).u32(0);
        assert_eq!(b.len(), 0xd8);
        b.u64(0x7fff_5000_0000);
        b.name("/usr/lib/libA.dylib", 32);
        b.pad_to(0x200).u32(9);
        b.pad_to(0x2000);
        b.buf
    }

    #[test]
    fn parses_old_header_and_tables() {
        let r = BinaryReader::from_bytes(old_cache(), true);
        let mut h = DyldCacheHeader::new(&r).unwrap();
        assert_eq!(h.get_mapping_offset(), 0x78);
        assert_eq!(h.get_architecture(), Some(DyldArchitecture::X86_64));
        assert_eq!(h.get_base_address(), 0x7fff_2000_0000);
        assert_eq!(h.get_uuid(), Some(&[0x11u8; 16][..]));
        assert_eq!(h.get_cache_type(), 1);
        assert_eq!(h.get_branch_pools_count(), 1);
        assert_eq!(h.get_accelerate_info_addr_or_dyld_in_cache_mh(), 0, "past the header end");
        assert!(h.has_accelerate_info());
        assert!(!h.is_subcache());
        assert!(h.has_slide_info());
        let log = MessageLog::new();
        h.parse_from_file(false, &log, &DummyMonitor).unwrap();
        assert_eq!(h.get_mapping_infos().len(), 2);
        assert_eq!(h.unslid_load_address(), 0x7fff_2000_0000);
        assert_eq!(h.get_image_infos()[0].get_path(), "/usr/lib/libA.dylib");
        assert_eq!(h.get_branch_pool_addresses(), [0x7fff_5000_0000]);
        assert!(h.get_slide_infos().is_empty());
        assert!(log.messages().iter().any(|m| m.ends_with("Failed to parse dyld_cache_slide_info9")));
        let s = h.to_structure().unwrap();
        assert_eq!(s.get_length(), 0x78);
        assert_eq!(names(&s).last().unwrap(), "branchPoolsCount");
    }

    #[test]
    fn modern_fields_and_subcache_detection() {
        let mut b = Bytes::new(true);
        b.name("dyld_v1   arm64e", 16);
        let header_end = 0x1d0u32; // through cacheSubType/padding/objcOpts.. (partial)
        b.u32(header_end).u32(1).u32(0).u32(0).u64(0);
        while b.len() < 0x188 {
            b.u64(0);
        }
        // subCacheArrayOffset/Count at 0x188, then symbolFileUUID (all zero)
        b.u32(0).u32(0).raw(&[0u8; 16]);
        while b.len() < 0x1c0 {
            b.u64(0);
        }
        b.u32(0).u32(0).u32(1).u32(0); // imagesOffset, imagesCount, cacheSubType, padding
        assert_eq!(b.len() as u32, header_end);
        b.u64(0x1_8000_0000).u64(0x1000).u64(0).u32(1).u32(1);
        let h = DyldCacheHeader::new(&BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert_eq!(h.get_cache_sub_type(), Some(1));
        assert!(!h.has_accelerate_info());
        assert_eq!(h.get_sub_cache_array_count(), Some(0));
        assert!(h.get_symbol_file_uuid().is_none());
        assert!(h.is_subcache());
        assert_eq!(h.get_objc_opts_offset(), 0, "past the header end");
        let s = h.to_structure().unwrap();
        assert_eq!(s.get_length(), header_end as i32);
        assert!(names(&s).contains(&"dyldInCacheMH".to_string()));
    }
}
