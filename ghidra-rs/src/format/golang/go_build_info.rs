//! Port of `ghidra.app.util.bin.format.golang.GoBuildInfo`.

use std::fmt;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use super::go_build_settings::GoBuildSettings;
use super::go_constants::GOLANG_CATEGORYPATH;
use super::go_module_info::GoModuleInfo;
use super::go_ver::GoVer;
use super::rtti::go_rtti_mapper;
use crate::app::seam_stubs::PeLoader;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::app::util::bin::memory_byte_provider::MemoryByteProvider;
use crate::app::util::opinion::elf_loader::ElfLoader;
use crate::format::elf::info::elf_info_item::{ElfInfoItem, ItemWithAddress};
use crate::framework::options::Options;
use crate::program::model::address::Address;
use crate::program::model::data::abstract_integer_data_type::get_unsigned_data_type;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::byte_data_type::ByteDataType;
use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::data::unsigned_leb128_data_type::UnsignedLeb128DataType;
use crate::program::model::lang::endian::Endian;
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::util::msg::Msg;

/// `SECTION_NAME`.
pub const SECTION_NAME: &str = "go.buildinfo";
/// `ELF_SECTION_NAME`.
pub const ELF_SECTION_NAME: &str = ".go.buildinfo";
/// `MACHO_SECTION_NAME`.
pub const MACHO_SECTION_NAME: &str = "go_buildinfo";
/// `FALLBACK_GOVER_OPTION`: program info option holding a user supplied Go version.
pub const FALLBACK_GOVER_OPTION: &str = "Go version fallback";

/// `MachoLoader.MACH_O_NAME` (the Mach-O loader is not ported yet).
const MACH_O_NAME: &str = "Mac OS X Mach-O";

/// Defined in Go's `src/debug/buildinfo/buildinfo.go`: `"\xff Go buildinf:"`.
const GO_BUILDINF_MAGIC: &[u8; 14] = b"\xff Go buildinf:";

/// Defined in Go's `src/cmd/go/internal/modload/build.go`.
const INFOSTART_SENTINEL: [u8; 16] = [
    0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6,
];
const INFOEND_SENTINEL: [u8; 16] = [
    0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2,
];

const FLAG_ENDIAN: u16 = 1 << 0;
const FLAG_INLINE_STRING: u16 = 1 << 1;

/// Map from ghidra arch string to Go arch name (`GHIDRA_GOARCH_MAP`).
const GHIDRA_GOARCH_MAP: &[(&str, &str)] = &[
    ("aarch64_64", "arm64"),
    ("arm_32", "arm"),
    ("mips_64", "mips64"),
    ("mips_32", "mips"),
    ("x86_64", "amd64"),
    ("x86_32", "386"),
];

const GOLANG_DUALENDIAN_ARCH: &[&str] = &["mips", "mips64", "ppc64"];

struct GoDataUtil;
impl DataUtilities for GoDataUtil {}

/// A program section that contains Go build information strings, namely Go module package names,
/// Go module dependencies, and build/compiler flags, as well as the Go version itself.
#[derive(Clone)]
pub struct GoBuildInfo {
    pointer_size: i32,
    endian: Endian,
    /// Go compiler version.
    version: String,
    path: Option<String>,
    /// Info about the module that contains the main package; its version typically will be
    /// `"(devel)"`.
    module_info: Option<GoModuleInfo>,
    dependencies: Vec<GoModuleInfo>,
    /// Compile/linker flags used during the build process.
    build_settings: Vec<GoBuildSettings>,
    structure: Option<StructureDataType>,
}

impl GoBuildInfo {
    /// Reads a GoBuildInfo `.go.buildinfo` section from the specified program, if present
    /// (`fromProgram(Program)`).
    pub fn from_program(program: &dyn Program) -> Option<GoBuildInfo> {
        Self::find_build_info(program).map(|w| w.item)
    }

    /// Searches for the GoBuildInfo structure in the most common and easy locations
    /// (`findBuildInfo(Program)`).
    pub fn find_build_info(program: &dyn Program) -> Option<ItemWithAddress<GoBuildInfo>> {
        let section = go_rtti_mapper::get_first_go_section(program, &[SECTION_NAME, MACHO_SECTION_NAME]);
        let mut wrapped_item = read_item_from_section(program, section.as_deref(), 0);
        if wrapped_item.is_none() {
            // if not present, try common PE location for buildinfo
            if let Some(data_mb) = go_rtti_mapper::get_go_section(program, "data") {
                let memory = program.get_memory()?;
                let data_bp = MemoryByteProvider::create_memory_block_byte_provider(memory, data_mb.as_ref());
                let offset = Self::find_go_build_info_offset(&data_bp, 512);
                if offset != -1 {
                    wrapped_item = read_item_from_section(program, Some(data_mb.as_ref()), offset);
                }
            }
        }
        wrapped_item
    }

    /// Searches for the offset of the GoBuildInfo magic string, or `-1` if not found
    /// (`findGoBuildInfoOffset(ByteProvider, int)`).
    pub fn find_go_build_info_offset(bp: &dyn ByteProvider, max_search_length: i64) -> i64 {
        let len = bp.length() as i64;
        let mut pos = 0i64;
        while pos < max_search_length && pos < len {
            match bp.read_byte(pos as u64) {
                Ok(b) if b == GO_BUILDINF_MAGIC[0] => {
                    if let Ok(bytes) = bp.read_bytes(pos as u64, GO_BUILDINF_MAGIC.len() as u64) {
                        if bytes.as_slice() == GO_BUILDINF_MAGIC {
                            return pos;
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => return -1,
            }
            pos += 1;
        }
        -1
    }

    /// Reads a GoBuildInfo `.go.buildinfo` section from the specified stream
    /// (`read(BinaryReader, Program)`).
    ///
    /// # Errors
    /// Missing magic, mixed endianness, or an error reading the strings.
    pub fn read(reader: &mut BinaryReader, program: &dyn Program) -> io::Result<GoBuildInfo> {
        let start_offset = reader.get_pointer_index();
        let magic_bytes = reader.read_next_byte_array(GO_BUILDINF_MAGIC.len() /* 14 */)?;
        if magic_bytes.as_slice() != GO_BUILDINF_MAGIC {
            return Err(io::Error::other("Missing GoBuildInfo magic"));
        }
        let pointer_size = reader.read_next_unsigned_byte()? as i32;
        let flags = reader.read_next_unsigned_byte()?;
        let endian = if flags & FLAG_ENDIAN == 0 { Endian::Little } else { Endian::Big };
        let inline_str = flags & FLAG_INLINE_STRING != 0;

        if reader.is_big_endian() && endian != Endian::Big {
            return Err(io::Error::other("Mixed endian-ness"));
        }

        let dtm = program.get_data_type_manager();
        let mut structure =
            StructureDataType::with_manager(GOLANG_CATEGORYPATH.clone(), "GoBuildInfo", 0, dtm.as_deref());
        add_field(&mut structure, array(CharDataType::data_type(), 14)?, -1, "magic", Some("\\xff Go buildinf:"))?;
        add_field(&mut structure, ByteDataType::data_type(), -1, "ptrSize", None)?;
        add_field(&mut structure, ByteDataType::data_type(), -1, "flags", None)?;

        read_string_info(reader, start_offset, inline_str, program, pointer_size, structure)
    }

    /// `setFallbackVersion(Program, String)`.
    pub fn set_fallback_version(program: &dyn Program, fallback_go_ver_str: &str) {
        program.get_options(PROGRAM_INFO).set_string(FALLBACK_GOVER_OPTION, fallback_go_ver_str);
    }

    /// A build info made from a user supplied fallback Go version, `None` when there is no valid
    /// one (`fromFallbackInfo(Program)`).
    pub fn from_fallback_info(program: &dyn Program) -> Option<GoBuildInfo> {
        let fallback_go_ver_str = program.get_options(PROGRAM_INFO).get_string(FALLBACK_GOVER_OPTION, "");
        if fallback_go_ver_str.is_empty() || GoVer::parse(&fallback_go_ver_str).is_invalid() {
            return None;
        }
        let big_endian = program.get_memory().is_some_and(|m| m.is_big_endian());
        Some(GoBuildInfo {
            pointer_size: program.get_default_pointer_size(),
            endian: if big_endian { Endian::Big } else { Endian::Little },
            version: fallback_go_ver_str,
            path: Some("unknown path".to_string()),
            module_info: None,
            dependencies: Vec::new(),
            build_settings: Vec::new(),
            structure: None,
        })
    }

    /// `getPointerSize()`.
    pub fn get_pointer_size(&self) -> i32 {
        self.pointer_size
    }

    /// `getEndian()`.
    pub fn get_endian(&self) -> Endian {
        self.endian
    }

    /// `getVersion()`: the version string, without its `go` prefix.
    pub fn get_version(&self) -> &str {
        &self.version
    }

    /// `getGoVer()`.
    pub fn get_go_ver(&self) -> GoVer {
        GoVer::parse(&self.version)
    }

    /// `getPath()`.
    pub fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// `getModuleInfo()`.
    pub fn get_module_info(&self) -> Option<&GoModuleInfo> {
        self.module_info.as_ref()
    }

    /// `getDependencies()`.
    pub fn get_dependencies(&self) -> &[GoModuleInfo] {
        &self.dependencies
    }

    /// `getBuildSettings()`.
    pub fn get_build_settings(&self) -> &[GoBuildSettings] {
        &self.build_settings
    }

    /// `getBuildSetting(String)`.
    pub fn get_build_setting(&self, key: &str) -> Option<&GoBuildSettings> {
        self.build_settings.iter().find(|bs| bs.key == key)
    }

    /// Returns the Go OS string ("GOOS") for the program, either from the build settings or from
    /// a static Ghidra-loader to Go mapping (`getGOOS(Program)`).
    pub fn get_goos(&self, program: &dyn Program) -> String {
        match self.get_build_setting("GOOS") {
            Some(goos) => goos.value.clone(),
            None => Self::get_program_goos(program),
        }
    }

    /// Returns a Go "GOOS" string created by a mapping from the program's loader type
    /// (`getProgramGOOS(Program)`).
    pub fn get_program_goos(program: &dyn Program) -> String {
        let loader_name = program.get_executable_format();
        if ElfLoader::is_elf(&loader_name) {
            "linux".to_string()
        }
        else if loader_name == PeLoader::PE_NAME {
            "windows".to_string()
        }
        else if loader_name == MACH_O_NAME {
            "darwin".to_string()
        }
        else {
            "unknown".to_string()
        }
    }

    /// Returns the Go arch string for the program, either from the build settings or from a
    /// static Ghidra language to Go mapping (`getGOARCH(Program)`).
    pub fn get_goarch(&self, program: &dyn Program) -> String {
        match self.get_build_setting("GOARCH") {
            Some(goarch) => goarch.value.clone(),
            None => Self::get_program_goarch(program),
        }
    }

    /// Returns a Go "GOARCH" string created by a mapping from the program's language
    /// (`getProgramGOARCH(Program)`).
    pub fn get_program_goarch(program: &dyn Program) -> String {
        let lang_arch = format!(
            "{}_{}",
            get_language_arch(&program.get_language_id()).to_lowercase(),
            program.get_default_pointer_size() * 8
        );
        let mut goarch = GHIDRA_GOARCH_MAP
            .iter()
            .find(|(k, _)| *k == lang_arch)
            .map_or("unknown", |(_, v)| v)
            .to_string();
        let big_endian = program.get_memory().is_some_and(|m| m.is_big_endian());
        if GOLANG_DUALENDIAN_ARCH.contains(&goarch.as_str()) && !big_endian {
            // Go seems to mark the LE variant and assumes BE as the default if not marked
            goarch.push_str("le");
        }
        goarch
    }

    /// `decorateProgramInfo(Options)`: records the version, path, main module, dependencies and
    /// build settings as program info properties.
    pub fn decorate_program_info(&self, props: &mut dyn Options) {
        GoVer::set_program_properties_with_original_version_string(props, self.get_version());
        props.set_string("Golang app path", self.path.as_deref().unwrap_or(""));
        if let Some(mi) = &self.module_info {
            let mut pairs: Vec<(String, String)> = mi.as_key_value_pairs("Golang main package ").into_iter().collect();
            pairs.sort();
            for (k, v) in pairs {
                props.set_string(&k, &v);
            }
        }
        for (dep_num, dep) in self.dependencies.iter().enumerate() {
            let key = format!("Golang dep[{dep_num:4}]");
            props.set_string(&key, &dep.get_formatted_string());
        }
        for build_setting in &self.build_settings {
            props.set_string(
                &format!("Golang build[{}]", build_setting.key.replace('.', "_")),
                &build_setting.value,
            );
        }
    }

    /// `toStructure(DataTypeManager)`: a copy of the structure describing the build info bytes.
    pub fn to_structure(&self, _dtm: &dyn DataTypeManager) -> Option<StructureDataType> {
        self.structure.clone()
    }
}

impl ElfInfoItem for GoBuildInfo {
    fn markup_program(&self, program: &mut dyn Program, address: &Address) {
        self.decorate_program_info(program.get_options(PROGRAM_INFO).as_mut());

        if let Some(structure) = &self.structure {
            let result = GoDataUtil.create_data(
                &*program,
                address,
                Box::new(structure.clone()),
                -1,
                ClearDataMode::ClearAllDefaultConflictData,
            );
            if result.is_err() {
                Msg::error("GoBuildInfo", &format!("Failed to markup GoBuildInfo at {address}: {self}"));
            }
        }
    }
}

impl fmt::Display for GoBuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GoBuildInfo [pointerSize={}, endian={}, version={}, path={}]",
            self.pointer_size,
            self.endian,
            self.version,
            self.path.as_deref().unwrap_or("null")
        )
    }
}

impl fmt::Debug for GoBuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn get_language_arch(lang_id: &str) -> &str {
    match lang_id.find(':') {
        Some(first_colon) if first_colon > 0 => &lang_id[..first_colon],
        _ => lang_id,
    }
}

fn array(element: Arc<dyn DataType>, count: i32) -> io::Result<Arc<dyn DataType>> {
    ArrayDataType::with_element_length(element, count, -1)
        .map(|a| Arc::new(a) as Arc<dyn DataType>)
        .map_err(io::Error::other)
}

fn add_field(
    structure: &mut StructureDataType,
    dt: Arc<dyn DataType>,
    length: i32,
    name: &str,
    comment: Option<&str>,
) -> io::Result<()> {
    let boxed: Box<dyn DataType> = crate::program::seam_stubs::share_data_type(&dt);
    structure
        .add_with_length_and_name(boxed, length, Some(name.to_string()), comment.map(str::to_string))
        .map(|_| ())
        .map_err(io::Error::other)
}

fn read_item_from_section(
    program: &dyn Program,
    mem_block: Option<&dyn crate::program::model::mem::MemoryBlock>,
    offset: i64,
) -> Option<ItemWithAddress<GoBuildInfo>> {
    let mem_block = mem_block?;
    let memory = program.get_memory()?;
    let big_endian = memory.is_big_endian();
    let bp = MemoryByteProvider::create_memory_block_byte_provider(memory, mem_block);
    let mut br = BinaryReader::new(Rc::new(bp), !big_endian);
    br.set_pointer_index(offset as u64);
    let item = GoBuildInfo::read(&mut br, program).ok()?;
    let address = mem_block.get_start().add(offset).ok()?;
    Some(ItemWithAddress { item, address })
}

fn read_string_info(
    reader: &mut BinaryReader,
    start_offset: u64,
    inline_str: bool,
    program: &dyn Program,
    ptr_size: i32,
    mut structure: StructureDataType,
) -> io::Result<GoBuildInfo> {
    let dtm = program.get_data_type_manager();
    let module_string;
    let version_string;

    if inline_str {
        reader.set_pointer_index(start_offset + 32 /* static start of inline strings */);

        let ver_str_len = LEB128Info::unsigned(reader)?;
        let ver_len = ver_str_len.as_int32().map_err(|e| io::Error::other(e.to_string()))?;
        let version_string_bytes = reader.read_next_byte_array(ver_len as usize)?;
        version_string = String::from_utf8_lossy(&version_string_bytes).to_string();

        let mod_str_len = LEB128Info::unsigned(reader)?;
        let mod_len = mod_str_len.as_int32().map_err(|e| io::Error::other(e.to_string()))?;
        let module_string_bytes = reader.read_next_byte_array(mod_len as usize)?;

        let leb: Arc<dyn DataType> = Arc::new(UnsignedLeb128DataType::new(dtm.as_deref()));
        add_field(&mut structure, array(ByteDataType::data_type(), 16)?, -1, "padding", None)?;
        add_field(&mut structure, leb.clone(), ver_str_len.get_length(), "versionlen", None)?;
        add_field(&mut structure, array(CharDataType::data_type(), ver_len)?, -1, "version", None)?;
        add_field(&mut structure, leb, mod_str_len.get_length(), "modulelen", None)?;

        module_string = extract_module_string(&module_string_bytes, Some(&mut structure))?;

        let struct_name_suffix = format!(
            "_inline_{}_{}_{}_{}",
            ver_str_len.get_length(),
            ver_len,
            mod_str_len.get_length(),
            mod_len
        );
        let new_name = format!("{}{struct_name_suffix}", structure.get_name());
        let _ = structure.set_name(&new_name); // ignore InvalidNameException
    }
    else {
        reader.set_pointer_index(start_offset + 16 /* static start of 2 string pointers */);
        let version_str_offset = reader.read_next_unsigned_value(ptr_size as usize)?;
        let module_str_offset = reader.read_next_unsigned_value(ptr_size as usize)?;

        let memory = program.get_memory().ok_or_else(|| io::Error::other("Program has no memory"))?;
        let space = program
            .get_image_base()
            .map(|b| b.space().clone())
            .ok_or_else(|| io::Error::other("Program has no image base"))?;
        let mem_bp = MemoryByteProvider::new(memory, &space);
        let mut full_reader = BinaryReader::new(Rc::new(mem_bp), reader.is_little_endian());

        full_reader.set_pointer_index(version_str_offset);
        version_string = read_go_string(&mut full_reader, ptr_size)?;

        full_reader.set_pointer_index(module_str_offset);
        let module_str_bytes = read_raw_go_string(&mut full_reader, ptr_size)?;
        module_string = extract_module_string(&module_str_bytes, None)?;

        let ofs_dt = get_unsigned_data_type(ptr_size, dtm.as_deref());
        add_field(&mut structure, ofs_dt.clone(), -1, "versionofs", None)?;
        add_field(&mut structure, ofs_dt, -1, "moduleofs", None)?;
    }

    let endian = if reader.is_big_endian() { Endian::Big } else { Endian::Little };
    parse_build_info(ptr_size, endian, version_string, &module_string, structure)
}

fn parse_build_info(
    pointer_size: i32,
    endian: Endian,
    mut version_string: String,
    module_string: &str,
    structure: StructureDataType,
) -> io::Result<GoBuildInfo> {
    let mut path = None;
    let mut module = None;
    let mut deps = Vec::new();
    let mut build_settings = Vec::new();

    let lines = java_split(module_string, '\n');
    let mut line_num = 0;
    while line_num < lines.len() {
        let line = lines[line_num];
        let replace_info = if line_num + 1 < lines.len() && lines[line_num + 1].starts_with("=>\t") {
            line_num += 1;
            Some(&lines[line_num][3..])
        }
        else {
            None
        };
        line_num += 1;

        if line.trim().is_empty() {
            continue;
        }

        // lines start with key of "path", "mod", "dep", "=>" (replacement info attached
        // to previous line), and "build"
        let mut line_parts = line.splitn(2, '\t');
        let key = line_parts.next().unwrap_or("");
        let value = line_parts.next();
        let value_or_err = || value.ok_or_else(|| io::Error::other(format!("Bad build info line: {line}")));
        match key {
            "path" => path = Some(value_or_err()?.to_string()),
            "mod" => {
                let replace = match replace_info {
                    Some(r) => Some(GoModuleInfo::from_string(r, None)?),
                    None => None,
                };
                module = Some(GoModuleInfo::from_string(value_or_err()?, replace)?);
            }
            "dep" => deps.push(GoModuleInfo::from_string(value_or_err()?, None)?),
            "build" => build_settings.push(GoBuildSettings::from_string(value_or_err()?)?),
            _ => {}
        }
    }

    if let Some(stripped) = version_string.strip_prefix("go") {
        version_string = stripped.to_string(); // skip the "go"
    }

    Ok(GoBuildInfo {
        pointer_size,
        endian,
        version: version_string,
        path,
        module_info: module,
        dependencies: deps,
        build_settings,
        structure: Some(structure),
    })
}

/// Java `String.split(String)` semantics: trailing empty strings are removed.
fn java_split(s: &str, sep: char) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split(sep).collect();
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() {
        // "".split(...) yields [""] in Java
        return parts;
    }
    parts
}

fn extract_module_string(bytes: &[u8], structure: Option<&mut StructureDataType>) -> io::Result<String> {
    let sent_len = INFOSTART_SENTINEL.len(); // both are same len
    if bytes.len() < sent_len * 2 {
        return Ok(String::new());
    }

    let sent_end_start = bytes.len() - sent_len;
    if bytes[..sent_len] != INFOSTART_SENTINEL || bytes[sent_end_start..] != INFOEND_SENTINEL {
        return Err(io::Error::other("bad sentinel"));
    }

    let module_str_len = bytes.len() - sent_len * 2;
    if let Some(structure) = structure {
        add_field(structure, array(ByteDataType::data_type(), sent_len as i32)?, -1, "sentinelstart", None)?;
        add_field(structure, array(CharDataType::data_type(), module_str_len as i32)?, -1, "moduleinfo", None)?;
        add_field(structure, array(ByteDataType::data_type(), sent_len as i32)?, -1, "sentinelend", None)?;
    }

    Ok(String::from_utf8_lossy(&bytes[sent_len..sent_len + module_str_len]).to_string())
}

fn read_go_string(reader: &mut BinaryReader, ptr_size: i32) -> io::Result<String> {
    let bytes = read_raw_go_string(reader, ptr_size)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Low-level reading of a Go string structure (`struct { void *; long len }`) without using RTTI
/// info (`readRawGoString`).
fn read_raw_go_string(reader: &mut BinaryReader, ptr_size: i32) -> io::Result<Vec<u8>> {
    let data_addr = reader.read_next_unsigned_value(ptr_size as usize)?;
    let data_len = reader.read_next_unsigned_value(ptr_size as usize)?;
    if data_addr == 0 || data_len == 0 {
        return Ok(Vec::new());
    }
    reader.read_byte_array(data_addr, data_len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module_blob(text: &str) -> Vec<u8> {
        let mut v = INFOSTART_SENTINEL.to_vec();
        v.extend_from_slice(text.as_bytes());
        v.extend_from_slice(&INFOEND_SENTINEL);
        v
    }

    /// Writes a ULEB128 length then the bytes.
    fn leb_str(out: &mut Vec<u8>, bytes: &[u8]) {
        let mut n = bytes.len();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
        out.extend_from_slice(bytes);
    }

    const MODULE_TEXT: &str = "path\texample.com/hello\nmod\texample.com/hello\t(devel)\t\ndep\tgolang.org/x/text\tv0.3.7\th1:abc=\n=>\t../text\t(devel)\t\nbuild\t-compiler=gc\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\n";

    /// A Go 1.18+ (inline strings) `.go.buildinfo` section, as `debug/buildinfo` writes it.
    fn inline_buildinfo() -> Vec<u8> {
        let mut v = GO_BUILDINF_MAGIC.to_vec();
        v.push(8); // ptrSize
        v.push(FLAG_INLINE_STRING as u8); // flags: little endian, inline strings
        v.resize(32, 0);
        leb_str(&mut v, b"go1.21.4");
        leb_str(&mut v, &module_blob(MODULE_TEXT));
        v
    }

    fn read_inline(bytes: Vec<u8>) -> io::Result<GoBuildInfo> {
        // `read` only needs the program for its DTM in inline mode
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let (program, _) = crate::format::golang::structmapping::test_support::test_program(Vec::new());
        GoBuildInfo::read(&mut reader, program.as_ref())
    }

    #[test]
    fn reads_inline_string_build_info() {
        let bi = read_inline(inline_buildinfo()).unwrap();
        assert_eq!(bi.get_pointer_size(), 8);
        assert_eq!(bi.get_endian(), Endian::Little);
        assert_eq!(bi.get_version(), "1.21.4");
        assert_eq!(bi.get_go_ver(), GoVer::new(1, 21, 4));
        assert_eq!(bi.get_path(), Some("example.com/hello"));
        let main = bi.get_module_info().unwrap();
        assert_eq!(main.path, "example.com/hello");
        assert_eq!(main.version, "(devel)");
        assert_eq!(bi.get_dependencies().len(), 1);
        assert_eq!(bi.get_dependencies()[0].path, "golang.org/x/text");
        assert_eq!(bi.get_dependencies()[0].version, "v0.3.7");
        assert_eq!(bi.get_build_settings().len(), 3);
        assert_eq!(bi.get_build_setting("GOARCH").map(|b| b.value.as_str()), Some("amd64"));
        assert_eq!(bi.get_build_setting("GOOS").map(|b| b.value.as_str()), Some("linux"));
        assert!(bi.get_build_setting("CGO_ENABLED").is_none());

        // magic(14) + ptrSize + flags + padding(16) + versionlen(1) + version(8) + modulelen(2) +
        // sentinel(16) + moduleinfo + sentinel(16)
        let s = bi.structure.as_ref().unwrap();
        assert!(s.get_name().starts_with("GoBuildInfo_inline_1_8_"));
        let mod_len = module_blob(MODULE_TEXT).len();
        assert!((128..16384).contains(&mod_len)); // 2 byte uleb128 module length
        assert_eq!(s.get_name(), format!("GoBuildInfo_inline_1_8_2_{mod_len}"));
        assert_eq!(s.get_length() as usize, 14 + 1 + 1 + 16 + 1 + 8 + 2 + mod_len);
        assert_eq!(bi.to_string(), "GoBuildInfo [pointerSize=8, endian=little, version=1.21.4, path=example.com/hello]");
    }

    #[test]
    fn rejects_bad_magic_and_sentinel() {
        let mut bad = inline_buildinfo();
        bad[1] = b'X';
        assert_eq!(read_inline(bad).unwrap_err().to_string(), "Missing GoBuildInfo magic");

        let mut v = GO_BUILDINF_MAGIC.to_vec();
        v.push(8);
        v.push(FLAG_INLINE_STRING as u8);
        v.resize(32, 0);
        leb_str(&mut v, b"go1.21.4");
        let mut blob = module_blob(MODULE_TEXT);
        blob[0] ^= 0xff;
        leb_str(&mut v, &blob);
        assert_eq!(read_inline(v).unwrap_err().to_string(), "bad sentinel");
    }

    #[test]
    fn short_module_string_is_empty() {
        let mut v = GO_BUILDINF_MAGIC.to_vec();
        v.push(4);
        v.push(FLAG_INLINE_STRING as u8);
        v.resize(32, 0);
        leb_str(&mut v, b"go1.16");
        leb_str(&mut v, b"");
        let bi = read_inline(v).unwrap();
        assert_eq!(bi.get_go_ver(), GoVer::new(1, 16, 0));
        assert_eq!(bi.get_path(), None);
        assert!(bi.get_module_info().is_none());
    }

    #[test]
    fn finds_magic_offset() {
        let mut v = vec![0u8; 40];
        v.extend_from_slice(GO_BUILDINF_MAGIC);
        let bp = crate::app::util::bin::byte_array_provider::ByteArrayProvider::new(v);
        assert_eq!(GoBuildInfo::find_go_build_info_offset(&bp, 512), 40);
        assert_eq!(GoBuildInfo::find_go_build_info_offset(&bp, 40), -1);
    }

    #[test]
    fn language_arch() {
        assert_eq!(get_language_arch("x86:LE:64:default"), "x86");
        assert_eq!(get_language_arch("AARCH64"), "AARCH64");
        assert_eq!(java_split("a\nb\n\n", '\n'), vec!["a", "b"]);
    }
}
