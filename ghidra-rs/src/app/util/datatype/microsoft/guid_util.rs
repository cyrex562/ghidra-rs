//! Port of `ghidra.app.util.datatype.microsoft.GuidUtil`.
//!
//! Java hangs all of this off a `GuidUtil` class because Java has nowhere else to put a static;
//! there is no `GuidUtil` instance anywhere in Ghidra and no instance state. The Rust port is
//! therefore a plain module of free functions plus one process-wide lazily-built lookup table,
//! which is the direct analogue of Java's `initialized` flag guarding the static `idTables`.
//!
//! Two Java-isms are resolved here rather than reproduced:
//!
//! * `GuidInfo` and its subclass `VersionedGuidInfo` are returned interchangeably from
//!   `parseLine` and stored in the same table. Rust has no inheritance, so [`GuidEntry`] carries
//!   that choice as a sum type.
//! * `Application.getModuleDataSubDirectory(String)` resolves the *calling class's* module, which
//!   for `GuidUtil` is `Base`. This crate's [`Application`] only offers the explicit two-argument
//!   form, so [`MODULE_NAME`] names that module and the `Application` is passed in by the caller,
//!   following [`extension_utils`](crate::util::extensions::extension_utils).

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

use crate::app::seam_stubs::NewGuid;
use crate::framework::application::Application;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::conv::Conv;
use crate::util::data_converter::DataConverter;
use crate::util::msg::Msg;

use super::guid_info::GuidInfo;
use super::guid_type::GuidType;
use super::versioned_guid_info::VersionedGuidInfo;

/// Originator passed to [`Msg`], standing in for Java's `GuidUtil.class`.
const ORIGINATOR: &str = "GuidUtil";

/// Directory holding the GUID archive files, relative to [`ARCHIVE_DIR_PARENT`].
const ARCHIVE_DIR: &str = "msvcrt";

/// Path of [`ARCHIVE_DIR`]'s parent, relative to the module's `data` directory.
const ARCHIVE_DIR_PARENT: &str = "typeinfo/win32";

/// The module whose `data` directory holds the GUID archives. Java gets this implicitly, from
/// the module that `GuidUtil` itself lives in.
const MODULE_NAME: &str = "Base";

/// The GUID categories that are read into the lookup tables, in the order Java searches them.
const GUID_TYPES: [GuidType; 4] =
    [GuidType::Clsid, GuidType::Iid, GuidType::Guid, GuidType::Syntax];

/// Prefix of the symbol names Microsoft generates for a GUID constant.
const MS_GUID_PREFIX: &str = "_GUID_";

/// A GUID archive entry: either a plain [`GuidInfo`] or, for versioned (syntax) archives, a
/// [`VersionedGuidInfo`].
///
/// Stands in for Java's use of `GuidInfo` as the static type of a value that may really be a
/// `VersionedGuidInfo`; the two differ only in `getUniqueIdString`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuidEntry {
    /// An entry from a `clsids.txt`/`iids.txt`/`guids.txt` archive.
    Plain(GuidInfo),
    /// An entry from a `syntaxes.txt` archive, which carries a version.
    Versioned(VersionedGuidInfo),
}

impl GuidEntry {
    /// The key this entry is filed under: the GUID string, plus `" <VERSION>"` when versioned.
    pub fn unique_id_string(&self) -> &str {
        match self {
            Self::Plain(info) => info.unique_id_string(),
            Self::Versioned(info) => info.unique_id_string(),
        }
    }

    /// The GUID string, e.g. `"00000000-0000-0000-C000-000000000046"`.
    pub fn guid_string(&self) -> &str {
        match self {
            Self::Plain(info) => info.guid_string(),
            Self::Versioned(info) => info.guid_string(),
        }
    }

    /// The symbolic name this GUID is known by, e.g. `"IUnknown"`.
    pub fn name(&self) -> &str {
        match self {
            Self::Plain(info) => info.name(),
            Self::Versioned(info) => info.name(),
        }
    }

    /// The archive category this entry came from.
    pub fn guid_type(&self) -> GuidType {
        match self {
            Self::Plain(info) => info.guid_type(),
            Self::Versioned(info) => info.guid_type(),
        }
    }
}

/// One lookup table per [`GuidType`], keyed by [`GuidEntry::unique_id_string`].
type GuidTables = HashMap<GuidType, HashMap<String, GuidEntry>>;

static ID_TABLES: OnceLock<GuidTables> = OnceLock::new();

/// Reads every GUID archive once and caches the result for the life of the process.
///
/// Replaces Java's `initialized` flag plus static `idTables`. As in Java, the archives are read
/// exactly once: the first caller's [`Application`] is the one whose module data directory is
/// searched, and later callers reuse whatever it found.
fn initialize(app: &dyn Application) -> &'static GuidTables {
    ID_TABLES.get_or_init(|| build_guid_map(app))
}

fn build_guid_map(app: &dyn Application) -> GuidTables {
    GUID_TYPES.iter().map(|&guid_type| (guid_type, read_guid_file(app, guid_type))).collect()
}

fn read_guid_file(app: &dyn Application, guid_type: GuidType) -> HashMap<String, GuidEntry> {
    let mut table = HashMap::new();
    let filename = guid_type.filename();

    let dir = match app
        .get_module_data_sub_directory(MODULE_NAME, &format!("{ARCHIVE_DIR_PARENT}/{ARCHIVE_DIR}"))
    {
        Ok(dir) => dir,
        Err(e) => {
            Msg::error(ORIGINATOR, &format!("Unexpected Exception: {e}"));
            return table;
        }
    };

    let infile = dir.join(filename);
    if !infile.exists() {
        Msg::error(ORIGINATOR, &format!("ERROR: file not found: {filename}"));
        return table;
    }

    let input = match infile.get_input_stream() {
        Ok(input) => input,
        Err(e) => {
            Msg::error(ORIGINATOR, &format!("Unexpected Exception: {e}"));
            return table;
        }
    };

    for line in BufReader::new(input).lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                Msg::error(ORIGINATOR, &format!("Unexpected Exception: {e}"));
                break;
            }
        };
        if line.starts_with('#') || line.len() < 30 {
            continue;
        }
        if let Some(entry) = parse_line(&line, "-", guid_type) {
            table.insert(entry.unique_id_string().to_string(), entry);
        }
    }

    table
}

/// Looks up the GUID stored at `address` within `program` among the known non-versioned GUIDs.
///
/// Port of `GuidUtil.getKnownGuid(Program, Address)`.
pub fn known_guid_at(
    app: &dyn Application,
    program: &dyn Program,
    address: &Address,
) -> Option<&'static GuidEntry> {
    let guid = guid_string(program, address, false)?;
    known_guid(app, &guid)
}

/// Looks `guid_string` up among the known CLSIDs, IIDs and GUIDs, ignoring case.
///
/// Port of `GuidUtil.getKnownGuid(String)`. Versioned (syntax) archives are deliberately skipped;
/// use [`known_versioned_guid`] for those.
pub fn known_guid(app: &dyn Application, guid_string: &str) -> Option<&'static GuidEntry> {
    let tables = initialize(app);
    let key = guid_string.to_uppercase();
    GUID_TYPES
        .iter()
        .filter(|guid_type| **guid_type != GuidType::Syntax)
        .find_map(|guid_type| tables.get(guid_type)?.get(&key))
}

/// Looks `versioned_guid_string` (a `"<guid> V<major>.<minor>"` key) up among the known syntaxes.
///
/// Port of `GuidUtil.getKnownVersionedGuid(String)`.
pub fn known_versioned_guid(
    app: &dyn Application,
    versioned_guid_string: &str,
) -> Option<&'static GuidEntry> {
    let tables = initialize(app);
    let key = versioned_guid_string.to_uppercase();
    tables.get(&GuidType::Syntax)?.get(&key)
}

/// Parses one `"<guid><whitespace>[version ]<name>"` archive line.
///
/// Port of `GuidUtil.parseLine`. `delim` is the separator to strip out of the GUID field (always
/// `"-"` in practice). Returns `None` for a line Java would reject or throw on -- a GUID field
/// that is not 32 hex digits once `delim` is removed, a line with no whitespace, or a line under
/// 36 characters.
pub fn parse_line(guid_name_line: &str, delim: &str, guid_type: GuidType) -> Option<GuidEntry> {
    /// Length of a GUID in bytes; the GUID field must be twice this many hex digits.
    const NUM_BYTES: usize = 16;

    let has_version = guid_type.has_version();
    let line = guid_name_line.replace('\t', " ");

    let guid_part = &line[..line.find(' ')?];
    let stripped = guid_part.replace(delim, "");
    if stripped.len() != NUM_BYTES * 2 {
        Msg::error(ORIGINATOR, &format!("ERROR PARSING GUID: {line}"));
        return None;
    }

    // Java decodes the four little-endian words purely to hand them to `isOK`, which (see below)
    // accepts anything -- but a non-hex digit here throws out of `parseLine`, so the decode is
    // still what rejects a malformed GUID field. Reproduced with the same word/byte swizzling.
    let mut data = [0u32; 4];
    data[0] = parse_hex_u32(stripped.get(0..8)?)?;
    let word = stripped.get(8..16)?;
    data[1] = parse_hex_u32(&format!("{}{}", word.get(4..8)?, word.get(0..4)?))?;
    for (i, word_start) in [16usize, 24].into_iter().enumerate() {
        let word = stripped.get(word_start..word_start + 8)?;
        let swapped = format!(
            "{}{}{}{}",
            word.get(6..8)?,
            word.get(4..6)?,
            word.get(2..4)?,
            word.get(0..2)?
        );
        data[2 + i] = parse_hex_u32(&swapped)?;
    }

    // Java indexes past the GUID by its fixed rendered width rather than by the delimiter found
    // above, so a line whose GUID field is shorter than 36 characters shifts the name field.
    let mut left = line.get(36..)?;
    let mut version = None;
    if has_version {
        if let Some(vpos) = left.find('v').filter(|&vpos| vpos > 0) {
            left = &left[vpos..];
            let v = match left.find(' ') {
                Some(sppos) if sppos > 0 => &left[..sppos],
                _ => left,
            };
            version = Some(v);
            left = &left[v.len()..];
        }
    }
    let name = match left.find(' ') {
        Some(sppos) => &left[sppos + 1..],
        None => left,
    };

    if !is_ok(&data) {
        return None;
    }
    if !has_version {
        return Some(GuidEntry::Plain(GuidInfo::new(
            guid_part.to_string(),
            name.to_string(),
            guid_type,
        )));
    }
    // Java passes a null version straight into `VersionedGuidInfo`, which then throws on
    // `version.toUpperCase()`. An archive line with no `v` field becomes version-less here.
    Some(GuidEntry::Versioned(VersionedGuidInfo::new(
        guid_part.to_string(),
        version.unwrap_or_default().to_string(),
        name.to_string(),
        guid_type,
    )))
}

/// Port of `GuidUtil.isOK(long[])`.
///
/// The Java predicate is `(element != 0) || (element != 0xFFFFFFFFL)`, which no single value can
/// fail, so this returns `true` for any non-empty `data` -- and `parseLine` always passes four
/// words. Kept because it is what decides `parseLine`'s result, and correcting the intent (almost
/// certainly `&&`, i.e. "reject all-zero and all-ones GUIDs") would change which archive entries
/// load.
fn is_ok(data: &[u32]) -> bool {
    data.iter().any(|&element| element != 0 || element != 0xFFFF_FFFF)
}

/// Renders the 16-byte GUID stored at `address` as `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`, in
/// lower case.
///
/// Port of `GuidUtil.getGuidString`. Returns `None` if the bytes cannot be read, or -- when
/// `validate` is set -- if they are not a plausible GUID per [`NewGuid::is_ok_for_guid`].
pub fn guid_string(program: &dyn Program, address: &Address, validate: bool) -> Option<String> {
    let mut bytes = [0u8; 16];
    let data = read_guid_data(program, address, &mut bytes)?;
    if validate && !NewGuid::is_ok_for_guid(&bytes, 0) {
        return None;
    }
    Some(render_guid(&data))
}

/// Renders the 20-byte versioned GUID stored at `address` as `"<guid> v<major>.<minor>"`.
///
/// Port of `GuidUtil.getVersionedGuidString`.
pub fn versioned_guid_string(
    program: &dyn Program,
    address: &Address,
    validate: bool,
) -> Option<String> {
    let mut bytes = [0u8; 20];
    let data = read_guid_data(program, address, &mut bytes)?;
    if validate && !NewGuid::is_ok_for_guid(&bytes, 0) {
        return None;
    }
    // Java assembles each version half from *signed* bytes, so a high byte over 0x7F yields a
    // negative version number. Preserved rather than corrected.
    let major = (i32::from(bytes[17] as i8) << 8) + i32::from(bytes[16] as i8);
    let minor = (i32::from(bytes[19] as i8) << 8) + i32::from(bytes[18] as i8);
    Some(format!("{} v{}.{}", render_guid(&data), major, minor))
}

/// Verifies that `label` is the Microsoft symbol name for the GUID stored at `address` within
/// `program`.
///
/// Port of `GuidUtil.isGuidLabel`. Java renders the address through `GuidDataType`, then asks
/// whether that rendering ends with the label's GUID; since `GuidDataType.getString` produces
/// exactly [`guid_string`]'s 36-character rendering (optionally prefixed by a known GUID's name
/// and a space), "ends with" is equivalent to "equals" here, and the extra `new GUID(..)` parse
/// Java performs first can only succeed when that equality already holds. So this compares
/// against [`guid_string`] directly rather than reaching for the unported `GuidDataType`,
/// `DumbMemBufferImpl` and `SettingsImpl`. Like Java, the comparison is case-sensitive, so it
/// matches the lower-case hex MSVC emits.
pub fn is_guid_label(program: &dyn Program, address: &Address, label: &str) -> bool {
    let Some(rest) = label.strip_prefix(MS_GUID_PREFIX) else {
        return false;
    };
    let candidate = rest.replace('_', "-");
    guid_string(program, address, false).is_some_and(|rendered| rendered == candidate)
}

/// Fills `bytes` from `address` and decodes its leading 16 bytes as four words in the program's
/// byte order. `None` if the program has no memory or the read came up short.
///
/// Java's `MemoryAccessException` catch becomes the `None`; its subsequent `conv.getBytes` write
/// back into `bytes` re-encodes each word with the converter that just decoded it, so it is an
/// identity and is dropped.
fn read_guid_data(program: &dyn Program, address: &Address, bytes: &mut [u8]) -> Option<[u32; 4]> {
    let memory = program.get_memory()?;
    if memory.get_bytes(address, bytes) != bytes.len() {
        return None;
    }
    let conv = converter(memory.is_big_endian());
    let mut data = [0u32; 4];
    for (i, word) in data.iter_mut().enumerate() {
        *word = conv.get_int_at(bytes, i * 4) as u32;
    }
    Some(data)
}

/// Stands in for `DataConverter.getInstance(boolean)`.
fn converter(is_big_endian: bool) -> &'static dyn DataConverter {
    if is_big_endian {
        &crate::util::big_endian_data_converter::INSTANCE
    }
    else {
        &crate::util::little_endian_data_converter::INSTANCE
    }
}

/// Formats four decoded GUID words the way both `GuidUtil` and `GuidDataType` do: the first word
/// whole, the second as two halves, then the remaining two words a byte at a time, least
/// significant first.
fn render_guid(data: &[u32; 4]) -> String {
    const DELIM: &str = "-";
    let mut out = String::with_capacity(36);
    out.push_str(&Conv::to_hex_string_int(data[0] as i32));
    out.push_str(DELIM);
    out.push_str(&Conv::to_hex_string_short(data[1] as u16));
    out.push_str(DELIM);
    out.push_str(&Conv::to_hex_string_short((data[1] >> 16) as u16));
    out.push_str(DELIM);
    for i in 0..4 {
        out.push_str(&Conv::to_hex_string_byte((data[2] >> (i * 8)) as u8));
        if i == 1 {
            out.push_str(DELIM);
        }
    }
    for i in 0..4 {
        out.push_str(&Conv::to_hex_string_byte((data[3] >> (i * 8)) as u8));
    }
    out
}

/// Stands in for `NumericUtilities.parseHexLong` over an 8-digit field, which is unported.
fn parse_hex_u32(hex: &str) -> Option<u32> {
    u32::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::{Memory, MemoryAccessException};

    /// `IUnknown`, laid out as a `GUID` struct is in little-endian memory.
    const IUNKNOWN_BYTES: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, // Data1
        0x00, 0x00, // Data2
        0x00, 0x00, // Data3
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, // Data4
    ];
    const IUNKNOWN_STRING: &str = "00000000-0000-0000-c000-000000000046";

    struct FakeMemory {
        bytes: Vec<u8>,
        big_endian: bool,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(addr.offset() as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("beyond fake memory"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let start = addr.offset() as usize;
            let available = self.bytes.len().saturating_sub(start);
            let n = available.min(dest.len());
            dest[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }
    }

    struct FakeProgram {
        memory: Arc<dyn Memory>,
    }

    impl crate::framework::model::DomainObject for FakeProgram {}

    impl Program for FakeProgram {
        fn get_name(&self) -> String {
            "guid_util_test".to_string()
        }

        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn program_with(bytes: &[u8]) -> FakeProgram {
        FakeProgram {
            memory: Arc::new(FakeMemory { bytes: bytes.to_vec(), big_endian: false }),
        }
    }

    fn address(offset: i64) -> Address {
        Address::new(AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0), offset)
    }

    #[test]
    fn guid_string_renders_iunknown() {
        let program = program_with(&IUNKNOWN_BYTES);
        assert_eq!(
            guid_string(&program, &address(0), false).as_deref(),
            Some(IUNKNOWN_STRING)
        );
    }

    #[test]
    fn guid_string_validates_ole_variant() {
        let program = program_with(&IUNKNOWN_BYTES);
        // bytes[7] == 0x00, bytes[8] == 0xC0, bytes[15] == 0x46 -- the OLE range.
        assert_eq!(
            guid_string(&program, &address(0), true).as_deref(),
            Some(IUNKNOWN_STRING)
        );

        let mut broken = IUNKNOWN_BYTES;
        broken[15] = 0x00;
        let program = program_with(&broken);
        assert_eq!(guid_string(&program, &address(0), true), None);
        assert!(guid_string(&program, &address(0), false).is_some());
    }

    #[test]
    fn guid_string_is_none_on_short_read() {
        let program = program_with(&IUNKNOWN_BYTES[..8]);
        assert_eq!(guid_string(&program, &address(0), false), None);
    }

    #[test]
    fn guid_string_honors_big_endian_memory() {
        let program = FakeProgram {
            memory: Arc::new(FakeMemory { bytes: IUNKNOWN_BYTES.to_vec(), big_endian: true }),
        };
        // Data4's two words decode as 0xC0000000 and 0x00000046 rather than 0x000000C0 and
        // 0x46000000, and each still renders least-significant byte first, so the 0xC0 and the
        // 0x46 move to the opposite end of their group.
        assert_eq!(
            guid_string(&program, &address(0), false).as_deref(),
            Some("00000000-0000-0000-0000-00c046000000")
        );
    }

    #[test]
    fn versioned_guid_string_appends_version() {
        let mut bytes = IUNKNOWN_BYTES.to_vec();
        bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        let program = program_with(&bytes);
        assert_eq!(
            versioned_guid_string(&program, &address(0), false).as_deref(),
            Some("00000000-0000-0000-c000-000000000046 v2.0")
        );
    }

    #[test]
    fn is_guid_label_matches_ms_symbol_name() {
        let program = program_with(&IUNKNOWN_BYTES);
        assert!(is_guid_label(
            &program,
            &address(0),
            "_GUID_00000000_0000_0000_c000_000000000046"
        ));
        // Java compares case-sensitively against the lower-case rendering.
        assert!(!is_guid_label(
            &program,
            &address(0),
            "_GUID_00000000_0000_0000_C000_000000000046"
        ));
        assert!(!is_guid_label(&program, &address(0), "IID_IUnknown"));
        assert!(!is_guid_label(
            &program,
            &address(0),
            "_GUID_00000000_0000_0000_c000_000000000047"
        ));
    }

    #[test]
    fn parse_line_reads_plain_archive_entry() {
        let entry =
            parse_line("00000000-0000-0000-C000-000000000046 IUnknown", "-", GuidType::Iid)
                .expect("line should parse");
        assert_eq!(entry.guid_string(), "00000000-0000-0000-C000-000000000046");
        assert_eq!(entry.name(), "IUnknown");
        assert_eq!(entry.guid_type(), GuidType::Iid);
        assert_eq!(entry.unique_id_string(), "00000000-0000-0000-C000-000000000046");
        assert!(matches!(entry, GuidEntry::Plain(_)));
    }

    #[test]
    fn parse_line_reads_versioned_archive_entry() {
        let entry = parse_line(
            "8A885D04-1CEB-11C9-9FE8-08002B104860 v2.0 NDR_SYNTAX",
            "-",
            GuidType::Syntax,
        )
        .expect("line should parse");
        assert_eq!(entry.guid_string(), "8A885D04-1CEB-11C9-9FE8-08002B104860");
        assert_eq!(entry.name(), "NDR_SYNTAX");
        assert_eq!(
            entry.unique_id_string(),
            "8A885D04-1CEB-11C9-9FE8-08002B104860 V2.0"
        );
        match entry {
            GuidEntry::Versioned(info) => assert_eq!(info.guid_version_string(), "V2.0"),
            other => panic!("expected a versioned entry, got {other:?}"),
        }
    }

    #[test]
    fn parse_line_accepts_tab_separated_entries() {
        let entry = parse_line("00000000-0000-0000-C000-000000000046\tIUnknown", "-", GuidType::Iid)
            .expect("tabs become spaces before splitting");
        assert_eq!(entry.name(), "IUnknown");
    }

    #[test]
    fn parse_line_rejects_malformed_guids() {
        // Wrong digit count once the delimiter is stripped.
        assert_eq!(parse_line("00000000-0000-0000-C000-00000000 IUnknown", "-", GuidType::Iid), None);
        // Non-hex digits in a word.
        assert_eq!(
            parse_line("ZZZZZZZZ-0000-0000-C000-000000000046 IUnknown", "-", GuidType::Iid),
            None
        );
        // No whitespace at all, so there is no GUID field to cut.
        assert_eq!(parse_line("00000000-0000-0000-C000-000000000046", "-", GuidType::Iid), None);
    }

    #[test]
    fn is_ok_accepts_any_word_reproducing_javas_tautology() {
        assert!(is_ok(&[0, 0, 0, 0]));
        assert!(is_ok(&[0xFFFF_FFFF; 4]));
        assert!(!is_ok(&[]));
    }
}
