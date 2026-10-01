//! Port of `ghidra.app.util.bin.format.golang.rtti.GoApiSnapshot`.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::go_symbol_name::GoSymbolName;
use super::json_patch::JsonPatch;
use super::json_patch_applier::{JsonPatchApplier, JsonPatchError};
use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::format::golang::go_ver::GoVer;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Error from [`GoApiSnapshot::get`]: Java's `IOException` or `CancelledException`.
#[derive(Debug)]
pub enum GoApiSnapshotError {
    /// Error parsing json or opening the snapshot file.
    Io(io::Error),
    /// The user cancelled.
    Cancelled(CancelledException),
}

impl fmt::Display for GoApiSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GoApiSnapshotError::Io(e) => write!(f, "{e}"),
            GoApiSnapshotError::Cancelled(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GoApiSnapshotError {}

impl From<io::Error> for GoApiSnapshotError {
    fn from(e: io::Error) -> Self {
        GoApiSnapshotError::Io(e)
    }
}

impl From<JsonPatchError> for GoApiSnapshotError {
    fn from(e: JsonPatchError) -> Self {
        match e {
            JsonPatchError::Io(e) => GoApiSnapshotError::Io(e),
            JsonPatchError::Cancelled(e) => GoApiSnapshotError::Cancelled(e),
        }
    }
}

/// The `Base` module's `data/typeinfo/golang` directory, where the snapshot json files (and the
/// `patchverdiffs/` they are patched with) live. Stands in for
/// `Application.getModuleDataFile("typeinfo/golang/...")`; like the crate's other data-file
/// consumers it resolves against the Ghidra source tree next to this crate.
pub fn default_snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../orig_src/Ghidra/Features/Base/data/typeinfo/golang")
}

static IS_GOOS_UNIX: &[&str] = &[
    "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "linux", "netbsd", "openbsd",
    "solaris",
];

/// Contains function definitions and type information found in a specific Go runtime toolchain
/// version.
///
/// Useful to apply function parameter information to functions found in a Go binary.
///
/// Snapshot json files contain function / type information about functions and types extracted
/// from the Go toolchain itself, for each arch and OSes that the Go toolchain supports, via
/// cross-compiling against each GOARCH and GOOS.
///
/// Function and type info that is incompatible or not present in other arch / os targets will be
/// split into different arch lookup keys that can be specified when deserializing the json.
///
/// The arch names will be one of "all", cpu-arch-name (eg. amd64), operating-system-name (eg.
/// linux), operating-system-cpu-arch-name (eg. linux-amd64), or "unix" (artificial arch name that
/// indicates the sub-elements are common to all unix-like arches).
#[derive(Debug, Clone)]
pub struct GoApiSnapshot {
    /// The kept arches, in search priority order (Java's `LinkedHashMap`).
    arches: Vec<(String, GoArch)>,
    ver: GoVer,
}

/// A name / data type pair: a function parameter or result, or a struct field
/// (`GoApiSnapshot.GoNameTypePair`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct GoNameTypePair {
    /// `Name`, may be absent.
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    /// `DataType`, may be absent.
    #[serde(rename = "DataType", default)]
    pub data_type: Option<String>,
}

impl GoNameTypePair {
    /// `getPairString()`: `"name type"`, or whichever part is present.
    pub fn get_pair_string(&self) -> String {
        let mut s = self.name.clone().unwrap_or_default();
        if let Some(dt) = self.data_type.as_deref().filter(|dt| !dt.is_empty()) {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(dt);
        }
        s
    }

    /// `listToString(List<GoNameTypePair>)`: the pair strings, comma separated.
    pub fn list_to_string(list: &[GoNameTypePair]) -> String {
        list.iter().map(GoNameTypePair::get_pair_string).collect::<Vec<_>>().join(", ")
    }
}

impl fmt::Display for GoNameTypePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GoNameTypePair [Name={}, DataType={}]",
            self.name.as_deref().unwrap_or("null"),
            self.data_type.as_deref().unwrap_or("null")
        )
    }
}

/// Function flags (`GoApiSnapshot.FuncFlags`); values need to be kept in sync with
/// go-api-parser's `FuncFlags_*` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FuncFlags {
    /// Variadic function.
    VarArg = 1,
    /// Generic function.
    Generic = 2,
    /// Method.
    Method = 4,
    /// Function does not return.
    NoReturn = 8,
    /// Interface function.
    InterfaceFunc = 16,
}

impl FuncFlags {
    const VALUES: [FuncFlags; 5] =
        [FuncFlags::VarArg, FuncFlags::Generic, FuncFlags::Method, FuncFlags::NoReturn, FuncFlags::InterfaceFunc];

    /// `parse(int)`: the flags set in `i`, in declaration order (Java `EnumSet`).
    pub fn parse(i: i32) -> Vec<FuncFlags> {
        Self::VALUES.iter().copied().filter(|ff| i & (*ff as i32) != 0).collect()
    }
}

/// A function definition (`GoApiSnapshot.GoFuncDef`). Missing lists deserialize as empty, as
/// Java's `fixupAfterDeserialization` arranges.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct GoFuncDef {
    /// `Params`.
    #[serde(rename = "Params", default, deserialize_with = "null_as_empty")]
    pub params: Vec<GoNameTypePair>,
    /// `Results`.
    #[serde(rename = "Results", default, deserialize_with = "null_as_empty")]
    pub results: Vec<GoNameTypePair>,
    /// `TypeParams`.
    #[serde(rename = "TypeParams", default, deserialize_with = "null_as_empty")]
    pub type_params: Vec<String>,
    /// `Flags`.
    #[serde(rename = "Flags", default)]
    pub flags: i32,
}

impl GoFuncDef {
    /// `getFuncFlags()`.
    pub fn get_func_flags(&self) -> Vec<FuncFlags> {
        FuncFlags::parse(self.flags)
    }

    /// `getDefinitionString(GoSymbolName)`: a Go-like `func name(params) results` string. The
    /// receiver (the first param of a method) is omitted from the parameter list.
    pub fn get_definition_string(&self, symbol_name: &GoSymbolName) -> String {
        let results_str = if self.results.is_empty() {
            String::new()
        }
        else if self.results.len() == 1 && self.results[0].name.as_deref().unwrap_or("").is_empty() {
            format!(" {}", self.results[0].data_type.as_deref().unwrap_or("null"))
        }
        else {
            format!(" ({})", GoNameTypePair::list_to_string(&self.results))
        };

        let tmp_params = if symbol_name.has_receiver() && !self.params.is_empty() {
            &self.params[1..]
        }
        else {
            &self.params[..]
        };

        format!(
            "func {}({}){}",
            symbol_name.as_string(),
            GoNameTypePair::list_to_string(tmp_params),
            results_str
        )
    }
}

impl fmt::Display for GoFuncDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GoFuncDef [Params={:?}, Results={:?}, TypeParams={:?}, Flags={}]",
            self.params, self.results, self.type_params, self.flags
        )
    }
}

/// A type definition (`GoApiSnapshot.GoTypeDef` and its subclasses), selected by the json
/// `Kind` field.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "Kind")]
pub enum GoTypeDef {
    /// `GoStructDef` (`"struct"`).
    #[serde(rename = "struct")]
    Struct {
        /// `Fields`.
        #[serde(rename = "Fields", default, deserialize_with = "null_as_empty")]
        fields: Vec<GoNameTypePair>,
        /// `TypeParams`.
        #[serde(rename = "TypeParams", default, deserialize_with = "null_as_empty")]
        type_params: Vec<String>,
    },
    /// `GoInterfaceDef` (`"iface"`).
    #[serde(rename = "iface")]
    Interface,
    /// `GoBasicDef` (`"basic"`).
    #[serde(rename = "basic")]
    Basic {
        /// `DataType`.
        #[serde(rename = "DataType", default)]
        data_type: Option<String>,
        /// `EnumValues` (work in progress upstream).
        #[serde(rename = "EnumValues", default)]
        enum_values: Option<HashMap<String, String>>,
    },
    /// `GoAliasDef` (`"alias"`).
    #[serde(rename = "alias")]
    Alias {
        /// `Target`.
        #[serde(rename = "Target", default)]
        target: Option<String>,
    },
    /// `GoFuncTypeDef` (`"funcdef"`).
    #[serde(rename = "funcdef")]
    FuncType {
        /// `Params`.
        #[serde(rename = "Params", default, deserialize_with = "null_as_empty")]
        params: Vec<GoNameTypePair>,
        /// `Results`.
        #[serde(rename = "Results", default, deserialize_with = "null_as_empty")]
        results: Vec<GoNameTypePair>,
        /// `TypeParams`.
        #[serde(rename = "TypeParams", default, deserialize_with = "null_as_empty")]
        type_params: Vec<String>,
        /// `Flags` (unused upstream).
        #[serde(rename = "Flags", default)]
        flags: i32,
    },
    /// Any other `Kind`: Java's deserializer returns `null` for these, so lookups skip them.
    #[serde(other)]
    Unknown,
}

impl GoTypeDef {
    /// `getDataTypeSize(GoApiSnapshot)`: not implemented by any snapshot type upstream; always
    /// an error.
    pub fn get_data_type_size(&self, _snapshot: &GoApiSnapshot) -> io::Result<i32> {
        Err(io::Error::other("data type size not available"))
    }
}

/// The function and type definitions of one arch key (`GoApiSnapshot.GoArch`).
#[derive(Debug, Clone, Default, Deserialize)]
struct GoArch {
    #[serde(rename = "Funcs", default, deserialize_with = "null_as_empty_map")]
    funcs: HashMap<String, GoFuncDef>,
    #[serde(rename = "Types", default, deserialize_with = "null_as_empty_map")]
    types: HashMap<String, Option<GoTypeDef>>,
}

fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

fn null_as_empty_map<'de, D, T>(d: D) -> Result<HashMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<HashMap<String, T>>::deserialize(d)?.unwrap_or_default())
}

/// Reads the top level `{ archName: GoArch, ... }` object, skipping the arches not in `keep`
/// (Java streams the object with a `JsonReader` and `skipValue()`s those).
struct ArchFilter<'a> {
    keep: &'a HashSet<String>,
}

impl<'de> DeserializeSeed<'de> for ArchFilter<'_> {
    type Value = HashMap<String, GoArch>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ArchFilter<'_> {
    type Value = HashMap<String, GoArch>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a map of arch name to GoArch")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut result = HashMap::new();
        while let Some(arch_name) = map.next_key::<String>()? {
            if self.keep.contains(&arch_name) {
                result.insert(arch_name, map.next_value::<GoArch>()?);
            }
            else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(result)
    }
}

impl GoApiSnapshot {
    /// The `EMPTY` instance: no arches, invalid version.
    pub fn empty() -> GoApiSnapshot {
        GoApiSnapshot { arches: Vec::new(), ver: GoVer::INVALID }
    }

    /// Returns a matching snapshot for the specified Go version (`get(GoVer, String, String,
    /// TaskMonitor)`). If an exact match isn't found, earlier patch revs will be tried until all
    /// patch levels are exhausted. Returns [`empty`](Self::empty) if no matching snapshot file is
    /// found.
    ///
    /// # Errors
    /// Error parsing json or opening the snapshot file, or cancellation.
    pub fn get(
        go_ver: GoVer,
        go_arch: &str,
        go_os: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<GoApiSnapshot, GoApiSnapshotError> {
        Self::get_from_dir(&default_snapshot_dir(), go_ver, go_arch, go_os, monitor)
    }

    /// [`get`](Self::get) with an explicit snapshot directory.
    ///
    /// # Errors
    /// See [`get`](Self::get).
    pub fn get_from_dir(
        dir: &Path,
        go_ver: GoVer,
        go_arch: &str,
        go_os: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<GoApiSnapshot, GoApiSnapshotError> {
        let Some(json) = Self::get_api_snapshot_json(dir, go_ver, monitor)? else {
            return Ok(Self::empty());
        };
        let unix = if IS_GOOS_UNIX.contains(&go_os) { "unix" } else { "" };
        let os_arch = format!("{go_os}-{go_arch}");
        let arch_search_order = [os_arch.as_str(), go_os, unix, go_arch, "all"];
        Ok(Self::read(&json, &arch_search_order, go_ver)?)
    }

    /// `getApiSnapshotJsonFile(GoVer, TaskMonitor)`: the snapshot json for `go_ver`, as a byte
    /// provider; see [`get_api_snapshot_json`](Self::get_api_snapshot_json).
    ///
    /// # Errors
    /// See [`get_api_snapshot_json`](Self::get_api_snapshot_json).
    pub fn get_api_snapshot_json_file(
        go_ver: GoVer,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<ByteArrayProvider>, GoApiSnapshotError> {
        Ok(Self::get_api_snapshot_json(&default_snapshot_dir(), go_ver, monitor)?
            .map(|bytes| ByteArrayProvider::with_name(&format!("go{go_ver}.json"), bytes)))
    }

    /// The snapshot json bytes for `go_ver`: the `go<major>.<minor>.0.json` base file, patched
    /// with the closest `patchverdiffs/go<ver>.json.diff` at or below `go_ver`'s patch level.
    /// `None` when there is no base file for the minor version.
    ///
    /// Java caches the patched json as a derived file through `FileSystemService`; this port
    /// patches in memory on each call.
    ///
    /// # Errors
    /// Error reading or patching the json, or cancellation.
    pub fn get_api_snapshot_json(
        dir: &Path,
        go_ver: GoVer,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Vec<u8>>, GoApiSnapshotError> {
        let base_ver = go_ver.with_patch(0);
        let Some(json_file) = get_api_snapshot_file(dir, base_ver, "", "") else {
            return Ok(None);
        };
        let Some(patch_diff_file) = get_patch_ver_diff_file(dir, go_ver) else {
            return Ok(Some(std::fs::read(&json_file)?));
        };

        let json_patch = JsonPatch::read_file(&patch_diff_file)?;
        let mut jpa = JsonPatchApplier::from_file(&json_file)?;
        monitor.initialize(json_patch.get_section_count() as i64);
        monitor.set_message(&format!("Patching Go API snapshot {base_ver} -> {go_ver}"));
        jpa.apply(&json_patch, monitor)?;
        let json = jpa.into_json().unwrap_or(serde_json::Value::Null);
        Ok(Some(serde_json::to_vec(&json).map_err(io::Error::other)?))
    }

    /// Reads a json snapshot file produced by the go-api-parser exfil tool (`read(InputStream,
    /// List<String>, GoVer)`). Information for archs that are not needed is skipped.
    ///
    /// `arch_names` lists the arch names to retain, in search priority, example:
    /// `["linux-amd64", "linux", "amd64", "all"]`; empty names are ignored.
    ///
    /// # Errors
    /// Error parsing the json.
    pub fn read(json: &[u8], arch_names: &[&str], ver: GoVer) -> io::Result<GoApiSnapshot> {
        let keep: HashSet<String> = arch_names.iter().map(|s| s.to_string()).collect();
        let mut de = serde_json::Deserializer::from_slice(json);
        let mut arches = ArchFilter { keep: &keep }
            .deserialize(&mut de)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        de.end().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut results = Vec::new();
        for arch_name in arch_names {
            if arch_name.is_empty() || results.iter().any(|(n, _): &(String, GoArch)| n == arch_name) {
                continue;
            }
            if let Some(arch) = arches.remove(*arch_name) {
                results.push((arch_name.to_string(), arch));
            }
        }
        Ok(GoApiSnapshot { arches: results, ver })
    }

    /// `getVer()`.
    pub fn get_ver(&self) -> GoVer {
        self.ver
    }

    /// `isInvalid()`: no arch information was found.
    pub fn is_invalid(&self) -> bool {
        self.arches.is_empty()
    }

    /// Returns the function definition for the specified function name, which should not contain
    /// generics (eg. `"cmp.Compare"` and not `"cmp.Compare[sometypename]"`) (`getFuncdef`).
    pub fn get_funcdef(&self, func_name: &str) -> Option<&GoFuncDef> {
        self.arches.iter().find_map(|(_, arch)| arch.funcs.get(func_name))
    }

    /// `getTypeDef(String)`.
    pub fn get_type_def(&self, type_name: &str) -> Option<&GoTypeDef> {
        self.arches.iter().find_map(|(_, arch)| match arch.types.get(type_name) {
            Some(Some(td)) if *td != GoTypeDef::Unknown => Some(td),
            _ => None,
        })
    }
}

/// `getPatchVerDiffFile(GoVer)`: the closest patch file at or below `go_ver`'s patch level, or
/// `None` if the patch number is already 0 or no patch diff files are found for the
/// major.minor version.
fn get_patch_ver_diff_file(dir: &Path, go_ver: GoVer) -> Option<PathBuf> {
    let mut patch_ver = go_ver;
    let mut patch_diff_file = None;
    while patch_ver.patch > 0 {
        patch_diff_file = get_api_snapshot_file(dir, patch_ver, "patchverdiffs/", ".diff");
        if patch_diff_file.is_some() {
            break;
        }
        patch_ver = patch_ver.prev_patch();
    }

    if patch_ver.patch != go_ver.patch {
        Msg::warn("GoApiSnapshot", &format!("Falling back from {go_ver} to {patch_ver} for Go API snapshot"));
    }
    else {
        Msg::info("GoApiSnapshot", &format!("Using Go API snapshot for {go_ver}"));
    }
    patch_diff_file
}

/// `getApiSnapshotFile(GoVer, String, String)`: `<dir>/<subdir>go<ver>.json<suffix>`, if it
/// exists.
pub fn get_api_snapshot_file(dir: &Path, go_ver: GoVer, subdir: &str, suffix: &str) -> Option<PathBuf> {
    let f = dir.join(format!("{subdir}go{go_ver}.json{suffix}"));
    f.is_file().then_some(f)
}

/// `getApiFile(File, GoVer)`: `go<major>.<minor>.<patch>.json` in `base_dir`, or for a `.0`
/// version the `go<major>.<minor>.json` spelling.
pub fn get_api_file(base_dir: &Path, ver: GoVer) -> Option<PathBuf> {
    let mut f = base_dir.join(format!("go{}.{}.{}.json", ver.major, ver.minor, ver.patch));
    if !f.is_file() && ver.patch == 0 {
        f = base_dir.join(format!("go{}.{}.json", ver.major, ver.minor));
    }
    f.is_file().then_some(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::go_ver_range::GoVerRange;
    use crate::util::task::DummyMonitor;

    fn supported_versions() -> Vec<GoVer> {
        // GoRttiMapper.SUPPORTED_VERSIONS
        GoVerRange::parse("1.15-1.26").as_list().unwrap()
    }

    /// Port of `GoApiSnapshotTest.testSnapshotsExistForAllSupportedMinorVers`.
    #[test]
    fn snapshots_exist_for_all_supported_minor_vers() {
        for ver in supported_versions() {
            assert!(get_api_snapshot_file(&default_snapshot_dir(), ver, "", "").is_some(), "{ver}");
        }
    }

    /// Port of `GoApiSnapshotTest.testWellKnownSymbolsInEachSnapshot`.
    #[test]
    fn well_known_symbols_in_each_snapshot() {
        for ver in supported_versions() {
            let gas = GoApiSnapshot::get(ver, "amd64", "linux", &DummyMonitor).unwrap();
            assert!(!gas.is_invalid());
            let runtime_type = gas.get_type_def("runtime._type").unwrap_or_else(|| panic!("{ver}"));
            assert!(matches!(runtime_type, GoTypeDef::Struct { .. } | GoTypeDef::Alias { .. }), "{ver}");
        }
    }

    /// Port of `GoApiSnapshotTest.testSnapshotFallback`: a never-seen patch level falls back to
    /// the closest patch diff and still yields a snapshot.
    #[test]
    fn snapshot_fallback() {
        for ver in [GoVer::new(1, 21, 0), GoVer::new(1, 24, 0)] {
            let bytes = GoApiSnapshot::get_api_snapshot_json(&default_snapshot_dir(), ver.with_patch(99), &DummyMonitor)
                .unwrap();
            assert!(bytes.is_some(), "{ver}");
        }
        assert!(GoApiSnapshot::get_api_snapshot_json_file(GoVer::new(1, 15, 99), &DummyMonitor).unwrap().is_some());
        assert!(GoApiSnapshot::get_api_snapshot_json(&default_snapshot_dir(), GoVer::new(1, 2, 0), &DummyMonitor)
            .unwrap()
            .is_none());
    }

    #[test]
    fn patched_snapshot_differs_from_base() {
        let dir = default_snapshot_dir();
        // go1.21.1's diff moves crypto/tls positions; the funcs themselves survive
        let gas = GoApiSnapshot::get_from_dir(&dir, GoVer::new(1, 21, 1), "amd64", "linux", &DummyMonitor).unwrap();
        assert_eq!(gas.get_ver(), GoVer::new(1, 21, 1));
        assert!(gas.get_funcdef("crypto/tls.checkALPN").is_some());
    }

    #[test]
    fn reads_and_searches_arches_in_priority_order() {
        let json = br#"{
            "all": {"Funcs": {"pkg.f": {"Params": [{"Name": "a", "DataType": "int"}], "Results": [{"DataType": "bool"}]}},
                    "Types": {"pkg.T": {"Kind": "basic", "DataType": "int"}, "pkg.U": {"Kind": "weird"}}},
            "linux": {"Funcs": {"pkg.f": {"Flags": 9}}, "Types": {"pkg.U": {"Kind": "alias", "Target": "int"}}},
            "windows": {"Funcs": {"pkg.w": {}}}
        }"#;
        let gas = GoApiSnapshot::read(json, &["linux-amd64", "linux", "unix", "amd64", "all"], GoVer::new(1, 21, 0))
            .unwrap();
        // linux wins over all
        let f = gas.get_funcdef("pkg.f").unwrap();
        assert_eq!(f.flags, 9);
        assert_eq!(f.get_func_flags(), vec![FuncFlags::VarArg, FuncFlags::NoReturn]);
        assert!(f.params.is_empty() && f.results.is_empty());
        assert!(gas.get_funcdef("pkg.w").is_none());
        assert_eq!(
            gas.get_type_def("pkg.T"),
            Some(&GoTypeDef::Basic { data_type: Some("int".to_string()), enum_values: None })
        );
        assert_eq!(gas.get_type_def("pkg.U"), Some(&GoTypeDef::Alias { target: Some("int".to_string()) }));
        assert!(GoApiSnapshot::empty().is_invalid());
    }

    #[test]
    fn definition_strings() {
        let json = br#"{"all": {"Funcs": {
            "pkg.f": {"Params": [{"Name": "a", "DataType": "int"}, {"Name": "b", "DataType": "string"}], "Results": [{"DataType": "bool"}]},
            "pkg.g": {"Params": [{"Name": "r", "DataType": "*T"}, {"DataType": "int"}], "Results": [{"Name": "n", "DataType": "int"}, {"Name": "err", "DataType": "error"}]}
        }}}"#;
        let gas = GoApiSnapshot::read(json, &["all"], GoVer::new(1, 21, 0)).unwrap();
        let f = gas.get_funcdef("pkg.f").unwrap();
        assert_eq!(f.get_definition_string(&GoSymbolName::parse("pkg.f")), "func pkg.f(a int, b string) bool");
        let g = gas.get_funcdef("pkg.g").unwrap();
        assert_eq!(
            g.get_definition_string(&GoSymbolName::parse("pkg.(*T).g")),
            "func pkg.(*T).g(int) (n int, err error)"
        );
    }
}
