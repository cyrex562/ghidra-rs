//! Port of `ghidra.util.charset.CharsetInfoManager`.
//!
//! Maintains a list of charsets and info about each charset, with the more common charsets
//! ordered toward the beginning of the list.
//!
//! Created instances are immutable, but the global instance can be replaced by one that also
//! carries the user-defined information in `charset_info.json`, by calling
//! [`CharsetInfoManager::reinitialize_with_user_defined_charsets`]. (Java does this lazily to
//! avoid reading the config file during startup.) The JVM's charset registry is
//! [`JavaCharset`]; see its module docs for which charsets exist.
//!
//! `Application.findDataFileInAnyModule` is a static in Java; here the [`Application`] whose
//! modules are searched is passed in explicitly.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::framework::application::Application;
use crate::generic::jar::resource_file::ResourceFile;
use crate::util::msg::Msg;

use super::charset_info::{CharsetInfo, UnicodeScript};
use super::java_charset::JavaCharset;

/// `CharsetInfoManager.UTF8`.
pub const UTF8: &str = "UTF-8";
/// `CharsetInfoManager.UTF16`.
pub const UTF16: &str = "UTF-16";
/// `CharsetInfoManager.UTF32`.
pub const UTF32: &str = "UTF-32";
/// `CharsetInfoManager.USASCII`.
pub const USASCII: &str = "US-ASCII";

/// The file name of the charset information config file.
pub const CONFIG_FILE_NAME: &str = "charset_info.json";

/// `CharsetInfoManager.CHARSET_NAME_COMP`: compares charset names ignoring case and any `x-`
/// prefix.
pub fn charset_name_comp(s1: &str, s2: &str) -> Ordering {
    compare_ignore_case(strip_charset_x(s1), strip_charset_x(s2))
}

/// `CharsetInfoManager.CHARSET_COMP`: [`charset_name_comp`] over the infos' names.
pub fn charset_comp(csi1: &CharsetInfo, csi2: &CharsetInfo) -> Ordering {
    charset_name_comp(csi1.name(), csi2.name())
}

/// `String.compareToIgnoreCase`: compares char by char after case folding.
fn compare_ignore_case(a: &str, b: &str) -> Ordering {
    let fold = |c: char| c.to_uppercase().next().unwrap_or(c).to_lowercase().next().unwrap_or(c);
    a.chars().map(fold).cmp(b.chars().map(fold))
}

fn strip_charset_x(cs_name: &str) -> &str {
    cs_name.strip_prefix("x-").unwrap_or(cs_name)
}

fn global() -> &'static RwLock<Arc<CharsetInfoManager>> {
    static INSTANCE: OnceLock<RwLock<Arc<CharsetInfoManager>>> = OnceLock::new();
    INSTANCE.get_or_init(|| RwLock::new(Arc::new(CharsetInfoManager::new(Vec::new()))))
}

/// Maintains a list of charsets and info about each charset. More common charsets are ordered
/// toward the beginning of the list.
///
/// Port of `ghidra.util.charset.CharsetInfoManager`.
#[derive(Debug, Clone)]
pub struct CharsetInfoManager {
    /// Infos in addition order (Java's `LinkedHashMap`).
    charsets: Vec<CharsetInfo>,
}

impl CharsetInfoManager {
    /// `CharsetInfoManager.getInstance()`: the global instance. It only has generic information
    /// until [`reinitialize_with_user_defined_charsets`](Self::reinitialize_with_user_defined_charsets)
    /// is called.
    pub fn get_instance() -> Arc<CharsetInfoManager> {
        global().read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// `CharsetInfoManager.isBOMCharset(String)`: true if the charset needs additional care for
    /// byte-order-mark handling (`UTF-16`/`UTF-32`); a `LE`/`BE` variant needs none.
    pub fn is_bom_charset(charset_name: &str) -> bool {
        charset_name == UTF32 || charset_name == UTF16
    }

    /// The private `CharsetInfoManager(List<CharsetInfo>)` constructor: the standard charsets,
    /// then the user-defined ones present in the charset registry, then every other available
    /// charset sorted by [`charset_name_comp`].
    fn new(user_defined_info: Vec<CharsetInfo>) -> Self {
        let mut manager = CharsetInfoManager { charsets: Vec::new() };
        for csi in get_standard_charsets() {
            manager.put(csi);
        }
        for csi in user_defined_info {
            if JavaCharset::is_supported(csi.name()) {
                manager.put(csi);
            }
        }
        let mut avail_cs_names: Vec<&str> = JavaCharset::available_charsets().iter().map(|cs| cs.name()).collect();
        avail_cs_names.sort_by(|a, b| charset_name_comp(a, b));
        for cs_name in avail_cs_names {
            if manager.get(cs_name).is_none() {
                manager.put(CharsetInfo::from_charset_name(cs_name));
            }
        }
        manager
    }

    /// `LinkedHashMap.put`: replaces an existing entry in place, or appends.
    fn put(&mut self, csi: CharsetInfo) {
        match self.charsets.iter_mut().find(|existing| existing.name() == csi.name()) {
            Some(existing) => *existing = csi,
            None => self.charsets.push(csi),
        }
    }

    /// `getCharsetNames()`: the names of the configured charsets, in order.
    pub fn get_charset_names(&self) -> Vec<String> {
        self.charsets.iter().map(|csi| csi.name().to_string()).collect()
    }

    /// `getCharsets()`: every configured charset, in order.
    pub fn get_charsets(&self) -> Vec<CharsetInfo> {
        self.charsets.clone()
    }

    /// `getCharsetCharSize(String)`: the number of bytes the charset needs to specify a
    /// character (its minimum bytes per char), defaulting to 1 for an unknown charset.
    pub fn get_charset_char_size(&self, charset_name: &str) -> i32 {
        self.get(charset_name).map(|csi| csi.min_bytes_per_char()).unwrap_or(1)
    }

    /// `getCharsetNamesWithCharSize(int)`: the charsets whose minimum bytes per char is `size`.
    pub fn get_charset_names_with_char_size(&self, size: i32) -> Vec<String> {
        self.charsets
            .iter()
            .filter(|csi| csi.min_bytes_per_char() == size)
            .map(|csi| csi.name().to_string())
            .collect()
    }

    /// `get(Charset)`.
    pub fn get_for_charset(&self, cs: JavaCharset) -> Option<&CharsetInfo> {
        self.get(cs.name())
    }

    /// `get(String)`.
    pub fn get(&self, name: &str) -> Option<&CharsetInfo> {
        self.charsets.iter().find(|csi| csi.name() == name)
    }

    /// `get(String, Charset)`: the info for `name`, falling back to `default_cs`'s.
    pub fn get_or_default(&self, name: &str, default_cs: Option<JavaCharset>) -> Option<&CharsetInfo> {
        self.get(name).or_else(|| default_cs.and_then(|cs| self.get(cs.name())))
    }

    /// `getMostImplementedScripts()`: the non-Latin scripts supported by some charset that does
    /// not support all scripts, sorted by name.
    pub fn get_most_implemented_scripts(&self) -> Vec<UnicodeScript> {
        let ignore = [
            UnicodeScript::Common,
            UnicodeScript::Inherited,
            UnicodeScript::Unknown,
            UnicodeScript::Latin,
            UnicodeScript::Greek,
        ];
        let mut scripts: Vec<UnicodeScript> = self
            .charsets
            .iter()
            .filter(|csi| !csi.supports_all_scripts())
            .flat_map(|csi| csi.scripts().iter().copied())
            .filter(|script| !ignore.contains(script))
            .collect();
        scripts.sort_by_key(|s| script_name(*s));
        scripts.dedup();
        scripts
    }

    /// `getStandardCharsetNames()`.
    pub fn get_standard_charset_names() -> Vec<String> {
        [USASCII, UTF8, UTF16, UTF32].iter().map(|s| s.to_string()).collect()
    }

    /// `reinitializeWithUserDefinedCharsets()`: replaces the global instance with one that also
    /// carries the information in `app`'s `charset_info.json`, if it has any.
    pub fn reinitialize_with_user_defined_charsets(app: &dyn Application) {
        let config_file = CharsetInfoConfigFile::read(Self::get_config_file_location(app).as_ref());
        Self::reinitialize_with(config_file);
    }

    /// Replaces the global instance using an already-read config file (the second half of
    /// `reinitializeWithUserDefinedCharsets()`); nothing changes if it names no charsets.
    pub fn reinitialize_with(config_file: CharsetInfoConfigFile) {
        if !config_file.get_charsets().is_empty() {
            let manager = Arc::new(CharsetInfoManager::new(config_file.charsets));
            *global().write().unwrap_or_else(|e| e.into_inner()) = manager;
        }
    }

    /// `getConfigFileLocation()`: `charset_info.json` in any of `app`'s module data directories.
    pub fn get_config_file_location(app: &dyn Application) -> Option<ResourceFile> {
        app.find_data_file_in_any_module(CONFIG_FILE_NAME)
    }
}

/// `UnicodeScript.name()`, the Java constant name (the enum's serialized form).
fn script_name(script: UnicodeScript) -> String {
    serde_json::to_value(script).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// The standard charsets (`getStandardCharsets()`): ASCII and the UTF encodings, which are the
/// most commonly used, plus ISO-8859-1.
fn get_standard_charsets() -> Vec<CharsetInfo> {
    let all_scripts: BTreeSet<UnicodeScript> = UnicodeScript::ALL.iter().copied().collect();
    let latin: BTreeSet<UnicodeScript> = [UnicodeScript::Common, UnicodeScript::Latin].into_iter().collect();
    let info = |name: &str, min: i32, max: i32, align: i32, scripts: &BTreeSet<UnicodeScript>, can_error: bool, contains: &[&str]| {
        CharsetInfo::new(
            name,
            None,
            min,
            max,
            align,
            -1,
            true,
            can_error,
            scripts.clone(),
            contains.iter().map(|s| s.to_string()).collect::<HashSet<String>>(),
        )
    };
    vec![
        info(USASCII, 1, 1, 1, &latin, true, &[]),
        info(UTF8, 1, 4, 1, &all_scripts, true, &[]),
        info(UTF16, 2, 4, 2, &all_scripts, true, &[]),
        info(JavaCharset::UTF_16BE.name(), 2, 4, 2, &all_scripts, true, &[]),
        info(JavaCharset::UTF_16LE.name(), 2, 4, 2, &all_scripts, true, &[]),
        info(JavaCharset::UTF_32.name(), 4, 4, 4, &all_scripts, true, &[]),
        info(JavaCharset::UTF_32BE.name(), 4, 4, 4, &all_scripts, true, &[]),
        info(JavaCharset::UTF_32LE.name(), 4, 4, 4, &all_scripts, true, &[]),
        info(JavaCharset::iso_8859_1().name(), 1, 1, 1, &latin, false, &[USASCII]),
    ]
}

/// The contents of the `charset_info.json` configuration file.
///
/// Port of `CharsetInfoManager.CharsetInfoConfigFile`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CharsetInfoConfigFile {
    /// Broken up into a list of lines so it looks good in the json.
    comments: Vec<String>,
    charsets: Vec<CharsetInfo>,
}

impl CharsetInfoConfigFile {
    /// `CharsetInfoConfigFile(String, List<CharsetInfo>)`.
    pub fn new(comment: &str, charsets: Vec<CharsetInfo>) -> Self {
        CharsetInfoConfigFile { comments: comment.lines().map(str::to_string).collect(), charsets }
    }

    /// `CharsetInfoConfigFile.read(ResourceFile)`: the config file's contents, or an empty
    /// instance if there is no file or it cannot be read (the error is logged).
    pub fn read(config_file: Option<&ResourceFile>) -> CharsetInfoConfigFile {
        let Some(config_file) = config_file else {
            return CharsetInfoConfigFile::default();
        };
        let result = config_file.get_input_stream().and_then(|mut is| {
            let mut json = String::new();
            is.read_to_string(&mut json)?;
            Ok(json)
        });
        match result.map(|json| Self::parse(&json)) {
            Ok(Ok(file)) => file,
            Ok(Err(e)) => {
                Msg::error("CharsetInfoManager", &format!("Error reading {CONFIG_FILE_NAME}: {e}"));
                CharsetInfoConfigFile::default()
            }
            Err(e) => {
                Msg::error("CharsetInfoManager", &format!("Error reading {CONFIG_FILE_NAME}: {e}"));
                CharsetInfoConfigFile::default()
            }
        }
    }

    /// Parses config file json and validates it (Java does both inside `read`). A `null`
    /// document is an empty config.
    pub fn parse(json: &str) -> Result<CharsetInfoConfigFile, serde_json::Error> {
        let parsed: Option<CharsetInfoConfigFile> = serde_json::from_str(json)?;
        let file = parsed.unwrap_or_default();
        file.validate_data();
        Ok(file)
    }

    /// `getComment()`.
    pub fn get_comment(&self) -> String {
        self.comments.join("\n")
    }

    /// `getCharsets()`.
    pub fn get_charsets(&self) -> &[CharsetInfo] {
        &self.charsets
    }

    /// `validateData()`: warns about duplicate and unsupported charset names.
    pub fn validate_data(&self) {
        let mut names = HashSet::new();
        let mut dups = BTreeSet::new();
        let mut unknowns = BTreeSet::new();
        for csi in &self.charsets {
            if !names.insert(csi.name()) {
                dups.insert(csi.name());
            }
            if !JavaCharset::is_supported(csi.name()) {
                unknowns.insert(csi.name());
            }
        }
        if !dups.is_empty() {
            Msg::warn("CharsetInfoManager", &format!("Duplicate charset names found in {CONFIG_FILE_NAME}: {dups:?}"));
        }
        if !unknowns.is_empty() {
            Msg::warn(
                "CharsetInfoManager",
                &format!("Unknown/unsupported charset names found in {CONFIG_FILE_NAME}: {unknowns:?}"),
            );
        }
    }

    /// The json `write` produces: pretty printed, without each info's `standardCharset` field.
    pub fn to_json(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(charsets) = value.get_mut("charsets").and_then(|c| c.as_array_mut()) {
            for csi in charsets {
                if let Some(obj) = csi.as_object_mut() {
                    obj.remove("standardCharset");
                }
            }
        }
        serde_json::to_string_pretty(&value).unwrap_or_default()
    }

    /// `write(File)`: writes this config to `config_filename` via a `.tmp` file, keeping the
    /// previous file as `.prev` until the new one is in place.
    pub fn write(&self, config_filename: &Path) -> io::Result<()> {
        let config_dir = config_filename.parent().unwrap_or_else(|| Path::new("."));
        let file_name = config_filename.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let tmp_config_file = config_dir.join(format!("{file_name}.tmp"));
        let prev_config_file = config_dir.join(format!("{file_name}.prev"));
        {
            let mut fw = std::fs::File::create(&tmp_config_file)?;
            fw.write_all(self.to_json().as_bytes())?;
        }
        let _ = std::fs::remove_file(&prev_config_file);
        let _ = std::fs::rename(config_filename, &prev_config_file);
        if std::fs::rename(&tmp_config_file, config_filename).is_ok() {
            let _ = std::fs::remove_file(&prev_config_file);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of `CharsetInfoManagerTest.testCharsetsArePresent`: every charset of the registry is
    /// listed.
    #[test]
    fn charsets_are_present() {
        let jvm_charset_count = JavaCharset::available_charsets().len();
        let csim_count = CharsetInfoManager::new(Vec::new()).get_charset_names().len();
        assert_eq!(jvm_charset_count, csim_count);
    }

    #[test]
    fn standard_charsets_come_first_then_the_rest_sorted_without_x_prefix() {
        let names = CharsetInfoManager::new(Vec::new()).get_charset_names();
        assert_eq!(
            &names[..9],
            &["US-ASCII", "UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE", "UTF-32", "UTF-32BE", "UTF-32LE", "ISO-8859-1"]
        );
        // An "x-" prefix is ignored: "x-IBM1006" sorts as "IBM1006", "x-iso-8859-11" as
        // "iso-8859-11".
        let pos = |n: &str| names.iter().position(|x| x == n).unwrap();
        assert!(pos("x-IBM1006") < pos("x-IBM1025"));
        assert!(pos("IBM1026") < pos("x-IBM1046"));
        assert!(pos("x-iso-8859-11") < pos("ISO-8859-13"));
        assert!(pos("ISO-8859-16") < pos("ISO-8859-2"));
    }

    #[test]
    fn char_sizes() {
        let csim = CharsetInfoManager::new(Vec::new());
        assert_eq!(csim.get_charset_char_size("US-ASCII"), 1);
        assert_eq!(csim.get_charset_char_size("UTF-8"), 1);
        assert_eq!(csim.get_charset_char_size("UTF-16"), 2);
        assert_eq!(csim.get_charset_char_size("UTF-16LE"), 2);
        assert_eq!(csim.get_charset_char_size("UTF-32BE"), 4);
        assert_eq!(csim.get_charset_char_size("IBM-Thai"), 1);
        assert_eq!(csim.get_charset_char_size("no-such"), 1);
        assert_eq!(csim.get_charset_names_with_char_size(4), vec!["UTF-32", "UTF-32BE", "UTF-32LE"]);
        assert!(CharsetInfoManager::is_bom_charset("UTF-16"));
        assert!(CharsetInfoManager::is_bom_charset("UTF-32"));
        assert!(!CharsetInfoManager::is_bom_charset("UTF-16LE"));
        let info = csim.get_or_default("no-such", Some(JavaCharset::UTF_8)).unwrap();
        assert_eq!(info.name(), "UTF-8");
        assert!(info.is_standard_charset());
        assert_eq!(csim.get_for_charset(JavaCharset::UTF_16LE).unwrap().alignment(), 2);
    }

    #[test]
    fn user_defined_info_is_used_when_the_charset_is_supported() {
        let json = r#"{
          "comments": ["line one", "line two"],
          "charsets": [
            { "name": "IBM-Thai", "comment": "Thai EBCDIC", "minBytesPerChar": 1, "maxBytesPerChar": 1,
              "alignment": 1, "codePointCount": 190, "scripts": ["COMMON", "LATIN", "THAI"],
              "contains": [], "canProduceError": true },
            { "name": "Big5", "minBytesPerChar": 1, "maxBytesPerChar": 2, "alignment": 1,
              "codePointCount": 13830, "scripts": ["HAN"], "contains": ["US-ASCII"], "canProduceError": true }
          ]
        }"#;
        let config = CharsetInfoConfigFile::parse(json).unwrap();
        assert_eq!(config.get_comment(), "line one\nline two");
        assert_eq!(config.get_charsets().len(), 2);
        let csim = CharsetInfoManager::new(config.charsets.clone());
        let names = csim.get_charset_names();
        // After the 9 standard charsets comes the supported user-defined one; Big5 is not
        // supported by this registry, so it is skipped exactly as Java skips a charset its JVM lacks.
        assert_eq!(names[9], "IBM-Thai");
        assert!(!names.contains(&"Big5".to_string()));
        let thai = csim.get("IBM-Thai").unwrap();
        assert_eq!(thai.comment(), Some("Thai EBCDIC"));
        assert_eq!(thai.code_point_count(), 190);
        assert!(!thai.is_standard_charset());
        assert_eq!(csim.get_most_implemented_scripts(), vec![UnicodeScript::Thai]);
    }

    #[test]
    fn null_or_bad_config_is_empty() {
        assert!(CharsetInfoConfigFile::parse("null").unwrap().get_charsets().is_empty());
        assert!(CharsetInfoConfigFile::parse("{").is_err());
        assert!(CharsetInfoConfigFile::read(None).get_charsets().is_empty());
    }

    #[test]
    fn write_then_read_round_trips_without_standard_charset_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "old").unwrap();
        let infos = vec![CharsetInfo::from_charset_name("IBM-Thai").with_comment(Some("c".into()))];
        CharsetInfoConfigFile::new("hello\nworld", infos).write(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("standardCharset"));
        assert!(!dir.path().join(format!("{CONFIG_FILE_NAME}.prev")).exists());
        let back = CharsetInfoConfigFile::read(Some(&ResourceFile::new(path)));
        assert_eq!(back.get_comment(), "hello\nworld");
        assert_eq!(back.get_charsets()[0].comment(), Some("c"));
    }

    /// The real `charset_info.json` shipped with Ghidra parses, and its supported entries are
    /// picked up.
    #[test]
    fn ghidra_charset_info_json_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../orig_src/Ghidra/Framework/SoftwareModeling/data/charset_info.json");
        let Ok(json) = std::fs::read_to_string(&path) else {
            return;
        };
        let config = CharsetInfoConfigFile::parse(&json).unwrap();
        assert_eq!(config.get_charsets().len(), 160);
        let csim = CharsetInfoManager::new(config.charsets.clone());
        let thai = csim.get("IBM-Thai").unwrap();
        assert!(thai.comment().is_some());
        assert_eq!(csim.get_charset_names().len(), JavaCharset::available_charsets().len());
    }

    #[test]
    fn name_comparator_ignores_case_and_x_prefix() {
        assert_eq!(charset_name_comp("x-IBM874", "ibm874"), Ordering::Equal);
        assert_eq!(charset_name_comp("a", "B"), Ordering::Less);
    }
}
