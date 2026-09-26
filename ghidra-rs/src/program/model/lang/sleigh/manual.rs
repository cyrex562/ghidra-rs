//! The processor-manual index behind [`SleighLanguage`](super::SleighLanguage)'s
//! `getManualEntry`/`getManualInstructionMnemonicKeys`/`hasManual`/`getManualException`.
//!
//! Port of the manual-index portion of `ghidra.app.plugin.processors.sleigh.SleighLanguage`
//! (`initManual`, `loadIndex`, `getManualEntry`, and the `COMMENT`/`FILE_INCLUDE`/`FILE_SWITCH`/
//! `FILE_SWITCH_WITH_DESCRIPTION`/`INSTRUCTION` line patterns).
//!
//! Representation notes:
//! * Java keys a `TreeMap<String, ManualEntry>` with a null-tolerant case-insensitive comparator,
//!   storing the default manual under the `null` key. Every non-null key is upper-cased on insert,
//!   so ordering the upper-cased keys in a [`BTreeMap`] is equivalent; the `null`-keyed default
//!   entry is held separately in [`ManualIndex::default_entry`].
//! * [`ManualEntry`] has non-optional `String` fields, so the default entry's Java `null`
//!   mnemonic and page number are represented by empty strings.
//! * In Ghidra development mode Java first searches every module for `manuals/<file>` via
//!   `Application.findDataFileInAnyModule` (not ported); this port always takes the
//!   production-mode path, including its quirk that a `@file[description]` line only sets the
//!   current manual if none has been set yet by an earlier switch line in the same index file.
//! * `FileUtilities.existsAndIsCaseDependent` (not yet ported) is reproduced by the private
//!   [`exists_and_is_case_dependent`] helper, using the ported [`FileResolutionResult`].

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

use regex::Regex;

use crate::generic::jar::resource_file::ResourceFile;
use crate::util::manual_entry::ManualEntry;
use crate::util::msg::Msg;
use crate::util::util::FileResolutionResult;

const ORIGINATOR: &str = "SleighLanguage";
const NO_INFORMATION: &str = "(no information available)";

fn comment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*#(.*)").unwrap())
}

fn file_include() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*<(.*)").unwrap())
}

fn file_switch() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*@(.*)").unwrap())
}

fn file_switch_with_description() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*@(.*)\[(.*)\]").unwrap())
}

fn instruction() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s*([^,]+)\s*,\s*(.+)").unwrap())
}

/// A loaded processor-manual index: mnemonic (upper-cased) to [`ManualEntry`], plus the default
/// entry used when a mnemonic is not indexed.
#[derive(Debug, Default, Clone)]
pub(crate) struct ManualIndex {
    entries: BTreeMap<String, ManualEntry>,
    default_entry: Option<ManualEntry>,
}

/// The lazily-initialized manual state: the index (possibly partially loaded) and the error, if
/// any, raised while loading it. Port of the `manual`/`manualException` field pair.
#[derive(Debug, Default)]
pub(crate) struct ManualState {
    pub(crate) index: ManualIndex,
    pub(crate) error: Option<String>,
}

impl ManualState {
    /// Port of `SleighLanguage.initManual()`: loads `index_file` if there is one, recording (and
    /// logging) any failure instead of propagating it.
    pub(crate) fn load(index_file: Option<&ResourceFile>) -> Self {
        let mut state = ManualState::default();
        if let Some(file) = index_file {
            if let Err(e) = state.index.load_index(file) {
                Msg::error(ORIGINATOR, &format!("error loading manual index: {e}"));
                state.error = Some(e);
            }
        }
        state
    }
}

impl ManualIndex {
    /// Port of `SleighLanguage.getManualEntry(String)`: the entry whose (upper-cased) mnemonic is
    /// the longest prefix of `instruction` among keys sharing its first character, falling back
    /// to the default entry.
    pub(crate) fn get_entry(&self, instruction: &str) -> Option<ManualEntry> {
        if instruction.is_empty() {
            return self.default_entry.clone();
        }
        let instruction = instruction.to_uppercase();
        let first = instruction.chars().next().expect("non-empty");
        let first_key = first.to_string();
        let candidates: Vec<(&String, &ManualEntry)> =
            match char::from_u32(first as u32 + 1).map(|c| c.to_string()) {
                Some(last_key) => self
                    .entries
                    .range::<String, _>(first_key.clone()..last_key)
                    .collect(),
                // Java's `headMap` throws `IllegalArgumentException` when the bound is out of
                // range and falls back to the whole tail map.
                None => self.entries.range::<String, _>(first_key..).collect(),
            };

        let mut best: Option<&ManualEntry> = None;
        let mut max_in_common: i64 = -1;
        for (key, entry) in candidates {
            if instruction.starts_with(key.as_str()) && key.len() as i64 > max_in_common {
                best = Some(entry);
                max_in_common = key.len() as i64;
            }
        }
        match best {
            Some(entry) => Some(entry.clone()),
            None => self.default_entry.clone(),
        }
    }

    /// Port of `SleighLanguage.getManualInstructionMnemonicKeys()`. Java's key set also contains
    /// the `null` key of the default entry, which a `HashSet<String>` cannot represent; only the
    /// mnemonic keys are returned.
    pub(crate) fn keys(&self) -> HashSet<String> {
        self.entries.keys().cloned().collect()
    }

    /// Port of `SleighLanguage.loadIndex(ResourceFile)`.
    ///
    /// # Errors
    /// Returns a message describing the failure: an unreadable index file, an include or `@file`
    /// switch that does not exist or is not properly case dependent, or an instruction line
    /// before any manual has been named.
    pub(crate) fn load_index(&mut self, processor_file: &ResourceFile) -> Result<(), String> {
        let manual_directory = processor_file
            .get_parent_file()
            .ok_or_else(|| format!("index file {} has no parent directory", processor_file.absolute_path()))?
            .get_canonical_file();
        let mut current_manual: Option<ResourceFile> = None;
        let mut default_manual: Option<String> = None;
        let mut missing_description = NO_INFORMATION.to_string();

        let stream = processor_file
            .get_input_stream()
            .map_err(|e| format!("{}: {e}", processor_file.absolute_path()))?;
        for line in BufReader::new(stream).lines() {
            let line = line.map_err(|e| format!("{}: {e}", processor_file.absolute_path()))?;
            if comment().is_match(&line) {
                continue;
            }
            if let Some(m) = file_include().captures(&line) {
                let included = manual_directory.join(m[1].trim());
                let result = exists_and_is_case_dependent(&included);
                if !result.is_ok() {
                    return Err(format!(
                        "manual index file {} is not properly case dependent: {}",
                        included.absolute_path(),
                        result.message()
                    ));
                }
                self.load_index(&included)?;
            } else if let Some(m) = file_switch_with_description().captures(&line) {
                if current_manual.is_none() {
                    current_manual = Some(manual_directory.join(m[1].trim()));
                }
                let manual = current_manual.as_ref().expect("set above");
                let result = exists_and_is_case_dependent(manual);
                missing_description = m[2].trim().to_string();
                if default_manual.is_none() {
                    default_manual = Some(manual.absolute_path());
                }
                if !result.is_ok() {
                    // Since we do not always deliver manuals, generate warning only.
                    Msg::warn(
                        ORIGINATOR,
                        &format!(
                            "manual file {} not found or is not properly case dependent.\n  >>  {}",
                            manual.absolute_path(),
                            missing_description
                        ),
                    );
                }
            } else if let Some(m) = file_switch().captures(&line) {
                let manual = manual_directory.join(m[1].trim());
                let result = exists_and_is_case_dependent(&manual);
                if !result.is_ok() {
                    return Err(format!(
                        "manual file {} is not properly case dependent: {}",
                        manual.absolute_path(),
                        result.message()
                    ));
                }
                missing_description = NO_INFORMATION.to_string();
                if default_manual.is_none() {
                    default_manual = Some(manual.absolute_path());
                }
                current_manual = Some(manual);
            } else if let Some(m) = instruction().captures(&line) {
                let Some(manual) = current_manual.as_ref() else {
                    return Err(format!(
                        "index file {} does not specify manual first",
                        processor_file.absolute_path()
                    ));
                };
                let mnemonic = m[1].trim().to_uppercase();
                let page = m[2].trim().to_string();
                let entry = ManualEntry::new(
                    mnemonic.clone(),
                    manual.absolute_path(),
                    missing_description.clone(),
                    page,
                );
                self.entries.insert(mnemonic, entry);
            }
        }
        if let Some(default_path) = default_manual {
            self.default_entry = Some(ManualEntry::new(
                String::new(),
                default_path,
                missing_description,
                String::new(),
            ));
        }
        Ok(())
    }
}

/// Port of `FileUtilities.existsAndIsCaseDependent(ResourceFile)`.
fn exists_and_is_case_dependent(file: &ResourceFile) -> FileResolutionResult {
    if !file.exists() {
        return FileResolutionResult::does_not_exist(file);
    }
    let Ok(canonical_path) = file.canonical_path() else {
        return FileResolutionResult::does_not_exist(file);
    };
    path_is_case_dependent(&canonical_path, &file.absolute_path())
}

/// Port of `FileUtilities.pathIsCaseDependent(String, String)`: walks both paths from the end,
/// reporting a mismatch when a component matches ignoring case but not exactly, and skipping
/// absolute-path components (like `..`) that do not match at all.
fn path_is_case_dependent(canonical_path: &str, absolute_path: &str) -> FileResolutionResult {
    let canonical: Vec<&str> = canonical_path.split(['\\', '/']).collect();
    let absolute: Vec<&str> = absolute_path.split(['\\', '/']).collect();
    let mut c_index = canonical.len() as isize - 1;
    let mut a_index = absolute.len() as isize - 1;
    while a_index >= 0 && c_index >= 0 {
        let c = canonical[c_index as usize];
        let a = absolute[a_index as usize];
        if c.to_lowercase() == a.to_lowercase() {
            if c != a {
                return FileResolutionResult::not_case_dependent(canonical_path, absolute_path);
            }
            c_index -= 1;
        }
        a_index -= 1;
    }
    FileResolutionResult::ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ghidra_rs_sleigh_manual_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn path_case_dependence_matches_java() {
        assert!(path_is_case_dependent("/a/b/File.pdf", "/a/b/File.pdf").is_ok());
        assert!(!path_is_case_dependent("/a/b/File.pdf", "/a/b/file.pdf").is_ok());
        // Relative components that do not match at all are skipped.
        assert!(path_is_case_dependent("/a/b/File.pdf", "/a/b/c/../File.pdf").is_ok());
    }

    #[test]
    fn loads_index_and_finds_longest_prefix_entry() {
        let dir = temp_dir("load");
        std::fs::write(dir.join("man.pdf"), b"pdf").unwrap();
        std::fs::write(
            dir.join("proc.idx"),
            "# comment line\n@man.pdf[Intel manual]\nADD, 12\naddc, 13\nMOV , 40\n",
        )
        .unwrap();
        let mut index = ManualIndex::default();
        index
            .load_index(&ResourceFile::new(dir.join("proc.idx")))
            .unwrap();

        let keys = index.keys();
        assert_eq!(
            keys,
            ["ADD", "ADDC", "MOV"].iter().map(|s| s.to_string()).collect::<HashSet<String>>()
        );
        // Longest indexed prefix wins; lookups are case-insensitive.
        assert_eq!(index.get_entry("addcx").unwrap().page_number(), "13");
        assert_eq!(index.get_entry("ADDX").unwrap().page_number(), "12");
        let mov = index.get_entry("mov").unwrap();
        assert_eq!(mov.mnemonic(), "MOV");
        assert_eq!(mov.missing_manual_description(), "Intel manual");
        assert!(mov.manual_path().ends_with("man.pdf"));
        // Unknown mnemonics and the empty string fall back to the default (null-keyed) entry.
        let default = index.get_entry("JMP").unwrap();
        assert_eq!(default.mnemonic(), "");
        assert_eq!(default.page_number(), "");
        assert!(default.manual_path().ends_with("man.pdf"));
        assert_eq!(index.get_entry(""), Some(default));
    }

    #[test]
    fn instruction_before_manual_is_an_error() {
        let dir = temp_dir("nomanual");
        std::fs::write(dir.join("proc.idx"), "ADD, 12\n").unwrap();
        let state = ManualState::load(Some(&ResourceFile::new(dir.join("proc.idx"))));
        assert!(state.error.unwrap().contains("does not specify manual first"));
    }

    #[test]
    fn missing_plain_switch_manual_is_an_error_but_described_switch_only_warns() {
        let dir = temp_dir("missing");
        std::fs::write(dir.join("a.idx"), "@absent.pdf\nADD, 1\n").unwrap();
        let state = ManualState::load(Some(&ResourceFile::new(dir.join("a.idx"))));
        assert!(state.error.unwrap().contains("absent.pdf"));

        std::fs::write(dir.join("b.idx"), "@absent.pdf[not shipped]\nADD, 1\n").unwrap();
        let state = ManualState::load(Some(&ResourceFile::new(dir.join("b.idx"))));
        assert!(state.error.is_none());
        assert_eq!(
            state.index.get_entry("ADD").unwrap().missing_manual_description(),
            "not shipped"
        );
    }

    #[test]
    fn no_index_file_means_empty_manual_and_no_error() {
        let state = ManualState::load(None);
        assert!(state.error.is_none());
        assert!(state.index.get_entry("ADD").is_none());
        assert!(state.index.keys().is_empty());
    }
}
