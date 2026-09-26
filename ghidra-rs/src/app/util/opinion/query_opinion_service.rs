//! Port of `ghidra.app.util.opinion.QueryOpinionService`.
//!
//! Java's version is a final class of statics (private constructor, only `static`/`private
//! static` members), so this is ported as a plain module of free functions rather than a
//! zero-instance struct, per this crate's convention for statics holders (see
//! `elf_loader_options_factory` in this same package).
//!
//! # Departures from the Java class
//!
//! * The static `languageService` field is dropped. Java lazily resolves it once from the
//!   `DefaultLanguageService` singleton (`DefaultLanguageService.getLanguageService()`), but that
//!   singleton accessor was dropped when `DefaultLanguageService` was ported (see its module
//!   docs). [`query`] and [`initialize`] instead take an explicit `&dyn LanguageService`
//!   parameter, the same substitution `elf_loader_options_factory` already made for the same
//!   singleton.
//! * Likewise, `Application.findFilesByExtensionInApplication` resolves the process-wide
//!   `Application` singleton; [`initialize`]/[`search_and_find_all_opinion_xmls`] take an
//!   explicit `&dyn Application` parameter instead, mirroring `guid_util`'s `initialize`.
//! * `doInit` plus the nullable static `DATABASE` field collapse into a single
//!   `OnceLock<Mutex<Database>>`, the direct analogue of Java's `synchronized` lazy-init guard
//!   (again see `guid_util::initialize` for the same pattern in this crate).
//! * `QueryOpinionServiceHandler` (the `<constraint>`-XML walker `initialize` delegates to via
//!   `parseFile`) and `QueryResult` are not ported yet, so [`parse_file`] and [`add_query`]/
//!   [`query`] use the placeholders in [`crate::app::seam_stubs`] (see `STUBS.tsv`).
//!   `QueryOpinionServiceHandler` additionally forms a dependency cycle back into this module
//!   (`QueryOpinionServiceHandler.read` calls `QueryOpinionService.addQuery`), which is why it is
//!   stubbed as a no-op rather than ported alongside this type.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use crate::app::seam_stubs::{query_opinion_service_handler, QueryResult};
use crate::framework::application::Application;
use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::seam_stubs::{LanguageCompilerSpecQuery, Processor};
use crate::util::msg::Msg;

/// Originator passed to [`Msg`], standing in for Java's `QueryOpinionService.class`.
const ORIGINATOR: &str = "QueryOpinionService";

/// Extension searched for by [`search_and_find_all_opinion_xmls`].
const OPINION_EXTENSION: &str = ".opinion";

/// `loader -> primary -> secondary -> results`, mirroring the Java static `DATABASE` field's
/// `Map<String, Map<String, Map<String, Set<QueryResult>>>>`. A `None` key stands in for a Java
/// `null` key, which every level (not just the innermost) can hold.
type Database =
    HashMap<Option<String>, HashMap<Option<String>, HashMap<Option<String>, HashSet<QueryResult>>>>;

/// Replaces Java's `doInit` flag plus the nullable static `DATABASE` field.
static DATABASE: OnceLock<Mutex<Database>> = OnceLock::new();

/// A `Processor` that reports a fixed name, standing in for cloning `query.processor` (`Box<dyn
/// Processor>` is not `Clone`) when [`add_query`] builds its "broad" query.
struct NamedProcessor(String);

impl Processor for NamedProcessor {
    fn name(&self) -> String {
        self.0.clone()
    }
}

/// Parses every `.opinion` file found in the application and populates the shared database,
/// exactly once for the life of the process.
///
/// Port of the private `QueryOpinionService.initialize()`.
fn initialize(app: &dyn Application, language_service: &dyn LanguageService) -> &'static Mutex<Database> {
    DATABASE.get_or_init(|| {
        let mut database = Database::new();
        for file in search_and_find_all_opinion_xmls(app) {
            if let Err(e) = parse_file(&file, &mut database, language_service) {
                Msg::warn_with_error(
                    ORIGINATOR,
                    &format!("Problem parsing {}", file.absolute_path()),
                    &e,
                );
            }
        }
        Mutex::new(database)
    })
}

/// Port of the private `QueryOpinionService.searchAndFindAllOpinionXMLs()`.
fn search_and_find_all_opinion_xmls(app: &dyn Application) -> Vec<ResourceFile> {
    app.find_files_by_extension_in_application(OPINION_EXTENSION)
}

/// Port of the private `QueryOpinionService.parseFile(ResourceFile)`.
///
/// `ghidra.xml.XmlPullParser` (which the Java version parses `file` with) is not ported yet, so
/// this currently defers to the [`query_opinion_service_handler`] stub, which is a no-op until
/// both it and `QueryOpinionServiceHandler` itself are ported.
fn parse_file(
    file: &ResourceFile,
    database: &mut Database,
    language_service: &dyn LanguageService,
) -> std::io::Result<()> {
    let _ = (file, &database, language_service);
    query_opinion_service_handler::read();
    Ok(())
}

/// Registers `query` under `loader`/`primary`/`secondary`, expanding it into every matching
/// `(language, compiler spec)` pair `language_service` knows about (ignoring `query`'s own
/// compiler spec ID, which only decides whether each resulting pair is marked `preferred`).
///
/// Port of the package-private `QueryOpinionService.addQuery(String, String, String,
/// LanguageCompilerSpecQuery)`.
pub(crate) fn add_query(
    database: &mut Database,
    language_service: &dyn LanguageService,
    loader: Option<&str>,
    primary: Option<&str>,
    secondary: Option<&str>,
    query: &LanguageCompilerSpecQuery,
) {
    let specs = database
        .entry(loader.map(str::to_string))
        .or_default()
        .entry(primary.map(str::to_string))
        .or_default()
        .entry(secondary.map(str::to_string))
        .or_default();

    let broad_processor: Option<Box<dyn Processor>> =
        query.processor.as_ref().map(|p| Box::new(NamedProcessor(p.name())) as Box<dyn Processor>);
    let broad_query = LanguageCompilerSpecQuery::new(
        broad_processor,
        query.endian,
        query.size,
        query.variant.clone(),
        None,
    );

    for pair in language_service.get_language_compiler_spec_pairs(&broad_query) {
        let preferred = Some(pair.get_compiler_spec_id()) == query.compiler_spec_id.as_ref();
        specs.insert(QueryResult::new(pair, preferred));
    }
}

/// Returns every `QueryResult` registered for the given loader/primary/secondary key triple, or
/// an empty list if none are found.
///
/// Port of the public `QueryOpinionService.query(String, String, String)`.
pub fn query(
    app: &dyn Application,
    language_service: &dyn LanguageService,
    loader_name: &str,
    primary_key: &str,
    secondary_key: &str,
) -> Vec<QueryResult> {
    let lock = initialize(app, language_service);
    let database = lock.lock().unwrap();

    let no_results_message = || {
        format!(
            "No query results found for loader {loader_name} with primary key {primary_key} \
             and secondary key {secondary_key}"
        )
    };

    let mut results = Vec::new();

    let Some(loaders_by_name) = database.get(&Some(loader_name.to_string())) else {
        Msg::debug(ORIGINATOR, &no_results_message());
        return results;
    };

    let Some(loaders_by_id) = get_primary_loaders(loaders_by_name, primary_key) else {
        Msg::debug(ORIGINATOR, &no_results_message());
        return results;
    };

    get_specs(loaders_by_id, secondary_key, &mut results);
    if results.is_empty() {
        Msg::debug(ORIGINATOR, &no_results_message());
    }

    results
}

/// Port of the private `QueryOpinionService.getSpecs(Map, String, List)`.
fn get_specs(
    loaders_by_id: &HashMap<Option<String>, HashSet<QueryResult>>,
    secondary_key: &str,
    results: &mut Vec<QueryResult>,
) {
    // SCR 10746 - Enhancements to the Opinion file processing, enhance the original signed
    // decimal string matching with don't-cares. If there's no exact match, try masking.
    let mut secondary_specs = loaders_by_id.get(&Some(secondary_key.to_string())).cloned();
    if secondary_specs.is_none() {
        secondary_specs = get_query_result_with_secondary_masking(secondary_key, loaders_by_id);
    }
    if secondary_specs.is_none() {
        secondary_specs = loaders_by_id.get(&None).cloned();
    }

    if let Some(specs) = secondary_specs {
        results.extend(specs);
    }
}

/// Port of the private `QueryOpinionService.getPrimaryLoaders(Map, String)`.
fn get_primary_loaders<'a>(
    loaders_by_name: &'a HashMap<Option<String>, HashMap<Option<String>, HashSet<QueryResult>>>,
    primary_key: &str,
) -> Option<&'a HashMap<Option<String>, HashSet<QueryResult>>> {
    if let Some(loaders) = loaders_by_name.get(&Some(primary_key.to_string())) {
        return Some(loaders);
    }

    // Check for primary attribute strings that have a list of comma separated primary values.
    // For example, MIPS can have the primary (e_machine) value 8 or 10.
    for (primary_key_original, loaders) in loaders_by_name {
        let Some(primary_key_original) = primary_key_original else {
            continue;
        };

        let primary_key_cleaned: String =
            primary_key_original.chars().filter(|c| !c.is_whitespace()).collect();

        if primary_key_cleaned.split(',').any(|token| token == primary_key) {
            return Some(loaders);
        }
    }

    None
}

/// Matches `secondary_key` against every secondary attribute string keyed in `by_primary`,
/// unioning the results of every match.
///
/// Port of the public `QueryOpinionService.getQueryResultWithSecondaryMasking(String, Map)`.
pub fn get_query_result_with_secondary_masking(
    secondary_key: &str,
    by_primary: &HashMap<Option<String>, HashSet<QueryResult>>,
) -> Option<HashSet<QueryResult>> {
    let mut query_result = HashSet::new();
    for (secondary_attribute_string, specs) in by_primary {
        if let Some(secondary_attribute_string) = secondary_attribute_string {
            if secondary_attribute_matches(secondary_key, secondary_attribute_string) {
                query_result.extend(specs.iter().cloned());
            }
        }
    }

    if query_result.is_empty() {
        None
    } else {
        Some(query_result)
    }
}

/// Match a `secondary_key` decimal integer string against a binary or hex formatted constraint.
///
/// The constraint must be patterned as:
/// - Binary: `"0b1110_0001 111..."` (spaces and `_` ignored, dots are wildcards)
/// - Hex:    `"0xaabb_ccdd"` (hex digits, spaces and `_` ignored)
///
/// Returns `true` if `secondary_key` matches the constraint; `false` if it doesn't match,
/// if the constraint isn't a binary or hex constraint, or if `secondary_key` isn't an integer.
pub fn secondary_attribute_matches(secondary_key: &str, constraint: &str) -> bool {
    let secondary_key_int: i32 = match secondary_key.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    let constraint: String = constraint
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect::<String>()
        .to_lowercase();

    if constraint.starts_with("0x") {
        match u32::from_str_radix(&constraint[2..], 16) {
            Ok(hex_val) => secondary_key_int == hex_val as i32,
            Err(_) => false,
        }
    } else if constraint.starts_with("0b") {
        let secondary_bits = format!("{:032b}", secondary_key_int as u32);
        let constraint_suffix = &constraint[2..];
        // Left-pad with '0' to 32 chars (mirrors Java StringUtils.leftPad)
        let constraint_bits = if constraint_suffix.len() < 32 {
            format!("{:0>32}", constraint_suffix)
        } else {
            constraint_suffix.to_string()
        };
        // Compare only the first 32 positions (mirrors Java for loop i < 32)
        for (s, c) in secondary_bits.chars().zip(constraint_bits.chars()).take(32) {
            if c == '.' {
                continue;
            }
            if s != c {
                return false;
            }
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::LanguageCompilerSpecPair;

    /// Values taken from MIPS.opinion:
    ///   00110000111100000011000100001111
    ///   00010000000011110001010000000000
    ///   00000000101001010001000100000101
    #[test]
    fn test_secondary_attribute_matches() {
        let attribute = "0b 00.. ..00 .... .... 00.1 0.0. 0000 ....";

        assert!(!secondary_attribute_matches("111", attribute));
        assert!(secondary_attribute_matches("821047567", attribute));
        assert!(secondary_attribute_matches("821047567", attribute));
        assert!(secondary_attribute_matches("269423616", attribute));
        assert!(secondary_attribute_matches("10817797", attribute));
    }

    #[test]
    fn test_hex_constraint() {
        assert!(secondary_attribute_matches("85", "0x55"));
        assert!(secondary_attribute_matches("-1", "0xff ff_ff ff"));
    }

    #[test]
    fn test_not_binary_or_hex_constraint() {
        assert!(!secondary_attribute_matches("1", "not_a_valid_constraint"));
        assert!(!secondary_attribute_matches("1", "0b1x"));
        assert!(!secondary_attribute_matches("1", ""));
    }

    #[test]
    fn test_not_integer_key() {
        assert!(!secondary_attribute_matches("abc", "0x1"));
        assert!(!secondary_attribute_matches("", "0b...."));
    }

    struct MockLanguageService {
        pairs: Vec<LanguageCompilerSpecPair>,
    }

    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn crate::program::model::lang::language::Language>, crate::program::seam_stubs::LanguageNotFoundException>
        {
            Err(crate::program::seam_stubs::LanguageNotFoundException(format!(
                "No language '{language_id}'"
            )))
        }

        fn get_default_language(
            &self,
            _processor: &dyn Processor,
        ) -> Result<Box<dyn crate::program::model::lang::language::Language>, crate::program::seam_stubs::LanguageNotFoundException>
        {
            Err(crate::program::seam_stubs::LanguageNotFoundException("no default".to_string()))
        }

        fn get_language_description(
            &self,
            language_id: &LanguageID,
        ) -> Result<
            Box<dyn crate::program::model::lang::language_description::LanguageDescription>,
            crate::program::seam_stubs::LanguageNotFoundException,
        > {
            Err(crate::program::seam_stubs::LanguageNotFoundException(format!(
                "No description for '{language_id}'"
            )))
        }

        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            Vec::new()
        }

        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: Option<crate::program::model::lang::endian::Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            Vec::new()
        }

        fn get_language_compiler_spec_pairs(
            &self,
            _query: &LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            self.pairs.clone()
        }

        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &crate::program::seam_stubs::ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }

        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn Processor,
        ) -> Vec<Box<dyn crate::program::model::lang::language_description::LanguageDescription>> {
            Vec::new()
        }
    }

    fn pair(language: &str, compiler_spec: &str) -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new(
            LanguageID::new(language).unwrap(),
            CompilerSpecID::new(Some(compiler_spec)),
        )
    }

    #[test]
    fn add_query_marks_exact_compiler_spec_id_preferred() {
        let service = MockLanguageService {
            pairs: vec![pair("x86:LE:32:default", "gcc"), pair("x86:LE:32:default", "windows")],
        };
        let mut database = Database::new();
        let query = LanguageCompilerSpecQuery::new(
            None,
            None,
            None,
            None,
            Some(CompilerSpecID::new(Some("gcc"))),
        );

        add_query(&mut database, &service, Some("Elf"), Some("3"), Some("0"), &query);

        let specs = &database[&Some("Elf".to_string())][&Some("3".to_string())][&Some("0".to_string())];
        assert_eq!(specs.len(), 2);
        let gcc_result = specs.iter().find(|r| r.pair == pair("x86:LE:32:default", "gcc")).unwrap();
        assert!(gcc_result.preferred);
        let windows_result =
            specs.iter().find(|r| r.pair == pair("x86:LE:32:default", "windows")).unwrap();
        assert!(!windows_result.preferred);
    }

    #[test]
    fn get_primary_loaders_matches_comma_separated_tokens() {
        let mut loaders_by_name = HashMap::new();
        loaders_by_name.insert(Some("8, 10".to_string()), HashMap::new());

        assert!(get_primary_loaders(&loaders_by_name, "10").is_some());
        assert!(get_primary_loaders(&loaders_by_name, "11").is_none());
    }

    #[test]
    fn query_falls_back_to_secondary_masking_then_wildcard() {
        let service = MockLanguageService { pairs: vec![pair("mips:BE:32:default", "default")] };
        let mut database = Database::new();
        let masked_query = LanguageCompilerSpecQuery::new(None, None, None, None, None);
        add_query(&mut database, &service, Some("Elf"), Some("8"), Some("0x2"), &masked_query);

        let loaders_by_id = &database[&Some("Elf".to_string())][&Some("8".to_string())];
        let mut results = Vec::new();
        get_specs(loaders_by_id, "2", &mut results);
        assert_eq!(results.len(), 1);

        // No entry at all for secondary "99": falls through to the None (wildcard) bucket, which
        // is also empty here, so results stay empty without panicking.
        let mut empty_results = Vec::new();
        get_specs(loaders_by_id, "99", &mut empty_results);
        assert!(empty_results.is_empty());
    }
}
