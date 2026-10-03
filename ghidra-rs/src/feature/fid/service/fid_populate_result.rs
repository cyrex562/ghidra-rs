//! Port of `ghidra.feature.fid.service.FidPopulateResult`.
//!
//! # Relationship to `crate::feature::seam_stubs::FidPopulateResult`
//!
//! A separate, unrelated placeholder struct of the same name already exists at
//! `crate::feature::seam_stubs::FidPopulateResult` (an empty marker), returned by the still-
//! unported `FidServiceLibraryIngest::create()` stub. That ingest doesn't yet accumulate real
//! per-function disposition data to populate a result with, so wiring this concrete port into
//! that seam is left as a follow-up once `FidServiceLibraryIngest.java` itself is ported (see
//! that stub's own doc comment: "Java's tallies and disposition maps arrive with the port of
//! `FidPopulateResult.java`" -- this file).

use std::collections::HashMap;

use crate::feature::fid::db::library_record::LibraryRecord;
use crate::feature::fid::service::Location;
use crate::framework::model::DomainFile;
use crate::program::model::address::Address;

/// The actual state representing what happened to the function.
///
/// Port of `ghidra.feature.fid.service.FidPopulateResult.Disposition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// The only "positive" state: the function was included.
    Included,
    // All the following are "negative", as in the function was excluded.
    IsThunk,
    FailedFunctionFilter,
    FailsMinimumShorthashLength,
    NoDefinedSymbol,
    MemoryAccessException,
    DuplicateInfo,
}

/// A single named/counted entry in the child-reference histogram.
///
/// Port of `ghidra.feature.fid.service.FidPopulateResult.Count`.
#[derive(Debug, Clone, Default)]
pub struct Count {
    pub name: String,
    pub count: i32,
    pub is_very_common: bool,
}

impl PartialEq for Count {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count && self.name == other.name
    }
}

impl Eq for Count {}

impl PartialOrd for Count {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Count {
    /// Java: `compareTo(Count o)`: descending by count, then ascending by name for ties (bigger
    /// count comes first).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.count == other.count {
            self.name.cmp(&other.name)
        } else if self.count < other.count {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        }
    }
}

/// Implementation class for `FidPopulateResult`: reports the disposition of every function
/// considered during a FID library populate operation.
///
/// Port of `ghidra.feature.fid.service.FidPopulateResult`. The constructor and the two mutator
/// methods (`disposition`/`addUnresolvedSymbol`) are package-private in Java, called only by
/// `FidServiceLibraryIngest` as it walks a program's functions; kept `pub` here since Rust has no
/// package-private visibility tier narrower than the crate (matching the convention already used
/// elsewhere in this port, e.g.
/// [`FunctionVariableData`](crate::app::plugin::core::function::editor::FunctionVariableData)).
pub struct FidPopulateResult {
    library_record: LibraryRecord,
    extreme_failure_map: Vec<(Location, Disposition)>,
    unresolved_symbols: Vec<Location>,
    max_child_refs: Option<Vec<Count>>,
    total_disposition: i32,
    num_included: i32,
    num_thunk: i32,
    num_filtered: i32,
    num_failed_minimum: i32,
    num_mem_access: i32,
    num_no_defined_symbol: i32,
    num_duplicates: i32,
}

impl FidPopulateResult {
    /// Java: `FidPopulateResult(LibraryRecord libraryRecord)`.
    pub fn new(library_record: LibraryRecord) -> Self {
        FidPopulateResult {
            library_record,
            extreme_failure_map: Vec::new(),
            unresolved_symbols: Vec::new(),
            max_child_refs: None,
            total_disposition: 0,
            num_included: 0,
            num_thunk: 0,
            num_filtered: 0,
            num_failed_minimum: 0,
            num_mem_access: 0,
            num_no_defined_symbol: 0,
            num_duplicates: 0,
        }
    }

    /// Records the disposition of a single function.
    ///
    /// Java: `void disposition(DomainFile domainFile, String functionName, Address
    /// functionEntryPoint, Disposition disposition)`.
    pub fn disposition(
        &mut self,
        domain_file: Option<Box<dyn DomainFile>>,
        function_name: String,
        function_entry_point: Option<Address>,
        disposition: Disposition,
    ) {
        self.total_disposition += 1;
        match disposition {
            Disposition::FailedFunctionFilter => {
                self.num_filtered += 1;
                return; // Don't put in extreme list
            }
            Disposition::FailsMinimumShorthashLength => {
                self.num_failed_minimum += 1;
                return; // Don't put in extreme list
            }
            Disposition::Included => {
                self.num_included += 1;
                return; // Don't put in extreme list
            }
            Disposition::IsThunk => {
                self.num_thunk += 1;
                return; // Don't put in extreme list
            }
            Disposition::DuplicateInfo => {
                self.num_duplicates += 1;
                return; // Don't put in extreme list
            }
            Disposition::MemoryAccessException => {
                self.num_mem_access += 1;
                // Fall-thru to put in extreme list
            }
            Disposition::NoDefinedSymbol => {
                self.num_no_defined_symbol += 1;
                // Fall-thru to put in extreme list
            }
        }
        self.extreme_failure_map.push((
            Location::new(domain_file, Some(function_name), function_entry_point),
            disposition,
        ));
    }

    /// Java: `void addUnresolvedSymbol(String functionName)`.
    pub fn add_unresolved_symbol(&mut self, function_name: String) {
        self.unresolved_symbols.push(Location::new(None, Some(function_name), None));
    }

    /// Java: `getLibraryRecord()`.
    pub fn get_library_record(&self) -> &LibraryRecord {
        &self.library_record
    }

    /// Returns a complete map of locations to dispositions.
    ///
    /// Java: `Map<Location, Disposition> getResults()`. Java returns an unmodifiable *view* of a
    /// `LinkedHashMap` field (same [`Location`] objects, no copying, insertion order preserved,
    /// last write wins for a duplicate key). [`Location`] holds a non-`Clone` `Box<dyn
    /// DomainFile>`, so this returns a fresh `HashMap` borrowing the stored `Location`s instead of
    /// a view; `collect()` into a `HashMap` already gives last-write-wins for a duplicate key
    /// (matching `LinkedHashMap.put`'s overwrite), it just doesn't preserve insertion order, which
    /// isn't observable through a `Map` consumer anyway.
    pub fn get_results(&self) -> HashMap<&Location, Disposition> {
        self.extreme_failure_map.iter().map(|(loc, disp)| (loc, *disp)).collect()
    }

    /// Returns how many functions in total were added to the library.
    ///
    /// Java: `getTotalAdded()`.
    pub fn get_total_added(&self) -> i32 {
        self.num_included
    }

    /// Returns how many functions in total were excluded from the library.
    ///
    /// Java: `getTotalExcluded()`.
    pub fn get_total_excluded(&self) -> i32 {
        self.total_disposition - self.num_included
    }

    /// Returns how many functions in total were considered for inclusion.
    ///
    /// Java: `getTotalAttempted()`.
    pub fn get_total_attempted(&self) -> i32 {
        self.total_disposition
    }

    /// Returns a map of failed dispositions to their occurrence counts.
    ///
    /// Java: `Map<Disposition, Integer> getFailures()`.
    pub fn get_failures(&self) -> HashMap<Disposition, i32> {
        let mut result = HashMap::new();
        result.insert(Disposition::Included, self.num_included);
        result.insert(Disposition::IsThunk, self.num_thunk);
        result.insert(Disposition::FailedFunctionFilter, self.num_filtered);
        result.insert(Disposition::FailsMinimumShorthashLength, self.num_failed_minimum);
        result.insert(Disposition::MemoryAccessException, self.num_mem_access);
        result.insert(Disposition::NoDefinedSymbol, self.num_no_defined_symbol);
        result.insert(Disposition::DuplicateInfo, self.num_duplicates);
        result
    }

    /// Returns a list of symbols that could not be resolved in the end. Note that the domain file
    /// and function entry point will be `None` for all of these.
    ///
    /// Java: `List<Location> getUnresolvedSymbols()`, which defensively copies the list (`new
    /// ArrayList<>(unresolvedSymbols)`) but shares the same `Location` objects. Returned here as
    /// borrows of the stored `Location`s for the same non-`Clone` reason described on
    /// [`get_results`](Self::get_results).
    pub fn get_unresolved_symbols(&self) -> Vec<&Location> {
        self.unresolved_symbols.iter().collect()
    }

    /// Java: `getMaxChildReferences()`.
    pub fn get_max_child_references(&self) -> Option<&[Count]> {
        self.max_child_refs.as_deref()
    }

    /// Java: `addChildReferences(int max, Map<String, Count> childHistogram)`.
    pub fn add_child_references(&mut self, max: i32, child_histogram: HashMap<String, Count>) {
        // Resort the histogram on counts.
        let mut resort: Vec<Count> = child_histogram
            .into_iter()
            .map(|(name, mut count)| {
                count.name = name;
                count
            })
            .collect();
        resort.sort();

        let mut max_child_refs = Vec::new();
        let mut i = 0;
        for count in resort {
            max_child_refs.push(count);
            i += 1;
            if i >= max {
                break;
            }
        }
        self.max_child_refs = Some(max_child_refs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// Minimal `LibraryRecord`, built the same way as
    /// [`crate::feature::fid::db::library_record`]'s own test helper: `FidPopulateResult` never
    /// inspects its contents (only holds and returns it via [`FidPopulateResult::get_library_record`]),
    /// so the exact column values don't matter here.
    fn library_record() -> LibraryRecord {
        use crate::framework::db::field::{Field, FieldType};
        use crate::framework::db::record::DBRecord;
        use crate::framework::db::schema::Schema;
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String; 8],
            vec![
                "LibraryFamilyName".to_string(),
                "LibraryVersion".to_string(),
                "LibraryVariant".to_string(),
                "GhidraVersion".to_string(),
                "GhidraLanguageID".to_string(),
                "GhidraLanguageVersion".to_string(),
                "GhidraLanguageMinorVersion".to_string(),
                "GhidraCompilerSpecID".to_string(),
            ],
            vec![],
        ));
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        LibraryRecord::new(record)
    }

    #[test]
    fn get_library_record_returns_the_constructed_record() {
        let result = FidPopulateResult::new(library_record());
        assert_eq!(result.get_library_record().get_library_id(), 1);
    }

    #[test]
    fn positive_dispositions_are_tallied_but_not_in_extreme_list() {
        let mut result = FidPopulateResult::new(library_record());
        result.disposition(None, "foo".to_string(), Some(addr(0x100)), Disposition::Included);
        result.disposition(None, "bar".to_string(), Some(addr(0x200)), Disposition::IsThunk);
        result.disposition(None, "baz".to_string(), Some(addr(0x300)), Disposition::DuplicateInfo);

        assert_eq!(result.get_total_attempted(), 3);
        assert_eq!(result.get_total_added(), 1);
        assert_eq!(result.get_total_excluded(), 2);
        assert!(result.get_results().is_empty());
    }

    #[test]
    fn memory_access_and_no_defined_symbol_land_in_extreme_list() {
        let mut result = FidPopulateResult::new(library_record());
        result.disposition(
            None,
            "foo".to_string(),
            Some(addr(0x100)),
            Disposition::MemoryAccessException,
        );
        result.disposition(
            None,
            "bar".to_string(),
            Some(addr(0x200)),
            Disposition::NoDefinedSymbol,
        );

        let results = result.get_results();
        assert_eq!(results.len(), 2);
        assert_eq!(result.get_total_attempted(), 2);
        assert_eq!(result.get_total_added(), 0);
        assert_eq!(result.get_total_excluded(), 2);
    }

    #[test]
    fn get_failures_reports_all_counts() {
        let mut result = FidPopulateResult::new(library_record());
        result.disposition(None, "a".to_string(), None, Disposition::Included);
        result.disposition(None, "b".to_string(), None, Disposition::FailedFunctionFilter);
        result.disposition(None, "c".to_string(), None, Disposition::FailsMinimumShorthashLength);

        let failures = result.get_failures();
        assert_eq!(failures[&Disposition::Included], 1);
        assert_eq!(failures[&Disposition::FailedFunctionFilter], 1);
        assert_eq!(failures[&Disposition::FailsMinimumShorthashLength], 1);
        assert_eq!(failures[&Disposition::IsThunk], 0);
    }

    #[test]
    fn unresolved_symbols_have_no_domain_file_or_entry_point() {
        let mut result = FidPopulateResult::new(library_record());
        result.add_unresolved_symbol("mystery".to_string());

        let unresolved = result.get_unresolved_symbols();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].function_name(), Some("mystery"));
        assert!(unresolved[0].domain_file().is_none());
        assert!(unresolved[0].function_entry_point().is_none());
    }

    #[test]
    fn count_ordering_puts_bigger_counts_first_then_name() {
        let a = Count { name: "a".to_string(), count: 5, is_very_common: false };
        let b = Count { name: "b".to_string(), count: 10, is_very_common: false };
        let c = Count { name: "c".to_string(), count: 5, is_very_common: false };

        let mut v = vec![a.clone(), b.clone(), c.clone()];
        v.sort();
        assert_eq!(v, vec![b, a, c]);
    }

    #[test]
    fn add_child_references_sorts_and_truncates_to_max() {
        let mut result = FidPopulateResult::new(library_record());
        let mut histogram = HashMap::new();
        histogram.insert("low".to_string(), Count { name: String::new(), count: 1, is_very_common: false });
        histogram.insert("high".to_string(), Count { name: String::new(), count: 10, is_very_common: false });
        histogram.insert("mid".to_string(), Count { name: String::new(), count: 5, is_very_common: false });

        result.add_child_references(2, histogram);

        let refs = result.get_max_child_references().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "high");
        assert_eq!(refs[1].name, "mid");
    }

    #[test]
    fn max_child_references_defaults_to_none() {
        let result = FidPopulateResult::new(library_record());
        assert!(result.get_max_child_references().is_none());
    }
}
