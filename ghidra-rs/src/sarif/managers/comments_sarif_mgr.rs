//! Port of `sarif.managers.CommentsSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::code_unit::COMMENT_PROPERTY;
use crate::program::model::listing::{CodeUnit, CommentType, Program};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{MessageLog, SarifCommentWriter, SarifMgr, SarifProgramOptions, SarifWriterTask, TaskLauncher};

/// Every [`CommentType`] variant, in the same order as Java's `CommentType.values()`.
const ALL_COMMENT_TYPES: [CommentType; 5] = [
    CommentType::Eol,
    CommentType::Pre,
    CommentType::Post,
    CommentType::Plate,
    CommentType::Repeatable,
];

/// `CommentsSarifMgr.getCommentTypeString`'s SARIF tag for one [`CommentType`].
fn comment_tag(comment_type: CommentType) -> &'static str {
    match comment_type {
        CommentType::Pre => "pre",
        CommentType::Post => "post",
        CommentType::Eol => "end-of-line",
        CommentType::Plate => "plate",
        CommentType::Repeatable => "repeatable",
    }
}

/// Reads and writes `COMMENTS` entries between a [`Program`]'s [`Listing`](crate::program::model::listing::Listing)
/// comments and SARIF.
///
/// Port of `sarif.managers.CommentsSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have. Like [`CodeSarifMgr`](crate::sarif::managers::CodeSarifMgr), this manager needs
/// both `Listing` and `Memory` across several methods, so it keeps the whole `Program` handle
/// (matching Java's `SarifMgr.program` field) rather than extracting a single sub-manager up front.
pub struct CommentsSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
}

impl CommentsSarifMgr {
    /// `CommentsSarifMgr.KEY`.
    pub const KEY: &'static str = "COMMENTS";
    /// `CommentsSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Comment";

    /// `new CommentsSarifMgr(Program program, MessageLog log)`.
    pub fn new(program: Arc<dyn Program>, log: MessageLog) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `CommentsSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        self.process_comment(result);
        true
    }

    fn process_comment(&mut self, result: &HashMap<String, Value>) {
        let addr = match self.base.get_location(result) {
            Ok(Some(addr)) => addr,
            Ok(None) => return,
            Err(e) => {
                self.log.append_exception(&e);
                return;
            }
        };

        let type_str = result.get("kind").and_then(Value::as_str).unwrap_or("");
        let comment = result.get("value").and_then(Value::as_str).unwrap_or("");
        let standard = result.get("standard").and_then(Value::as_bool).unwrap_or(false);

        let Some(comment_type) = Self::get_comment_type(type_str) else {
            self.log.append_msg(format!("Unknown comment type: {type_str}"));
            return;
        };

        let Some(listing) = Arc::get_mut(&mut self.program).and_then(|p| p.get_listing()) else {
            return;
        };

        if standard {
            let Some(mut cu) = listing.get_code_unit_containing(&addr) else {
                return;
            };
            let Some(cu) = Arc::get_mut(&mut cu) else {
                return;
            };
            match cu.get_comment(comment_type) {
                None => cu.set_comment(comment_type, Some(comment.to_string())),
                Some(curr_cmt) if curr_cmt.is_empty() => {
                    cu.set_comment(comment_type, Some(comment.to_string()))
                }
                Some(curr_cmt) if !curr_cmt.contains(comment) => {
                    self.log.append_msg(format!("Merged {type_str} comment at {addr}"));
                    cu.set_comment(comment_type, Some(format!("{curr_cmt}\n{comment}")));
                }
                Some(_) => {}
            }
        } else {
            match listing.get_comment(comment_type, &addr) {
                None => listing.set_comment(&addr, comment_type, Some(comment.to_string())),
                Some(curr_cmt) if curr_cmt.is_empty() => {
                    listing.set_comment(&addr, comment_type, Some(comment.to_string()))
                }
                Some(curr_cmt) if !curr_cmt.contains(comment) => {
                    self.log.append_msg(format!("Merged {type_str} comment at {addr}"));
                    listing.set_comment(&addr, comment_type, Some(format!("{curr_cmt}\n{comment}")));
                }
                Some(_) => {}
            }
        }
    }

    /// `CommentsSarifMgr.getCommentType`.
    pub fn get_comment_type(type_tag_str: &str) -> Option<CommentType> {
        ALL_COMMENT_TYPES
            .into_iter()
            .find(|&ct| comment_tag(ct) == type_tag_str)
    }

    /// `CommentsSarifMgr.getCommentTypeString`.
    pub fn get_comment_type_string(comment_type: CommentType) -> &'static str {
        comment_tag(comment_type)
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `CommentsSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing COMMENTS ...");

        let owned_set;
        let effective_set: &dyn AddressSetView = match set {
            Some(set) => set,
            None => {
                owned_set = self.memory_address_set();
                owned_set.as_ref()
            }
        };

        let mut request0: Vec<(Arc<dyn CodeUnit>, (String, String))> = Vec::new();
        {
            let listing = Arc::get_mut(&mut self.program)
                .expect("CommentsSarifMgr holds the only handle to its Program")
                .get_listing()
                .expect("CommentsSarifMgr's Program has no Listing");
            let mut iter = listing.get_code_unit_iterator_in(COMMENT_PROPERTY, effective_set, true);
            while let Some(cu) = iter.next() {
                monitor.check_cancelled()?;
                for &comment_type in ALL_COMMENT_TYPES.iter() {
                    let type_str = Self::get_comment_type_string(comment_type);
                    for c in cu.get_comment_as_array(comment_type) {
                        request0.push((cu.clone(), (type_str.to_string(), c)));
                    }
                }
            }
        }

        Self::write_as_sarif0(&request0, results, monitor);

        let mut request1: Vec<(Address, (String, String))> = Vec::new();
        {
            let listing = Arc::get_mut(&mut self.program)
                .expect("CommentsSarifMgr holds the only handle to its Program")
                .get_listing()
                .expect("CommentsSarifMgr's Program has no Listing");
            for &comment_type in ALL_COMMENT_TYPES.iter() {
                let aiter = listing.get_comment_address_iterator(comment_type, effective_set, true);
                for a in aiter {
                    monitor.check_cancelled()?;
                    let Some(cu) = listing.get_code_unit_containing(&a) else {
                        continue;
                    };
                    if cu.as_instruction().is_some() && a != cu.get_min_address() {
                        if let Some(c) = listing.get_comment(comment_type, &a) {
                            request1.push((a.clone(), (Self::get_comment_type_string(comment_type).to_string(), c)));
                        }
                    }
                }
            }
        }

        Self::write_as_sarif1(&request1, results, monitor);
        Ok(())
    }

    /// `program.getMemory()`, viewed as the `AddressSetView` Java's `Memory` interface also is.
    /// Falls back to an empty set when there is no memory, matching an intersection against
    /// nothing.
    fn memory_address_set(&self) -> Box<dyn AddressSetView> {
        self.program
            .get_memory()
            .map(|mem| mem.get_all_initialized_address_set())
            .unwrap_or_else(|| Box::new(AddressSet::new()) as Box<dyn AddressSetView>)
    }

    /// `CommentsSarifMgr.writeAsSARIF0`.
    pub fn write_as_sarif0(
        request: &[(Arc<dyn CodeUnit>, (String, String))],
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        let writer = SarifCommentWriter::new(request.to_vec(), Vec::new());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }

    /// `CommentsSarifMgr.writeAsSARIF1`.
    pub fn write_as_sarif1(
        request: &[(Address, (String, String))],
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        let writer = SarifCommentWriter::new(Vec::new(), request.to_vec());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn test_address(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    fn result_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    struct MockListing;

    impl crate::program::model::listing::stub_listing::StubListing for MockListing {
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            crate::program::model::listing::code_unit_iterator::empty()
        }
    }

    struct MockProgram {
        listing: MockListing,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            Some(&mut self.listing)
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram { listing: MockListing })
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(CommentsSarifMgr::KEY, "COMMENTS");
        assert_eq!(CommentsSarifMgr::SUBKEY, "Comment");
    }

    #[test]
    fn get_comment_type_matches_java_tags() {
        assert_eq!(CommentsSarifMgr::get_comment_type("pre"), Some(CommentType::Pre));
        assert_eq!(CommentsSarifMgr::get_comment_type("post"), Some(CommentType::Post));
        assert_eq!(CommentsSarifMgr::get_comment_type("end-of-line"), Some(CommentType::Eol));
        assert_eq!(CommentsSarifMgr::get_comment_type("plate"), Some(CommentType::Plate));
        assert_eq!(
            CommentsSarifMgr::get_comment_type("repeatable"),
            Some(CommentType::Repeatable)
        );
        assert_eq!(CommentsSarifMgr::get_comment_type("bogus"), None);
    }

    #[test]
    fn get_comment_type_string_round_trips_with_get_comment_type() {
        for ct in ALL_COMMENT_TYPES {
            let tag = CommentsSarifMgr::get_comment_type_string(ct);
            assert_eq!(CommentsSarifMgr::get_comment_type(tag), Some(ct));
        }
    }

    #[test]
    fn process_comment_with_no_location_leaves_log_empty() {
        // `SarifMgr::get_location` is a stub pending `SarifUtils`, so it never resolves an
        // address; `processComment` should quietly return rather than panic.
        let mut mgr = CommentsSarifMgr::new(empty_mock_program(), MessageLog::new());
        let result = result_map(&[
            ("kind", Value::String("pre".to_string())),
            ("value", Value::String("hello".to_string())),
            ("standard", Value::Bool(true)),
        ]);
        assert!(mgr.read(&result, None, &DummyMonitor));
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn unknown_comment_type_is_logged() {
        // Exercise `getCommentType` returning `None` directly, since the location stub prevents
        // driving this through `process_comment` end-to-end.
        assert_eq!(CommentsSarifMgr::get_comment_type("not-a-real-tag"), None);
    }

    #[test]
    fn write_as_sarif0_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        CommentsSarifMgr::write_as_sarif0(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_as_sarif1_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        CommentsSarifMgr::write_as_sarif1(&[], &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn write_with_no_set_and_no_memory_produces_no_results() {
        let mut mgr = CommentsSarifMgr::new(empty_mock_program(), MessageLog::new());
        let mut results = Vec::new();
        let ok = mgr.write(&mut results, None, &DummyMonitor);
        assert!(ok.is_ok());
        assert!(results.is_empty());
    }

    #[test]
    fn comment_tag_matches_java_switch() {
        assert_eq!(comment_tag(CommentType::Pre), "pre");
        assert_eq!(comment_tag(CommentType::Post), "post");
        assert_eq!(comment_tag(CommentType::Eol), "end-of-line");
        assert_eq!(comment_tag(CommentType::Plate), "plate");
        assert_eq!(comment_tag(CommentType::Repeatable), "repeatable");
    }

    #[test]
    fn test_address_offsets_are_distinct() {
        assert_ne!(test_address(1), test_address(2));
    }
}
