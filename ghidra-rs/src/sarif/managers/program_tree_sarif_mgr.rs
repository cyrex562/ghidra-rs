//! Port of `sarif.managers.ProgramTreeSarifMgr`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::program::model::address::{AddressFactory, AddressFormatException, AddressRange, AddressSetView};
use crate::program::model::listing::{Program, ProgramFragment, ProgramModule};
use crate::util::exception::{CancelledException, DuplicateNameException, NotEmptyException, NotFoundException};
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifMgr, SarifProgramOptions, SarifTreeWriter, SarifWriterTask, TaskLauncher,
};

/// Everything the "outer try" in [`ProgramTreeSarifMgr::process_tree`] can fail with.
///
/// Combines Java's multi-catch `catch (NotFoundException | DuplicateNameException |
/// NotEmptyException e)` -- each of those is logged and swallowed -- with cancellation, which
/// Java's catch clause does *not* list, so a `CancelledException` skips it and propagates out of
/// `processTree` (and from there out of `read`) instead. [`Cancelled`](ProcessTreeError::Cancelled)
/// exists purely so a single `?`-driven block can express that difference in Rust.
#[derive(Error, Debug)]
enum ProcessTreeError {
    #[error(transparent)]
    NotFound(#[from] NotFoundException),
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error(transparent)]
    NotEmpty(#[from] NotEmptyException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Everything [`collect_fragment_ranges`] can fail with: `AddressFormatException`, thrown
/// explicitly, plus the (unchecked, in Java) `RuntimeException` `SarifMgr.parseAddress` raises
/// when the factory can't resolve a non-null address string.
#[derive(Error, Debug)]
enum CollectRangesError {
    #[error(transparent)]
    AddressFormat(#[from] AddressFormatException),
    #[error("{0}")]
    Runtime(String),
}

/// Everything [`process_fragment_range`] can fail with: `AddressFormatException` and
/// `NotFoundException`, both declared on `processFragmentRange`, plus the same unchecked
/// `parseAddress` failure as [`CollectRangesError`].
#[derive(Error, Debug)]
enum ProcessFragmentRangeError {
    #[error(transparent)]
    AddressFormat(#[from] AddressFormatException),
    #[error(transparent)]
    NotFound(#[from] NotFoundException),
    #[error("{0}")]
    Runtime(String),
}

/// Reads and writes `PROGRAM_TREES` entries -- a [`Program`]'s tree(s) of [`ProgramModule`]s and
/// [`ProgramFragment`]s -- between the program's [`Listing`] and SARIF.
///
/// Port of `sarif.managers.ProgramTreeSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have. Unlike Java, which caches `listing`/`factory` once in the base class
/// constructor, this keeps the whole `Program` handle and re-fetches each on use, matching the
/// convention set by [`MemoryMapSarifMgr`](crate::sarif::managers::MemoryMapSarifMgr) and
/// [`MarkupSarifMgr`](crate::sarif::managers::MarkupSarifMgr).
///
/// Java's `treeName` and `monitor` fields only ever hold state for the duration of a single
/// `read`/`write` call (nothing outside those calls reads them back), so neither is carried as a
/// struct field here; both are threaded through as local variables/parameters instead.
///
/// Two of Java's recovery paths are not fully expressible with the currently-ported
/// [`ProgramModule`]/[`ProgramFragment`] APIs and are documented where they're handled
/// ([`process_module`], [`process_fragment`]): both `ProgramModule::add_module` and
/// `ProgramModule::add_fragment` take ownership (`Box<dyn _>`), but `Listing::get_module`/
/// `get_fragment_by_name` only ever hand back a shared `Arc<dyn _>` -- there is no safe conversion
/// from one to the other, so Java's "duplicate name -> look up and reattach the existing group"
/// fallback degrades to logging and skipping that branch here.
pub struct ProgramTreeSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
}

impl ProgramTreeSarifMgr {
    /// `ProgramTreeSarifMgr.KEY`.
    pub const KEY: &'static str = "PROGRAM_TREES";
    /// `ProgramTreeSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "ProgramTree";

    /// `ProgramTreeSarifMgr(Program program, MessageLog log)`.
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

    /// `ProgramTreeSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledException> {
        self.process_tree(result, monitor)?;
        Ok(true)
    }

    /// `ProgramTreeSarifMgr.processTree`.
    fn process_tree(&mut self, result: &HashMap<String, Value>, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        let factory = self.program.get_address_factory();
        let mut tree_name = result.get("name").and_then(Value::as_str).unwrap_or_default().to_string();

        let Some(listing) = Arc::get_mut(&mut self.program).and_then(|p| p.get_listing()) else {
            self.log.append_msg("Program is not exclusively owned; cannot mutate its program tree");
            return Ok(());
        };

        // The inner `try { ... } catch (DuplicateNameException dne) { ... one-up retry ... }`:
        // resolves (creating if needed) the root module and gives it `treeName`, retrying with a
        // "(n)" suffix on a name clash until one succeeds. Always succeeds eventually, so nothing
        // downstream needs to handle a further naming failure.
        let root_result: Result<Arc<dyn ProgramModule>, DuplicateNameException> = (|| {
            let mut root = match listing.get_root_module(&tree_name) {
                Some(root) => root,
                None => listing.create_root_module(&tree_name)?,
            };
            let mut name = root.get_name();
            if let Some(idx) = name.find(".sarif") {
                name.truncate(idx);
            }
            if let Some(idx) = name.find(".json") {
                name.truncate(idx);
            }
            Arc::get_mut(&mut root)
                .expect("freshly fetched/created root module is uniquely owned")
                .set_name(&name)?;
            Ok(root)
        })();

        let mut root = match root_result {
            Ok(root) => root,
            Err(_dne) => {
                let mut one_up: u32 = 1;
                let root = loop {
                    match listing.create_root_module(&format!("{tree_name}({one_up})")) {
                        Ok(root) => break root,
                        Err(_) => one_up += 1,
                    }
                };
                tree_name = root.get_tree_name();
                root
            }
        };
        let _ = &tree_name;

        // The outer `try { ... } catch (NotFoundException | DuplicateNameException |
        // NotEmptyException e) { log.appendException(e); }`.
        let outcome: Result<(), ProcessTreeError> = (|| {
            let mut ranges: HashSet<AddressRange> = HashSet::new();
            if let Some(fragments) = result.get("fragments").and_then(Value::as_array) {
                for f in fragments {
                    if let Some(obj) = f.as_object() {
                        if let Err(e) = collect_fragment_ranges(&mut ranges, obj, factory.as_deref(), monitor) {
                            self.log.append_msg(e.to_string());
                        }
                    }
                }
            }

            let root_mut = Arc::get_mut(&mut root).expect("root module is uniquely owned while processing its own tree");

            let mut depot = root_mut.create_fragment("depot")?;
            for r in &ranges {
                depot.move_code_units(r.min_address(), r.max_address())?;
            }

            remove_empty_fragments(root_mut, &self.log);

            if let Some(modules) = result.get("modules").and_then(Value::as_array) {
                for m in modules {
                    monitor.check_cancelled()?;
                    if let Some(obj) = m.as_object() {
                        process_module(root_mut, obj, factory.as_deref(), &self.log);
                    }
                }
            }
            if let Some(fragments) = result.get("fragments").and_then(Value::as_array) {
                for f in fragments {
                    monitor.check_cancelled()?;
                    if let Some(obj) = f.as_object() {
                        process_fragment(root_mut, obj, factory.as_deref(), monitor, &self.log);
                    }
                }
            }

            root_mut.remove_child("depot")?;
            Ok(())
        })();

        match outcome {
            Ok(()) => {}
            Err(ProcessTreeError::Cancelled(e)) => return Err(e),
            Err(other) => self.log.append_exception(&other),
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `ProgramTreeSarifMgr.write`. `addrs` goes unused, matching Java (the write walks every
    /// tree in the program, not a caller-supplied address restriction).
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        _addrs: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing PROGRAM TREES ...");

        let mut request: Vec<(String, Arc<dyn ProgramModule>)> = Vec::new();
        if let Some(listing) = Arc::get_mut(&mut self.program).and_then(|p| p.get_listing()) {
            for n in listing.get_tree_names() {
                if monitor.is_cancelled() {
                    return Err(CancelledException::default());
                }
                if let Some(root) = listing.get_root_module(&n) {
                    request.push((n, root));
                }
            }
        }

        Self::write_as_sarif(request, results, monitor);
        Ok(())
    }

    /// `ProgramTreeSarifMgr.writeAsSARIF`. Takes `monitor` explicitly, unlike the Java static
    /// method: the ported [`TaskLauncher::launch`] needs one to run [`SarifWriterTask::run`],
    /// where Java's `new TaskLauncher(task, null)` drives its own (GUI-backed) monitor instead.
    pub fn write_as_sarif(request: Vec<(String, Arc<dyn ProgramModule>)>, results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifTreeWriter::new(request);
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

/// `ProgramTreeSarifMgr.collectFragmentRanges`.
fn collect_fragment_ranges(
    ranges: &mut HashSet<AddressRange>,
    fragment: &Map<String, Value>,
    factory: Option<&dyn AddressFactory>,
    monitor: &dyn TaskMonitor,
) -> Result<(), CollectRangesError> {
    let Some(range_list) = fragment.get("ranges").and_then(Value::as_array) else {
        return Ok(());
    };
    for r in range_list {
        if monitor.is_cancelled() {
            break;
        }
        let Some(obj) = r.as_object() else { continue };
        let start_str = obj.get("start").and_then(Value::as_str);
        let end_str = obj.get("end").and_then(Value::as_str);
        let start = SarifMgr::parse_address(factory, start_str).map_err(CollectRangesError::Runtime)?;
        let end = SarifMgr::parse_address(factory, end_str).map_err(CollectRangesError::Runtime)?;
        let (Some(start), Some(end)) = (start, end) else {
            return Err(AddressFormatException::new(format!(
                "Incompatible Fragment Address Range: [{},{}]",
                start_str.unwrap_or_default(),
                end_str.unwrap_or_default(),
            ))
            .into());
        };
        ranges.insert(AddressRange::new(start, end));
    }
    Ok(())
}

/// `ProgramTreeSarifMgr.processFragmentRange`.
fn process_fragment_range(
    fragment: &Map<String, Value>,
    frag: &mut dyn ProgramFragment,
    factory: Option<&dyn AddressFactory>,
    monitor: &dyn TaskMonitor,
) -> Result<(), ProcessFragmentRangeError> {
    let Some(range_list) = fragment.get("ranges").and_then(Value::as_array) else {
        return Ok(());
    };
    for r in range_list {
        if monitor.is_cancelled() {
            break;
        }
        let Some(obj) = r.as_object() else { continue };
        let start_str = obj.get("start").and_then(Value::as_str);
        let end_str = obj.get("end").and_then(Value::as_str);
        let start = SarifMgr::parse_address(factory, start_str).map_err(ProcessFragmentRangeError::Runtime)?;
        let end = SarifMgr::parse_address(factory, end_str).map_err(ProcessFragmentRangeError::Runtime)?;
        let (Some(start), Some(end)) = (start, end) else {
            return Err(AddressFormatException::new(format!(
                "Incompatible Fragment Address Range: [{},{}]",
                start_str.unwrap_or_default(),
                end_str.unwrap_or_default(),
            ))
            .into());
        };
        frag.move_code_units(&start, &end)?;
    }
    Ok(())
}

/// `ProgramTreeSarifMgr.processModule`.
///
/// On a name clash, Java re-fetches the existing module via `listing.getModule` and reattaches it
/// with `parent.add(newModule)`, then recurses into it regardless of whether that lookup or
/// reattachment succeeded -- only a failed *lookup* (`newModule == null`) makes it bail early. The
/// ported `ProgramModule::add_module` takes ownership (`Box<dyn ProgramModule>`), which a
/// `Listing::get_module` lookup (only ever `Arc<dyn ProgramModule>`) cannot safely produce, so
/// reattachment/recursion for an existing module cannot be replicated here; every duplicate-name
/// outcome collapses to the same log-and-return Java uses for its "not found" case.
fn process_module(parent: &mut dyn ProgramModule, module: &Map<String, Value>, factory: Option<&dyn AddressFactory>, log: &MessageLog) {
    let name = module.get("name").and_then(Value::as_str).unwrap_or_default();
    let mut new_module = match parent.create_module(name) {
        Ok(m) => m,
        Err(DuplicateNameException(_)) => {
            log.append_msg(format!("Duplicate name for {name}"));
            return;
        }
    };

    if let Some(modules) = module.get("modules").and_then(Value::as_array) {
        for m in modules {
            if let Some(obj) = m.as_object() {
                process_module(&mut *new_module, obj, factory, log);
            }
        }
    }
    if let Some(fragments) = module.get("fragments").and_then(Value::as_array) {
        for f in fragments {
            if let Some(obj) = f.as_object() {
                // `processFragment` doesn't check cancellation itself in Java either -- only the
                // per-item loop in `processTree` does -- so a dummy always-running monitor here
                // matches that (this nested call has no monitor of its own to check).
                process_fragment(&mut *new_module, obj, factory, &crate::util::task::DummyMonitor, log);
            }
        }
    }
    remove_empty_fragments(&mut *new_module, log);
}

/// `ProgramTreeSarifMgr.processFragment`.
///
/// Same duplicate-name limitation as [`process_module`]: Java's `parent.add(frag)` reattachment
/// needs owned (`Box<dyn ProgramFragment>`) input that a `Listing::getFragment` lookup (only ever
/// `Arc<dyn ProgramFragment>`) can't safely provide, so this also collapses to a logged skip.
fn process_fragment(
    parent: &mut dyn ProgramModule,
    fragment: &Map<String, Value>,
    factory: Option<&dyn AddressFactory>,
    monitor: &dyn TaskMonitor,
    log: &MessageLog,
) {
    let name = fragment.get("name").and_then(Value::as_str).unwrap_or_default();
    let mut frag = match parent.create_fragment(name) {
        Ok(f) => f,
        Err(DuplicateNameException(_)) => {
            log.append_msg(format!("Duplicate name for {name}"));
            return;
        }
    };

    if let Err(e) = process_fragment_range(fragment, &mut *frag, factory, monitor) {
        match e {
            ProcessFragmentRangeError::NotFound(NotFoundException(msg)) => log.append_msg(msg),
            other => log.append_msg(other.to_string()),
        }
    }
}

/// `ProgramTreeSarifMgr.removeEmptyFragments`.
///
/// Only prunes *direct* empty-fragment children: [`Group::as_program_module`] returns
/// `&dyn ProgramModule`, not `&mut`, so recursing into a child module to prune *its* children --
/// which Java does freely, since its object references carry no such restriction -- is not
/// expressible with the currently-ported API. Deeper empty fragments are left in place.
fn remove_empty_fragments(module: &mut dyn ProgramModule, log: &MessageLog) {
    for group in module.get_children() {
        if group.as_program_fragment().is_some_and(|frag| frag.is_empty()) {
            let name = group.get_name();
            if let Err(NotEmptyException(_)) = module.remove_child(&name) {
                log.append_msg(format!(
                    "Warning: Extra Program Tree fragment '{name}' did not exist in imported SARIF file"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::code_unit_iterator::{CodeUnitIterator, EmptyCodeUnitIterator};
    use crate::program::model::listing::Group;
    use crate::util::task::DummyMonitor;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn factory() -> DefaultAddressFactory {
        DefaultAddressFactory::new(vec![space()])
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(ProgramTreeSarifMgr::KEY, "PROGRAM_TREES");
        assert_eq!(ProgramTreeSarifMgr::SUBKEY, "ProgramTree");
    }

    #[test]
    fn get_key_returns_program_trees() {
        let mgr = ProgramTreeSarifMgr::new(Arc::new(MockProgram), MessageLog::new());
        assert_eq!(mgr.get_key(), "PROGRAM_TREES");
    }

    #[test]
    fn read_bails_gracefully_without_an_exclusive_listing() {
        // `MockProgram::get_listing` defaults to `None` (nothing backs a real tree), matching the
        // "cannot obtain exclusive access" bail path rather than Java's always-present listing.
        let mut mgr = ProgramTreeSarifMgr::new(Arc::new(MockProgram), MessageLog::new());
        let result: HashMap<String, Value> = [("name".to_string(), Value::String("Program Tree".to_string()))].into();

        assert_eq!(mgr.read(&result, None, &DummyMonitor), Ok(true));
        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("not exclusively owned"), "{}", messages[0]);
    }

    #[test]
    fn write_with_no_listing_produces_no_results() {
        let mut mgr = ProgramTreeSarifMgr::new(Arc::new(MockProgram), MessageLog::new());
        let addrs = AddressSet::new();
        let mut results = Vec::new();

        assert!(mgr.write(&mut results, &addrs, &DummyMonitor).is_ok());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_address_returns_none_for_a_null_address_string() {
        assert_eq!(SarifMgr::parse_address(Some(&factory()), None), Ok(None));
    }

    #[test]
    fn parse_address_resolves_a_valid_address() {
        let f = factory();
        let resolved = SarifMgr::parse_address(Some(&f), Some("1000")).unwrap();
        assert_eq!(resolved, f.get_address("1000"));
        assert!(resolved.is_some());
    }

    #[test]
    fn parse_address_errors_for_an_unresolvable_address_string() {
        // No factory at all mirrors `SarifMgr.parseAddress`'s `RuntimeException` when the address
        // string can't be resolved.
        let err = SarifMgr::parse_address(None, Some("1000")).unwrap_err();
        assert!(err.contains("1000"), "{err}");
    }

    #[test]
    fn collect_fragment_ranges_builds_the_expected_range() {
        let f = factory();
        let fragment: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "ranges": [{"start": "1000", "end": "1010"}]
        }))
        .unwrap();

        let mut ranges = HashSet::new();
        collect_fragment_ranges(&mut ranges, &fragment, Some(&f), &DummyMonitor).unwrap();

        assert_eq!(ranges.len(), 1);
        assert!(ranges.contains(&AddressRange::new(addr(0x1000), addr(0x1010))));
    }

    #[test]
    fn collect_fragment_ranges_errors_on_an_incompatible_range() {
        let f = factory();
        let fragment: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "ranges": [{"end": "1010"}]
        }))
        .unwrap();

        let mut ranges = HashSet::new();
        let err = collect_fragment_ranges(&mut ranges, &fragment, Some(&f), &DummyMonitor).unwrap_err();
        assert!(matches!(err, CollectRangesError::AddressFormat(_)));
        assert!(err.to_string().contains("Incompatible Fragment Address Range"), "{err}");
    }

    struct MockFragment {
        name: String,
        addresses: AddressSet,
    }

    impl Group for MockFragment {
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
            self.name = name.to_string();
            Ok(())
        }
        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            false
        }
        fn get_num_parents(&self) -> i32 {
            0
        }
        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }
        fn get_parent_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_tree_name(&self) -> String {
            "Program Tree".to_string()
        }
        fn is_deleted(&self) -> bool {
            false
        }
        fn get_min_address(&self) -> Option<Address> {
            self.addresses.min_address()
        }
        fn get_max_address(&self) -> Option<Address> {
            self.addresses.max_address()
        }
        fn as_program_fragment(&self) -> Option<&dyn ProgramFragment> {
            Some(self)
        }
    }

    impl AddressSetView for MockFragment {
        fn contains(&self, address: &Address) -> bool {
            AddressSetView::contains(&self.addresses, address)
        }
        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.contains_range(start, end)
        }
        fn contains_set(&self, set: &dyn AddressSetView) -> bool {
            self.addresses.contains_set(set)
        }
        fn is_empty(&self) -> bool {
            self.addresses.is_empty()
        }
        fn min_address(&self) -> Option<Address> {
            self.addresses.min_address()
        }
        fn max_address(&self) -> Option<Address> {
            self.addresses.max_address()
        }
        fn num_address_ranges(&self) -> usize {
            self.addresses.num_address_ranges()
        }
        fn address_ranges(&self) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            self.addresses.address_ranges()
        }
        fn address_ranges_ordered(&self, forward: bool) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            self.addresses.address_ranges_ordered(forward)
        }
        fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            self.addresses.address_ranges_from(start, forward)
        }
        fn num_addresses(&self) -> u64 {
            self.addresses.num_addresses()
        }
        fn addresses(&self, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            AddressSetView::addresses(&self.addresses, forward)
        }
        fn addresses_from(&self, start: &Address, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.addresses.addresses_from(start, forward)
        }
        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.addresses.intersects_set(set)
        }
        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.intersects_range(start, end)
        }
        fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.intersect(set)
        }
        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.addresses.intersect_range(start, end)
        }
        fn union(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.union(set)
        }
        fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.subtract(set)
        }
        fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.xor(set)
        }
        fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
            self.addresses.has_same_addresses(set)
        }
        fn first_range(&self) -> Option<AddressRange> {
            self.addresses.first_range()
        }
        fn last_range(&self) -> Option<AddressRange> {
            self.addresses.last_range()
        }
        fn range_containing(&self, address: &Address) -> Option<AddressRange> {
            self.addresses.range_containing(address)
        }
        fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
            self.addresses.find_first_address_in_common(set)
        }
    }

    impl ProgramFragment for MockFragment {
        fn get_code_units(&self) -> Box<dyn CodeUnitIterator> {
            Box::new(EmptyCodeUnitIterator)
        }
        fn move_code_units(&mut self, min: &Address, max: &Address) -> Result<(), NotFoundException> {
            self.addresses.add_range(min, max);
            Ok(())
        }
    }

    #[test]
    fn process_fragment_range_moves_code_units_for_valid_ranges() {
        let f = factory();
        let fragment: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "ranges": [{"start": "1000", "end": "1010"}]
        }))
        .unwrap();
        let mut frag = MockFragment { name: "frag".to_string(), addresses: AddressSet::new() };

        process_fragment_range(&fragment, &mut frag, Some(&f), &DummyMonitor).unwrap();

        assert!(frag.addresses.contains_range(&addr(0x1000), &addr(0x1010)));
    }

    #[test]
    fn process_fragment_range_errors_on_an_incompatible_range() {
        let f = factory();
        let fragment: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "ranges": [{"start": "1000"}]
        }))
        .unwrap();
        let mut frag = MockFragment { name: "frag".to_string(), addresses: AddressSet::new() };

        let err = process_fragment_range(&fragment, &mut frag, Some(&f), &DummyMonitor).unwrap_err();
        assert!(matches!(err, ProcessFragmentRangeError::AddressFormat(_)));
        assert!(frag.addresses.is_empty());
    }

    struct MockModule {
        name: String,
        children: Vec<MockFragment>,
    }

    impl Group for MockModule {
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
            self.name = name.to_string();
            Ok(())
        }
        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            false
        }
        fn get_num_parents(&self) -> i32 {
            0
        }
        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }
        fn get_parent_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_tree_name(&self) -> String {
            "Program Tree".to_string()
        }
        fn is_deleted(&self) -> bool {
            false
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_max_address(&self) -> Option<Address> {
            None
        }
        fn as_program_module(&self) -> Option<&dyn ProgramModule> {
            Some(self)
        }
    }

    impl ProgramModule for MockModule {
        fn contains_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            false
        }
        fn contains_module(&self, _module: &dyn ProgramModule) -> bool {
            false
        }
        fn get_num_children(&self) -> i32 {
            self.children.len() as i32
        }
        fn get_children(&self) -> Vec<Box<dyn Group>> {
            self.children
                .iter()
                .map(|f| Box::new(MockFragment { name: f.name.clone(), addresses: f.addresses.clone() }) as Box<dyn Group>)
                .collect()
        }
        fn get_index(&self, name: &str) -> i32 {
            self.children.iter().position(|c| c.name == name).map(|i| i as i32).unwrap_or(-1)
        }
        fn add_module(&mut self, _module: Box<dyn ProgramModule>) -> Result<(), crate::program::model::listing::AddModuleError> {
            unimplemented!("not exercised by remove_empty_fragments tests")
        }
        fn add_fragment(&mut self, _fragment: Box<dyn ProgramFragment>) -> Result<(), crate::program::model::listing::DuplicateGroupException> {
            unimplemented!("not exercised by remove_empty_fragments tests")
        }
        fn create_module(&mut self, _module_name: &str) -> Result<Box<dyn ProgramModule>, DuplicateNameException> {
            unimplemented!("not exercised by remove_empty_fragments tests")
        }
        fn create_fragment(&mut self, fragment_name: &str) -> Result<Box<dyn ProgramFragment>, DuplicateNameException> {
            if self.children.iter().any(|c| c.name == fragment_name) {
                return Err(DuplicateNameException::default());
            }
            self.children.push(MockFragment { name: fragment_name.to_string(), addresses: AddressSet::new() });
            Ok(Box::new(MockFragment { name: fragment_name.to_string(), addresses: AddressSet::new() }))
        }
        fn reparent(&mut self, _name: &str, _old_parent: &mut dyn ProgramModule) -> Result<(), NotFoundException> {
            unimplemented!("not exercised by remove_empty_fragments tests")
        }
        fn move_child(&mut self, _name: &str, _index: i32) -> Result<(), NotFoundException> {
            unimplemented!("not exercised by remove_empty_fragments tests")
        }
        fn remove_child(&mut self, name: &str) -> Result<bool, NotEmptyException> {
            if name == "protected" {
                return Err(NotEmptyException::default());
            }
            let before = self.children.len();
            self.children.retain(|c| c.name != name);
            Ok(self.children.len() != before)
        }
        fn is_descendant_module(&self, _module: &dyn ProgramModule) -> bool {
            false
        }
        fn is_descendant_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            false
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_max_address(&self) -> Option<Address> {
            None
        }
        fn get_first_address(&self) -> Option<Address> {
            None
        }
        fn get_last_address(&self) -> Option<Address> {
            None
        }
        fn get_address_set(&self) -> &dyn AddressSetView {
            static EMPTY: std::sync::OnceLock<AddressSet> = std::sync::OnceLock::new();
            EMPTY.get_or_init(AddressSet::new)
        }
        fn get_version_tag(&self) -> Box<dyn std::any::Any> {
            Box::new(0i32)
        }
        fn get_modification_number(&self) -> i64 {
            0
        }
        fn get_tree_id(&self) -> i64 {
            0
        }
    }

    #[test]
    fn remove_empty_fragments_removes_empty_but_keeps_nonempty_fragment() {
        let mut nonempty = AddressSet::new();
        nonempty.add_range(&addr(0), &addr(0xf));

        let mut module = MockModule {
            name: "root".to_string(),
            children: vec![
                MockFragment { name: "empty".to_string(), addresses: AddressSet::new() },
                MockFragment { name: "full".to_string(), addresses: nonempty },
            ],
        };

        let log = MessageLog::new();
        remove_empty_fragments(&mut module, &log);

        assert_eq!(module.children.len(), 1);
        assert_eq!(module.children[0].name, "full");
        assert!(log.messages().is_empty());
    }

    #[test]
    fn remove_empty_fragments_logs_a_warning_when_removal_fails() {
        let mut module = MockModule {
            name: "root".to_string(),
            children: vec![MockFragment { name: "protected".to_string(), addresses: AddressSet::new() }],
        };

        let log = MessageLog::new();
        remove_empty_fragments(&mut module, &log);

        // `remove_child` refuses to remove "protected" (simulating Java's `NotEmptyException`),
        // so the fragment survives and the warning matches Java's message text.
        assert_eq!(module.children.len(), 1);
        let messages = log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Extra Program Tree fragment 'protected'"), "{}", messages[0]);
    }
}
