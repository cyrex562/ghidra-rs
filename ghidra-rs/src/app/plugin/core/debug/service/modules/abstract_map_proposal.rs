//! Shared building blocks for concrete `MapProposal` implementations.
//!
//! Port of `ghidra.app.plugin.core.debug.service.modules.AbstractMapProposal<T, P, E extends
//! MapEntry<T, P>>`, an abstract class implementing
//! [`MapProposal`](crate::debug::api::modules::MapProposal) that itself leaves `computeScore()`,
//! `computeMap()`, and `getToObject(T)` abstract -- only its concrete subclasses (Java:
//! `DefaultRegionMapProposal`, `DefaultSectionMapProposal`, and presumably an unported
//! `DefaultModuleMapProposal`) supply those. Since it never fully implements the trait, this port
//! does not implement [`MapProposal`](crate::debug::api::modules::MapProposal) either; instead it
//! is a base a future concrete proposal is expected to *compose*, mirroring this crate's
//! composition-over-inheritance convention (e.g. how
//! [`AbstractLocationPluginEvent`](crate::app::events::AbstractLocationPluginEvent) is composed
//! by `ProgramLocationPluginEvent`).
//!
//! The two Java nested classes needing translation, `Matcher<T, P>` and `MatcherMap<K, T, P, M
//! extends Matcher<T, P>>`, are both meant to be subclassed with virtual-dispatch overrides
//! (`getFromRange()`, `getToRange()`, `computeScore()`, `newMatcher(...)`, `getFromJoinKey(...)`,
//! `getToJoinKey(...)`) -- including a classic "virtual call from the constructor" pattern, where
//! `Matcher`'s constructor computes `fromRange`/`toRange`/`score` by invoking methods a subclass
//! overrides. Rust has no inheritance or virtual dispatch, so both types take their
//! customization points as closures supplied at construction instead: [`Matcher::new`] takes
//! `get_from_range`/`get_to_range`/`compute_score` closures (invoked eagerly, exactly once, in
//! the same order Java's constructor would call the overridden methods), and [`MatcherMap::new`]
//! takes `new_matcher`/`get_from_join_key`/`get_to_join_key` closures. `M`, the matcher subtype
//! parameter, collapses away entirely: since a "subclass" is now just a different set of
//! closures rather than a different type, [`MatcherMap`] works directly in terms of `Matcher<T,
//! P>`.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::Arc;

use crate::program::model::address::AddressRange;
use crate::program::model::listing::Program;
use crate::trace::model::trace::Trace;

/// A candidate match between one "from" (trace-side) object and one "to" (program-side) object.
///
/// Port of the nested `AbstractMapProposal.Matcher<T, P>` abstract static class. See the module
/// docs for why the abstract `getFromRange()`/`getToRange()`/`computeScore()` methods become
/// constructor closures here instead of virtual overrides.
pub struct Matcher<T, P> {
    pub from_object: Option<T>,
    pub snap: i64,
    pub to_object: Option<P>,
    pub from_range: Option<AddressRange>,
    pub to_range: Option<AddressRange>,
    pub score: f64,
}

impl<T, P> Matcher<T, P> {
    /// Constructs a new matcher, mirroring `Matcher(T fromObject, long snap, P toObject)`.
    ///
    /// `get_from_range`/`get_to_range` are only invoked when the corresponding object is
    /// present, matching `fromObject == null ? null : getFromRange()`. `compute_score` is only
    /// invoked when *both* objects are present, matching `fromObject == null || toObject == null
    /// ? 0 : computeScore()`; the resulting ranges are passed in since a real
    /// `computeScore()` override (see [`Matcher::default_compute_score`]) needs them.
    pub fn new(
        from_object: Option<T>,
        snap: i64,
        to_object: Option<P>,
        get_from_range: impl FnOnce(&T) -> AddressRange,
        get_to_range: impl FnOnce(&P) -> AddressRange,
        compute_score: impl FnOnce(&AddressRange, &AddressRange) -> f64,
    ) -> Self {
        let from_range = from_object.as_ref().map(get_from_range);
        let to_range = to_object.as_ref().map(get_to_range);
        let score = match (&from_range, &to_range) {
            (Some(fr), Some(tr)) => compute_score(fr, tr),
            _ => 0.0,
        };
        Self {
            from_object,
            snap,
            to_object,
            from_range,
            to_range,
            score,
        }
    }

    /// The default (base-class) key-match contribution to a candidate's score.
    ///
    /// Mirrors `Matcher.computeKeyMatchScore()`. A concrete matcher's `compute_score` closure is
    /// free to ignore this and use its own value instead (mirroring an `@Override` in Java).
    pub fn compute_key_match_score() -> i32 {
        3
    }

    /// Mirrors `Matcher.shiftRight1RoundUp(long)`: an unsigned right-shift by one bit, rounding
    /// odd values up rather than down.
    pub fn shift_right1_round_up(val: u64) -> u64 {
        if val & 1 == 1 {
            (val >> 1) + 1
        } else {
            val >> 1
        }
    }

    /// The default (base-class) contribution to a candidate's score from how closely the "from"
    /// and "to" ranges' *lengths* match, independent of where they sit in memory.
    ///
    /// Mirrors `Matcher.computeLengthScore()`. Repeatedly halves (rounding up) both lengths,
    /// counting down from 64 matched bits, and returns as soon as the two halved lengths become
    /// equal; a perfect length match at the first comparison scores `64 / 6.4 == 10.0`, and the
    /// score decreases the more halvings are needed before the lengths agree.
    pub fn compute_length_score(from_range: &AddressRange, to_range: &AddressRange) -> f64 {
        let mut f_len = from_range.length();
        let mut t_len = to_range.length();
        for bits_matched in (1..=64).rev() {
            if f_len == t_len {
                return bits_matched as f64 / 6.4;
            }
            f_len = Self::shift_right1_round_up(f_len);
            t_len = Self::shift_right1_round_up(t_len);
        }
        0.0
    }

    /// The default (base-class) `computeScore()`: `computeKeyMatchScore() +
    /// computeLengthScore()`. A convenience for concrete matchers' `compute_score` closures that
    /// want the unmodified base behavior.
    pub fn default_compute_score(from_range: &AddressRange, to_range: &AddressRange) -> f64 {
        Self::compute_key_match_score() as f64 + Self::compute_length_score(from_range, to_range)
    }
}

/// Joins candidate "from" objects against candidate "to" objects, keeping the best-scoring match
/// for each "from" object seen so far.
///
/// Port of the nested `AbstractMapProposal.MatcherMap<K, T, P, M extends Matcher<T, P>>`
/// abstract static class. See the module docs for why the `M` type parameter and the abstract
/// `newMatcher`/`getFromJoinKey`/`getToJoinKey` methods collapse into constructor closures
/// working directly in terms of `Matcher<T, P>`.
pub struct MatcherMap<K, T, P> {
    pub snap: i64,
    // Java uses `LinkedHashMap`/`LinkedHashSet` here for deterministic iteration order; nothing
    // in this class's documented contract depends on iteration order (the only public
    // aggregates, `average_score`/`compute_map`, are order-insensitive), so plain `HashMap`/
    // `HashSet` are used instead.
    froms_by_join: HashMap<K, HashSet<T>>,
    map: HashMap<T, Matcher<T, P>>,
    new_matcher: Box<dyn Fn(&T, &P, i64) -> Matcher<T, P>>,
    get_from_join_key: Box<dyn Fn(&T) -> K>,
    get_to_join_key: Box<dyn Fn(&P) -> K>,
}

impl<K: Eq + Hash, T: Eq + Hash + Clone, P: Clone> MatcherMap<K, T, P> {
    /// Constructs a new, empty matcher map, mirroring `MatcherMap(long snap)`.
    pub fn new(
        snap: i64,
        new_matcher: impl Fn(&T, &P, i64) -> Matcher<T, P> + 'static,
        get_from_join_key: impl Fn(&T) -> K + 'static,
        get_to_join_key: impl Fn(&P) -> K + 'static,
    ) -> Self {
        Self {
            snap,
            froms_by_join: HashMap::new(),
            map: HashMap::new(),
            new_matcher: Box::new(new_matcher),
            get_from_join_key: Box::new(get_from_join_key),
            get_to_join_key: Box::new(get_to_join_key),
        }
    }

    /// Registers a candidate "from" object under its join key.
    ///
    /// Mirrors `processFromObject(T)`.
    pub fn process_from_object(&mut self, from_object: T) {
        let key = (self.get_from_join_key)(&from_object);
        self.froms_by_join
            .entry(key)
            .or_default()
            .insert(from_object);
    }

    /// Registers a candidate "to" object, matching it against every "from" object sharing its
    /// join key and keeping the best-scoring match seen so far for each.
    ///
    /// Mirrors `processToObject(P)`.
    pub fn process_to_object(&mut self, to_object: P) {
        let key = (self.get_to_join_key)(&to_object);
        let Some(froms) = self.froms_by_join.get(&key) else {
            return;
        };
        // Clone the join-key's from-set up front: we're about to mutate `self.map`, which would
        // otherwise conflict with the still-live borrow of `self.froms_by_join`.
        let froms: Vec<T> = froms.iter().cloned().collect();
        for from in froms {
            let candidate = (self.new_matcher)(&from, &to_object, self.snap);
            let better = match self.map.get(&from) {
                Some(best) => candidate.score > best.score,
                None => true,
            };
            if better {
                self.map.insert(from, candidate);
            }
        }
    }

    /// The mean score across all current best matches.
    ///
    /// Mirrors `averageScore()`. Faithfully preserves the Java quirk of dividing by
    /// `map.size()` unconditionally: on an empty map this is `0.0 / 0.0`, i.e. `NaN`, not a
    /// division-by-zero panic (`f64` division, unlike integer division, never panics).
    pub fn average_score(&self) -> f64 {
        let sum: f64 = self.map.values().map(|m| m.score).sum();
        sum / self.map.len() as f64
    }

    /// Builds the final trace-object-to-entry map from every current best match that has both a
    /// "from" and a "to" object.
    ///
    /// Mirrors `computeMap(Function<M, E>)`.
    pub fn compute_map<E>(&self, mut new_entry: impl FnMut(&Matcher<T, P>) -> E) -> HashMap<T, E> {
        self.map
            .values()
            .filter(|m| m.from_object.is_some() && m.to_object.is_some())
            .map(|m| (m.from_object.clone().unwrap(), new_entry(m)))
            .collect()
    }

    /// The best-matched "to" object for a given "from" object, if any.
    ///
    /// Mirrors `getToObject(T)`.
    pub fn get_to_object(&self, from_object: &T) -> Option<P> {
        self.map.get(from_object).and_then(|m| m.to_object.clone())
    }
}

/// Shared trace/program state for a concrete `MapProposal`.
///
/// Port of the fields and constructor of `AbstractMapProposal` itself (as opposed to its two
/// nested classes above): `protected final Trace trace; protected final Program program;` plus
/// `getTrace()`/`getProgram()`. A concrete proposal composes this the same way it would have
/// extended `AbstractMapProposal` in Java.
pub struct AbstractMapProposal {
    trace: Arc<dyn Trace>,
    program: Arc<dyn Program>,
}

impl AbstractMapProposal {
    /// Mirrors `AbstractMapProposal(Trace trace, Program program)`.
    pub fn new(trace: Arc<dyn Trace>, program: Arc<dyn Program>) -> Self {
        Self { trace, program }
    }

    /// Mirrors `getTrace()`.
    pub fn get_trace(&self) -> Arc<dyn Trace> {
        self.trace.clone()
    }

    /// Mirrors `getProgram()`.
    pub fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn range(start: i64, len: u64) -> AddressRange {
        AddressRange::from_start_len(addr(start), len).unwrap()
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "static.exe".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockTrace;
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_address_factory(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::model::property::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(
            &self,
        ) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(
            &self,
        ) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(
            &self,
        ) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(
            &self,
        ) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(
            &self,
        ) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(
            &self,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(
            &self,
        ) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    // --- Matcher ---

    #[test]
    fn matcher_with_both_objects_computes_ranges_and_score() {
        let m = Matcher::new(
            Some("region"),
            5,
            Some("block"),
            |_| range(0x1000, 0x100),
            |_| range(0x2000, 0x100),
            Matcher::<&str, &str>::default_compute_score,
        );
        assert_eq!(m.from_range, Some(range(0x1000, 0x100)));
        assert_eq!(m.to_range, Some(range(0x2000, 0x100)));
        // Equal lengths at the first comparison: 3 (key match) + 64/6.4 (10.0) == 13.0.
        assert_eq!(m.score, 13.0);
    }

    #[test]
    fn matcher_with_missing_from_object_has_no_from_range_and_zero_score() {
        let m: Matcher<&str, &str> = Matcher::new(
            None,
            5,
            Some("block"),
            |_| range(0x1000, 0x100),
            |_| range(0x2000, 0x100),
            Matcher::<&str, &str>::default_compute_score,
        );
        assert_eq!(m.from_range, None);
        assert!(m.to_range.is_some());
        assert_eq!(m.score, 0.0);
    }

    #[test]
    fn matcher_with_missing_to_object_has_no_to_range_and_zero_score() {
        let m: Matcher<&str, &str> = Matcher::new(
            Some("region"),
            5,
            None,
            |_| range(0x1000, 0x100),
            |_| range(0x2000, 0x100),
            Matcher::<&str, &str>::default_compute_score,
        );
        assert!(m.from_range.is_some());
        assert_eq!(m.to_range, None);
        assert_eq!(m.score, 0.0);
    }

    #[test]
    fn compute_key_match_score_is_three() {
        assert_eq!(Matcher::<(), ()>::compute_key_match_score(), 3);
    }

    #[test]
    fn shift_right1_round_up_rounds_odd_values_up() {
        assert_eq!(Matcher::<(), ()>::shift_right1_round_up(5), 3); // (5>>1)=2, +1 = 3
        assert_eq!(Matcher::<(), ()>::shift_right1_round_up(4), 2); // even: exact half
        assert_eq!(Matcher::<(), ()>::shift_right1_round_up(1), 1); // (1>>1)=0, +1 = 1
        assert_eq!(Matcher::<(), ()>::shift_right1_round_up(0), 0);
    }

    #[test]
    fn compute_length_score_is_ten_for_exactly_equal_lengths() {
        let score = Matcher::<(), ()>::compute_length_score(&range(0x1000, 0x100), &range(0x5000, 0x100));
        assert_eq!(score, 10.0); // 64 / 6.4
    }

    #[test]
    fn compute_length_score_decreases_as_lengths_diverge() {
        // Lengths 0x100 and 0x101 differ by one, so several halvings are needed before they
        // agree (both eventually shrink toward 1 by round-up shifting); the resulting score
        // must be strictly less than a perfect match's 10.0, but still >= 0.
        let score = Matcher::<(), ()>::compute_length_score(&range(0x1000, 0x100), &range(0x5000, 0x101));
        assert!(score < 10.0);
        assert!(score >= 0.0);
    }

    #[test]
    fn compute_length_score_matches_immediately_for_equal_length_one_ranges() {
        let score = Matcher::<(), ()>::compute_length_score(&range(0x1000, 1), &range(0x5000, 1));
        assert_eq!(score, 10.0);
    }

    // --- MatcherMap ---

    fn simple_matcher(from: &&'static str, to: &&'static str, snap: i64) -> Matcher<&'static str, &'static str> {
        // A trivial matcher: score equals the from-object's declared "affinity" for the to-object,
        // encoded directly in the fixture data below via range lengths (so default_compute_score
        // naturally favors the intended pairing).
        let from_range = FIXTURE_RANGES.with(|r| r.borrow()[from].clone());
        let to_range = FIXTURE_RANGES.with(|r| r.borrow()[to].clone());
        Matcher::new(
            Some(*from),
            snap,
            Some(*to),
            |_| from_range,
            |_| to_range,
            Matcher::<&str, &str>::default_compute_score,
        )
    }

    thread_local! {
        static FIXTURE_RANGES: std::cell::RefCell<HashMap<&'static str, AddressRange>> =
            std::cell::RefCell::new(HashMap::new());
    }

    fn with_fixture<F: FnOnce()>(entries: &[(&'static str, AddressRange)], f: F) {
        FIXTURE_RANGES.with(|r| {
            let mut map = r.borrow_mut();
            map.clear();
            for (k, v) in entries {
                map.insert(*k, v.clone());
            }
        });
        f();
    }

    #[test]
    fn matcher_map_joins_from_and_to_objects_by_key() {
        with_fixture(
            &[
                ("region-a", range(0x1000, 0x10)),
                ("block-a", range(0x9000, 0x10)),
                ("block-b", range(0x9100, 0x20)),
            ],
            || {
                let mut mm: MatcherMap<(), &str, &str> = MatcherMap::new(
                    0,
                    simple_matcher,
                    |_from: &&str| (),
                    |_to: &&str| (),
                );
                mm.process_from_object("region-a");
                mm.process_to_object("block-a");
                mm.process_to_object("block-b");

                // "block-a" has the same length as "region-a" (perfect length match, score
                // 13.0); "block-b" has a different length (lower score), so "block-a" should
                // win.
                assert_eq!(mm.get_to_object(&"region-a"), Some("block-a"));
            },
        );
    }

    #[test]
    fn matcher_map_keeps_the_better_scoring_candidate() {
        with_fixture(
            &[
                ("region-a", range(0x1000, 0x10)),
                ("block-a", range(0x9000, 0x11)), // slightly different length: lower score
                ("block-b", range(0x9100, 0x10)), // exact length match: higher score
            ],
            || {
                let mut mm: MatcherMap<(), &str, &str> =
                    MatcherMap::new(0, simple_matcher, |_: &&str| (), |_: &&str| ());
                mm.process_from_object("region-a");
                // Process the worse candidate first, to prove replacement (not just
                // first-write-wins) happens when a better one shows up later.
                mm.process_to_object("block-a");
                mm.process_to_object("block-b");

                assert_eq!(mm.get_to_object(&"region-a"), Some("block-b"));
            },
        );
    }

    #[test]
    fn matcher_map_average_score_is_the_mean_of_best_matches() {
        with_fixture(
            &[
                ("region-a", range(0x1000, 0x10)),
                ("region-b", range(0x2000, 0x10)),
                ("block-a", range(0x9000, 0x10)),
            ],
            || {
                let mut mm: MatcherMap<(), &str, &str> =
                    MatcherMap::new(0, simple_matcher, |_: &&str| (), |_: &&str| ());
                mm.process_from_object("region-a");
                mm.process_from_object("region-b");
                mm.process_to_object("block-a");

                // Both regions match the single block with an identical (perfect) length score.
                assert_eq!(mm.average_score(), 13.0);
            },
        );
    }

    #[test]
    fn matcher_map_average_score_is_nan_when_empty() {
        // Faithful reproduction of the Java quirk: `averageScore()` divides by `map.size()`
        // unconditionally, so an empty map yields `0.0 / 0.0 == NaN`, not a panic (`f64`
        // division never panics) and not some defensively-chosen default like `0.0`.
        let mm: MatcherMap<(), &str, &str> =
            MatcherMap::new(0, simple_matcher, |_: &&str| (), |_: &&str| ());
        assert!(mm.average_score().is_nan());
    }

    #[test]
    fn matcher_map_compute_map_only_includes_fully_matched_entries() {
        with_fixture(
            &[
                ("region-a", range(0x1000, 0x10)),
                ("block-a", range(0x9000, 0x10)),
            ],
            || {
                let mut mm: MatcherMap<(), &str, &str> =
                    MatcherMap::new(0, simple_matcher, |_: &&str| (), |_: &&str| ());
                mm.process_from_object("region-a");
                mm.process_to_object("block-a");

                let computed = mm.compute_map(|m| format!("{}->{}", m.from_object.unwrap(), m.to_object.unwrap()));
                assert_eq!(computed.get("region-a"), Some(&"region-a->block-a".to_string()));
                assert_eq!(computed.len(), 1);
            },
        );
    }

    #[test]
    fn matcher_map_to_object_with_unknown_join_key_is_ignored() {
        with_fixture(
            &[
                ("region-a", range(0x1000, 0x10)),
                ("block-a", range(0x9000, 0x10)),
            ],
            || {
                let mut mm: MatcherMap<i32, &str, &str> = MatcherMap::new(
                    0,
                    simple_matcher,
                    |_: &&str| 1,
                    |_: &&str| 2, // never matches key 1, so process_to_object always no-ops
                );
                mm.process_from_object("region-a");
                mm.process_to_object("block-a");
                assert_eq!(mm.get_to_object(&"region-a"), None);
            },
        );
    }

    // --- AbstractMapProposal ---

    #[test]
    fn abstract_map_proposal_exposes_trace_and_program() {
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let trace_ptr = Arc::as_ptr(&trace);
        let program_ptr = Arc::as_ptr(&program);

        let proposal = AbstractMapProposal::new(trace, program);

        assert_eq!(Arc::as_ptr(&proposal.get_trace()), trace_ptr);
        assert_eq!(Arc::as_ptr(&proposal.get_program()), program_ptr);
    }
}
