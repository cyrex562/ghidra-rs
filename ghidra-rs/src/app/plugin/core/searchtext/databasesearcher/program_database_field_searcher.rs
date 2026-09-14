//! Port of `ghidra.app.plugin.core.searchtext.databasesearcher.ProgramDatabaseFieldSearcher`.

use std::cmp::Ordering;
use std::collections::VecDeque;

use regex::Regex;

use crate::app::plugin::core::searchtext::searcher::TextSearchResult;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::util::program_location::ProgramLocation;

/// Stands in for the unported `ghidra.program.util.ProgramLocationComparator`, needed by
/// [`ProgramDatabaseFieldSearcherBase::trim_matches_for_start_location`]'s use of Java's
/// `startLocation.compareTo(programLoc)` (`ProgramLocation implements Comparable<ProgramLocation>`
/// entirely by delegating to that unported comparator). [`ProgramLocation`] itself deliberately
/// omits `compareTo` for the same reason (see that trait's module docs). Concrete searchers supply
/// one when constructing their [`ProgramDatabaseFieldSearcherBase`].
pub type ProgramLocationComparator =
    Box<dyn Fn(&dyn ProgramLocation, &dyn ProgramLocation) -> Ordering>;

/// Shared state for [`ProgramDatabaseFieldSearcher`] implementations, standing in for Java's
/// `extends`.
///
/// Port of the field/constructor/concrete-method portion of
/// `ghidra.app.plugin.core.searchtext.databasesearcher.ProgramDatabaseFieldSearcher`. Composition
/// over inheritance: a concrete searcher holds a `base: ProgramDatabaseFieldSearcherBase` field
/// and implements [`ProgramDatabaseFieldSearcher::base`]/[`ProgramDatabaseFieldSearcher::base_mut`]
/// to delegate to it, exactly as Java subclasses inherit this state.
pub struct ProgramDatabaseFieldSearcherBase {
    /// Java: `protected final Pattern pattern`.
    pub pattern: Regex,
    /// Java: `protected final boolean forward`.
    pub forward: bool,
    current_address: Option<Address>,
    start_location: Option<Box<dyn ProgramLocation>>,
    matches_for_current_address: VecDeque<TextSearchResult>,
    location_comparator: ProgramLocationComparator,
}

impl ProgramDatabaseFieldSearcherBase {
    /// Java: `protected ProgramDatabaseFieldSearcher(Pattern pattern, boolean forward,
    /// ProgramLocation startLoc, AddressSetView set)`.
    ///
    /// `location_comparator` stands in for the unported `ProgramLocationComparator` (see the type
    /// alias docs); it is only consulted by
    /// [`trim_matches_for_start_location`](Self::trim_matches_for_start_location).
    ///
    /// # Panics
    ///
    /// Panics if `start_loc` and `set` are inconsistent (`forward` and `set`'s minimum address
    /// doesn't match `start_loc`'s address, or `!forward` and `set`'s maximum address doesn't
    /// match). Java: `IllegalArgumentException("Start location and addressSet are inconsistent!")`.
    pub fn new(
        pattern: Regex,
        forward: bool,
        start_loc: Option<Box<dyn ProgramLocation>>,
        set: Option<&dyn AddressSetView>,
        location_comparator: ProgramLocationComparator,
    ) -> Self {
        if let (Some(set), Some(start_loc)) = (set, &start_loc) {
            if !set.is_empty() {
                let boundary = if forward { set.min_address() } else { set.max_address() };
                if boundary.as_ref() != Some(&start_loc.get_address()) {
                    panic!("Start location and addressSet are inconsistent!");
                }
            }
        }

        ProgramDatabaseFieldSearcherBase {
            pattern,
            forward,
            current_address: None,
            start_location: start_loc,
            matches_for_current_address: VecDeque::new(),
            location_comparator,
        }
    }
}

/// Search the program database for fields matching a pattern.
///
/// Port of `ghidra.app.plugin.core.searchtext.databasesearcher.ProgramDatabaseFieldSearcher`, an
/// abstract class with one abstract method (`advance`). See
/// [`ProgramDatabaseFieldSearcherBase`] for the concrete field/constructor portion.
pub trait ProgramDatabaseFieldSearcher {
    /// Returns the shared base state.
    fn base(&self) -> &ProgramDatabaseFieldSearcherBase;

    /// Returns the shared base state, mutably.
    fn base_mut(&mut self) -> &mut ProgramDatabaseFieldSearcherBase;

    /// Advances the search, refilling `current_matches` with the matches found for the next
    /// significant address and returning that address (or `None` if there are no more).
    ///
    /// Java: `protected abstract Address advance(List<TextSearchResult> currentMatches)`. The
    /// `currentMatches` parameter is the live `matchesForCurrentAddress` field, passed so
    /// implementations can populate it in place -- matches [`do_advance`](Self::do_advance)'s
    /// handling below.
    fn advance(&mut self, current_matches: &mut VecDeque<TextSearchResult>) -> Option<Address>;

    /// Java: private `doAdvance(List<TextSearchResult> currentMatches)`.
    ///
    /// Java's `currentMatches` parameter is dead: the method body always reads/writes the
    /// `matchesForCurrentAddress` *field* directly regardless of what was passed in (both call
    /// sites pass that same field back to it anyway). Faithfully reproduced by simply not taking
    /// a parameter here and always operating on the base's field.
    fn do_advance(&mut self) -> Option<Address> {
        let mut matches = std::mem::take(&mut self.base_mut().matches_for_current_address);
        let address = self.advance(&mut matches);
        if !self.base().forward {
            // Collections.reverse(matchesForCurrentAddress)
            let reversed: VecDeque<TextSearchResult> = matches.into_iter().rev().collect();
            matches = reversed;
        }
        self.base_mut().matches_for_current_address = matches;
        address
    }

    /// Java: private `initialize()`.
    fn initialize(&mut self) {
        let address = self.do_advance();
        self.base_mut().current_address = address;
        self.trim_matches_for_start_location();
    }

    /// Returns the next significant address after `address`, or the first significant address if
    /// `address` is `None`. Returns `None` if there are no more.
    ///
    /// Java: `public Address getNextSignificantAddress(Address address)`.
    fn get_next_significant_address(&mut self, address: Option<&Address>) -> Option<Address> {
        match address {
            None => {
                self.initialize();
                self.base().current_address.clone()
            }
            Some(address) => {
                if self.base().current_address.is_none() {
                    return None; // we have no more records in our iterator.
                }
                if self.base().current_address.as_ref() == Some(address) {
                    // we need to move to the next record
                    let next = self.do_advance();
                    self.base_mut().current_address = next;
                }
                self.base().current_address.clone()
            }
        }
    }

    /// Removes and returns the next match for the current address.
    ///
    /// Java: `public TextSearchResult getMatch()`.
    ///
    /// # Panics
    ///
    /// Panics if there are no matches for the current address, mirroring Java's unchecked
    /// `IndexOutOfBoundsException` from `List.remove(0)` on an empty list.
    fn get_match(&mut self) -> TextSearchResult {
        self.base_mut()
            .matches_for_current_address
            .pop_front()
            .expect("no matches for the current address")
    }

    /// Returns `true` if `address` is the current address and it still has at least one match.
    ///
    /// Java: `public boolean hasMatch(Address address)`.
    fn has_match(&self, address: &Address) -> bool {
        if self.base().current_address.as_ref() != Some(address) {
            return false;
        }
        !self.base().matches_for_current_address.is_empty()
    }

    /// Java: private `trimMatchesForStartLocation()`.
    fn trim_matches_for_start_location(&mut self) {
        let base = self.base();
        let Some(start_location) = base.start_location.as_deref() else {
            return;
        };
        if base.current_address.as_ref() != Some(&start_location.get_address()) {
            return;
        }
        let forward = base.forward;
        let to_remove: Vec<bool> = base
            .matches_for_current_address
            .iter()
            .map(|m| {
                let compare_val =
                    (base.location_comparator)(start_location, m.program_location());
                (forward && compare_val != Ordering::Less)
                    || (!forward && compare_val != Ordering::Greater)
            })
            .collect();

        let mut idx = 0;
        self.base_mut().matches_for_current_address.retain(|_| {
            let keep = !to_remove[idx];
            idx += 1;
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    #[derive(Clone)]
    struct FixedLocation {
        address: Address,
    }

    impl ProgramLocation for FixedLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn loc(offset: i64) -> Box<dyn ProgramLocation> {
        Box::new(FixedLocation { address: addr(offset) })
    }

    /// A comparator ordering locations by address, standing in for the real
    /// `ProgramLocationComparator`.
    fn address_comparator() -> ProgramLocationComparator {
        Box::new(|a, b| a.get_address().cmp(&b.get_address()))
    }

    fn result(offset: i64, search_offset: i32) -> TextSearchResult {
        TextSearchResult::new(loc(offset), search_offset)
    }

    /// A searcher over a fixed, pre-built sequence of (address -> matches) groups, advancing
    /// linearly through them. Exercises the trait's default methods against a simple, predictable
    /// backend.
    struct ListSearcher {
        base: ProgramDatabaseFieldSearcherBase,
        // `TextSearchResult` holds `Box<dyn ProgramLocation>`, which is not `Clone`, so each
        // group is consumed via `Option::take` (every group is only ever visited once by
        // `advance` anyway) rather than cloned.
        groups: Vec<Option<(Address, Vec<TextSearchResult>)>>,
        next_group: usize,
    }

    impl ListSearcher {
        fn new(
            groups: Vec<(Address, Vec<TextSearchResult>)>,
            forward: bool,
            start_loc: Option<Box<dyn ProgramLocation>>,
            set: Option<&dyn AddressSetView>,
        ) -> Self {
            let comparator: ProgramLocationComparator =
                Box::new(|a, b| a.get_address().cmp(&b.get_address()));
            ListSearcher {
                base: ProgramDatabaseFieldSearcherBase::new(
                    Regex::new("x").unwrap(),
                    forward,
                    start_loc,
                    set,
                    comparator,
                ),
                groups: groups.into_iter().map(Some).collect(),
                next_group: 0,
            }
        }
    }

    impl ProgramDatabaseFieldSearcher for ListSearcher {
        fn base(&self) -> &ProgramDatabaseFieldSearcherBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut ProgramDatabaseFieldSearcherBase {
            &mut self.base
        }
        fn advance(&mut self, current_matches: &mut VecDeque<TextSearchResult>) -> Option<Address> {
            current_matches.clear();
            if self.next_group >= self.groups.len() {
                return None;
            }
            let (address, matches) = self.groups[self.next_group].take()?;
            current_matches.extend(matches);
            self.next_group += 1;
            Some(address)
        }
    }

    #[test]
    fn get_next_significant_address_with_none_initializes_and_returns_first() {
        let groups = vec![
            (addr(0x100), vec![result(0x100, 0)]),
            (addr(0x200), vec![result(0x200, 0)]),
        ];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        assert_eq!(searcher.get_next_significant_address(None), Some(addr(0x100)));
    }

    #[test]
    fn get_next_significant_address_advances_when_given_current_address() {
        let groups = vec![
            (addr(0x100), vec![result(0x100, 0)]),
            (addr(0x200), vec![result(0x200, 0)]),
        ];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        let first = searcher.get_next_significant_address(None).unwrap();
        let second = searcher.get_next_significant_address(Some(&first)).unwrap();
        assert_eq!(second, addr(0x200));
        assert_eq!(searcher.get_next_significant_address(Some(&second)), None);
    }

    #[test]
    fn get_next_significant_address_returns_none_once_exhausted() {
        let mut searcher = ListSearcher::new(Vec::new(), true, None, None);
        assert_eq!(searcher.get_next_significant_address(None), None);
    }

    #[test]
    fn get_next_significant_address_does_not_advance_for_a_stale_address() {
        let groups = vec![(addr(0x100), vec![result(0x100, 0)])];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        let first = searcher.get_next_significant_address(None).unwrap();
        // Passing an address that isn't the current one should not advance.
        assert_eq!(searcher.get_next_significant_address(Some(&addr(0x999))), Some(first));
    }

    #[test]
    fn get_match_pops_matches_in_order() {
        let groups = vec![(
            addr(0x100),
            vec![result(0x100, 0), result(0x100, 1)],
        )];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        searcher.get_next_significant_address(None);
        assert_eq!(searcher.get_match().offset(), 0);
        assert_eq!(searcher.get_match().offset(), 1);
    }

    #[test]
    #[should_panic(expected = "no matches for the current address")]
    fn get_match_panics_when_empty() {
        let groups = vec![(addr(0x100), Vec::new())];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        searcher.get_next_significant_address(None);
        searcher.get_match();
    }

    #[test]
    fn has_match_checks_address_and_non_empty() {
        let groups = vec![(addr(0x100), vec![result(0x100, 0)])];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        let first = searcher.get_next_significant_address(None).unwrap();
        assert!(searcher.has_match(&first));
        assert!(!searcher.has_match(&addr(0x999)));
    }

    #[test]
    fn has_match_is_false_once_matches_are_drained() {
        let groups = vec![(addr(0x100), vec![result(0x100, 0)])];
        let mut searcher = ListSearcher::new(groups, true, None, None);
        let first = searcher.get_next_significant_address(None).unwrap();
        searcher.get_match();
        assert!(!searcher.has_match(&first));
    }

    #[test]
    fn reverse_search_reverses_matches_for_current_address() {
        let groups = vec![(
            addr(0x100),
            vec![result(0x100, 0), result(0x100, 1), result(0x100, 2)],
        )];
        let mut searcher = ListSearcher::new(groups, false, None, None);
        searcher.get_next_significant_address(None);
        assert_eq!(searcher.get_match().offset(), 2);
        assert_eq!(searcher.get_match().offset(), 1);
        assert_eq!(searcher.get_match().offset(), 0);
    }

    /// A trivial `ProgramDatabaseFieldSearcher` wrapping a bare
    /// [`ProgramDatabaseFieldSearcherBase`] directly, for tests that only need to exercise
    /// [`ProgramDatabaseFieldSearcher::trim_matches_for_start_location`] against hand-built base
    /// state (not a real `advance` loop).
    struct Wrapper(ProgramDatabaseFieldSearcherBase);
    impl ProgramDatabaseFieldSearcher for Wrapper {
        fn base(&self) -> &ProgramDatabaseFieldSearcherBase {
            &self.0
        }
        fn base_mut(&mut self) -> &mut ProgramDatabaseFieldSearcherBase {
            &mut self.0
        }
        fn advance(&mut self, _m: &mut VecDeque<TextSearchResult>) -> Option<Address> {
            None
        }
    }

    #[test]
    fn trim_matches_for_start_location_drops_matches_at_or_after_start_forward() {
        // All three matches share the same address (0x100) as the group/current address, but
        // their *finer-grained* program locations (modeled here via distinct addresses, since
        // this port's `ProgramLocation` has no row/column surface to compare on -- see the
        // `ProgramLocationComparator` type alias docs) place them at, or after, `start`. A
        // forward search keeps only matches strictly *before* `start`.
        let start = loc(0x100);
        let matches = vec![result(0x100, 0), result(0x101, 1), result(0x102, 2)];

        let mut base = ProgramDatabaseFieldSearcherBase::new(
            Regex::new("x").unwrap(),
            true,
            Some(start),
            None,
            address_comparator(),
        );
        base.current_address = Some(addr(0x100));
        base.matches_for_current_address = matches.into();

        let mut wrapper = Wrapper(base);
        wrapper.trim_matches_for_start_location();

        // start (0x100) compared to each match's address: Equal, Less, Less. Forward search
        // removes entries where `start` compares `!= Less` to the match (i.e. `>= 0`), so only
        // the first (Equal) entry is dropped.
        assert_eq!(wrapper.0.matches_for_current_address.len(), 2);
        assert_eq!(wrapper.0.matches_for_current_address[0].offset(), 1);
        assert_eq!(wrapper.0.matches_for_current_address[1].offset(), 2);
    }

    #[test]
    fn trim_matches_for_start_location_is_a_no_op_when_current_address_differs() {
        let start = loc(0x100);
        let matches = vec![result(0x100, 0)];

        let mut base = ProgramDatabaseFieldSearcherBase::new(
            Regex::new("x").unwrap(),
            true,
            Some(start),
            None,
            address_comparator(),
        );
        // current_address (0x200) doesn't match start's address (0x100), so nothing is trimmed.
        base.current_address = Some(addr(0x200));
        base.matches_for_current_address = matches.into();

        let mut wrapper = Wrapper(base);
        wrapper.trim_matches_for_start_location();
        assert_eq!(wrapper.0.matches_for_current_address.len(), 1);
    }

    #[test]
    fn trim_matches_for_start_location_is_a_no_op_without_a_start_location() {
        let matches = vec![result(0x100, 0)];
        let mut base = ProgramDatabaseFieldSearcherBase::new(
            Regex::new("x").unwrap(),
            true,
            None,
            None,
            address_comparator(),
        );
        base.current_address = Some(addr(0x100));
        base.matches_for_current_address = matches.into();

        let mut wrapper = Wrapper(base);
        wrapper.trim_matches_for_start_location();
        assert_eq!(wrapper.0.matches_for_current_address.len(), 1);
    }

    #[test]
    fn new_panics_on_inconsistent_start_location_and_address_set_forward() {
        let start = loc(0x200);
        let set = AddressSet::from_range(
            crate::program::model::address::AddressRange::new(addr(0x100), addr(0x300)),
        );
        let comparator: ProgramLocationComparator = Box::new(|_a, _b| Ordering::Equal);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ProgramDatabaseFieldSearcherBase::new(
                Regex::new("x").unwrap(),
                true,
                Some(start),
                Some(&set),
                comparator,
            )
        }));
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_consistent_start_location_and_address_set_forward() {
        let start = loc(0x100);
        let set = AddressSet::from_range(
            crate::program::model::address::AddressRange::new(addr(0x100), addr(0x300)),
        );
        let comparator: ProgramLocationComparator = Box::new(|_a, _b| Ordering::Equal);
        let _base = ProgramDatabaseFieldSearcherBase::new(
            Regex::new("x").unwrap(),
            true,
            Some(start),
            Some(&set),
            comparator,
        );
    }
}
