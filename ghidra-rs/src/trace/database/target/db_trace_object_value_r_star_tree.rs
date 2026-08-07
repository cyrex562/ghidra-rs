//! The R*-tree indexing [`DBTraceObjectValueData`](crate::trace::seam_stubs::DBTraceObjectValueData)
//! entries (trace object values) by parent key, entry key, lifespan, and address, and exposing
//! them as a spatial map.
//!
//! Java source: `ghidra.trace.database.target.DBTraceObjectValueRStarTree`, a concrete subclass
//! of the not-yet-ported `AbstractHyperRStarTree`. Ported as a pair of object-safe traits, a
//! cycle cut-point, so that dependents can hold `Box<dyn DBTraceObjectValueRStarTree>` /
//! `Box<dyn DBTraceObjectValueMap>` instead of a concrete type. Only the methods
//! `DBTraceObjectValueRStarTree` (and its nested public `DBTraceObjectValueMap`) itself declares
//! or overrides are represented; the constructor and the `protected` hook methods it overrides
//! from `AbstractHyperRStarTree` (`doUnparentEntry`, `createDataEntry`, `getNodeChildrenOf`, etc.)
//! belong to that base once it is ported.
use crate::program::model::address::AddressSetView;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::{DBTraceObjectValueData, TraceObjectValueQuery};

/// The R*-tree of trace object value entries.
///
/// Port of `ghidra.trace.database.target.DBTraceObjectValueRStarTree`.
pub trait DBTraceObjectValueRStarTree: Send + Sync {
    /// Returns this tree as a spatial map, unconstrained by any query.
    ///
    /// Mirrors `DBTraceObjectValueRStarTree.asSpatialMap()`.
    fn as_spatial_map(&self) -> Box<dyn DBTraceObjectValueMap>;
}

/// A spatial map view over a [`DBTraceObjectValueRStarTree`], optionally constrained by a
/// [`TraceObjectValueQuery`].
///
/// Port of the nested `ghidra.trace.database.target.DBTraceObjectValueRStarTree.DBTraceObjectValueMap`.
pub trait DBTraceObjectValueMap: Send + Sync {
    /// Returns a further-constrained view of this map, combining this map's existing query (if
    /// any) with `and_query`.
    ///
    /// Mirrors `DBTraceObjectValueMap.reduce(TraceObjectValueQuery)`.
    fn reduce(&self, and_query: Box<dyn TraceObjectValueQuery>) -> Box<dyn DBTraceObjectValueMap>;

    /// Returns an address set view over the entries in this map that overlap `at` and satisfy
    /// `predicate`.
    ///
    /// Mirrors `DBTraceObjectValueMap.getAddressSetView(Lifespan, Predicate)`.
    fn get_address_set_view(
        &self,
        at: Box<dyn Lifespan>,
        predicate: Box<dyn Fn(&dyn DBTraceObjectValueData) -> bool + Send + Sync>,
    ) -> Box<dyn AddressSetView>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockValueData(i64);
    impl DBTraceObjectValueData for MockValueData {}

    /// The mock query never inspects the tree's data; it only stands in for the opaque
    /// `Box<dyn TraceObjectValueQuery>` parameter `reduce` forwards.
    struct MockQuery;
    impl TraceObjectValueQuery for MockQuery {}

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }
        fn lmax(&self) -> i64 {
            self.max
        }
        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }
        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }
        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    /// A tiny in-memory stand-in for `DBTraceObjectValueMap`, holding a fixed set of
    /// `(key, snap)` entries and applying `reduce`/`get_address_set_view` against them, enough to
    /// prove the traits are object-safe and behave sensibly rather than trivially.
    struct MockMap {
        entries: Vec<(i64, i64)>,
    }

    impl DBTraceObjectValueMap for MockMap {
        fn reduce(
            &self,
            _and_query: Box<dyn TraceObjectValueQuery>,
        ) -> Box<dyn DBTraceObjectValueMap> {
            // Simulates narrowing by an "AND"ed query: drop every entry keyed 2, mirroring how
            // a real reduce() returns a strictly-narrower, independent map.
            Box::new(MockMap {
                entries: self.entries.iter().filter(|(k, _)| *k != 2).cloned().collect(),
            })
        }

        fn get_address_set_view(
            &self,
            at: Box<dyn Lifespan>,
            predicate: Box<dyn Fn(&dyn DBTraceObjectValueData) -> bool + Send + Sync>,
        ) -> Box<dyn AddressSetView> {
            let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
            let mut set = crate::program::model::address::AddressSet::new();
            for (key, snap) in &self.entries {
                if at.contains(*snap) && predicate(&MockValueData(*key)) {
                    let addr = Address::new(space.clone(), *key);
                    set.add_range(&addr, &addr);
                }
            }
            Box::new(set)
        }
    }

    fn make_map() -> MockMap {
        MockMap { entries: vec![(1, 0), (2, 5), (3, 10)] }
    }

    #[test]
    fn reduce_returns_a_strictly_narrower_map() {
        let map = make_map();
        let full = map.get_address_set_view(
            Box::new(MockLifespan { min: 0, max: 10 }),
            Box::new(|_| true),
        );
        assert_eq!(full.num_addresses(), 3);

        let reduced = map.reduce(Box::new(MockQuery));
        let narrowed = reduced.get_address_set_view(
            Box::new(MockLifespan { min: 0, max: 10 }),
            Box::new(|_| true),
        );
        assert_eq!(narrowed.num_addresses(), 2);
    }

    #[test]
    fn get_address_set_view_filters_by_lifespan() {
        let map = make_map();
        let at = Box::new(MockLifespan { min: 0, max: 5 });
        let view = map.get_address_set_view(at, Box::new(|_| true));
        // Entries at snaps 0 and 5 fall within [0, 5]; the one at snap 10 does not.
        assert_eq!(view.num_addresses(), 2);
    }

    #[test]
    fn get_address_set_view_applies_predicate() {
        let map = make_map();
        let at = Box::new(MockLifespan { min: 0, max: 10 });
        let view = map.get_address_set_view(at, Box::new(|_| false));
        assert!(view.is_empty());
    }

    #[test]
    fn trait_object_is_usable() {
        struct Tree(Vec<(i64, i64)>);
        impl DBTraceObjectValueRStarTree for Tree {
            fn as_spatial_map(&self) -> Box<dyn DBTraceObjectValueMap> {
                Box::new(MockMap { entries: self.0.clone() })
            }
        }
        let tree: Box<dyn DBTraceObjectValueRStarTree> = Box::new(Tree(vec![(1, 0), (2, 1)]));
        let map = tree.as_spatial_map();
        let view = map.get_address_set_view(
            Box::new(MockLifespan { min: 0, max: 1 }),
            Box::new(|_| true),
        );
        assert_eq!(view.num_addresses(), 2);
    }
}
