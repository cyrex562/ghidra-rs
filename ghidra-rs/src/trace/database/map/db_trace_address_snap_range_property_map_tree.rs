//! Port of `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree`.
//!
//! This class was selected as a dependency-cycle cut-point, so only its own added public/
//! `@Internal` surface -- beyond the `Abstract2DRStarTree` contract it extends -- is ported here:
//!
//! - [`get_map_space`](DBTraceAddressSnapRangePropertyMapTree::get_map_space) -- `getMapSpace()`,
//!   the per-space delegate this tree backs.
//! - [`paint`](DBTraceAddressSnapRangePropertyMapTree::paint),
//!   [`get_depth`](DBTraceAddressSnapRangePropertyMapTree::get_depth),
//!   [`get_root_bounds`](DBTraceAddressSnapRangePropertyMapTree::get_root_bounds), and
//!   [`internal_get_children_of`](DBTraceAddressSnapRangePropertyMapTree::internal_get_children_of)
//!   -- all `@Internal`, "for developers and testers" -- mirror `paint(Painter, int)`,
//!   `getDepth()`, `getRootBounds()`, and `internalGetChildrenOf(DBTreeNodeRecord<?>)`
//!   respectively.
//!
//! The Java class's `doChooseSplitAxis`/`doChooseSplitIndex`/`getChildrenOf` overrides ("expose
//! for testing") merely widen a superclass method's visibility without changing its contract, so
//! they add nothing beyond what an `Abstract2DRStarTree` port would already declare, and are not
//! redeclared here. Likewise the constructor -- and the `DBCachedObjectStoreFactory`/table-name/
//! `DBTraceAddressSnapRangePropertyMapSpace`/`Class<DR>`/data-factory/upgradable dependencies it
//! takes -- is implementation, not public contract.
//!
//! The nested `Painter` functional interface is ported alongside as its own trait, since it is
//! introduced by this class rather than referenced from elsewhere. The other two nested types --
//! `TraceAddressSnapRangeQuery` and `AbstractDBTraceAddressSnapRangePropertyMapData` -- are
//! already represented as placeholder stubs in [`crate::trace::seam_stubs`], referenced by
//! sibling ports that needed them first.
//!
//! `DR` stands in for the Java class's `DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>`
//! type parameter.
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::{
    AbstractDBTraceAddressSnapRangePropertyMapData, DBTraceAddressSnapRangePropertyMapSpace,
    DBTreeNodeRecord, DBTreeRecord,
};

/// Callback for walking the tree's nodes and data entries at a given depth. Port of the nested
/// `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.Painter` interface.
pub trait Painter {
    /// Mirrors `Painter.paint(TraceAddressSnapRange, int)`.
    fn paint(&self, shape: &dyn TraceAddressSnapRange, depth: i32);
}

/// An R*-tree, keyed by [`TraceAddressSnapRange`], backing a
/// [`DBTraceAddressSnapRangePropertyMap`](crate::trace::database::map::db_trace_address_snap_range_property_map::DBTraceAddressSnapRangePropertyMap)'s
/// per-space storage.
///
/// Port of `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree<T, DR>`.
pub trait DBTraceAddressSnapRangePropertyMapTree<T, DR>: Send + Sync
where
    DR: AbstractDBTraceAddressSnapRangePropertyMapData,
{
    /// Returns the per-space delegate this tree backs. Mirrors `getMapSpace()`.
    fn get_map_space(&self) -> Box<dyn DBTraceAddressSnapRangePropertyMapSpace<T>>;

    /// Walks the tree, invoking `painter` on every node/data entry at the given `depth`. Mirrors
    /// the `@Internal` `paint(Painter, int)`, "for developers and testers."
    fn paint(&self, painter: &dyn Painter, depth: i32);

    /// Returns the tree's depth (leaf level plus two). Mirrors the `@Internal` `getDepth()`.
    fn get_depth(&self) -> i32;

    /// Returns the bounds of the tree's root node. Mirrors the `@Internal` `getRootBounds()`.
    fn get_root_bounds(&self) -> Box<dyn TraceAddressSnapRange>;

    /// Returns the direct children (node or data records) of `rec`, or empty if `rec` is not one
    /// of this tree's own node records. Mirrors the `@Internal`
    /// `internalGetChildrenOf(DBTreeNodeRecord<?>)`.
    fn internal_get_children_of(&self, rec: &dyn DBTreeNodeRecord) -> Vec<Box<dyn DBTreeRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use std::sync::Arc;

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

    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        y1: i64,
        y2: i64,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.y1,
                max: self.y2,
            })
        }

        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }

        fn immutable(
            &self,
            x1: Address,
            x2: Address,
            y1: i64,
            y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockRange {
                range: AddressRange::new(x1, x2),
                y1,
                y2,
            })
        }
    }

    struct MockSpace {
        space: Arc<AddressSpace>,
    }

    impl DBTraceAddressSnapRangePropertyMapSpace<i32> for MockSpace {
        fn address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    struct MockNodeRecord;
    impl DBTreeNodeRecord for MockNodeRecord {}

    struct MockData {
        space: Arc<AddressSpace>,
    }

    impl AbstractDBTraceAddressSnapRangePropertyMapData for MockData {
        fn address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    /// A single-node, in-memory tree: enough to prove object-safety and exercise real depth /
    /// bounds / child-lookup / paint behavior without a real R*-tree backing store.
    struct MockTree {
        map_space: Arc<AddressSpace>,
        root: MockRange,
        depth: i32,
        children: Vec<MockRange>,
    }

    impl DBTraceAddressSnapRangePropertyMapTree<i32, MockData> for MockTree {
        fn get_map_space(&self) -> Box<dyn DBTraceAddressSnapRangePropertyMapSpace<i32>> {
            Box::new(MockSpace {
                space: self.map_space.clone(),
            })
        }

        fn paint(&self, painter: &dyn Painter, depth: i32) {
            if depth == 0 {
                painter.paint(&self.root, 0);
            } else {
                for child in &self.children {
                    painter.paint(child, depth);
                }
            }
        }

        fn get_depth(&self) -> i32 {
            self.depth
        }

        fn get_root_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.root.clone())
        }

        fn internal_get_children_of(
            &self,
            rec: &dyn DBTreeNodeRecord,
        ) -> Vec<Box<dyn DBTreeRecord>> {
            let _ = rec;
            Vec::new()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn tree() -> MockTree {
        let space = ram_space();
        let root = MockRange {
            range: AddressRange::new(
                Address::new(space.clone(), 0),
                Address::new(space.clone(), 0x2000),
            ),
            y1: 0,
            y2: 10,
        };
        let children = vec![
            MockRange {
                range: AddressRange::new(
                    Address::new(space.clone(), 0),
                    Address::new(space.clone(), 0x1000),
                ),
                y1: 0,
                y2: 5,
            },
            MockRange {
                range: AddressRange::new(
                    Address::new(space.clone(), 0x1001),
                    Address::new(space.clone(), 0x2000),
                ),
                y1: 6,
                y2: 10,
            },
        ];
        MockTree {
            map_space: space,
            root,
            depth: 2,
            children,
        }
    }

    #[test]
    fn get_map_space_reports_own_address_space() {
        let t = tree();
        assert_eq!(t.get_map_space().address_space().name(), "ram");
    }

    #[test]
    fn paint_visits_root_at_depth_zero_and_children_below() {
        let t = tree();

        struct RecordingPainter {
            visits: std::cell::RefCell<Vec<(i64, i64, i32)>>,
        }
        impl Painter for RecordingPainter {
            fn paint(&self, shape: &dyn TraceAddressSnapRange, depth: i32) {
                self.visits
                    .borrow_mut()
                    .push((shape.get_y1(), shape.get_y2(), depth));
            }
        }

        let painter = RecordingPainter {
            visits: std::cell::RefCell::new(Vec::new()),
        };
        t.paint(&painter, 0);
        assert_eq!(painter.visits.borrow().as_slice(), &[(0, 10, 0)]);

        painter.visits.borrow_mut().clear();
        t.paint(&painter, 1);
        assert_eq!(
            painter.visits.borrow().as_slice(),
            &[(0, 5, 1), (6, 10, 1)]
        );
    }

    #[test]
    fn get_depth_and_root_bounds_reflect_the_tree() {
        let t = tree();
        assert_eq!(t.get_depth(), 2);
        assert_eq!(t.get_root_bounds().get_y1(), 0);
        assert_eq!(t.get_root_bounds().get_y2(), 10);
    }

    #[test]
    fn internal_get_children_of_is_reachable_through_the_dyn_trait() {
        let t = tree();
        let obj: &dyn DBTraceAddressSnapRangePropertyMapTree<i32, MockData> = &t;
        assert!(obj.internal_get_children_of(&MockNodeRecord).is_empty());
        assert_eq!(obj.get_map_space().address_space().name(), "ram");
    }
}
