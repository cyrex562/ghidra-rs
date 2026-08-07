//! A trace object value's persisted record: storage for a [`TraceObjectValueStorage`] entry that
//! is also a spatial [`ValueShape`](crate::trace::database::target::value_shape::ValueShape)
//! entry in the [`DBTraceObjectValueRStarTree`](crate::trace::database::target::db_trace_object_value_r_star_tree::DBTraceObjectValueRStarTree).
//!
//! Java source: `ghidra.trace.database.target.DBTraceObjectValueData`, a concrete
//! `DBTreeDataRecord<ValueShape, ValueBox, DBTraceObjectValueData>` implementing both
//! `TraceObjectValueStorage` and `ValueShape`.
//!
//! Ported as a trait because it was selected as a cycle cut-point: it is the R*-tree's own data
//! entry type, so [`DBTraceObjectValueRStarTree`](crate::trace::database::target::db_trace_object_value_r_star_tree::DBTraceObjectValueRStarTree)
//! (and its `DBTraceObjectValueMap`) reference it, while it in turn references the tree's parent
//! object/manager/value types. It supertraits
//! [`TraceObjectValueStorage`](crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage),
//! whose full method set it overrides in Java, and adds the members of
//! [`ValueShape`](crate::trace::database::target::value_shape::ValueShape) not already covered
//! there (`getChild`, the address-space/offset accessors and their `AddressFactory`-resolving
//! defaults) plus its own additions (`description`, the R*-tree's own structural parent key,
//! distinct from `TraceObjectValueStorage::get_parent`'s object-tree parent, and `setShape`).
//!
//! `ValueShape` itself is not used as a supertrait here: it is generic over its bounding-box type
//! `B: ValueBox` (since [`ValueBox`](crate::trace::database::target::value_box::ValueBox)'s
//! `HyperBox` methods return `Self` and so cannot be erased to `dyn ValueBox`), which would force
//! this trait to be generic too -- but it must stay object-safe, since
//! `DBTraceObjectValueRStarTree`'s `DBTraceObjectValueMap::get_address_set_view` already holds it
//! as `&dyn DBTraceObjectValueData`. For the same reason, `ValueShape`/`ValueBox`'s
//! `getBounds()`/`getShape()` (which return the non-object-safe box/shape types) are not
//! represented; `description()` is kept since it is expressible as a plain `String`.
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressFactory};
use crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::DBTraceObject;

/// A trace object value's persisted, spatially-indexed record.
///
/// Port of `ghidra.trace.database.target.DBTraceObjectValueData`.
pub trait DBTraceObjectValueData: TraceObjectValueStorage {
    /// Get the child object of this value, cast from [`TraceObjectValueStorage::get_value`].
    ///
    /// Mirrors `DBTraceObjectValueData.getChild()`.
    fn get_child(&self) -> Box<dyn DBTraceObject>;

    /// If the value is an address or range, the id of the address space.
    ///
    /// Mirrors `DBTraceObjectValueData.getAddressSpaceId()`.
    ///
    /// Returns the space id, or -1 for a non-address value.
    fn get_address_space_id(&self) -> i32;

    /// Mirrors `DBTraceObjectValueData.getMinAddressOffset()`.
    fn get_min_address_offset(&self) -> i64;

    /// Mirrors `DBTraceObjectValueData.getMaxAddressOffset()`.
    fn get_max_address_offset(&self) -> i64;

    /// Resolves this value's minimum address in the given factory's address space, or `None` if
    /// this value is not an address or range.
    ///
    /// Mirrors `ValueShape.getMinAddress(AddressFactory)`, as inherited/implemented by
    /// `DBTraceObjectValueData`.
    fn get_min_address(&self, factory: &dyn AddressFactory) -> Option<Address> {
        let space_id = self.get_address_space_id();
        if space_id == -1 {
            return None;
        }
        let space = factory.get_address_space_by_id(space_id)?;
        Some(space.address(self.get_min_address_offset()))
    }

    /// Resolves this value's maximum address in the given factory's address space, or `None` if
    /// this value is not an address or range.
    ///
    /// Mirrors `ValueShape.getMaxAddress(AddressFactory)`, as inherited/implemented by
    /// `DBTraceObjectValueData`.
    fn get_max_address(&self, factory: &dyn AddressFactory) -> Option<Address> {
        let space_id = self.get_address_space_id();
        if space_id == -1 {
            return None;
        }
        let space = factory.get_address_space_by_id(space_id)?;
        Some(space.address(self.get_max_address_offset()))
    }

    /// Resolves this value's address range in the given factory's address space, or `None` if
    /// this value is not an address or range.
    ///
    /// Mirrors `ValueShape.getRange(AddressFactory)`, as inherited/implemented by
    /// `DBTraceObjectValueData`.
    fn get_range(&self, factory: &dyn AddressFactory) -> Option<AddressRange> {
        let min = self.get_min_address(factory)?;
        let max = self.get_max_address(factory)?;
        Some(AddressRange::new(min, max))
    }

    /// Returns a human-readable description of this entry's shape.
    ///
    /// Mirrors `DBTraceObjectValueData.description()`.
    fn description(&self) -> String;

    /// Get this entry's structural parent key within the R*-tree, distinct from
    /// [`TraceObjectValueStorage::get_parent`]'s object-tree parent.
    ///
    /// Mirrors `DBTraceObjectValueData.getParentKey()`.
    fn get_parent_key(&self) -> i64;

    /// Set this entry's structural parent key within the R*-tree.
    ///
    /// Mirrors `DBTraceObjectValueData.setParentKey(long)`.
    fn set_parent_key(&mut self, parent_key: i64);

    /// Replaces this entry's shape: its object-tree parent, child (if any), entry key, and
    /// lifespan.
    ///
    /// Mirrors `DBTraceObjectValueData.setShape(ValueShape)`, which pulls these fields out of the
    /// passed-in `ValueShape`; taking them directly here avoids requiring a `ValueShape` argument
    /// (not object-safe, see the module docs).
    fn set_shape(
        &mut self,
        parent: Box<dyn DBTraceObject>,
        child: Option<Box<dyn DBTraceObject>>,
        entry_key: String,
        lifespan: &dyn Lifespan,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::trace::seam_stubs::{DBTraceObjectManager, DBTraceObjectValue};

    struct MockManager;
    impl DBTraceObjectManager for MockManager {}

    struct MockValue;
    impl DBTraceObjectValue for MockValue {}

    struct MockObject(&'static str);
    impl DBTraceObject for MockObject {}

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

    struct MockData {
        entry_key: String,
        lifespan: MockLifespan,
        has_child: bool,
        deleted: bool,
        address_space_id: i32,
        min_offset: i64,
        max_offset: i64,
        parent_key: i64,
    }

    impl TraceObjectValueStorage for MockData {
        fn get_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockManager)
        }

        fn get_wrapper(&self) -> Box<dyn DBTraceObjectValue> {
            Box::new(MockValue)
        }

        fn get_parent(&self) -> Box<dyn DBTraceObject> {
            Box::new(MockObject("parent"))
        }

        fn get_entry_key(&self) -> String {
            self.entry_key.clone()
        }

        fn do_set_lifespan(&mut self, lifespan: &dyn Lifespan) {
            self.lifespan = MockLifespan { min: lifespan.lmin(), max: lifespan.lmax() };
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(self.lifespan)
        }

        fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>> {
            if self.has_child { Some(Box::new(MockObject("child"))) } else { None }
        }

        fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync> {
            Box::new(self.has_child)
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }

        fn do_delete(&mut self) {
            self.deleted = true;
        }
    }

    impl DBTraceObjectValueData for MockData {
        fn get_child(&self) -> Box<dyn DBTraceObject> {
            Box::new(MockObject("child"))
        }

        fn get_address_space_id(&self) -> i32 {
            self.address_space_id
        }

        fn get_min_address_offset(&self) -> i64 {
            self.min_offset
        }

        fn get_max_address_offset(&self) -> i64 {
            self.max_offset
        }

        fn description(&self) -> String {
            format!("ValueShape[entryKey={}]", self.entry_key)
        }

        fn get_parent_key(&self) -> i64 {
            self.parent_key
        }

        fn set_parent_key(&mut self, parent_key: i64) {
            self.parent_key = parent_key;
        }

        fn set_shape(
            &mut self,
            _parent: Box<dyn DBTraceObject>,
            child: Option<Box<dyn DBTraceObject>>,
            entry_key: String,
            lifespan: &dyn Lifespan,
        ) {
            self.entry_key = entry_key;
            self.has_child = child.is_some();
            self.lifespan = MockLifespan { min: lifespan.lmin(), max: lifespan.lmax() };
        }
    }

    fn make_data() -> MockData {
        MockData {
            entry_key: "key1".to_string(),
            lifespan: MockLifespan { min: 0, max: 10 },
            has_child: false,
            deleted: false,
            address_space_id: -1,
            min_offset: 0,
            max_offset: 0,
            parent_key: -1,
        }
    }

    fn ram_factory() -> DefaultAddressFactory {
        let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        DefaultAddressFactory::new(vec![ram])
    }

    #[test]
    fn non_address_value_resolves_min_max_range_to_none() {
        let data = make_data();
        let factory = ram_factory();
        assert!(data.get_min_address(&factory).is_none());
        assert!(data.get_max_address(&factory).is_none());
        assert!(data.get_range(&factory).is_none());
    }

    #[test]
    fn address_value_resolves_min_max_range_through_factory() {
        let factory = ram_factory();
        let space_id = factory.get_address_spaces()[0].space_id();
        let mut data = make_data();
        data.address_space_id = space_id;
        data.min_offset = 0x1000;
        data.max_offset = 0x2000;

        let min = data.get_min_address(&factory).expect("min address");
        let max = data.get_max_address(&factory).expect("max address");
        assert_eq!(min.offset(), 0x1000);
        assert_eq!(max.offset(), 0x2000);

        let range = data.get_range(&factory).expect("range");
        assert_eq!(range.min_address(), &min);
        assert_eq!(range.max_address(), &max);
    }

    #[test]
    fn set_shape_replaces_entry_key_child_and_lifespan() {
        let mut data = make_data();
        assert!(data.get_child_or_null().is_none());

        data.set_shape(
            Box::new(MockObject("new_parent")),
            Some(Box::new(MockObject("new_child"))),
            "key2".to_string(),
            &MockLifespan { min: 5, max: 20 },
        );

        assert_eq!(data.get_entry_key(), "key2");
        assert!(data.get_child_or_null().is_some());
        assert_eq!(data.get_lifespan().lmin(), 5);
        assert_eq!(data.get_lifespan().lmax(), 20);
    }

    #[test]
    fn parent_key_is_distinct_from_object_tree_parent() {
        let mut data = make_data();
        assert_eq!(data.get_parent_key(), -1);
        data.set_parent_key(42);
        assert_eq!(data.get_parent_key(), 42);
        // The object-tree parent (get_parent) is unaffected by the R*-tree parent key.
        let _parent = data.get_parent();
    }

    #[test]
    fn trait_object_is_usable() {
        let data: Box<dyn DBTraceObjectValueData> = Box::new(make_data());
        assert_eq!(data.description(), "ValueShape[entryKey=key1]");
        assert_eq!(data.get_address_space_id(), -1);
        let _child = data.get_child();
    }
}
