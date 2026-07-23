//! Port of `ghidra.program.database.properties.UnsupportedMapDB`.
//!
//! `UnsupportedMapDB` is a "dummy" [`PropertyMapDB`] used when a stored property map's value
//! type can no longer be resolved to a known Java class (e.g. after a plugin providing a custom
//! property value type has been removed) but its underlying database table must still be kept
//! around and accounted for. Every accessor reports "nothing here" (`getValueClass`/`get` return
//! `null`, `hasProperty` returns `false`) and the sole mutator, `add`, unconditionally throws
//! `UnsupportedOperationException` since writing a typed value into an unresolvable map makes no
//! sense.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait
//! rather than a concrete struct. Its Java public API — `getValueClass`/`get`/`hasProperty`/`add`
//! — is exactly the subset of [`PropertyMap`](crate::program::model::util::PropertyMap) (reached
//! through the [`PropertyMapDB`] supertrait) that `UnsupportedMapDB` overrides, so this trait adds
//! no new members of its own: it is a marker that documents the fixed "dummy" contract an
//! implementation must uphold (see the method docs below) so that code holding a `Box<dyn
//! UnsupportedMapDB>`/`Arc<dyn UnsupportedMapDB>` knows it is dealing with an unsupported/opaque
//! map rather than a real, value-bearing one.
//!
//! Not ported here: the package-private constructor (`DBHandle`, `OpenMode`, `ErrorHandler`,
//! `ChangeManager`, `AddressMap`, `name`, `TaskMonitor` params) and its `checkMapVersion` call are
//! construction-time details for a concrete implementation, not part of the dynamic-dispatch
//! surface this trait exists to cut the cycle for — the same convention [`PropertyMapDB`] itself
//! already follows for `checkMapVersion`/`createTable`. All of those constructor parameter types
//! (`DBHandle`, `ErrorHandler`, `ChangeManager`, `AddressMap`, `OpenMode`,
//! `DatabaseVersionException`, `CancelledException`, `TaskMonitor`) are already ported elsewhere
//! in this crate, so no new `seam_stubs` placeholders were needed for this port.

use crate::program::database::properties::PropertyMapDB;

/// A dummy database-backed property map used to represent a property whose value type can no
/// longer be resolved.
///
/// Port of `ghidra.program.database.properties.UnsupportedMapDB`. See the module docs for why
/// this is a marker trait and what was intentionally left out. Implementations must uphold the
/// "dummy" contract documented on each method below.
pub trait UnsupportedMapDB: PropertyMapDB {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBRecord;
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::model::address::{
        Address, AddressIterator, AddressIteratorAdapter, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::util::PropertyMap;
    use crate::program::seam_stubs::AddressKeyIteratorLike;
    use std::any::{Any, TypeId};
    use std::io;

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    /// Mock "dummy" property map, proving [`UnsupportedMapDB`] (with its [`PropertyMapDB`],
    /// [`crate::program::database::db_object::DbObject`], and
    /// [`PropertyMap`](crate::program::model::util::PropertyMap) supertraits) is object-safe and
    /// reproduces `UnsupportedMapDB`'s fixed dummy behavior when driven through a `Box<dyn
    /// UnsupportedMapDB>`.
    struct MockUnsupportedMapDB {
        state: DbObjectState,
        name: String,
    }

    impl MockUnsupportedMapDB {
        fn new(name: &str) -> Self {
            MockUnsupportedMapDB {
                state: DbObjectState::new(0),
                name: name.to_string(),
            }
        }
    }

    impl DbObject for MockUnsupportedMapDB {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            true
        }
    }

    impl PropertyMap for MockUnsupportedMapDB {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        // Stands in for `UnsupportedMapDB.getValueClass()`, which always returns `null`.
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }

        fn clear(&mut self) {}

        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }

        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn remove_range(&mut self, _start: &Address, _end: &Address) -> bool {
            false
        }

        fn remove(&mut self, _addr: &Address) -> bool {
            false
        }

        // Stands in for `UnsupportedMapDB.hasProperty(Address)`, which always returns `false`.
        fn has_property(&self, _addr: &Address) -> bool {
            false
        }

        // Stands in for `UnsupportedMapDB.add(Address, Object)`, which always throws
        // `UnsupportedOperationException`.
        fn add(&mut self, _addr: &Address, _value: Option<Box<dyn Any>>) {
            panic!("UnsupportedOperationException: cannot add to an unsupported property map");
        }

        // Stands in for `UnsupportedMapDB.get(Address)`, which always returns `null`.
        fn get(&self, _addr: &Address) -> Option<Box<dyn Any>> {
            None
        }

        fn get_next_property_address(&self, _addr: &Address) -> Option<Address> {
            None
        }

        fn get_previous_property_address(&self, _addr: &Address) -> Option<Address> {
            None
        }

        fn get_first_property_address(&self) -> Option<Address> {
            None
        }

        fn get_last_property_address(&self) -> Option<Address> {
            None
        }

        fn get_size(&self) -> usize {
            0
        }

        fn get_property_iterator_range(
            &self,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(Vec::new()))
        }

        fn get_property_iterator_range_ordered(
            &self,
            _start: &Address,
            _end: &Address,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(Vec::new()))
        }

        fn get_property_iterator(&self) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(Vec::new()))
        }

        fn get_property_iterator_set(&self, _asv: &dyn AddressSetView) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(Vec::new()))
        }

        fn get_property_iterator_set_ordered(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(Vec::new()))
        }

        fn get_property_iterator_from(&self, _start: &Address, _forward: bool) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(Vec::new()))
        }

        fn move_range(&mut self, _start: &Address, _end: &Address, _new_start: &Address) {}
    }

    impl PropertyMapDB for MockUnsupportedMapDB {
        fn set_cache_size(&mut self, _size: usize) {}

        fn delete(&mut self) -> io::Result<()> {
            self.set_deleted();
            Ok(())
        }

        fn get_address_key_iterator_for_set(
            &self,
            _set: Option<&dyn AddressSetView>,
            _at_start: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            Ok(Box::new(EmptyAddressKeyIterator))
        }

        fn get_address_key_iterator_from(
            &self,
            _start: &Address,
            _before: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            Ok(Box::new(EmptyAddressKeyIterator))
        }

        fn get_address_key_iterator_range(
            &self,
            _start: &Address,
            _end: &Address,
            _at_start: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            Ok(Box::new(EmptyAddressKeyIterator))
        }

        fn invalidate(&mut self) {
            self.state.set_invalid();
        }
    }

    impl UnsupportedMapDB for MockUnsupportedMapDB {}

    struct EmptyAddressKeyIterator;

    impl AddressKeyIteratorLike for EmptyAddressKeyIterator {
        fn has_next(&mut self) -> bool {
            false
        }

        fn has_previous(&mut self) -> bool {
            false
        }

        fn next(&mut self) -> Option<i64> {
            None
        }

        fn previous(&mut self) -> Option<i64> {
            None
        }
    }

    #[test]
    fn usable_as_trait_object_and_reports_dummy_values() {
        let map: Box<dyn UnsupportedMapDB> = Box::new(MockUnsupportedMapDB::new("mystery"));

        assert_eq!(map.get_name(), "mystery");
        assert_eq!(map.get_value_class(), None);
        assert!(map.get(&addr(0x1000)).is_none());
        assert!(!map.has_property(&addr(0x1000)));
        assert_eq!(map.get_size(), 0);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn add_is_unsupported() {
        let mut map: Box<dyn UnsupportedMapDB> = Box::new(MockUnsupportedMapDB::new("mystery"));
        map.add(&addr(0x1000), Some(Box::new(42i32)));
    }
}
