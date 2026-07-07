//! Port of `ghidra.program.database.map.AddressMap`.
//!
//! NOTE: types implementing this trait are not intended for use outside of the
//! `crate::program::database` modules.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressFactory, AddressSetView, KeyRange};

/// Reserved key for an invalid key.
pub const INVALID_ADDRESS_KEY: i64 = -1;

/// Address map interface adding methods needed by the program database implementation to manage
/// its address map.
pub trait AddressMap {
    /// Get the database key associated with the given relative address. This key uniquely
    /// identifies a relative location within the program. If the program's image base is moved
    /// to another address, this key will map to a new address that is the same distance to the
    /// new base as the old address was to the old base. If the requested key does not exist and
    /// `create` is `false`, [`INVALID_ADDRESS_KEY`] is returned. Nothing should ever be stored
    /// using the returned key unless `create` is `true`.
    fn get_key(&self, addr: &Address, create: bool) -> i64;

    /// Get the database key associated with the given absolute address. This key uniquely
    /// identifies an absolute location within the program. If the requested key does not exist
    /// and `create` is `false`, [`INVALID_ADDRESS_KEY`] is returned. Nothing should ever be
    /// stored using the returned key unless `create` is `true`.
    fn get_absolute_encoding(&self, addr: &Address, create: bool) -> i64;

    /// Search for `addr` within the "sorted" `key_range_list` and return the index of the key
    /// range which contains `addr`, if it is contained in the list; otherwise,
    /// `-(insertion point) - 1`. An `addr` of `None` always results in a returned index of `-1`.
    fn find_key_range(&self, key_range_list: &[KeyRange], addr: Option<&Address>) -> i32;

    /// Generates a properly ordered list of database key ranges for the specified address range,
    /// using standard/relocatable address key encodings. See
    /// [`Self::get_key_ranges_absolute`] for the full contract.
    fn get_key_ranges(&self, start: &Address, end: &Address, create: bool) -> Vec<KeyRange> {
        self.get_key_ranges_absolute(start, end, false, create)
    }

    /// Generates a properly ordered list of database key ranges for the specified address set,
    /// using standard/relocatable address key encodings. `set` of `None` means all addresses;
    /// must not be `None` if `create` is `true`.
    fn get_key_ranges_for_set(
        &self,
        set: Option<&dyn AddressSetView>,
        create: bool,
    ) -> Vec<KeyRange> {
        self.get_key_ranges_for_set_absolute(set, false, create)
    }

    /// Returns the address that was used to generate the given key. (If the image base was
    /// moved, then a different address is returned unless the value was encoded using
    /// [`Self::get_absolute_encoding`].)
    fn decode_address(&self, value: i64) -> Address;

    /// Returns the address factory associated with this map, or `None` if this map is not
    /// associated with a specific address factory.
    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>>;

    /// Generates a properly ordered list of database key ranges for the specified address range.
    /// If `absolute` is `true`, only memory addresses are included. Returned key ranges are
    /// generally intended for read-only operations since new keys will never be generated unless
    /// `create` is `true`.
    ///
    /// NOTE: if `create` is `true`, the given range must not extend in the upper 32 bits by more
    /// than 1 segment.
    fn get_key_ranges_absolute(
        &self,
        start: &Address,
        end: &Address,
        absolute: bool,
        create: bool,
    ) -> Vec<KeyRange>;

    /// Generates a properly ordered list of database key ranges for the specified address set.
    /// If `absolute` is `true`, only memory addresses are included. `set` of `None` means all
    /// addresses; must not be `None` if `create` is `true`.
    fn get_key_ranges_for_set_absolute(
        &self,
        set: Option<&dyn AddressSetView>,
        absolute: bool,
        create: bool,
    ) -> Vec<KeyRange>;

    /// Returns an address map capable of decoding old address encodings.
    fn get_old_address_map(&self) -> Box<dyn AddressMap>;

    /// Returns true if this address map has been upgraded.
    fn is_upgraded(&self) -> bool;

    /// Returns the current image base setting.
    fn get_image_base(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockAddressMap {
        base: Address,
    }

    impl AddressMap for MockAddressMap {
        fn get_key(&self, _addr: &Address, _create: bool) -> i64 {
            0
        }

        fn get_absolute_encoding(&self, _addr: &Address, _create: bool) -> i64 {
            0
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], addr: Option<&Address>) -> i32 {
            match addr {
                None => -1,
                Some(_) => -1,
            }
        }

        fn decode_address(&self, _value: i64) -> Address {
            self.base.clone()
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }

        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(MockAddressMap {
                base: self.base.clone(),
            })
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.base.clone()
        }
    }

    #[test]
    fn mock_address_map_is_object_safe_and_usable() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let base = space.address(0);
        let map: Box<dyn AddressMap> = Box::new(MockAddressMap { base: base.clone() });

        assert_eq!(map.get_key(&base, false), 0);
        assert_eq!(map.decode_address(0), base);
        assert_eq!(map.find_key_range(&[], None), -1);
        assert!(map.get_key_ranges(&base, &base, false).is_empty());
        assert!(map.get_key_ranges_for_set(None, false).is_empty());
        assert!(!map.is_upgraded());
        assert_eq!(map.get_image_base(), base);
        assert!(map.get_address_factory().is_none());
        assert!(!map.get_old_address_map().is_upgraded());
    }
}
