//! Maps pixel positions to addresses in a listing display.

use crate::program::model::address::{Address, AddressSetView};

/// Maps vertical pixel positions to addresses in a listing display.
///
/// This trait defines the contract for mapping pixel coordinates in the vertical
/// dimension of a code listing view to their corresponding addresses in the program.
/// It also provides information about layout positions, which are the rectangular
/// regions used to display code and data.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap`.
pub trait VerticalPixelAddressMap {
    /// Returns the address of the first layout in this map.
    ///
    /// # Returns
    ///
    /// The starting address of the first layout.
    fn get_start_address(&self) -> Address;

    /// Returns the address of the last layout in this map.
    ///
    /// # Returns
    ///
    /// The ending address of the last layout.
    fn get_end_address(&self) -> Address;

    /// Returns the number of layouts in this map.
    ///
    /// Layouts are rectangular regions that display code or data.
    ///
    /// # Returns
    ///
    /// The count of layouts.
    fn get_num_layouts(&self) -> i32;

    /// Returns the address of the i'th layout in this map.
    ///
    /// # Arguments
    ///
    /// * `i` - The index into the local array of layouts.
    ///
    /// # Returns
    ///
    /// The address of the i'th layout.
    fn get_layout_address(&self, i: i32) -> Address;

    /// Returns the y position of the top of the i'th layout.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the layout.
    ///
    /// # Returns
    ///
    /// The pixel y coordinate of the top of the layout.
    fn get_begin_position(&self, i: i32) -> i32;

    /// Returns the y position of the bottom of the i'th layout.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the layout.
    ///
    /// # Returns
    ///
    /// The pixel y coordinate of the bottom of the layout.
    fn get_end_position(&self, i: i32) -> i32;

    /// Returns the pixel location to draw a marker icon.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the layout to be marked with an icon.
    ///
    /// # Returns
    ///
    /// The vertical pixel location at which to draw the icon.
    fn get_mark_position(&self, i: i32) -> i32;

    /// Determines if the given layout index contains the primary field.
    ///
    /// The primary field typically represents the main instruction or data
    /// definition at a particular address.
    ///
    /// # Arguments
    ///
    /// * `i` - The layout index to test.
    ///
    /// # Returns
    ///
    /// `true` if the layout contains the primary field, `false` otherwise.
    fn has_primary_field(&self, i: i32) -> bool;

    /// Finds the layout containing the given pixel y coordinate.
    ///
    /// # Arguments
    ///
    /// * `y` - The y coordinate of the layout to be found.
    ///
    /// # Returns
    ///
    /// The index of the layout at the given pixel position, or -1 if no layout
    /// is found at that position.
    fn find_layout_at(&self, y: i32) -> i32;

    /// Returns the address at the bottom of the i'th layout.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the layout.
    ///
    /// # Returns
    ///
    /// The address at the bottom of the layout, or `None` if at the end of an
    /// overlay block.
    fn get_layout_end_address(&self, i: i32) -> Option<Address>;

    /// Gets the address set of this map.
    ///
    /// The address set contains all addresses represented in this map.
    ///
    /// # Returns
    ///
    /// A view of the address set.
    fn get_address_set(&self) -> &dyn AddressSetView;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct TestAddressMap {
        start_address: Address,
        end_address: Address,
        num_layouts: i32,
        address_set: AddressSet,
    }

    impl TestAddressMap {
        fn new() -> Self {
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let start = Address::new(space.clone(), 0);
            let end = Address::new(space, 0x100);
            Self {
                start_address: start,
                end_address: end,
                num_layouts: 10,
                address_set: AddressSet::new(),
            }
        }
    }

    impl VerticalPixelAddressMap for TestAddressMap {
        fn get_start_address(&self) -> Address {
            self.start_address.clone()
        }

        fn get_end_address(&self) -> Address {
            self.end_address.clone()
        }

        fn get_num_layouts(&self) -> i32 {
            self.num_layouts
        }

        fn get_layout_address(&self, _i: i32) -> Address {
            self.start_address.clone()
        }

        fn get_begin_position(&self, i: i32) -> i32 {
            i * 20
        }

        fn get_end_position(&self, i: i32) -> i32 {
            (i + 1) * 20
        }

        fn get_mark_position(&self, i: i32) -> i32 {
            (i * 20) + 10
        }

        fn has_primary_field(&self, _i: i32) -> bool {
            true
        }

        fn find_layout_at(&self, y: i32) -> i32 {
            if y < 0 {
                -1
            } else {
                y / 20
            }
        }

        fn get_layout_end_address(&self, _i: i32) -> Option<Address> {
            Some(self.end_address.clone())
        }

        fn get_address_set(&self) -> &dyn AddressSetView {
            &self.address_set
        }
    }

    #[test]
    fn test_get_start_address() {
        let map = TestAddressMap::new();
        let start = map.get_start_address();
        assert_eq!(start.offset(), 0);
    }

    #[test]
    fn test_get_end_address() {
        let map = TestAddressMap::new();
        let end = map.get_end_address();
        assert_eq!(end.offset(), 0x100);
    }

    #[test]
    fn test_get_num_layouts() {
        let map = TestAddressMap::new();
        assert_eq!(map.get_num_layouts(), 10);
    }

    #[test]
    fn test_get_layout_address() {
        let map = TestAddressMap::new();
        let addr = map.get_layout_address(0);
        assert_eq!(addr.offset(), 0);
    }

    #[test]
    fn test_get_begin_position() {
        let map = TestAddressMap::new();
        assert_eq!(map.get_begin_position(0), 0);
        assert_eq!(map.get_begin_position(1), 20);
        assert_eq!(map.get_begin_position(5), 100);
    }

    #[test]
    fn test_get_end_position() {
        let map = TestAddressMap::new();
        assert_eq!(map.get_end_position(0), 20);
        assert_eq!(map.get_end_position(1), 40);
        assert_eq!(map.get_end_position(5), 120);
    }

    #[test]
    fn test_get_mark_position() {
        let map = TestAddressMap::new();
        assert_eq!(map.get_mark_position(0), 10);
        assert_eq!(map.get_mark_position(1), 30);
        assert_eq!(map.get_mark_position(5), 110);
    }

    #[test]
    fn test_has_primary_field() {
        let map = TestAddressMap::new();
        assert!(map.has_primary_field(0));
        assert!(map.has_primary_field(5));
    }

    #[test]
    fn test_find_layout_at() {
        let map = TestAddressMap::new();
        assert_eq!(map.find_layout_at(0), 0);
        assert_eq!(map.find_layout_at(19), 0);
        assert_eq!(map.find_layout_at(20), 1);
        assert_eq!(map.find_layout_at(39), 1);
        assert_eq!(map.find_layout_at(-1), -1);
    }

    #[test]
    fn test_get_layout_end_address() {
        let map = TestAddressMap::new();
        let end = map.get_layout_end_address(0);
        assert!(end.is_some());
        assert_eq!(end.unwrap().offset(), 0x100);
    }

    #[test]
    fn test_get_address_set() {
        let map = TestAddressMap::new();
        let set = map.get_address_set();
        assert!(set.is_empty());
    }

    #[test]
    fn test_trait_object() {
        let map = TestAddressMap::new();
        let _obj: &dyn VerticalPixelAddressMap = &map;
        assert_eq!(_obj.get_num_layouts(), 10);
    }

    #[test]
    fn test_layout_position_boundaries() {
        let map = TestAddressMap::new();
        for i in 0..map.get_num_layouts() {
            let begin = map.get_begin_position(i);
            let end = map.get_end_position(i);
            assert!(begin < end);
            let mark = map.get_mark_position(i);
            assert!(mark >= begin && mark <= end);
        }
    }
}
