use crate::program::model::address::Address;
use crate::docking::widgets::table::DisplayStringProvider;

/// A displayable offset that provides access to an address and its offset representation.
///
/// This trait is implemented by classes that represent offsets in version tracking,
/// providing both a display string for UI rendering and underlying address/offset data.
/// Implementors are expected to be comparable via standard ordering traits.
///
/// Corresponds to `ghidra.feature.vt.gui.editors.DisplayableOffset` in the Java source.
pub trait DisplayableOffset: DisplayStringProvider + Ord {
    /// A constant string representing "No Offset".
    const NO_OFFSET: &'static str = "No Offset";

    /// Returns the address associated with this offset.
    fn get_address(&self) -> Address;

    /// Returns the offset as a signed 64-bit integer.
    fn get_offset(&self) -> i64;

    /// Returns the offset as a 128-bit integer (representing Java's BigInteger).
    fn get_offset_as_big_integer(&self) -> i128;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    struct MockDisplayableOffset {
        address: Address,
        offset: i64,
        display: String,
    }

    impl DisplayStringProvider for MockDisplayableOffset {
        fn display_string(&self) -> String {
            self.display.clone()
        }
    }

    impl Ord for MockDisplayableOffset {
        fn cmp(&self, other: &Self) -> Ordering {
            self.offset.cmp(&other.offset)
        }
    }

    impl PartialOrd for MockDisplayableOffset {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Eq for MockDisplayableOffset {}

    impl PartialEq for MockDisplayableOffset {
        fn eq(&self, other: &Self) -> bool {
            self.offset == other.offset
        }
    }

    impl DisplayableOffset for MockDisplayableOffset {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_offset(&self) -> i64 {
            self.offset
        }

        fn get_offset_as_big_integer(&self) -> i128 {
            self.offset as i128
        }
    }

    #[test]
    fn test_no_offset_constant() {
        assert_eq!(MockDisplayableOffset::NO_OFFSET, "No Offset");
    }

    #[test]
    fn test_display_string_from_provider() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);

        let offset = MockDisplayableOffset {
            address: addr,
            offset: 0x1000,
            display: "test_display".to_string(),
        };

        assert_eq!(offset.display_string(), "test_display");
    }

    #[test]
    fn test_get_offset_returns_correct_value() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x2000);

        let offset = MockDisplayableOffset {
            address: addr,
            offset: 0x2000,
            display: "test".to_string(),
        };

        assert_eq!(offset.get_offset(), 0x2000);
    }

    #[test]
    fn test_get_offset_as_big_integer() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x3000);

        let offset = MockDisplayableOffset {
            address: addr,
            offset: 0x3000,
            display: "test".to_string(),
        };

        assert_eq!(offset.get_offset_as_big_integer(), 0x3000i128);
    }

    #[test]
    fn test_comparable_ordering() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);

        let offset1 = MockDisplayableOffset {
            address: space.address(0x1000),
            offset: 0x1000,
            display: "offset1".to_string(),
        };

        let offset2 = MockDisplayableOffset {
            address: space.address(0x2000),
            offset: 0x2000,
            display: "offset2".to_string(),
        };

        assert!(offset1 < offset2);
        assert_eq!(offset1.cmp(&offset2), Ordering::Less);
    }
}
