use crate::program::model::address::{
    Address, AddressFormatException, AddressSet, AddressSetView, AddressSpace,
};
use std::sync::Arc;

pub const OV_SEPARATOR: &str = ":";

/// Overlay address-space behavior shared by Ghidra overlay spaces.
///
/// Java models this as an abstract class whose concrete implementations supply
/// region containment.  This Rust port stores the overlay regions directly as
/// an `AddressSet`, which gives the same public behavior without requiring a
/// placeholder subclass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayAddressSpace {
    space: Arc<AddressSpace>,
    base_space: Arc<AddressSpace>,
    ordered_key: String,
    overlay_set: AddressSet,
}

impl OverlayAddressSpace {
    pub fn new(
        name: &str,
        base_space: Arc<AddressSpace>,
        unique: i32,
        ordered_key: impl Into<String>,
        overlay_set: AddressSet,
    ) -> Self {
        let space = AddressSpace::new(
            name,
            base_space.size(),
            base_space.unit_size(),
            base_space.space_type(),
            unique,
        );
        Self {
            space,
            base_space,
            ordered_key: ordered_key.into(),
            overlay_set,
        }
    }

    pub fn address_space(&self) -> &Arc<AddressSpace> {
        &self.space
    }

    pub fn name(&self) -> &str {
        self.space.name()
    }

    pub fn ordered_key(&self) -> &str {
        &self.ordered_key
    }

    pub fn overlayed_space(&self) -> &Arc<AddressSpace> {
        &self.base_space
    }

    pub fn physical_space(&self) -> &Arc<AddressSpace> {
        &self.base_space
    }

    pub fn is_overlay_space(&self) -> bool {
        true
    }

    pub fn base_space_id(&self) -> i32 {
        self.base_space.space_id()
    }

    pub fn contains(&self, offset: i64) -> bool {
        self.overlay_set
            .contains(&Address::new(self.space.clone(), offset))
    }

    pub fn overlay_address_set(&self) -> AddressSet {
        AddressSet::from_set(&self.overlay_set)
    }

    pub fn parse_address(
        &self,
        address: &str,
        case_sensitive: bool,
    ) -> Result<Option<Address>, AddressFormatException> {
        let normalized = address.replace("::", ":");
        self.space.parse_address(&normalized, case_sensitive)
    }

    pub fn address_in_this_space_only(&self, offset: i64) -> Address {
        Address::new(self.space.clone(), offset)
    }

    pub fn address(&self, offset: i64) -> Address {
        if self.contains(offset) {
            Address::new(self.space.clone(), offset)
        } else {
            Address::new(self.base_space.clone(), offset)
        }
    }

    pub fn overlay_address(&self, address: &Address) -> Address {
        if address.space() == &self.base_space && self.contains(address.offset()) {
            Address::new(self.space.clone(), address.offset())
        } else {
            address.clone()
        }
    }

    pub fn translate_address(
        &self,
        address: Option<&Address>,
        force_translation: bool,
    ) -> Option<Address> {
        let address = address?;
        if !force_translation && self.contains(address.offset()) {
            return Some(address.clone());
        }
        Some(Address::new(self.base_space.clone(), address.offset()))
    }

    pub fn subtract(&self, left: &Address, right: &Address) -> i64 {
        let left_space = if left.space() == &self.space {
            &self.base_space
        } else {
            left.space()
        };
        let right_space = if right.space() == &self.space {
            &self.base_space
        } else {
            right.space()
        };
        if left_space != right_space {
            panic!(
                "Address are in different spaces {} != {}",
                left.space().name(),
                right.space().name()
            );
        }
        left.offset().wrapping_sub(right.offset())
    }

    pub fn compare_overlay(&self, other: &OverlayAddressSpace) -> std::cmp::Ordering {
        self.base_space
            .cmp(&other.base_space)
            .then((self.space.space_type() as i32).cmp(&(other.space.space_type() as i32)))
            .then(self.ordered_key.cmp(&other.ordered_key))
    }
}

impl std::fmt::Display for OverlayAddressSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.name(), OV_SEPARATOR)
    }
}

impl std::hash::Hash for OverlayAddressSpace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ordered_key.hash(state);
        self.base_space.hash(state);
        self.space.size().hash(state);
        (self.space.space_type() as i32).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    #[test]
    fn overlay_contains_and_returns_overlay_or_base_addresses() {
        let base = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay(&base, "ov", 0x100, 0x1ff);

        assert!(overlay.is_overlay_space());
        assert!(overlay.contains(0x100));
        assert!(!overlay.contains(0x200));
        assert_eq!(overlay.address(0x100).space(), overlay.address_space());
        assert_eq!(overlay.address(0x200).space(), &base);
        assert_eq!(
            overlay.address_in_this_space_only(0x200).space(),
            overlay.address_space()
        );
        assert_eq!(overlay.base_space_id(), base.space_id());
        assert_eq!(overlay.to_string(), "ov:");
    }

    #[test]
    fn overlay_converts_base_addresses_inside_region() {
        let base = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay(&base, "ov", 0x100, 0x1ff);
        let base_inside = Address::new(base.clone(), 0x120);
        let base_outside = Address::new(base.clone(), 0x220);

        let overlaid = overlay.overlay_address(&base_inside);
        assert_eq!(overlaid.space(), overlay.address_space());
        assert_eq!(overlaid.offset(), 0x120);
        assert_eq!(overlay.overlay_address(&base_outside), base_outside);
    }

    #[test]
    fn overlay_translation_respects_force_flag() {
        let base = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay(&base, "ov", 0x100, 0x1ff);
        let overlay_addr = overlay.address_in_this_space_only(0x140);

        assert_eq!(
            overlay.translate_address(Some(&overlay_addr), false),
            Some(overlay_addr.clone())
        );
        let translated = overlay
            .translate_address(Some(&overlay_addr), true)
            .unwrap();
        assert_eq!(translated.space(), &base);
        assert_eq!(translated.offset(), 0x140);
        assert_eq!(overlay.translate_address(None, true), None);
    }

    #[test]
    fn overlay_parse_accepts_double_colon_separator() {
        let base = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay(&base, "ov", 0x100, 0x1ff);

        assert_eq!(
            overlay.parse_address("ov::120", true).unwrap(),
            Some(overlay.address_in_this_space_only(0x120))
        );
        assert_eq!(overlay.parse_address("ram:120", true).unwrap(), None);
    }

    #[test]
    fn overlay_subtract_treats_overlay_and_base_as_same_space() {
        let base = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay(&base, "ov", 0x100, 0x1ff);
        let overlay_addr = overlay.address_in_this_space_only(0x150);
        let base_addr = Address::new(base, 0x140);

        assert_eq!(overlay.subtract(&overlay_addr, &base_addr), 0x10);
    }

    #[test]
    fn overlay_ordering_uses_base_type_and_ordered_key() {
        let base = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 1);
        let first = overlay(&base, "ov1", 0x100, 0x1ff);
        let second = OverlayAddressSpace::new(
            "renamed",
            base.clone(),
            3,
            "ov2",
            AddressSet::from_start_end(
                Address::new(base.clone(), 0x100),
                Address::new(base, 0x1ff),
            ),
        );

        assert!(first.compare_overlay(&second).is_lt());
        assert_ne!(first, second);
        assert_eq!(first.ordered_key(), "ov1");
    }

    fn overlay(base: &Arc<AddressSpace>, name: &str, start: i64, end: i64) -> OverlayAddressSpace {
        let overlay_space =
            AddressSpace::new(name, base.size(), base.unit_size(), base.space_type(), 2);
        let set = AddressSet::from_start_end(
            Address::new(overlay_space.clone(), start),
            Address::new(overlay_space, end),
        );
        OverlayAddressSpace::new(name, base.clone(), 2, name, set)
    }
}
