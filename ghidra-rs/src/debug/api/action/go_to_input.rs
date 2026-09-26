use crate::program::model::address::Address;

/// Input specification for "go to" navigation, decomposing a location into
/// address space and offset components.
///
/// Mirrors `ghidra.debug.api.action.GoToInput` (Java 16+ record).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoToInput {
    pub space: Option<String>,
    pub offset: String,
}

impl GoToInput {
    /// Parses a string into a `GoToInput`, splitting on the first `:` if present.
    ///
    /// - `"space:offset"` → `GoToInput { space: Some("space"), offset: "offset" }`
    /// - `"offset"` → `GoToInput { space: None, offset: "offset" }`
    pub fn from_string(s: &str) -> Self {
        if let Some(colon_idx) = s.find(':') {
            let (space_part, offset_part) = s.split_at(colon_idx);
            GoToInput {
                space: Some(space_part.to_string()),
                offset: offset_part[1..].to_string(),
            }
        } else {
            GoToInput {
                space: None,
                offset: s.to_string(),
            }
        }
    }

    /// Constructs a `GoToInput` from an `Address`, extracting its space and offset.
    ///
    /// Mirrors `ghidra.debug.api.action.GoToInput.fromAddress(Address)`.
    pub fn from_address(address: &Address) -> Self {
        let space_name = address.space().name().to_string();
        let offset_str = address.format(false, 8);
        GoToInput {
            space: Some(space_name),
            offset: offset_str,
        }
    }

    /// Constructs a `GoToInput` with only an offset and no address space.
    pub fn offset_only(offset: &str) -> Self {
        GoToInput {
            space: None,
            offset: offset.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use std::sync::Arc;

    #[test]
    fn from_string_with_colon() {
        let input = GoToInput::from_string("RAM:0x1000");
        assert_eq!(input.space, Some("RAM".to_string()));
        assert_eq!(input.offset, "0x1000");
    }

    #[test]
    fn from_string_without_colon() {
        let input = GoToInput::from_string("0x2000");
        assert_eq!(input.space, None);
        assert_eq!(input.offset, "0x2000");
    }

    #[test]
    fn from_string_multiple_colons_splits_on_first() {
        let input = GoToInput::from_string("RAM:0x100:extra");
        assert_eq!(input.space, Some("RAM".to_string()));
        assert_eq!(input.offset, "0x100:extra");
    }

    #[test]
    fn from_string_empty_space() {
        let input = GoToInput::from_string(":0x5000");
        assert_eq!(input.space, Some("".to_string()));
        assert_eq!(input.offset, "0x5000");
    }

    #[test]
    fn offset_only() {
        let input = GoToInput::offset_only("0x3000");
        assert_eq!(input.space, None);
        assert_eq!(input.offset, "0x3000");
    }

    #[test]
    fn from_address() {
        use crate::program::model::address::AddressSpaceType;

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let address = Address::new(ram, 0x1234);
        let input = GoToInput::from_address(&address);

        assert_eq!(input.space, Some("RAM".to_string()));
        assert_eq!(input.offset, "00001234");
    }

    #[test]
    fn equality() {
        let a = GoToInput::from_string("RAM:0x100");
        let b = GoToInput::from_string("RAM:0x100");
        let c = GoToInput::from_string("RAM:0x200");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn clone() {
        let input = GoToInput::from_string("Register:0x5");
        let cloned = input.clone();
        assert_eq!(input, cloned);
    }

    #[test]
    fn hash() {
        use std::collections::HashSet;

        let a = GoToInput::from_string("RAM:0x100");
        let b = GoToInput::from_string("RAM:0x100");
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }
}
