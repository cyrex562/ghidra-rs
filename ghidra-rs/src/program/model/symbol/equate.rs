use crate::program::model::address::Address;
use crate::program::model::symbol::{validate_name, EquateReference, SimpleEquateReference};
use std::fmt;

/// Universal identifier used by enum-backed equates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniversalId(u64);

impl UniversalId {
    /// Creates a universal identifier from its raw value.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw identifier value.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// Associates a string with a scalar value and its use sites.
///
/// This mirrors Ghidra's `Equate` interface while using Rust result values for
/// operations that can fail.
pub trait Equate {
    /// Returns the actual equate name.
    fn name(&self) -> &str;

    /// Returns the user-facing display name.
    fn display_name(&self) -> String;

    /// Returns the scalar value associated with this equate.
    fn value(&self) -> i64;

    /// Returns the signed hexadecimal display value.
    fn display_value(&self) -> String;

    /// Returns the number of references to this equate.
    fn reference_count(&self) -> usize;

    /// Adds or replaces a reference at the given address and operand position.
    fn add_reference(&mut self, ref_addr: Address, opnd_position: i16);

    /// Adds or replaces a dynamic-hash reference at the given address.
    fn add_dynamic_reference(&mut self, dynamic_hash: i64, ref_addr: Address);

    /// Renames the equate.
    fn rename_equate(&mut self, new_name: &str) -> Result<(), String>;

    /// Returns all references for this equate.
    fn references(&self) -> Vec<SimpleEquateReference>;

    /// Returns references attached to a specific address.
    fn references_at(&self, ref_addr: &Address) -> Vec<SimpleEquateReference>;

    /// Removes the reference at the given address and operand position.
    fn remove_reference(&mut self, ref_addr: &Address, opnd_position: i16) -> bool;

    /// Removes the reference at the given address and dynamic hash.
    fn remove_dynamic_reference(&mut self, dynamic_hash: i64, ref_addr: &Address) -> bool;

    /// Returns true if this equate is either not enum-backed or has a valid enum id.
    fn is_valid_uuid(&self) -> bool;

    /// Returns true if this equate is backed by an enum id.
    fn is_enum_based(&self) -> bool;

    /// Returns the enum universal id if present.
    fn enum_uuid(&self) -> Option<UniversalId>;
}

/// In-memory equate implementation for model-level use and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleEquate {
    name: String,
    value: i64,
    enum_uuid: Option<UniversalId>,
    references: Vec<SimpleEquateReference>,
}

impl SimpleEquate {
    /// Creates a non-enum equate.
    pub fn new(name: impl Into<String>, value: i64) -> Result<Self, String> {
        Self::with_enum_uuid(name, value, None)
    }

    /// Creates an equate with an optional enum universal id.
    pub fn with_enum_uuid(
        name: impl Into<String>,
        value: i64,
        enum_uuid: Option<UniversalId>,
    ) -> Result<Self, String> {
        let name = name.into();
        validate_name(Some(&name))?;
        Ok(Self {
            name,
            value,
            enum_uuid,
            references: Vec::new(),
        })
    }

    fn replace_reference<F>(&mut self, reference: SimpleEquateReference, matches: F)
    where
        F: Fn(&SimpleEquateReference) -> bool,
    {
        self.references.retain(|existing| !matches(existing));
        self.references.push(reference);
    }
}

impl Equate for SimpleEquate {
    fn name(&self) -> &str {
        &self.name
    }

    fn display_name(&self) -> String {
        self.name.clone()
    }

    fn value(&self) -> i64 {
        self.value
    }

    fn display_value(&self) -> String {
        if self.value < 0 {
            format!("-0x{:x}", self.value.wrapping_neg())
        } else {
            format!("0x{:x}", self.value)
        }
    }

    fn reference_count(&self) -> usize {
        self.references.len()
    }

    fn add_reference(&mut self, ref_addr: Address, opnd_position: i16) {
        let match_addr = ref_addr.clone();
        let reference = SimpleEquateReference::new(ref_addr, opnd_position, 0);
        self.replace_reference(reference, |existing| {
            existing.address() == &match_addr && existing.op_index() == opnd_position
        });
    }

    fn add_dynamic_reference(&mut self, dynamic_hash: i64, ref_addr: Address) {
        let match_addr = ref_addr.clone();
        let reference = SimpleEquateReference::new(ref_addr, -1, dynamic_hash);
        self.replace_reference(reference, |existing| {
            existing.address() == &match_addr && existing.dynamic_hash_value() == dynamic_hash
        });
    }

    fn rename_equate(&mut self, new_name: &str) -> Result<(), String> {
        validate_name(Some(new_name))?;
        self.name = new_name.to_string();
        Ok(())
    }

    fn references(&self) -> Vec<SimpleEquateReference> {
        self.references.clone()
    }

    fn references_at(&self, ref_addr: &Address) -> Vec<SimpleEquateReference> {
        self.references
            .iter()
            .filter(|reference| reference.address() == ref_addr)
            .cloned()
            .collect()
    }

    fn remove_reference(&mut self, ref_addr: &Address, opnd_position: i16) -> bool {
        let old_len = self.references.len();
        self.references.retain(|reference| {
            !(reference.address() == ref_addr && reference.op_index() == opnd_position)
        });
        self.references.len() != old_len
    }

    fn remove_dynamic_reference(&mut self, dynamic_hash: i64, ref_addr: &Address) -> bool {
        let old_len = self.references.len();
        self.references.retain(|reference| {
            !(reference.address() == ref_addr && reference.dynamic_hash_value() == dynamic_hash)
        });
        self.references.len() != old_len
    }

    fn is_valid_uuid(&self) -> bool {
        true
    }

    fn is_enum_based(&self) -> bool {
        self.enum_uuid.is_some()
    }

    fn enum_uuid(&self) -> Option<UniversalId> {
        self.enum_uuid
    }
}

impl fmt::Display for SimpleEquate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(offset)
    }

    #[test]
    fn stores_equate_fields_and_display_values() {
        let equate = SimpleEquate::new("FLAG", 0x80).unwrap();
        assert_eq!(equate.name(), "FLAG");
        assert_eq!(equate.display_name(), "FLAG");
        assert_eq!(equate.value(), 0x80);
        assert_eq!(equate.display_value(), "0x80");
        assert_eq!(equate.to_string(), "FLAG");

        let negative = SimpleEquate::new("NEG", -10).unwrap();
        assert_eq!(negative.display_value(), "-0xa");
    }

    #[test]
    fn validates_name_on_create_and_rename() {
        assert!(SimpleEquate::new("bad name", 1).is_err());

        let mut equate = SimpleEquate::new("GOOD", 1).unwrap();
        assert!(equate.rename_equate("new name").is_err());
        equate.rename_equate("BETTER").unwrap();
        assert_eq!(equate.name(), "BETTER");
    }

    #[test]
    fn operand_references_replace_matching_address_and_operand() {
        let mut equate = SimpleEquate::new("VALUE", 5).unwrap();
        let first = address(0x1000);
        let second = address(0x1004);

        equate.add_reference(first.clone(), 1);
        equate.add_reference(first.clone(), 1);
        equate.add_reference(first.clone(), 2);
        equate.add_reference(second.clone(), 1);

        assert_eq!(equate.reference_count(), 3);
        assert_eq!(equate.references_at(&first).len(), 2);
        assert!(equate.remove_reference(&first, 1));
        assert!(!equate.remove_reference(&first, 1));
        assert_eq!(equate.reference_count(), 2);
    }

    #[test]
    fn dynamic_references_replace_matching_address_and_hash() {
        let mut equate = SimpleEquate::new("VALUE", 5).unwrap();
        let first = address(0x1000);
        let second = address(0x1004);

        equate.add_dynamic_reference(0x55, first.clone());
        equate.add_dynamic_reference(0x55, first.clone());
        equate.add_dynamic_reference(0x66, first.clone());
        equate.add_dynamic_reference(0x55, second.clone());

        assert_eq!(equate.reference_count(), 3);
        assert_eq!(equate.references_at(&first).len(), 2);
        assert!(equate.remove_dynamic_reference(0x55, &first));
        assert!(!equate.remove_dynamic_reference(0x55, &first));
        assert_eq!(equate.reference_count(), 2);
    }

    #[test]
    fn enum_uuid_state_is_exposed() {
        let uuid = UniversalId::new(0x1234);
        let equate = SimpleEquate::with_enum_uuid("ENUM_VALUE", 3, Some(uuid)).unwrap();

        assert!(equate.is_enum_based());
        assert!(equate.is_valid_uuid());
        assert_eq!(equate.enum_uuid(), Some(uuid));
        assert_eq!(uuid.value(), 0x1234);
    }
}
