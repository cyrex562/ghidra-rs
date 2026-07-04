use crate::program::model::address::Address;

/// Relocation status.
///
/// Mirrors `ghidra.program.model.reloc.Relocation.Status`. The associated
/// values must not change since they are retained within the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationStatus {
    /// Relocation status is unknown and is assumed to have modified memory bytes.
    /// This status is intended for relocation data upgrades when actual status
    /// can not be determined.
    Unknown,
    /// Relocation has been intentionally skipped and should not be treated as a failure.
    Skipped,
    /// Relocation type is not supported at the time relocations were applied.
    Unsupported,
    /// A supported relocation fail to apply properly. This may be the result of an
    /// unexpected or unsupported condition which prevented its application.
    Failure,
    /// Relocation was processed successfully although relies on a subsequent
    /// relocation to affect memory.
    Partial,
    /// Relocation was applied successfully and resulted in the modification of
    /// memory bytes.
    Applied,
    /// Loaded memory has been altered during the load process and may, or may not,
    /// be directly associated with a standard relocation type.
    AppliedOther,
}

impl RelocationStatus {
    /// Returns true if relocation reflects original bytes that may have been
    /// modified, else false.
    pub fn has_bytes(self) -> bool {
        match self {
            RelocationStatus::Unknown => true,
            RelocationStatus::Skipped => false,
            RelocationStatus::Unsupported => false,
            RelocationStatus::Failure => false,
            RelocationStatus::Partial => false,
            RelocationStatus::Applied => true,
            RelocationStatus::AppliedOther => true,
        }
    }

    /// Get the storage value associated with this status.
    pub fn value(self) -> i32 {
        match self {
            RelocationStatus::Unknown => 0,
            RelocationStatus::Skipped => 1,
            RelocationStatus::Unsupported => 2,
            RelocationStatus::Failure => 3,
            RelocationStatus::Partial => 4,
            RelocationStatus::Applied => 5,
            RelocationStatus::AppliedOther => 6,
        }
    }

    /// Get the [`RelocationStatus`] which corresponds to the specified value.
    ///
    /// Returns `None` if `value` does not correspond to a known status,
    /// mirroring the Java `IllegalArgumentException` thrown by `getStatus(int)`.
    pub fn from_value(value: i32) -> Option<Self> {
        match value {
            0 => Some(RelocationStatus::Unknown),
            1 => Some(RelocationStatus::Skipped),
            2 => Some(RelocationStatus::Unsupported),
            3 => Some(RelocationStatus::Failure),
            4 => Some(RelocationStatus::Partial),
            5 => Some(RelocationStatus::Applied),
            6 => Some(RelocationStatus::AppliedOther),
            _ => None,
        }
    }
}

/// A class to store the information needed for a single program relocation.
///
/// Mirrors `ghidra.program.model.reloc.Relocation`.
#[derive(Debug, Clone, PartialEq)]
pub struct Relocation {
    addr: Address,
    status: RelocationStatus,
    type_: i32,
    values: Vec<i64>,
    bytes: Option<Vec<u8>>,
    symbol_name: Option<String>,
}

impl Relocation {
    /// Constructs a new relocation.
    ///
    /// * `addr` - the address where the relocation is required
    /// * `status` - relocation status
    /// * `type_` - the type of relocation to perform
    /// * `values` - the values needed when performing the relocation. Definition of
    ///   values is specific to loader used and relocation type.
    /// * `bytes` - original instruction bytes affected by relocation
    /// * `symbol_name` - the name of the symbol being relocated
    pub fn new(
        addr: Address,
        status: RelocationStatus,
        type_: i32,
        values: Vec<i64>,
        bytes: Option<Vec<u8>>,
        symbol_name: Option<String>,
    ) -> Self {
        Self {
            addr,
            status,
            type_,
            values,
            bytes,
            symbol_name,
        }
    }

    /// Returns the address where the relocation is required.
    pub fn address(&self) -> &Address {
        &self.addr
    }

    /// Return the relocation's application status within the program.
    pub fn status(&self) -> RelocationStatus {
        self.status
    }

    /// Returns the type of the relocation to perform.
    pub fn type_(&self) -> i32 {
        self.type_
    }

    /// Returns the value needed when performing the relocation.
    pub fn values(&self) -> &[i64] {
        &self.values
    }

    /// Returns the original instruction bytes affected by applied relocation, if it
    /// was successfully applied (i.e. [`RelocationStatus::Applied`],
    /// [`RelocationStatus::AppliedOther`]), otherwise `None` may be returned.
    pub fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }

    /// Returns the number of original instruction bytes affected by applied
    /// relocation, if it was successfully applied (i.e.
    /// [`RelocationStatus::Applied`], [`RelocationStatus::AppliedOther`]),
    /// otherwise `0` is returned.
    pub fn length(&self) -> usize {
        self.bytes.as_ref().map_or(0, |b| b.len())
    }

    /// The name of the symbol being relocated or `None` if there is no symbol name.
    pub fn symbol_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn status_value_round_trips() {
        let statuses = [
            RelocationStatus::Unknown,
            RelocationStatus::Skipped,
            RelocationStatus::Unsupported,
            RelocationStatus::Failure,
            RelocationStatus::Partial,
            RelocationStatus::Applied,
            RelocationStatus::AppliedOther,
        ];
        for status in statuses {
            assert_eq!(RelocationStatus::from_value(status.value()), Some(status));
        }
    }

    #[test]
    fn status_from_value_rejects_unknown_value() {
        assert_eq!(RelocationStatus::from_value(42), None);
    }

    #[test]
    fn status_has_bytes_matches_java() {
        assert!(RelocationStatus::Unknown.has_bytes());
        assert!(!RelocationStatus::Skipped.has_bytes());
        assert!(!RelocationStatus::Unsupported.has_bytes());
        assert!(!RelocationStatus::Failure.has_bytes());
        assert!(!RelocationStatus::Partial.has_bytes());
        assert!(RelocationStatus::Applied.has_bytes());
        assert!(RelocationStatus::AppliedOther.has_bytes());
    }

    #[test]
    fn relocation_exposes_constructor_fields() {
        let addr = test_address(0x1000);
        let reloc = Relocation::new(
            addr.clone(),
            RelocationStatus::Applied,
            5,
            vec![1, 2, 3],
            Some(vec![0xde, 0xad, 0xbe, 0xef]),
            Some("main".to_string()),
        );

        assert_eq!(reloc.address(), &addr);
        assert_eq!(reloc.status(), RelocationStatus::Applied);
        assert_eq!(reloc.type_(), 5);
        assert_eq!(reloc.values(), &[1, 2, 3]);
        assert_eq!(reloc.bytes(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        assert_eq!(reloc.length(), 4);
        assert_eq!(reloc.symbol_name(), Some("main"));
    }

    #[test]
    fn relocation_length_is_zero_without_bytes() {
        let addr = test_address(0x2000);
        let reloc = Relocation::new(
            addr,
            RelocationStatus::Skipped,
            0,
            Vec::new(),
            None,
            None,
        );

        assert_eq!(reloc.bytes(), None);
        assert_eq!(reloc.length(), 0);
        assert_eq!(reloc.symbol_name(), None);
    }
}
