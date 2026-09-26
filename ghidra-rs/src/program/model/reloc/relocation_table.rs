//! Port of `ghidra.program.model.reloc.RelocationTable`.
//!
//! The Java type is an interface implemented by the (unported) `RelocationManager`, which is
//! backed by [`RelocationDBAdapter`](crate::program::database::reloc::relocation_db_adapter::RelocationDBAdapter).
//! This trait was selected as a dependency-cycle cut-point, so it is ported standalone as an
//! object-safe trait ahead of any concrete implementation.

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::{Relocation, RelocationStatus};

/// Name of the relocatable property in the program information property list. Stands in for
/// `RelocationTable.RELOCATABLE_PROP_NAME`.
pub const RELOCATABLE_PROP_NAME: &str = "Relocatable";

/// An interface for storing the relocations defined in a program.
///
/// Table must preserve the order in which relocations are added such that the iterators return
/// them in the same order.
pub trait RelocationTable {
    /// Adds a new relocation entry when the original bytes being replaced are to be specified.
    ///
    /// Port of `RelocationTable.add(Address, Status, int, long[], byte[], String)`.
    ///
    /// * `addr` - the memory address where the relocation is required
    /// * `status` - relocation status (use [`RelocationStatus::Unknown`] if not known)
    /// * `type_` - the type of relocation to perform
    /// * `values` - relocation-specific values which may be useful in diagnosing relocation
    /// * `bytes` - original memory bytes affected by relocation. If `None` and
    ///   [`RelocationStatus::has_bytes`] is true a default number of original bytes will be
    ///   assumed and obtained from the underlying memory `FileBytes` if possible.
    /// * `symbol_name` - the name of the symbol being relocated; may be `None`
    fn add(
        &mut self,
        addr: Address,
        status: RelocationStatus,
        type_: i32,
        values: Vec<i64>,
        bytes: Option<Vec<u8>>,
        symbol_name: Option<String>,
    ) -> Relocation;

    /// Adds a new relocation entry when the original bytes being replaced should be determined
    /// from the underlying `FileBytes`.
    ///
    /// Port of `RelocationTable.add(Address, Status, int, long[], int, String)`.
    ///
    /// * `addr` - the memory address where the relocation is required
    /// * `status` - relocation status (use [`RelocationStatus::Unknown`] if not known)
    /// * `type_` - the type of relocation to perform
    /// * `values` - relocation-specific values which may be useful in diagnosing relocation
    /// * `byte_length` - the number of bytes affected by this relocation. Only used with a
    ///   status of [`RelocationStatus::Unknown`], [`RelocationStatus::Applied`] or
    ///   [`RelocationStatus::AppliedOther`]. Valid range is 1..8 bytes.
    /// * `symbol_name` - the name of the symbol being relocated; may be `None`
    fn add_with_byte_length(
        &mut self,
        addr: Address,
        status: RelocationStatus,
        type_: i32,
        values: Vec<i64>,
        byte_length: i32,
        symbol_name: Option<String>,
    ) -> Relocation;

    /// Returns the ordered list of relocations which have been defined for the specified
    /// address. In most cases there will be one or none, but in some cases multiple relocations
    /// may be applied to a single address.
    ///
    /// Port of `RelocationTable.getRelocations(Address)`.
    fn get_relocations(&self, addr: &Address) -> Vec<Relocation>;

    /// Determine if the specified address has a relocation defined.
    ///
    /// Port of `RelocationTable.hasRelocation(Address)`.
    fn has_relocation(&self, addr: &Address) -> bool;

    /// Returns an iterator over all defined relocations (in ascending address order) located
    /// within the program.
    ///
    /// Port of `RelocationTable.getRelocations()`.
    fn relocation_iter(&self) -> Box<dyn Iterator<Item = Relocation>>;

    /// Returns an iterator over all defined relocations (in ascending address order) located
    /// within the program over the specified address set.
    ///
    /// Port of `RelocationTable.getRelocations(AddressSetView)`.
    fn relocation_iter_in(&self, set: &dyn AddressSetView) -> Box<dyn Iterator<Item = Relocation>>;

    /// Returns the next relocation address which follows the specified address, or `None` if
    /// none.
    ///
    /// Port of `RelocationTable.getRelocationAddressAfter(Address)`.
    fn get_relocation_address_after(&self, addr: &Address) -> Option<Address>;

    /// Returns the number of relocations in this table.
    ///
    /// Port of `RelocationTable.getSize()`.
    fn get_size(&self) -> i32;

    /// Returns true if this relocation table contains relocations for a relocatable binary. Some
    /// binaries may contain relocations, but not actually be relocatable. For example, ELF
    /// executables.
    ///
    /// Port of `RelocationTable.isRelocatable()`.
    fn is_relocatable(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    struct MockRelocationTable {
        relocations: Vec<Relocation>,
        relocatable: bool,
    }

    impl RelocationTable for MockRelocationTable {
        fn add(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            bytes: Option<Vec<u8>>,
            symbol_name: Option<String>,
        ) -> Relocation {
            let reloc = Relocation::new(addr, status, type_, values, bytes, symbol_name);
            self.relocations.push(reloc.clone());
            reloc
        }

        fn add_with_byte_length(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            byte_length: i32,
            symbol_name: Option<String>,
        ) -> Relocation {
            let bytes = if byte_length > 0 {
                Some(vec![0u8; byte_length as usize])
            } else {
                None
            };
            self.add(addr, status, type_, values, bytes, symbol_name)
        }

        fn get_relocations(&self, addr: &Address) -> Vec<Relocation> {
            self.relocations
                .iter()
                .filter(|r| r.address() == addr)
                .cloned()
                .collect()
        }

        fn has_relocation(&self, addr: &Address) -> bool {
            self.relocations.iter().any(|r| r.address() == addr)
        }

        fn relocation_iter(&self) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(self.relocations.clone().into_iter())
        }

        fn relocation_iter_in(
            &self,
            set: &dyn AddressSetView,
        ) -> Box<dyn Iterator<Item = Relocation>> {
            let matches: Vec<Relocation> = self
                .relocations
                .iter()
                .filter(|r| set.contains(r.address()))
                .cloned()
                .collect();
            Box::new(matches.into_iter())
        }

        fn get_relocation_address_after(&self, addr: &Address) -> Option<Address> {
            self.relocations
                .iter()
                .map(|r| r.address().clone())
                .filter(|a| a > addr)
                .min()
        }

        fn get_size(&self) -> i32 {
            self.relocations.len() as i32
        }

        fn is_relocatable(&self) -> bool {
            self.relocatable
        }
    }

    #[test]
    fn mock_table_tracks_added_relocations_in_order() {
        let mut table = MockRelocationTable {
            relocations: Vec::new(),
            relocatable: true,
        };

        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x2000);

        table.add(
            addr1.clone(),
            RelocationStatus::Applied,
            1,
            vec![],
            Some(vec![0xde, 0xad]),
            Some("foo".to_string()),
        );
        table.add_with_byte_length(addr2.clone(), RelocationStatus::Unknown, 2, vec![], 4, None);

        assert_eq!(table.get_size(), 2);
        assert!(table.has_relocation(&addr1));
        assert!(!table.has_relocation(&test_address(0x3000)));
        assert_eq!(table.get_relocations(&addr1).len(), 1);

        let all: Vec<Relocation> = table.relocation_iter().collect();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].address(), &addr1);
        assert_eq!(all[1].address(), &addr2);

        assert_eq!(table.get_relocation_address_after(&addr1), Some(addr2));
        assert!(table.is_relocatable());
    }
}
