//! Port of `ghidra.program.database.reloc.RelocationManager` as a trait (cycle cut-point).
//!
//! The Java class is a concrete `RelocationTable`/`ManagerDB` implementation that owns a
//! `RelocationDBAdapter` and calls back into `ProgramDB` (`program.getMemory()`,
//! `program.setChanged(...)`, `program.dbError(...)`) on every mutating/lookup method. That
//! dependency on the unported `ProgramDB` -- itself depending on the manager classes it owns -- is
//! what makes `RelocationManager` a cycle cut-point.
//!
//! `RelocationManager`'s entire public surface is already covered by the two already-ported
//! interfaces it implements: [`RelocationTable`] (the `add`/`getRelocations`/`hasRelocation`/...
//! query and mutation API) and [`ManagerDB`] (`invalidateCache`/`deleteAddressRange`/
//! `moveAddressRange`). So unlike most manager cut-points, this trait adds no new methods of its
//! own -- it exists purely to give a name to "something that is both a relocation table and a
//! `ManagerDB`", letting other unported code depend on `dyn RelocationManager` without pulling in
//! `ProgramDB`. `setProgram`/`programReady`, from the `ManagerDB` Java interface, are not modeled
//! here, following the precedent already set by this crate's [`ManagerDB`] port (see
//! [`EquateManager`](crate::program::database::symbol::EquateManager)'s module docs) and by
//! [`CodeManager`](crate::program::database::code::CodeManager).
//!
//! Left out: the constructor (`DBHandle`/`AddressMap`/`OpenMode`/`Lock`/`TaskMonitor` wiring and
//! adapter selection), and the two package-private static helpers `getDefaultOriginalByteLength`/
//! `getOriginalBytes` used internally by `add(...)` to backfill original bytes from a program's
//! `Memory` when the caller doesn't supply them directly -- these are implementation details of
//! whichever concrete `RelocationDBAdapter`-backed type is added later, not part of the callable
//! API other managers depend on, matching the precedent set by
//! [`ReferenceDbManager`](crate::program::database::references::ReferenceDbManager) for its own
//! such constructor/helper exclusions.

use crate::program::database::ManagerDB;
use crate::program::model::reloc::RelocationTable;

/// An implementation of the relocation table interface, additionally acting as a program manager.
///
/// Port of `ghidra.program.database.reloc.RelocationManager`. See the module docs for what was
/// intentionally left out (the constructor and internal byte-backfill helpers).
pub trait RelocationManager: RelocationTable + ManagerDB {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::reloc::relocation::{Relocation, RelocationStatus};
    use std::io;

    fn test_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        test_space().address(offset)
    }

    /// Mock backed by a flat `Vec`, exercising real add/query/delete behavior through the combined
    /// trait object rather than trivially-true assertions.
    struct MockRelocationManager {
        relocations: Vec<Relocation>,
    }

    impl RelocationTable for MockRelocationManager {
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
            self.relocations.iter().filter(|r| r.address() == addr).cloned().collect()
        }

        fn has_relocation(&self, addr: &Address) -> bool {
            self.relocations.iter().any(|r| r.address() == addr)
        }

        fn relocation_iter(&self) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(self.relocations.clone().into_iter())
        }

        fn relocation_iter_in(&self, set: &dyn AddressSetView) -> Box<dyn Iterator<Item = Relocation>> {
            let matches: Vec<Relocation> =
                self.relocations.iter().filter(|r| set.contains(r.address())).cloned().collect();
            Box::new(matches.into_iter())
        }

        fn get_relocation_address_after(&self, addr: &Address) -> Option<Address> {
            self.relocations.iter().map(|r| r.address().clone()).filter(|a| a > addr).min()
        }

        fn get_size(&self) -> i32 {
            self.relocations.len() as i32
        }

        fn is_relocatable(&self) -> bool {
            !self.relocations.is_empty()
        }
    }

    impl ManagerDB for MockRelocationManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            // Mirrors `RelocationManager.invalidateCache`: no cache or DB objects to invalidate.
            Ok(())
        }

        fn delete_address_range(&mut self, start_addr: &Address, end_addr: &Address) -> io::Result<()> {
            self.relocations.retain(|r| !(r.address() >= start_addr && r.address() <= end_addr));
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl RelocationManager for MockRelocationManager {}

    #[test]
    fn object_safe_combined_trait_tracks_and_deletes_relocations() {
        let mut mgr: Box<dyn RelocationManager> = Box::new(MockRelocationManager { relocations: Vec::new() });

        let addr1 = addr(0x1000);
        let addr2 = addr(0x2000);

        mgr.add(
            addr1.clone(),
            RelocationStatus::Applied,
            1,
            vec![],
            Some(vec![0xde, 0xad]),
            Some("foo".to_string()),
        );
        mgr.add_with_byte_length(addr2.clone(), RelocationStatus::Unknown, 2, vec![], 4, None);

        assert_eq!(mgr.get_size(), 2);
        assert!(mgr.has_relocation(&addr1));
        assert!(mgr.is_relocatable());
        assert_eq!(mgr.get_relocation_address_after(&addr1), Some(addr2.clone()));

        mgr.invalidate_cache(true).unwrap();
        assert_eq!(mgr.get_size(), 2);

        mgr.delete_address_range(&addr1, &addr1).unwrap();
        assert_eq!(mgr.get_size(), 1);
        assert!(!mgr.has_relocation(&addr1));
        assert!(mgr.has_relocation(&addr2));
    }
}
