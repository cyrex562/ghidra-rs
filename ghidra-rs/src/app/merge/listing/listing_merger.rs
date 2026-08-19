//! Ported from `ghidra.app.merge.listing.ListingMerger`.
//!
//! An interface implemented by an individual listing merge manager. It defines methods that the
//! overall `ListingMergeManager` can call on the individual listing merge managers.

use crate::app::seam_stubs::ListingMergePanel;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::mem::memory_access_exception::MemoryAccessException;
use crate::program::util::program_conflict_exception::ProgramConflictException;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Java `interface ListingMerger` -- a genuine extension point implemented by each of the
/// per-conflict-type listing merge managers (function, symbol, etc.), each independently driven
/// by the overall `ListingMergeManager`.
pub trait ListingMerger {
    /// Performs the automatic merge for all changes in my Checked Out program version.
    /// It also determines the conflicts requiring manual resolution.
    ///
    /// `progress_min`/`progress_max` are the progress bounds, between 0 and 100, that this auto
    /// merge should report through as it runs.
    fn auto_merge(
        &mut self,
        progress_min: i32,
        progress_max: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), AutoMergeError>;

    /// Called when the Apply button is pressed on the GUI conflict resolution window.
    /// Returns true if apply succeeded.
    fn apply(&mut self) -> bool;

    /// Called when the Cancel button is pressed on the GUI conflict resolution window.
    fn cancel(&mut self);

    /// A string indicating the type of listing conflict this merger handles, e.g. Function,
    /// Symbol, etc.
    fn get_conflict_type(&self) -> String;

    /// The number of conflicts that have currently been resolved on the conflict resolution
    /// window (by the user selecting buttons or checkboxes).
    fn get_num_conflicts_resolved(&self) -> i32;

    /// True if there is one or more conflicts at the address.
    fn has_conflict(&self, addr: &Address) -> bool;

    /// The number of conflicts at the indicated address.
    fn get_conflict_count(&self, addr: &Address) -> i32;

    /// Performs a manual merge of all conflicts at the indicated address for the type of
    /// conflicts that this merge manager handles.
    ///
    /// `listing_panel` is the listing merge panel with the 4 version listings. `conflict_option`
    /// of `ASK_USER` means interactively resolve conflicts; JUnit testing also allows setting
    /// this to LATEST, MY, or ORIGINAL to force selection of a particular version change.
    fn merge_conflicts(
        &mut self,
        listing_panel: &ListingMergePanel,
        addr: &Address,
        conflict_option: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MergeConflictsError>;

    /// An address set indicating where there are conflicts to resolve.
    fn get_conflicts(&self) -> Box<dyn AddressSetView>;
}

/// Failure modes of [`ListingMerger::auto_merge`], mirroring the Java method's checked
/// `throws` clause.
#[derive(Debug)]
pub enum AutoMergeError {
    ProgramConflict(ProgramConflictException),
    MemoryAccess(MemoryAccessException),
    Cancelled(CancelledException),
}

impl std::fmt::Display for AutoMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoMergeError::ProgramConflict(e) => write!(f, "{}", e.message()),
            AutoMergeError::MemoryAccess(e) => {
                write!(f, "{}", e.message().unwrap_or_default())
            }
            AutoMergeError::Cancelled(e) => write!(f, "{}", e.0),
        }
    }
}

impl std::error::Error for AutoMergeError {}

/// Failure modes of [`ListingMerger::merge_conflicts`], mirroring the Java method's checked
/// `throws` clause.
#[derive(Debug)]
pub enum MergeConflictsError {
    Cancelled(CancelledException),
    MemoryAccess(MemoryAccessException),
}

impl std::fmt::Display for MergeConflictsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeConflictsError::Cancelled(e) => write!(f, "{}", e.0),
            MergeConflictsError::MemoryAccess(e) => {
                write!(f, "{}", e.message().unwrap_or_default())
            }
        }
    }
}

impl std::error::Error for MergeConflictsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::merge::listing::listing_merge_constants::ASK_USER;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    /// Minimal implementor exercising the trait surface end-to-end, standing in for one of the
    /// concrete per-conflict-type mergers (e.g. `FunctionTagListingMerger`).
    struct StubMerger {
        resolved: i32,
        applied: bool,
        cancelled: bool,
        conflicts: AddressSet,
    }

    impl ListingMerger for StubMerger {
        fn auto_merge(
            &mut self,
            progress_min: i32,
            progress_max: i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), AutoMergeError> {
            if progress_min > progress_max {
                return Err(AutoMergeError::ProgramConflict(
                    ProgramConflictException::with_message("bad progress range"),
                ));
            }
            Ok(())
        }

        fn apply(&mut self) -> bool {
            self.applied = true;
            true
        }

        fn cancel(&mut self) {
            self.cancelled = true;
        }

        fn get_conflict_type(&self) -> String {
            "Function".to_string()
        }

        fn get_num_conflicts_resolved(&self) -> i32 {
            self.resolved
        }

        fn has_conflict(&self, addr: &Address) -> bool {
            self.conflicts.contains(addr)
        }

        fn get_conflict_count(&self, addr: &Address) -> i32 {
            if self.conflicts.contains(addr) {
                1
            } else {
                0
            }
        }

        fn merge_conflicts(
            &mut self,
            _listing_panel: &ListingMergePanel,
            _addr: &Address,
            conflict_option: i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MergeConflictsError> {
            self.resolved += 1;
            let _ = conflict_option;
            Ok(())
        }

        fn get_conflicts(&self) -> Box<dyn AddressSetView> {
            Box::new(self.conflicts.clone())
        }
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn apply_and_cancel_update_state() {
        let mut merger = StubMerger {
            resolved: 0,
            applied: false,
            cancelled: false,
            conflicts: AddressSet::new(),
        };
        assert!(merger.apply());
        assert!(merger.applied);
        merger.cancel();
        assert!(merger.cancelled);
    }

    #[test]
    fn conflict_queries_reflect_address_set() {
        let space = test_space();
        let a = addr(&space, 0x100);
        let b = addr(&space, 0x200);
        let mut conflicts = AddressSet::new();
        conflicts.add_address(&a);
        let merger = StubMerger {
            resolved: 0,
            applied: false,
            cancelled: false,
            conflicts,
        };
        assert!(merger.has_conflict(&a));
        assert_eq!(merger.get_conflict_count(&a), 1);
        assert!(!merger.has_conflict(&b));
        assert_eq!(merger.get_conflict_count(&b), 0);
    }

    #[test]
    fn merge_conflicts_increments_resolved_count() {
        let space = test_space();
        let a = addr(&space, 0x100);
        let panel = ListingMergePanel;
        let monitor = DummyMonitor;
        let mut merger = StubMerger {
            resolved: 0,
            applied: false,
            cancelled: false,
            conflicts: AddressSet::new(),
        };
        merger
            .merge_conflicts(&panel, &a, ASK_USER, &monitor)
            .unwrap();
        assert_eq!(merger.get_num_conflicts_resolved(), 1);
    }

    #[test]
    fn auto_merge_reports_program_conflict_error() {
        let monitor = DummyMonitor;
        let mut merger = StubMerger {
            resolved: 0,
            applied: false,
            cancelled: false,
            conflicts: AddressSet::new(),
        };
        let err = merger.auto_merge(50, 10, &monitor).unwrap_err();
        assert!(matches!(err, AutoMergeError::ProgramConflict(_)));
    }
}
