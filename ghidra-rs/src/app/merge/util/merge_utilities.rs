use crate::program::model::address::{AddressSet, AddressSetView};

/// Generic static methods for use by the multi-user program merge managers.
///
/// Corresponds to Java `ghidra.app.merge.util.MergeUtilities`.
pub struct MergeUtilities;

impl MergeUtilities {
    /// Adds addresses to `auto_changes` where there are changes in the `my_diffs` set,
    /// but none in the `latest_diffs` set.
    /// Adds addresses to `conflict_changes` where there are changes in the `my_diffs`
    /// set and also some changes in the `latest_diffs` set.
    ///
    /// * `latest_diffs` - the address set of the changes in LATEST.
    /// * `my_diffs` - the address set of the changes in MY.
    /// * `auto_changes` - address set for the `my_diffs` non-conflicting changes.
    /// * `conflict_changes` - address set for the `my_diffs` conflicting changes.
    pub fn adjust_sets(
        latest_diffs: &dyn AddressSetView,
        my_diffs: &dyn AddressSetView,
        auto_changes: &mut AddressSet,
        conflict_changes: &mut AddressSet,
    ) {
        let mut diff_auto_changes = AddressSet::from_set(my_diffs);
        diff_auto_changes.delete_set(latest_diffs);
        let diff_conflict_changes = AddressSet::from_set(my_diffs).intersect(latest_diffs);
        auto_changes.add_set(&diff_auto_changes);
        conflict_changes.add_set(&diff_conflict_changes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn adjust_sets_routes_non_overlapping_changes_to_auto() {
        let latest_diffs = AddressSet::from_start_end(addr(0x2000), addr(0x2010));
        let my_diffs = AddressSet::from_start_end(addr(0x1000), addr(0x1010));
        let mut auto_changes = AddressSet::new();
        let mut conflict_changes = AddressSet::new();

        MergeUtilities::adjust_sets(
            &latest_diffs,
            &my_diffs,
            &mut auto_changes,
            &mut conflict_changes,
        );

        assert!(auto_changes.contains_range(&addr(0x1000), &addr(0x1010)));
        assert!(conflict_changes.is_empty());
    }

    #[test]
    fn adjust_sets_routes_overlapping_changes_to_conflict() {
        let latest_diffs = AddressSet::from_start_end(addr(0x1005), addr(0x1015));
        let my_diffs = AddressSet::from_start_end(addr(0x1000), addr(0x1010));
        let mut auto_changes = AddressSet::new();
        let mut conflict_changes = AddressSet::new();

        MergeUtilities::adjust_sets(
            &latest_diffs,
            &my_diffs,
            &mut auto_changes,
            &mut conflict_changes,
        );

        assert!(auto_changes.contains_range(&addr(0x1000), &addr(0x1004)));
        assert!(!auto_changes.contains(&addr(0x1005)));
        assert!(conflict_changes.contains_range(&addr(0x1005), &addr(0x1010)));
        assert!(!conflict_changes.contains(&addr(0x1011)));
    }

    #[test]
    fn adjust_sets_accumulates_into_existing_changes() {
        let latest_diffs = AddressSet::new();
        let my_diffs = AddressSet::from_start_end(addr(0x3000), addr(0x3010));
        let mut auto_changes = AddressSet::from_start_end(addr(0x1000), addr(0x1010));
        let mut conflict_changes = AddressSet::new();

        MergeUtilities::adjust_sets(
            &latest_diffs,
            &my_diffs,
            &mut auto_changes,
            &mut conflict_changes,
        );

        assert!(auto_changes.contains_range(&addr(0x1000), &addr(0x1010)));
        assert!(auto_changes.contains_range(&addr(0x3000), &addr(0x3010)));
        assert!(conflict_changes.is_empty());
    }
}
