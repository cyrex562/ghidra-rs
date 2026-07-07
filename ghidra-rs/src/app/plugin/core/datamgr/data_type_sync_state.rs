/// Enumeration representing the synchronization state of a data type.
///
/// Corresponds to the Java enum `ghidra.app.plugin.core.datamgr.DataTypeSyncState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeSyncState {
    /// Data type is synchronized.
    InSync,
    /// Data type has an update pending.
    Update,
    /// Data type changes should be committed.
    Commit,
    /// Data type has conflicting changes.
    Conflict,
    /// Data type is orphaned.
    Orphan,
    /// Data type synchronization state is unknown.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_states_exist() {
        // Verify all enum variants can be instantiated.
        let _ = DataTypeSyncState::InSync;
        let _ = DataTypeSyncState::Update;
        let _ = DataTypeSyncState::Commit;
        let _ = DataTypeSyncState::Conflict;
        let _ = DataTypeSyncState::Orphan;
        let _ = DataTypeSyncState::Unknown;
    }

    #[test]
    fn test_state_equality() {
        assert_eq!(DataTypeSyncState::InSync, DataTypeSyncState::InSync);
        assert_ne!(DataTypeSyncState::InSync, DataTypeSyncState::Update);
    }

    #[test]
    fn test_state_clone() {
        let state = DataTypeSyncState::Conflict;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_state_copy() {
        let state = DataTypeSyncState::Orphan;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_state_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(DataTypeSyncState::InSync);
        set.insert(DataTypeSyncState::Update);
        set.insert(DataTypeSyncState::Conflict);

        assert!(set.contains(&DataTypeSyncState::InSync));
        assert!(!set.contains(&DataTypeSyncState::Commit));
    }

    #[test]
    fn test_state_debug_format() {
        let state = DataTypeSyncState::InSync;
        let debug_str = format!("{:?}", state);
        assert!(debug_str.contains("InSync"));
    }
}
