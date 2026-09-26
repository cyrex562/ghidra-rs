use crate::framework::db::{DBRecord, RecordIterator};

/// Implementation of a RecordIterator that is always empty.
///
/// Port of `ghidra.program.database.util.EmptyRecordIterator`. The Java class exposes a single
/// shared `INSTANCE` static field since the type carries no state; [`EmptyRecordIterator::INSTANCE`]
/// mirrors that here. `has_previous`/`previous`/`delete` are left to
/// [`RecordIterator`]'s default implementations, which already report "nothing
/// available"/"not deleted" -- exactly what Java's explicit overrides below return.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyRecordIterator;

impl EmptyRecordIterator {
    /// Shared, stateless singleton instance, mirroring Java's `EmptyRecordIterator.INSTANCE`.
    pub const INSTANCE: EmptyRecordIterator = EmptyRecordIterator;

    pub fn new() -> Self {
        Self
    }
}

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> std::io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_next_is_always_false() {
        let iter = EmptyRecordIterator::new();
        assert!(!iter.has_next());
    }

    #[test]
    fn test_next_is_always_none() {
        let mut iter = EmptyRecordIterator::new();
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn test_has_previous_is_always_false() {
        let iter = EmptyRecordIterator::new();
        assert!(!iter.has_previous().unwrap());
    }

    #[test]
    fn test_previous_is_always_none() {
        let mut iter = EmptyRecordIterator::new();
        assert!(iter.previous().unwrap().is_none());
    }

    #[test]
    fn test_delete_is_always_false() {
        let mut iter = EmptyRecordIterator::new();
        assert!(!iter.delete().unwrap());
    }

    #[test]
    fn test_instance_singleton_behaves_the_same() {
        let mut instance = EmptyRecordIterator::INSTANCE;
        assert!(!instance.has_next());
        assert!(instance.next().unwrap().is_none());
    }
}
