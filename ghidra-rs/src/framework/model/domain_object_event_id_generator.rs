use std::sync::atomic::{AtomicI32, Ordering};

static NEXT_ID: AtomicI32 = AtomicI32::new(0);

/// Provides unique, compact ids for domain object event types.
pub struct DomainObjectEventIdGenerator;

impl DomainObjectEventIdGenerator {
    /// Returns the next unique event id. Ids are positive integers starting at 1.
    pub fn next() -> i32 {
        NEXT_ID.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn reset_counter(value: i32) {
        NEXT_ID.store(value, Ordering::SeqCst);
    }

    #[test]
    fn test_first_id_is_positive() {
        reset_counter(0);
        assert!(DomainObjectEventIdGenerator::next() > 0);
    }

    #[test]
    fn test_ids_are_sequential() {
        reset_counter(0);
        let a = DomainObjectEventIdGenerator::next();
        let b = DomainObjectEventIdGenerator::next();
        assert_eq!(b, a + 1);
    }

    #[test]
    fn test_ids_are_unique() {
        reset_counter(0);
        let ids: Vec<i32> = (0..10).map(|_| DomainObjectEventIdGenerator::next()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }

    #[test]
    fn test_starts_at_one_after_reset() {
        reset_counter(0);
        assert_eq!(DomainObjectEventIdGenerator::next(), 1);
    }
}
