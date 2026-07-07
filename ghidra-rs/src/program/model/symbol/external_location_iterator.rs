//! Iterator for external locations.
//!
//! Port of `ghidra.program.model.symbol.ExternalLocationIterator`.

use crate::program::model::symbol::ExternalLocation;
use std::sync::Arc;

/// Iterator that returns external locations.
///
/// This mirrors Ghidra's `ExternalLocationIterator`, using `Option` in place of
/// Java's null return when no external location is available.
pub trait ExternalLocationIterator {
    /// Returns true when another external location is available.
    fn has_next(&self) -> bool;

    /// Returns the next external location, or `None` when no external location is available.
    fn next_external_location(&mut self) -> Option<Arc<dyn ExternalLocation>>;
}

/// Empty external location iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyExternalLocationIterator;

impl ExternalLocationIterator for EmptyExternalLocationIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_external_location(&mut self) -> Option<Arc<dyn ExternalLocation>> {
        None
    }
}

/// Adapter from a vector of external locations to an `ExternalLocationIterator`.
pub struct ExternalLocationIteratorAdapter {
    locations: Vec<Arc<dyn ExternalLocation>>,
    index: usize,
}

impl ExternalLocationIteratorAdapter {
    /// Creates an adapter over the supplied external locations.
    pub fn new(locations: Vec<Arc<dyn ExternalLocation>>) -> Self {
        Self { locations, index: 0 }
    }
}

impl ExternalLocationIterator for ExternalLocationIteratorAdapter {
    fn has_next(&self) -> bool {
        self.index < self.locations.len()
    }

    fn next_external_location(&mut self) -> Option<Arc<dyn ExternalLocation>> {
        if !self.has_next() {
            return None;
        }
        let location = self.locations[self.index].clone();
        self.index += 1;
        Some(location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_iterator_has_no_locations() {
        let mut iterator = EmptyExternalLocationIterator;

        assert!(!iterator.has_next());
        assert!(iterator.next_external_location().is_none());
    }

    #[test]
    fn adapter_iterates_locations_and_then_returns_none() {
        let locations: Vec<Arc<dyn ExternalLocation>> = vec![
            Arc::new(MockExternalLocation),
            Arc::new(MockExternalLocation),
        ];
        let mut iterator = ExternalLocationIteratorAdapter::new(locations);

        assert!(iterator.has_next());
        assert!(iterator.next_external_location().is_some());
        assert!(iterator.has_next());
        assert!(iterator.next_external_location().is_some());
        assert!(!iterator.has_next());
        assert!(iterator.next_external_location().is_none());
    }

    struct MockExternalLocation;

    impl ExternalLocation for MockExternalLocation {}
}
