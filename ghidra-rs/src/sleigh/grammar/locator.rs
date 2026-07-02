use std::collections::BTreeMap;
use super::Location;

/// Maps expanded line numbers to real source locations.
///
/// Mirrors `ghidra.sleigh.grammar.Locator`, providing a bidirectional mapping
/// from expanded line numbers (in a preprocessed file) to actual source file locations.
pub struct Locator {
    map: BTreeMap<i32, Location>,
}

impl Locator {
    /// Creates a new empty `Locator`.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Registers a mapping from an expanded line number to its real source location.
    ///
    /// Mirrors `ghidra.sleigh.grammar.Locator.registerLocation`.
    pub fn register_location(&mut self, expanded_line_no: i32, real_location: Location) {
        self.map.insert(expanded_line_no, real_location);
    }

    /// Gets the real source location for a given expanded line number.
    ///
    /// Mirrors `ghidra.sleigh.grammar.Locator.getLocation`, returning the location
    /// based on the registered mappings. The algorithm finds the largest registered
    /// line number less than or equal to the query, then calculates the actual line
    /// number by adjusting for the difference.
    ///
    /// Returns `None` if no mapping exists for or before the expanded line number.
    pub fn get_location(&self, expanded_line_no: i32) -> Option<Location> {
        let head_map = self.map.range(..=expanded_line_no);
        let (key, location) = head_map.last()?;
        let actual_line_number = expanded_line_no - key + location.lineno;
        Some(Location::new(location.filename.clone(), actual_line_number))
    }
}

impl Default for Locator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_retrieve_single_mapping() {
        let mut locator = Locator::new();
        let loc = Location::new("test.sleigh", 10);
        locator.register_location(100, loc);

        let result = locator.get_location(100);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.filename, "test.sleigh");
        assert_eq!(retrieved.lineno, 10);
    }

    #[test]
    fn get_location_with_offset() {
        let mut locator = Locator::new();
        let loc = Location::new("file.sleigh", 5);
        locator.register_location(10, loc);

        let result = locator.get_location(15);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.filename, "file.sleigh");
        assert_eq!(retrieved.lineno, 10);
    }

    #[test]
    fn get_location_exact_match() {
        let mut locator = Locator::new();
        let loc = Location::new("exact.sleigh", 20);
        locator.register_location(50, loc);

        let result = locator.get_location(50);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.lineno, 20);
    }

    #[test]
    fn get_location_uses_closest_preceding_mapping() {
        let mut locator = Locator::new();
        locator.register_location(10, Location::new("a.sleigh", 1));
        locator.register_location(20, Location::new("b.sleigh", 5));
        locator.register_location(30, Location::new("c.sleigh", 10));

        let result = locator.get_location(25);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.filename, "b.sleigh");
        assert_eq!(retrieved.lineno, 10);
    }

    #[test]
    fn get_location_before_any_mapping_returns_none() {
        let mut locator = Locator::new();
        locator.register_location(100, Location::new("test.sleigh", 10));
        let result = locator.get_location(50);
        assert!(result.is_none());
    }

    #[test]
    fn get_location_on_empty_locator_returns_none() {
        let locator = Locator::new();
        let result = locator.get_location(1);
        assert!(result.is_none());
    }

    #[test]
    fn multiple_registrations_with_updates() {
        let mut locator = Locator::new();
        locator.register_location(100, Location::new("old.sleigh", 5));
        locator.register_location(100, Location::new("new.sleigh", 10));

        let result = locator.get_location(100);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.filename, "new.sleigh");
        assert_eq!(retrieved.lineno, 10);
    }

    #[test]
    fn large_line_offset() {
        let mut locator = Locator::new();
        let loc = Location::new("large.sleigh", 1);
        locator.register_location(1000, loc);

        let result = locator.get_location(2000);
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.lineno, 1001);
    }

    #[test]
    fn default_creates_empty_locator() {
        let locator = Locator::default();
        let result = locator.get_location(1);
        assert!(result.is_none());
    }
}
