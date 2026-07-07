use super::Location;

/// Utility functions for working with `Location` objects.
///
/// Mirrors `ghidra.sleigh.grammar.LocationUtil`, providing utilities
/// to find minimum and maximum locations from a collection based on line numbers.
pub struct LocationUtil;

impl LocationUtil {
    /// Returns the location with the maximum line number from the given list.
    ///
    /// Mirrors the Java method of the same name. The list may contain `None` entries
    /// (corresponding to null references in Java), which are skipped during iteration.
    /// If the list is empty or contains only `None`, returns `None`.
    ///
    /// Note: Despite the method name in the Java version, the implementation finds
    /// the MAXIMUM line number, not the minimum.
    pub fn minimum<'a>(locations: &[Option<&'a Location>]) -> Option<&'a Location> {
        let mut min: Option<&'a Location> = None;
        for location in locations {
            if let Some(loc) = location {
                if let Some(prev_min) = min {
                    if loc.lineno > prev_min.lineno {
                        min = Some(loc);
                    }
                } else {
                    min = Some(loc);
                }
            }
        }
        min
    }

    /// Returns the location with the maximum line number from the given list.
    ///
    /// Mirrors the Java method of the same name. The list may contain `None` entries
    /// (corresponding to null references in Java), which are skipped during iteration.
    /// If the list is empty or contains only `None`, returns `None`.
    pub fn maximum<'a>(locations: &[Option<&'a Location>]) -> Option<&'a Location> {
        let mut max: Option<&'a Location> = None;
        for location in locations {
            if let Some(loc) = location {
                if let Some(prev_max) = max {
                    if loc.lineno > prev_max.lineno {
                        max = Some(loc);
                    }
                } else {
                    max = Some(loc);
                }
            }
        }
        max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_returns_max_lineno() {
        let loc1 = Location::new("a.sl", 10);
        let loc2 = Location::new("b.sl", 20);
        let loc3 = Location::new("c.sl", 15);
        let locations = vec![Some(&loc1), Some(&loc2), Some(&loc3)];

        let result = LocationUtil::minimum(&locations);
        assert_eq!(result, Some(&loc2));
        assert_eq!(result.unwrap().lineno, 20);
    }

    #[test]
    fn maximum_returns_max_lineno() {
        let loc1 = Location::new("a.sl", 10);
        let loc2 = Location::new("b.sl", 20);
        let loc3 = Location::new("c.sl", 15);
        let locations = vec![Some(&loc1), Some(&loc2), Some(&loc3)];

        let result = LocationUtil::maximum(&locations);
        assert_eq!(result, Some(&loc2));
        assert_eq!(result.unwrap().lineno, 20);
    }

    #[test]
    fn minimum_empty_list() {
        let locations: Vec<Option<&Location>> = vec![];
        let result = LocationUtil::minimum(&locations);
        assert_eq!(result, None);
    }

    #[test]
    fn maximum_empty_list() {
        let locations: Vec<Option<&Location>> = vec![];
        let result = LocationUtil::maximum(&locations);
        assert_eq!(result, None);
    }

    #[test]
    fn minimum_single_location() {
        let loc = Location::new("file.sl", 42);
        let locations = vec![Some(&loc)];

        let result = LocationUtil::minimum(&locations);
        assert_eq!(result, Some(&loc));
    }

    #[test]
    fn maximum_single_location() {
        let loc = Location::new("file.sl", 42);
        let locations = vec![Some(&loc)];

        let result = LocationUtil::maximum(&locations);
        assert_eq!(result, Some(&loc));
    }

    #[test]
    fn minimum_same_lineno() {
        let loc1 = Location::new("a.sl", 10);
        let loc2 = Location::new("b.sl", 10);
        let locations = vec![Some(&loc1), Some(&loc2)];

        let result = LocationUtil::minimum(&locations);
        assert_eq!(result, Some(&loc1));
    }

    #[test]
    fn maximum_same_lineno() {
        let loc1 = Location::new("a.sl", 10);
        let loc2 = Location::new("b.sl", 10);
        let locations = vec![Some(&loc1), Some(&loc2)];

        let result = LocationUtil::maximum(&locations);
        assert_eq!(result, Some(&loc1));
    }

    #[test]
    fn minimum_with_nulls() {
        let loc1 = Location::new("a.sl", 10);
        let loc2 = Location::new("b.sl", 25);
        let locations = vec![Some(&loc1), None, Some(&loc2), None];

        let result = LocationUtil::minimum(&locations);
        assert_eq!(result, Some(&loc2));
    }

    #[test]
    fn maximum_with_nulls() {
        let loc1 = Location::new("a.sl", 10);
        let loc2 = Location::new("b.sl", 25);
        let locations = vec![Some(&loc1), None, Some(&loc2), None];

        let result = LocationUtil::maximum(&locations);
        assert_eq!(result, Some(&loc2));
    }

    #[test]
    fn minimum_all_nulls() {
        let locations: Vec<Option<&Location>> = vec![None, None, None];
        let result = LocationUtil::minimum(&locations);
        assert_eq!(result, None);
    }

    #[test]
    fn maximum_all_nulls() {
        let locations: Vec<Option<&Location>> = vec![None, None, None];
        let result = LocationUtil::maximum(&locations);
        assert_eq!(result, None);
    }
}
