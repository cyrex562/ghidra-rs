/// Direction of navigation through data types (forward or backward).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigationDirection {
    Forward,
    Backward,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variants_are_distinct() {
        assert_ne!(NavigationDirection::Forward, NavigationDirection::Backward);
    }

    #[test]
    fn test_clone_and_copy() {
        let dir = NavigationDirection::Forward;
        let cloned = dir;
        assert_eq!(dir, cloned);
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", NavigationDirection::Forward), "Forward");
        assert_eq!(format!("{:?}", NavigationDirection::Backward), "Backward");
    }
}
