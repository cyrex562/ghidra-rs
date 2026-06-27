use std::cmp::Ordering;

/// Comparator for comparing two data component paths.
pub struct DtComponentPathComparator;

impl DtComponentPathComparator {
    pub fn new() -> Self {
        Self
    }

    pub fn compare(&self, o1: &[i32], o2: &[i32]) -> Ordering {
        let len = o1.len().min(o2.len());
        for i in 0..len {
            let cmp = o1[i].cmp(&o2[i]);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
        o1.len().cmp(&o2.len())
    }
}

impl Default for DtComponentPathComparator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &[i32], b: &[i32]) -> Ordering {
        DtComponentPathComparator::new().compare(a, b)
    }

    #[test]
    fn test_equal_paths() {
        assert_eq!(cmp(&[1, 2, 3], &[1, 2, 3]), Ordering::Equal);
    }

    #[test]
    fn test_empty_paths() {
        assert_eq!(cmp(&[], &[]), Ordering::Equal);
    }

    #[test]
    fn test_first_element_differs() {
        assert_eq!(cmp(&[1, 2], &[2, 2]), Ordering::Less);
        assert_eq!(cmp(&[2, 2], &[1, 2]), Ordering::Greater);
    }

    #[test]
    fn test_later_element_differs() {
        assert_eq!(cmp(&[1, 1, 3], &[1, 1, 4]), Ordering::Less);
        assert_eq!(cmp(&[1, 1, 4], &[1, 1, 3]), Ordering::Greater);
    }

    #[test]
    fn test_prefix_is_less() {
        assert_eq!(cmp(&[1, 2], &[1, 2, 3]), Ordering::Less);
        assert_eq!(cmp(&[1, 2, 3], &[1, 2]), Ordering::Greater);
    }

    #[test]
    fn test_empty_vs_nonempty() {
        assert_eq!(cmp(&[], &[1]), Ordering::Less);
        assert_eq!(cmp(&[1], &[]), Ordering::Greater);
    }

    #[test]
    fn test_single_element_equal() {
        assert_eq!(cmp(&[5], &[5]), Ordering::Equal);
    }
}
