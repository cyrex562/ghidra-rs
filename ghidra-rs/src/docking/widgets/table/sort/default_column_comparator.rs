use std::any::Any;
use std::cmp::Ordering;

/// A column comparator that is used when columns do not supply their own comparator.
/// This comparator will use natural sorting (i.e., the value implements `Ord`),
/// defaulting to the String representation for the given value.
///
/// Corresponds to `docking.widgets.table.sort.DefaultColumnComparator` in the Java source.
pub struct DefaultColumnComparator;

impl DefaultColumnComparator {
    /// Creates a new `DefaultColumnComparator`.
    pub fn new() -> Self {
        DefaultColumnComparator
    }

    /// Compares two values using the default comparison strategy.
    ///
    /// The comparison strategy is:
    /// 1. If either value is `None`, handle via null comparison
    /// 2. If both are strings, compare case-insensitively
    /// 3. If both are the same type and implement `Ord`, compare using `Ord`
    /// 4. Otherwise return `Equal` to signal further comparing is needed
    pub fn compare(&self, o1: Option<&dyn Any>, o2: Option<&dyn Any>) -> Ordering {
        match (o1, o2) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(v1), Some(v2)) => self.compare_values(v1, v2),
        }
    }

    fn compare_values(&self, o1: &dyn Any, o2: &dyn Any) -> Ordering {
        if let (Some(s1), Some(s2)) = (o1.downcast_ref::<String>(), o2.downcast_ref::<String>()) {
            return self.compare_as_strings(s1, s2);
        }

        if let (Some(s1), Some(s2)) = (o1.downcast_ref::<&str>(), o2.downcast_ref::<&str>()) {
            return self.compare_as_str_refs(s1, s2);
        }

        if let (Some(i1), Some(i2)) = (o1.downcast_ref::<i32>(), o2.downcast_ref::<i32>()) {
            return i1.cmp(i2);
        }

        if let (Some(i1), Some(i2)) = (o1.downcast_ref::<i64>(), o2.downcast_ref::<i64>()) {
            return i1.cmp(i2);
        }

        if let (Some(f1), Some(f2)) = (o1.downcast_ref::<f64>(), o2.downcast_ref::<f64>()) {
            return f1.partial_cmp(f2).unwrap_or(Ordering::Equal);
        }

        if let (Some(f1), Some(f2)) = (o1.downcast_ref::<f32>(), o2.downcast_ref::<f32>()) {
            return f1.partial_cmp(f2).unwrap_or(Ordering::Equal);
        }

        if let (Some(b1), Some(b2)) = (o1.downcast_ref::<bool>(), o2.downcast_ref::<bool>()) {
            return b1.cmp(b2);
        }

        if let (Some(u1), Some(u2)) = (o1.downcast_ref::<usize>(), o2.downcast_ref::<usize>()) {
            return u1.cmp(u2);
        }

        Ordering::Equal
    }

    fn compare_as_strings(&self, s1: &str, s2: &str) -> Ordering {
        let lower1 = s1.to_lowercase();
        let lower2 = s2.to_lowercase();
        lower1.cmp(&lower2)
    }

    fn compare_as_str_refs(&self, s1: &&str, s2: &&str) -> Ordering {
        self.compare_as_strings(s1, s2)
    }
}

impl Default for DefaultColumnComparator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_none_returns_equal() {
        let comparator = DefaultColumnComparator::new();
        assert_eq!(comparator.compare(None, None), Ordering::Equal);
    }

    #[test]
    fn left_none_returns_less() {
        let comparator = DefaultColumnComparator::new();
        let s = "test".to_string();
        assert_eq!(
            comparator.compare(None, Some(&s as &dyn Any)),
            Ordering::Less
        );
    }

    #[test]
    fn right_none_returns_greater() {
        let comparator = DefaultColumnComparator::new();
        let s = "test".to_string();
        assert_eq!(
            comparator.compare(Some(&s as &dyn Any), None),
            Ordering::Greater
        );
    }

    #[test]
    fn string_comparison_case_insensitive() {
        let comparator = DefaultColumnComparator::new();
        let s1 = "Apple".to_string();
        let s2 = "banana".to_string();

        let result = comparator.compare(Some(&s1 as &dyn Any), Some(&s2 as &dyn Any));
        assert_eq!(result, Ordering::Less);

        let result = comparator.compare(Some(&s2 as &dyn Any), Some(&s1 as &dyn Any));
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn string_comparison_equal_case_insensitive() {
        let comparator = DefaultColumnComparator::new();
        let s1 = "Test".to_string();
        let s2 = "test".to_string();

        let result = comparator.compare(Some(&s1 as &dyn Any), Some(&s2 as &dyn Any));
        assert_eq!(result, Ordering::Equal);
    }

    #[test]
    fn str_ref_comparison_case_insensitive() {
        let comparator = DefaultColumnComparator::new();
        let s1: &str = "Hello";
        let s2: &str = "HELLO";

        let result = comparator.compare(Some(&s1 as &dyn Any), Some(&s2 as &dyn Any));
        assert_eq!(result, Ordering::Equal);
    }

    #[test]
    fn i32_comparison() {
        let comparator = DefaultColumnComparator::new();
        let a: i32 = 5;
        let b: i32 = 10;

        let result = comparator.compare(Some(&a as &dyn Any), Some(&b as &dyn Any));
        assert_eq!(result, Ordering::Less);

        let result = comparator.compare(Some(&b as &dyn Any), Some(&a as &dyn Any));
        assert_eq!(result, Ordering::Greater);

        let result = comparator.compare(Some(&a as &dyn Any), Some(&5 as &dyn Any));
        assert_eq!(result, Ordering::Equal);
    }

    #[test]
    fn i64_comparison() {
        let comparator = DefaultColumnComparator::new();
        let a: i64 = 100;
        let b: i64 = 200;

        let result = comparator.compare(Some(&a as &dyn Any), Some(&b as &dyn Any));
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn f64_comparison() {
        let comparator = DefaultColumnComparator::new();
        let a: f64 = 1.5;
        let b: f64 = 2.5;

        let result = comparator.compare(Some(&a as &dyn Any), Some(&b as &dyn Any));
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn bool_comparison() {
        let comparator = DefaultColumnComparator::new();
        let f: bool = false;
        let t: bool = true;

        let result = comparator.compare(Some(&f as &dyn Any), Some(&t as &dyn Any));
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn usize_comparison() {
        let comparator = DefaultColumnComparator::new();
        let a: usize = 5;
        let b: usize = 10;

        let result = comparator.compare(Some(&a as &dyn Any), Some(&b as &dyn Any));
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn different_types_returns_equal() {
        let comparator = DefaultColumnComparator::new();
        let i: i32 = 5;
        let s = "5".to_string();

        let result = comparator.compare(Some(&i as &dyn Any), Some(&s as &dyn Any));
        assert_eq!(result, Ordering::Equal);
    }

    #[test]
    fn f32_comparison() {
        let comparator = DefaultColumnComparator::new();
        let a: f32 = 1.5;
        let b: f32 = 2.5;

        let result = comparator.compare(Some(&a as &dyn Any), Some(&b as &dyn Any));
        assert_eq!(result, Ordering::Less);
    }
}
